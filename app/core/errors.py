"""Errores con formato RFC 7807 (application/problem+json).

El cliente recibe un código estable y un mensaje apto para la interfaz;
el detalle técnico queda solo en el log del servidor.
"""
from __future__ import annotations

import logging
import traceback
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import get_settings

log = logging.getLogger("guardian.errors")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, extra: dict | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra or {}


def not_found(what: str = "recurso") -> ApiError:
    # 404 también para recursos de otro usuario: no se confirma que existan (anti-IDOR)
    return ApiError(404, "not_found", f"No se encontró el {what}")


def forbidden(msg: str = "No tiene permiso para esta acción") -> ApiError:
    return ApiError(403, "forbidden", msg)


def conflict(code: str, msg: str) -> ApiError:
    return ApiError(409, code, msg)


def _problem(request: Request, status: int, code: str, message: str, extra: dict | None = None):
    body = {
        "type": f"https://api.guardianai.dev/errors/{code}",
        "title": message,
        "status": status,
        "code": code,
        "request_id": getattr(request.state, "request_id", None),
    }
    if extra:
        body.update(extra)
    headers = {}
    if status == 429 and extra and "retry_after" in extra:
        headers["Retry-After"] = str(extra["retry_after"])
    return JSONResponse(body, status_code=status, media_type="application/problem+json", headers=headers)


def install(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api(request: Request, exc: ApiError):
        return _problem(request, exc.status, exc.code, exc.message, exc.extra)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        fields = [{"campo": ".".join(str(p) for p in e["loc"][1:]), "error": e["msg"]} for e in exc.errors()]
        return _problem(request, 422, "validation_error", "Datos inválidos", {"errores": fields})

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        return _problem(request, exc.status_code, "http_error", str(exc.detail))

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        incident = uuid.uuid4().hex[:12]
        log.exception("Error no controlado incidente=%s", incident)
        extra = {"incidente": incident}
        # Fuera de producción se devuelve la causa real: un «Error interno» sin más deja al
        # desarrollador adivinando. En producción nunca, porque la traza revela rutas y estructura.
        if not get_settings().is_production:
            extra["detalle"] = f"{type(exc).__name__}: {exc}"
            frame = next((f for f in reversed(traceback.extract_tb(exc.__traceback__))
                          if "/app/" in f.filename.replace("\\", "/")), None)
            if frame:
                extra["donde"] = f"{Path(frame.filename).name}:{frame.lineno} en {frame.name}()"
            extra["ayuda"] = "Detalle visible solo en desarrollo. Ejecute: python -m app.cli doctor"
        return _problem(request, 500, "internal_error", "Error interno", extra)
