"""Sandbox de código: prueba lo que escribe el asistente y muestra la salida en vivo (SSE).

Solo desde este mismo equipo, solo cuando la persona pulsa «Ejecutar» y con límites de tiempo, memoria y salida
(ver app/local/sandbox.py para qué aísla y qué no)."""
from __future__ import annotations

import json
import threading

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.api.deps import DB, CurrentUser, client_ip
from app.api.v1.local import solo_este_equipo
from app.core import audit
from app.core.errors import ApiError
from app.core.ratelimit import limiter
from app.local import sandbox

router = APIRouter(prefix="/sandbox", tags=["Sandbox de código"], dependencies=[Depends(solo_este_equipo)])
_simultaneas = threading.BoundedSemaphore(2)


class EjecutarIn(BaseModel):
    language: str = Field("python", max_length=20)
    code: str = Field(min_length=1, max_length=sandbox.MAX_CODIGO)
    timeout: float = Field(sandbox.TIMEOUT_DEFECTO, ge=1, le=sandbox.TIMEOUT_MAXIMO)
    modo: str = Field("auto", pattern="^(auto|docker|proceso)$")


@router.get("/estado")
def estado(p: CurrentUser):
    return sandbox.estado()


@router.post("/ejecutar")
def ejecutar(body: EjecutarIn, request: Request, p: CurrentUser, db: DB):
    limiter.hit(f"sandbox:{p.user.id}", 20, 60)
    try:
        lenguaje = sandbox.normalizar(body.language)
    except sandbox.ErrorSandbox as e:
        raise ApiError(422, "lenguaje_no_disponible", str(e)) from e
    if not _simultaneas.acquire(blocking=False):
        raise ApiError(429, "sandbox_ocupado", "Ya hay dos ejecuciones en curso. Espere a que termine alguna.")
    audit.record(db, "sandbox.ejecutar", actor_id=p.user.id, target_type="sandbox", target_id=lenguaje,
                 ip=client_ip(request), detail={"lenguaje": lenguaje, "caracteres": len(body.code)})

    def eventos():
        try:
            try:
                for ev in sandbox.ejecutar(lenguaje, body.code, body.timeout, body.modo):
                    yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
            except sandbox.ErrorSandbox as e:
                yield f"data: {json.dumps({'tipo': 'error', 'mensaje': str(e)}, ensure_ascii=False)}\n\n"
        finally:
            _simultaneas.release()

    return StreamingResponse(eventos(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
