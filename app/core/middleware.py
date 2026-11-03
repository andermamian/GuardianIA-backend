from __future__ import annotations

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import get_settings

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # La API sirve JSON; una CSP estricta evita que un navegador ejecute nada devuelto por error.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}

# "/vincular" es la página que abre el celular desde el QR: sin esto recibía la CSP de la API
# (default-src 'none') y el navegador bloqueaba TODO su CSS y JS, y además la ubicación.
WEB_PREFIXES = ("/app", "/consola", "/static", "/vincular")
# Interfaz web: solo recursos propios. Sin scripts ni estilos inline, sin CDNs, sin fuentes externas
# (una app de salud no debe avisarle a terceros cada vez que alguien la abre).
WEB_HEADERS = {
    # Única excepción externa: las imágenes del mapa (mosaicos de OpenStreetMap). Solo imágenes, nada
    # de scripts; OSM ve que se pidió un pedazo de mapa, no quién es el usuario ni el equipo.
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; style-src 'self'; "
                                "img-src 'self' data: blob: https://tile.openstreetmap.org; "
                                "connect-src 'self' ws: wss:; font-src 'self'; object-src 'none'; base-uri 'none'; "
                                "form-action 'self'; frame-ancestors 'none'"),
    # Ubicación para el SOS; nada más (Web Bluetooth lo controla el selector del navegador).
    "Permissions-Policy": "geolocation=(self), camera=(), microphone=(), payment=()",
}


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.request_id = request.headers.get("x-request-id", uuid.uuid4().hex)
        start = time.perf_counter()
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Response-Time-ms"] = f"{(time.perf_counter() - start) * 1000:.1f}"
        headers = {**SECURITY_HEADERS, **WEB_HEADERS} if request.url.path.startswith(WEB_PREFIXES) else SECURITY_HEADERS
        for k, v in headers.items():
            response.headers.setdefault(k, v)
        if get_settings().is_production:
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        limite = self.max_bytes
        if request.method == "POST" and request.url.path.endswith("/assistant/attachments"):
            limite = max(limite, get_settings().adjunto_max_mb * 1024 * 1024 + 1024 * 1024)
        if cl and cl.isdigit() and int(cl) > limite:
            from fastapi.responses import JSONResponse
            return JSONResponse({"code": "payload_too_large", "title": "La solicitud es demasiado grande",
                                 "status": 413}, status_code=413, media_type="application/problem+json")
        return await call_next(request)
