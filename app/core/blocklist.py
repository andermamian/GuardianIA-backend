"""Bloqueo de IP aplicado antes de tocar cualquier endpoint.

La tabla blocked_ips existía pero nada la consultaba: un bloqueo desde la consola no tenía efecto.
Se consulta desde un caché que se refresca cada 30 s (y al instante cuando la consola bloquea o
desbloquea) para no pegarle a la base de datos en cada petición.
"""
from __future__ import annotations

import ipaddress
import threading
import time

from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.security import utcnow

_TTL = 30.0


class Blocklist:
    def __init__(self) -> None:
        self._ips: set[str] = set()
        self._loaded_at = 0.0
        self._lock = threading.Lock()

    def invalidate(self) -> None:
        self._loaded_at = 0.0

    def _refresh(self) -> None:
        from app.db.models import BlockedIP
        from app.db.session import SessionLocal
        db = SessionLocal()
        try:
            now = utcnow()
            rows = db.execute(select(BlockedIP.ip, BlockedIP.expires_at)).all()
            self._ips = {r.ip for r in rows if r.expires_at is None or r.expires_at > now}
        finally:
            db.close()
        self._loaded_at = time.monotonic()

    def is_blocked(self, ip: str) -> bool:
        if time.monotonic() - self._loaded_at > _TTL:
            with self._lock:
                if time.monotonic() - self._loaded_at > _TTL:
                    try:
                        self._refresh()
                    except Exception:
                        # Falla abierta para no tumbar la API si la BD tiene un tropiezo;
                        # el limitador de tasa y la autenticación siguen protegiendo.
                        self._loaded_at = time.monotonic() - _TTL + 5
        return ip in self._ips


blocklist = Blocklist()


def normalize_ip(raw: str) -> str:
    return str(ipaddress.ip_address(raw.strip()))


class BlockedIPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else None
        if ip and blocklist.is_blocked(ip):
            return JSONResponse({"code": "ip_blocked", "title": "Acceso denegado", "status": 403},
                                status_code=403, media_type="application/problem+json")
        return await call_next(request)
