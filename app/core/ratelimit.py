"""Limitador de tasa por ventana deslizante.

En memoria para un solo proceso. Para varias réplicas, sustituir el almacén
por Redis (misma interfaz `hit`) — ver docs/SEGURIDAD.md.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from app.core.errors import ApiError


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_s: int = 60) -> None:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window_s:
                q.popleft()
            if len(q) >= limit:
                retry = max(1, int(window_s - (now - q[0])))
                raise ApiError(429, "rate_limited", "Demasiadas solicitudes, intente más tarde",
                               {"retry_after": retry})
            q.append(now)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()
