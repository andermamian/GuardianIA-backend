"""Hub de eventos en tiempo real (WebSocket) — seguro para llamar desde endpoints síncronos."""
from __future__ import annotations

import asyncio
import threading
from collections import defaultdict


class Hub:
    def __init__(self) -> None:
        self._subs: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

    def subscribe(self, channel: str) -> asyncio.Queue:
        self._loop = asyncio.get_running_loop()
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        with self._lock:
            self._subs[channel].add(q)
        return q

    def unsubscribe(self, channel: str, q: asyncio.Queue) -> None:
        with self._lock:
            self._subs[channel].discard(q)

    def escuchando(self, channel: str) -> bool:
        """¿Hay alguien suscrito ahora mismo? (p. ej., el teléfono con su canal en vivo abierto)."""
        with self._lock:
            return bool(self._subs.get(channel))

    def publish(self, channel: str, event: dict) -> None:
        with self._lock:
            queues = list(self._subs.get(channel, ()))
        if not queues or self._loop is None:
            return
        for q in queues:
            def _put(q=q):
                if q.full():
                    q.get_nowait()  # descarta el más viejo: el cliente lento no bloquea a nadie
                q.put_nowait(event)
            self._loop.call_soon_threadsafe(_put)


hub = Hub()


def user_channel(user_id: str) -> str:
    return f"user:{user_id}"


def device_channel(device_id: str) -> str:
    """Canal del propio equipo: por aquí le llegan las órdenes del dueño al instante."""
    return f"device:{device_id}"


STAFF_CHANNEL = "staff"
