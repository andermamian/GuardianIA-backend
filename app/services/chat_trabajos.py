"""Respuestas del asistente que siguen generándose aunque el cliente se desconecte.

**El problema.** La respuesta se generaba DENTRO de la conexión HTTP: si el celular cambiaba de app,
giraba la pantalla o la persona cambiaba de chat, la conexión se cortaba y el servidor dejaba de
generar. La respuesta quedaba a medias.

**La solución.** Cada respuesta es un *trabajo*: se genera en un hilo propio y sus eventos se guardan
en memoria. Quien la está viendo los recibe en vivo; si se desconecta, el trabajo sigue y guarda la
respuesta completa en la conversación. Al volver, el cliente se reconecta y recibe los eventos desde
donde quedó (``desde=N``) o, si ya terminó, todo de una vez.

Los trabajos terminados se olvidan a los 15 minutos (la respuesta ya quedó guardada, cifrada, en la
base de datos). Es memoria de un solo proceso: con varios procesos detrás de un balanceador habría
que llevar esto a Redis.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Iterator

RETENCION_S = 15 * 60          # cuánto se recuerda un trabajo terminado
MAX_POR_USUARIO = 3            # trabajos simultáneos por persona (evita que un cliente agote el servidor)
MAX_GLOBAL = 64                # trabajos simultáneos en todo el servidor (muchas cuentas a la vez)
MAX_EVENTOS = 20_000           # tope de eventos por respuesta (memoria acotada aunque el modelo se desboque)


@dataclass
class Trabajo:
    id: str
    user_id: str
    conversation_id: str
    eventos: list[dict] = field(default_factory=list)
    terminado: bool = False
    cancelado: bool = False
    creado: float = field(default_factory=time.time)
    terminado_en: float | None = None
    _cond: threading.Condition = field(default_factory=threading.Condition, repr=False)

    def agregar(self, evento: dict) -> None:
        with self._cond:
            if len(self.eventos) >= MAX_EVENTOS:
                self.cancelado = True            # la generación se corta sola: memoria acotada
                return
            self.eventos.append(evento)
            self._cond.notify_all()

    def terminar(self) -> None:
        with self._cond:
            self.terminado = True
            self.terminado_en = time.time()
            self._cond.notify_all()

    def seguir(self, desde: int = 0, espera_max_s: float = 25.0) -> Iterator[tuple[int, dict | None]]:
        """Entrega (índice, evento) desde ``desde``. Si no llega nada en ``espera_max_s`` entrega
        (índice, None) como latido, para que el cliente sepa que la conexión sigue viva."""
        i = max(0, desde)
        while True:
            with self._cond:
                if i >= len(self.eventos) and not self.terminado:
                    self._cond.wait(timeout=espera_max_s)
                pendientes = self.eventos[i:]
                fin = self.terminado
            if pendientes:
                for ev in pendientes:
                    yield i, ev
                    i += 1
            elif fin:
                return
            else:
                yield i, None       # latido
            if fin and i >= len(self.eventos):
                return

    def resumen(self) -> dict:
        texto = "".join(e.get("texto", "") for e in self.eventos if e.get("tipo") == "texto")
        return {"trabajo_id": self.id, "conversation_id": self.conversation_id, "terminado": self.terminado,
                "cancelado": self.cancelado, "eventos": len(self.eventos), "texto_parcial": texto[-2000:],
                "creado": self.creado}


_trabajos: dict[str, Trabajo] = {}
_lock = threading.Lock()


class Ocupado(Exception):
    """La persona (o el servidor) ya tiene demasiadas respuestas generándose a la vez."""


def _limpiar() -> None:
    ahora = time.time()
    with _lock:
        for tid in [t.id for t in _trabajos.values() if t.terminado and t.terminado_en
                    and ahora - t.terminado_en > RETENCION_S]:
            _trabajos.pop(tid, None)


def iniciar(user_id: str, conversation_id: str, generar: Callable[[Trabajo], None]) -> Trabajo:
    """Crea el trabajo y lo arranca en un hilo. ``generar`` agrega eventos y guarda la respuesta."""
    _limpiar()
    with _lock:
        activos = [t for t in _trabajos.values() if not t.terminado]
        if len(activos) >= MAX_GLOBAL or sum(1 for t in activos if t.user_id == user_id) >= MAX_POR_USUARIO:
            raise Ocupado()
        t = Trabajo(id=uuid.uuid4().hex, user_id=user_id, conversation_id=conversation_id)
        _trabajos[t.id] = t

    def correr() -> None:
        try:
            generar(t)
        except Exception as e:  # noqa: BLE001 - el trabajo debe terminar siempre, pase lo que pase
            t.agregar({"tipo": "error", "mensaje": f"La respuesta falló ({type(e).__name__}). Intente de nuevo."})
        finally:
            t.terminar()

    threading.Thread(target=correr, name=f"chat-{t.id[:8]}", daemon=True).start()
    return t


def obtener(trabajo_id: str, user_id: str) -> Trabajo | None:
    """Solo el dueño puede ver su trabajo."""
    t = _trabajos.get(trabajo_id)
    return t if t is not None and t.user_id == user_id else None


def activos(user_id: str) -> list[Trabajo]:
    _limpiar()
    return sorted((t for t in _trabajos.values() if t.user_id == user_id and not t.terminado),
                  key=lambda t: t.creado)


def recientes(user_id: str) -> list[Trabajo]:
    _limpiar()
    return sorted((t for t in _trabajos.values() if t.user_id == user_id), key=lambda t: t.creado)


def cancelar(trabajo_id: str, user_id: str) -> bool:
    t = obtener(trabajo_id, user_id)
    if t is None or t.terminado:
        return False
    t.cancelado = True
    return True
