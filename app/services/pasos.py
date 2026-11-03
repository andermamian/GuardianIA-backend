"""Pasos visibles del asistente: lo que la pantalla de progreso (estilo «computadora de Manus») muestra.

Cada paso tiene un título, la herramienta que usa, sus argumentos, una salida en vivo (terminal) y un
resultado. Se transmiten como eventos del chat (``paso``, ``paso_info``, ``paso_salida``, ``paso_fin``);
la pantalla los dibuja y deja revisar cualquier paso ya terminado."""
from __future__ import annotations

MAX_ARG = 600
MAX_RESULTADO = 1500


def _recortar(valor, limite: int):
    if isinstance(valor, str):
        return valor if len(valor) <= limite else valor[:limite] + "…"
    if isinstance(valor, dict):
        return {k: _recortar(v, limite) for k, v in list(valor.items())[:12]}
    if isinstance(valor, list):
        return [_recortar(v, limite) for v in valor[:12]]
    return valor


class Pasos:
    def __init__(self, trabajo) -> None:
        self.t = trabajo
        self.n = 0
        self.abierto: int | None = None

    def abrir(self, titulo: str, herramienta: str = "", args: dict | None = None, detalle: str = "") -> int:
        if self.abierto is not None:                  # un paso a la vez: el anterior se cierra solo
            self.cerrar()
        self.n += 1
        self.abierto = self.n
        self.t.agregar({"tipo": "paso", "id": self.n, "titulo": titulo, "herramienta": herramienta,
                        "args": _recortar(args or {}, MAX_ARG), "detalle": detalle, "estado": "activo"})
        return self.n

    def info(self, detalle: str) -> None:
        if self.abierto is not None:
            self.t.agregar({"tipo": "paso_info", "id": self.abierto, "detalle": detalle})

    def salida(self, texto: str, canal: str = "stdout") -> None:
        if self.abierto is not None and texto:
            self.t.agregar({"tipo": "paso_salida", "id": self.abierto, "texto": texto, "canal": canal})

    def cerrar(self, ok: bool = True, resultado: str = "") -> None:
        if self.abierto is None:
            return
        self.t.agregar({"tipo": "paso_fin", "id": self.abierto, "estado": "hecho" if ok else "error",
                        "resultado": _recortar(resultado, MAX_RESULTADO)})
        self.abierto = None
