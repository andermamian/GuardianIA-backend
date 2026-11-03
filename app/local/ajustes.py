"""Dónde guarda la protección local su estado, y los ajustes que sobreviven a un reinicio."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

RAIZ_PROYECTO = Path(__file__).resolve().parents[2]
_lock = threading.Lock()

POR_DEFECTO = {
    "tiempo_real": True,             # vigilancia de descargas, escritorio, temporales, USB y procesos
    "cuarentena_automatica": True,   # aísla solo lo malicioso con evidencia fuerte
    "segunda_opinion_defender": True,
    "auto_rapido_horas": 6,
    "auto_completo_dias": 7,
    "rendimiento": "auto",
    "propietario": None,             # cuenta que recibe las alertas del tiempo real y los automáticos
    "ultimo_rapido": 0.0,
    "ultimo_completo": 0.0,
    "exclusiones_sha256": [],        # falsos positivos que la persona restauró
    "exclusiones_rutas": [],
}


def carpeta() -> Path:
    base = Path(os.environ.get("GUARDIAN_LOCAL_DIR") or RAIZ_PROYECTO / "data" / "local")
    base.mkdir(parents=True, exist_ok=True)
    return base


def sub(nombre: str) -> Path:
    p = carpeta() / nombre
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass
    return p


def _archivo() -> Path:
    return carpeta() / "ajustes.json"


def leer() -> dict:
    with _lock:
        try:
            datos = json.loads(_archivo().read_text("utf-8"))
        except (OSError, ValueError):
            datos = {}
    return {**POR_DEFECTO, **datos}


def guardar(cambios: dict) -> dict:
    with _lock:
        try:
            actual = json.loads(_archivo().read_text("utf-8"))
        except (OSError, ValueError):
            actual = {}
        actual.update(cambios)
        tmp = _archivo().with_suffix(".tmp")
        tmp.write_text(json.dumps(actual, ensure_ascii=False, indent=1), "utf-8")
        os.replace(tmp, _archivo())
    return {**POR_DEFECTO, **actual}
