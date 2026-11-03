"""Zonas horarias que no tumban el servicio.

Windows no incluye la base de datos IANA que usa `zoneinfo`: sin el paquete `tzdata`,
`ZoneInfo("America/Bogota")` lanza ZoneInfoNotFoundError. Eso rompía el registro y el ingreso,
porque la hora local se usa para calcular el riesgo del acceso.

Una dependencia de sistema ausente no puede impedir que alguien entre a una app de seguridad:
se registra el problema una vez y se sigue con UTC, lo que a lo sumo hace menos fino el
análisis de «hora inusual».
"""
from __future__ import annotations

import logging
from datetime import timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

log = logging.getLogger("guardian")
_avisadas: set[str] = set()


def zone(name: str | None, default: str = "America/Bogota") -> tzinfo:
    key = name or default
    try:
        return ZoneInfo(key)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        if key not in _avisadas:
            _avisadas.add(key)
            log.warning(
                "No se encontró la zona horaria '%s'; se usará UTC. En Windows instale la base de "
                "datos de zonas:  pip install tzdata  (ya está en requirements.txt)", key)
        return timezone.utc


def available(name: str | None = "America/Bogota") -> bool:
    """Para el diagnóstico: ¿está instalada la base de zonas horarias?"""
    try:
        ZoneInfo(name or "America/Bogota")
        return True
    except Exception:  # noqa: BLE001
        return False
