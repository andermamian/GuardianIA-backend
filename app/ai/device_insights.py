"""Análisis de un dispositivo a partir de SUS datos reales (ubicaciones, batería, latidos).

No hay números inventados: si no hay datos suficientes para una conclusión, se dice «sin datos»
en lugar de adivinar. Todo es estadística simple y explicable, porque el dueño debe poder
entender por qué el sistema le dice «está fuera de su zona habitual» antes de actuar.

Qué calcula:
* movimiento: quieto / caminando / en vehículo, con la velocidad del GPS o la de los dos últimos puntos.
* recorrido de las últimas 24 h, ignorando el «temblor» del GPS (saltos menores que la precisión).
* consumo de batería por hora (regresión lineal) y horas restantes estimadas.
* zona habitual: la celda de ~250 m donde más tiempo pasa el equipo en 30 días; y si ahora está lejos.
* calidad del GPS y un nivel de riesgo con recomendaciones concretas.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

CELDA_GRADOS = 0.0025          # ≈ 250-280 m en Colombia: agrupa «casa», «colegio», «trabajo»
MIN_PUNTOS_ZONA = 10           # por debajo, la zona habitual sería una suposición
DISTANCIA_FUERA_KM = 1.0


@dataclass
class Punto:
    lat: float
    lon: float
    t: datetime
    precision_m: float | None = None
    bateria: int | None = None
    velocidad_ms: float | None = None


def _utc(t: datetime) -> datetime:
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def distancia_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _movimiento(puntos: list[Punto], ahora: datetime) -> dict:
    if not puntos:
        return {"estado": "sin_datos", "velocidad_kmh": None, "texto": "Aún no hay posiciones GPS."}
    ultimo = puntos[-1]
    if (ahora - _utc(ultimo.t)) > timedelta(minutes=10):
        return {"estado": "sin_datos", "velocidad_kmh": None,
                "texto": "La última posición tiene más de 10 minutos: no se sabe si se mueve ahora."}
    kmh = None
    if ultimo.velocidad_ms is not None:
        kmh = ultimo.velocidad_ms * 3.6
    elif len(puntos) >= 2:
        prev = puntos[-2]
        horas = (_utc(ultimo.t) - _utc(prev.t)).total_seconds() / 3600
        d = distancia_km(prev.lat, prev.lon, ultimo.lat, ultimo.lon)
        ruido_km = max(ultimo.precision_m or 0, prev.precision_m or 0) / 1000
        if horas > 0:
            kmh = 0.0 if d <= ruido_km else d / horas
    if kmh is None:
        return {"estado": "sin_datos", "velocidad_kmh": None, "texto": "Hace falta una posición más para medir movimiento."}
    kmh = round(kmh, 1)
    if kmh < 1.5:
        return {"estado": "quieto", "velocidad_kmh": kmh, "texto": "El equipo está quieto."}
    if kmh < 8:
        return {"estado": "caminando", "velocidad_kmh": kmh, "texto": f"Se mueve a pie (~{kmh:.0f} km/h)."}
    return {"estado": "en_vehiculo", "velocidad_kmh": kmh, "texto": f"Se mueve en un vehículo (~{kmh:.0f} km/h)."}


def _recorrido_km(puntos: list[Punto]) -> float:
    total = 0.0
    for a, b in zip(puntos, puntos[1:]):
        d = distancia_km(a.lat, a.lon, b.lat, b.lon)
        ruido = max(a.precision_m or 0, b.precision_m or 0) / 1000
        if d > ruido:            # el GPS «tiembla» unos metros aunque el equipo no se mueva
            total += d
    return round(total, 2)


def _bateria(puntos: list[Punto], actual: int | None, cargando: bool | None, ahora: datetime,
             gps_status: str | None = None) -> dict:
    if actual is None:
        texto = ("Batería no disponible: Chrome solo la entrega en páginas https://, igual que el GPS."
                 if gps_status == "https_required" else "El equipo no ha reportado batería.")
        return {"consumo_por_hora": None, "horas_restantes": None, "texto": texto}
    if cargando:
        return {"consumo_por_hora": None, "horas_restantes": None, "texto": f"{actual} % y cargando."}
    desde = ahora - timedelta(hours=6)
    muestras = [(_utc(p.t), p.bateria) for p in puntos if p.bateria is not None and _utc(p.t) >= desde]
    if len(muestras) < 3 or (muestras[-1][0] - muestras[0][0]) < timedelta(minutes=20):
        return {"consumo_por_hora": None, "horas_restantes": None,
                "texto": f"{actual} %. Faltan datos para estimar cuánto dura (se necesitan ~20 min de lecturas)."}
    t0 = muestras[0][0]
    xs = [(t - t0).total_seconds() / 3600 for t, _ in muestras]
    ys = [float(b) for _, b in muestras]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    den = sum((x - mx) ** 2 for x in xs)
    pendiente = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den if den else 0.0
    consumo = round(-pendiente, 1)
    if consumo <= 0.2:
        return {"consumo_por_hora": max(consumo, 0.0), "horas_restantes": None,
                "texto": f"{actual} %. La batería se mantiene estable."}
    horas = round(actual / consumo, 1)
    return {"consumo_por_hora": consumo, "horas_restantes": horas,
            "texto": f"{actual} %, baja ~{consumo:.0f} % por hora: le quedan unas {horas:.0f} h."}


def _celda(lat: float, lon: float) -> tuple[int, int]:
    return (math.floor(lat / CELDA_GRADOS), math.floor(lon / CELDA_GRADOS))


def _zona(historial: list[Punto], lat: float | None, lon: float | None) -> dict:
    buenos = [p for p in historial if (p.precision_m or 0) <= 150]
    if len(buenos) < MIN_PUNTOS_ZONA:
        return {"conocida": False, "fuera": None, "distancia_km": None,
                "texto": f"Aún aprendiendo su zona habitual ({len(buenos)} de {MIN_PUNTOS_ZONA} posiciones)."}
    (cy, cx), n = Counter(_celda(p.lat, p.lon) for p in buenos).most_common(1)[0]
    en_celda = [p for p in buenos if _celda(p.lat, p.lon) == (cy, cx)]
    zlat = sum(p.lat for p in en_celda) / len(en_celda)
    zlon = sum(p.lon for p in en_celda) / len(en_celda)
    base = {"conocida": True, "lat": round(zlat, 5), "lon": round(zlon, 5),
            "porcentaje_tiempo": round(100 * n / len(buenos))}
    if lat is None or lon is None:
        return {**base, "fuera": None, "distancia_km": None, "texto": "Zona habitual conocida; falta la posición actual."}
    d = round(distancia_km(zlat, zlon, lat, lon), 2)
    fuera = d > DISTANCIA_FUERA_KM
    texto = (f"Está a {d:.1f} km de su zona habitual." if fuera
             else "Está en su zona habitual.")
    return {**base, "fuera": fuera, "distancia_km": d, "texto": texto}


def _calidad_gps(precision_m: float | None, gps_status: str | None) -> dict:
    motivos = {
        "https_required": "El navegador bloquea el GPS porque la página no se abrió con https://.",
        "denied": "El permiso de ubicación fue negado en el teléfono.",
        "unavailable": "El teléfono no logra leer el GPS (¿ubicación apagada?).",
        "paused": "El seguimiento está pausado desde el PC.",
        "waiting": "Esperando la primera lectura del GPS.",
    }
    if gps_status in motivos:
        return {"nivel": "sin_gps" if gps_status != "waiting" else "esperando", "texto": motivos[gps_status]}
    if precision_m is None:
        return {"nivel": "sin_datos", "texto": "Sin lecturas de GPS todavía."}
    if precision_m <= 25:
        return {"nivel": "buena", "texto": f"Precisión de ±{precision_m:.0f} m."}
    if precision_m <= 100:
        return {"nivel": "aceptable", "texto": f"Precisión de ±{precision_m:.0f} m (probablemente en interiores)."}
    return {"nivel": "pobre", "texto": f"Precisión de ±{precision_m:.0f} m: es una ubicación aproximada por red."}


def analizar(*, estado: str, en_linea: bool, visto: datetime | None, bateria: int | None, cargando: bool | None,
             lat: float | None, lon: float | None, precision_m: float | None, gps_status: str | None,
             seguimiento: bool, puntos_24h: list[Punto], historial_30d: list[Punto],
             ahora: datetime | None = None) -> dict:
    ahora = ahora or datetime.now(timezone.utc)
    mov = _movimiento(puntos_24h, ahora)
    bat = _bateria(puntos_24h, bateria, cargando, ahora, gps_status)
    zona = _zona(historial_30d, lat, lon)
    gps = _calidad_gps(precision_m, gps_status)

    riesgo, recomendaciones = 0, []
    reportado = estado in ("lost", "stolen")
    if reportado:
        riesgo += 45 if estado == "stolen" else 35
    if not en_linea:
        riesgo += 20 if reportado else 5
        recomendaciones.append("No está reportando: revise que la pestaña de GuardianIA siga abierta en el "
                               "teléfono y que tenga internet." if not reportado else
                               "Dejó de reportar. Use la última ubicación del historial para la denuncia.")
    if bateria is not None and bateria <= 15 and not cargando:
        riesgo += 15 if reportado else 5
        recomendaciones.append("Batería baja: es probable que se apague pronto. Anote ya la última ubicación.")
    if zona.get("fuera"):
        riesgo += 20 if reportado else 10
        if not reportado:
            recomendaciones.append("Está lejos de donde suele estar. Si no lo tiene usted, márquelo como perdido.")
    if reportado and mov["estado"] == "en_vehiculo":
        riesgo += 15
        recomendaciones.append("Se desplaza en un vehículo: no lo persiga. Entregue la ubicación a la Policía (123).")
    if gps["nivel"] == "sin_gps":
        riesgo += 10 if reportado else 3
        if gps_status == "https_required":
            recomendaciones.append("Abra GuardianIA con HTTPS (INICIAR_GUARDIANIA.bat) y vuelva a vincular: "
                                   "sin eso el teléfono no puede entregar su GPS.")
        elif gps_status == "denied":
            recomendaciones.append("En el teléfono, toque el candado junto a la dirección y permita la ubicación.")
    if not seguimiento:
        recomendaciones.append("El seguimiento está pausado. Toque «Conectar» para volver a recibir su ubicación.")
    if reportado and not recomendaciones:
        recomendaciones.append("Denuncie en adenunciar.policia.gov.co o en el 123 y bloquee el IMEI con su operador.")

    riesgo = min(100, riesgo)
    nivel = "alto" if riesgo >= 60 else "medio" if riesgo >= 25 else "bajo"
    return {
        "riesgo": {"puntaje": riesgo, "nivel": nivel},
        "movimiento": mov,
        "recorrido_24h_km": _recorrido_km(puntos_24h) if len(puntos_24h) >= 2 else None,
        "bateria": bat,
        "zona_habitual": zona,
        "gps": gps,
        "recomendaciones": recomendaciones,
        "posiciones_24h": len(puntos_24h),
        "visto": visto,
        "generado": ahora,
    }
