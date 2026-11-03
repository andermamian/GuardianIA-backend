"""Riesgo de inicio de sesión (UEBA ligero) — alimenta el Security & Audit Center.

Señales: dispositivo nuevo, país nuevo, «viaje imposible», ráfaga de fallos desde la IP,
horario atípico para la persona. El resultado decide: permitir, pedir segundo factor o bloquear.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime

ENGINE_VERSION = "loginrisk-1.1.0"


@dataclass
class LoginContext:
    at: datetime
    ip: str
    device_id: str | None
    country: str | None
    lat: float | None
    lon: float | None
    local_hour: int


@dataclass
class PastLogin:
    at: datetime
    device_id: str | None
    country: str | None
    lat: float | None
    lon: float | None
    local_hour: int


@dataclass
class LoginRisk:
    score: int
    decision: str  # allow|step_up|deny
    reasons: list[str] = field(default_factory=list)
    engine_version: str = ENGINE_VERSION


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def assess_login(ctx: LoginContext, history: list[PastLogin], failures_from_ip_15m: int) -> LoginRisk:
    score, reasons = 0, []
    if history:
        devices = {h.device_id for h in history if h.device_id}
        if ctx.device_id and devices and ctx.device_id not in devices:
            score += 25
            reasons.append("Dispositivo nunca usado antes")
        countries = {h.country for h in history if h.country}
        if ctx.country and countries and ctx.country not in countries:
            score += 25
            reasons.append(f"Primer acceso desde {ctx.country}")
        last = max(history, key=lambda h: h.at)
        if None not in (ctx.lat, ctx.lon, last.lat, last.lon):
            hours = max((ctx.at - last.at).total_seconds() / 3600, 1 / 60)
            km = haversine_km(last.lat, last.lon, ctx.lat, ctx.lon)
            if km > 500 and km / hours > 900:
                score += 45
                reasons.append(f"Viaje imposible: {int(km)} km en {hours:.1f} h")
        hours_seen = [h.local_hour for h in history]
        if len(hours_seen) >= 10:
            usual = sum(1 for h in hours_seen if abs(h - ctx.local_hour) <= 2 or abs(h - ctx.local_hour) >= 22)
            if usual / len(hours_seen) < 0.05:
                score += 10
                reasons.append("Horario muy distinto al habitual")
    if failures_from_ip_15m >= 20:
        score += 40
        reasons.append("Ataque de fuerza bruta desde esta IP")
    elif failures_from_ip_15m >= 5:
        score += 15
        reasons.append("Varios intentos fallidos recientes desde esta IP")
    score = min(100, score)
    decision = "deny" if score >= 80 else "step_up" if score >= 40 else "allow"
    return LoginRisk(score, decision, reasons)
