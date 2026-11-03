"""VPN con IA — motor de selección inteligente de servidor.

La app Android ya define el contrato (VPNServerManager.kt):
    GET servers            → lista de servidores
    GET servers/ping       → latencia de un servidor
Este servicio lo respeta y añade la parte "IA": en vez de que la persona elija a ciegas,
un modelo de puntuación recomienda el mejor servidor según lo que quiere hacer.

La "IA" aquí es un optimizador multicriterio explicable (no una caja negra):
* Cada servidor recibe una puntuación 0-100 combinando latencia, carga, cercanía geográfica
  y ajuste al propósito (streaming, privacidad, juegos, general).
* Los pesos cambian según el propósito: para juegos manda la latencia; para privacidad,
  la jurisdicción y la baja carga.
* Aprende de la experiencia: registra la latencia real observada por los clientes (EWMA) y
  la usa para corregir la latencia anunciada de cada servidor.
* Explica por qué recomendó ese servidor.

Nada de esto cifra tráfico por sí mismo: la VPN real es WireGuard en los servidores. Este
servicio orquesta y recomienda; entregar la configuración de WireGuard se hace aparte.
"""
from __future__ import annotations

from dataclasses import dataclass, field

ENGINE_VERSION = "vpn-ai-1.0.0"

# Jurisdicciones con leyes de privacidad más protectoras (para el propósito "privacidad").
PRIVACY_FRIENDLY = {"CH", "IS", "PA", "RO", "SE"}
# Aproximación de continente por país, para estimar cercanía sin geolocalización exacta.
REGION = {"CO": "SA", "PE": "SA", "BR": "SA", "AR": "SA", "CL": "SA", "MX": "NA", "US": "NA", "CA": "NA",
          "ES": "EU", "DE": "EU", "FR": "EU", "GB": "EU", "NL": "EU", "CH": "EU", "SE": "EU", "RO": "EU",
          "IS": "EU", "JP": "AS", "SG": "AS", "IN": "AS", "PA": "NA"}


@dataclass
class Server:
    id: str
    country: str
    city: str
    host: str
    port: int
    protocol: str = "wireguard"
    is_premium: bool = False
    load: float = 0.0          # 0..1 ocupación
    latency_ms: int = 0        # latencia anunciada
    active: bool = True


@dataclass
class Recommendation:
    server: Server
    score: float
    reasons: list[str]
    estimated_latency_ms: int


@dataclass
class ScoredServer:
    server: Server
    score: float
    breakdown: dict = field(default_factory=dict)


PURPOSE_WEIGHTS = {
    "general":    {"latency": 0.35, "load": 0.30, "distance": 0.25, "purpose": 0.10},
    "streaming":  {"latency": 0.25, "load": 0.35, "distance": 0.15, "purpose": 0.25},
    "gaming":     {"latency": 0.55, "load": 0.25, "distance": 0.15, "purpose": 0.05},
    "privacy":    {"latency": 0.15, "load": 0.25, "distance": 0.05, "purpose": 0.55},
    "download":   {"latency": 0.15, "load": 0.45, "distance": 0.15, "purpose": 0.25},
    # Anonimato: lo que importa es la jurisdicción de salida; la cercanía no suma (salir por su propio
    # país lo deja bajo las mismas leyes y el mismo operador de red).
    "anonimato":  {"latency": 0.10, "load": 0.20, "distance": 0.00, "purpose": 0.70},
}


def _distance_score(user_country: str | None, server_country: str) -> float:
    if user_country is None:
        return 0.6
    if user_country == server_country:
        return 1.0
    if REGION.get(user_country) == REGION.get(server_country):
        return 0.75
    return 0.35


def _purpose_score(purpose: str, s: Server, target_country: str | None, user_country: str | None = None) -> float:
    if purpose == "anonimato":
        from app.ai.anonimato import jurisdiccion
        base = jurisdiccion(s.country)["puntaje"]
        return base * (0.6 if user_country and s.country == user_country else 1.0)
    if purpose == "privacy":
        return 1.0 if s.country in PRIVACY_FRIENDLY else 0.4
    if purpose == "streaming":
        # Streaming: suele quererse un país concreto (catálogo). Si se pidió, prémialo.
        return 1.0 if target_country and s.country == target_country else 0.5
    if purpose == "gaming":
        return 0.9 if s.protocol == "wireguard" else 0.5
    return 0.7


def score_server(s: Server, purpose: str, user_country: str | None, target_country: str | None,
                 observed_latency: dict[str, float]) -> ScoredServer:
    w = PURPOSE_WEIGHTS.get(purpose, PURPOSE_WEIGHTS["general"])
    eff_latency = observed_latency.get(s.id, float(s.latency_ms) or 80.0)
    latency_score = max(0.0, 1.0 - min(eff_latency, 400) / 400)
    load_score = max(0.0, 1.0 - s.load)
    distance_score = _distance_score(user_country, s.country)
    purpose_score = _purpose_score(purpose, s, target_country, user_country)
    total = 100 * (w["latency"] * latency_score + w["load"] * load_score +
                   w["distance"] * distance_score + w["purpose"] * purpose_score)
    return ScoredServer(s, round(total, 1), {"latencia": round(latency_score, 2), "carga": round(load_score, 2),
                                             "cercania": round(distance_score, 2),
                                             "ajuste_proposito": round(purpose_score, 2),
                                             "latencia_estimada_ms": round(eff_latency)})


def recommend(servers: list[Server], *, purpose: str = "general", user_country: str | None = None,
              target_country: str | None = None, allow_premium: bool = True,
              observed_latency: dict[str, float] | None = None) -> Recommendation | None:
    observed_latency = observed_latency or {}
    pool = [s for s in servers if s.active and (allow_premium or not s.is_premium)]
    if not pool:
        return None
    scored = sorted((score_server(s, purpose, user_country, target_country, observed_latency) for s in pool),
                    key=lambda x: -x.score)
    best = scored[0]
    reasons = []
    b = best.breakdown
    if b["latencia_estimada_ms"] <= 60:
        reasons.append(f"Baja latencia (~{b['latencia_estimada_ms']} ms)")
    if best.server.load < 0.4:
        reasons.append("Servidor poco ocupado")
    if b["cercania"] >= 0.75 and purpose != "anonimato":
        reasons.append("Cercano a su ubicación")
    if purpose == "anonimato":
        from app.ai.anonimato import jurisdiccion
        j = jurisdiccion(best.server.country)
        if j["alianza"] == "ninguna":
            reasons.append(f"Fuera de las alianzas de vigilancia 5/9/14 Ojos ({best.server.country})")
        if user_country and best.server.country != user_country:
            reasons.append("Sale por otro país: queda fuera de las leyes y del operador de su país")
    if purpose == "privacy" and best.server.country in PRIVACY_FRIENDLY:
        reasons.append(f"Jurisdicción con buena protección de datos ({best.server.country})")
    if purpose == "streaming" and target_country and best.server.country == target_country:
        reasons.append(f"Ubicado en {target_country} para el catálogo que busca")
    if not reasons:
        reasons.append("Mejor equilibrio general entre velocidad y carga")
    return Recommendation(best.server, best.score, reasons, b["latencia_estimada_ms"])


def rank(servers: list[Server], *, purpose: str = "general", user_country: str | None = None,
         target_country: str | None = None, observed_latency: dict[str, float] | None = None,
         limit: int = 10) -> list[ScoredServer]:
    observed_latency = observed_latency or {}
    scored = [score_server(s, purpose, user_country, target_country, observed_latency)
              for s in servers if s.active]
    return sorted(scored, key=lambda x: -x.score)[:limit]


def update_observed_latency(prev: float | None, sample_ms: float, alpha: float = 0.3) -> float:
    """Media móvil exponencial: el sistema aprende la latencia real que ven los clientes."""
    return sample_ms if prev is None else round(alpha * sample_ms + (1 - alpha) * prev, 1)


def anomaly_in_load(servers: list[Server]) -> list[str]:
    """Detecta servidores saturados (para el balanceo y las alertas de operación)."""
    return [s.id for s in servers if s.active and s.load >= 0.9]
