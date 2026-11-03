"""Motor de recomendaciones con revisión humana (pantalla Configuration Center).

Flujo que la interfaz ya dibuja: Guardian propone → IA experta revisa → el administrador
APRUEBA, MODIFICA o RECHAZA. Nada clínico se aplica solo.

Las propuestas se basan en evidencia calculada sobre los datos, no en frases inventadas:
p. ej. «con umbral 40 BPM se habrían evitado N falsas alarmas en mayores de 65 sin perder
ningún evento confirmado».
"""
from __future__ import annotations

from dataclasses import dataclass

ENGINE_VERSION = "recs-1.0.0"


@dataclass
class Proposal:
    area: str
    setting_key: str
    current_value: dict
    proposed_value: dict
    rationale: str
    evidence: dict
    expert_review: str


def propose_lockout(failed_bursts_24h: int, current_max: int) -> Proposal | None:
    if failed_bursts_24h < 10 or current_max <= 3:
        return None
    return Proposal(
        area="security", setting_key="auth.max_failed_logins",
        current_value={"intentos": current_max}, proposed_value={"intentos": max(3, current_max - 2)},
        rationale=f"Se detectaron {failed_bursts_24h} ráfagas de intentos fallidos en 24 h.",
        evidence={"rafagas_24h": failed_bursts_24h},
        expert_review=("Reducir intentos aumenta bloqueos legítimos; combinar con bloqueo progresivo y "
                       "CAPTCHA en lugar de solo bajar el número."),
    )
