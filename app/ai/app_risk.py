"""Evaluación explicable de riesgo de aplicaciones Android (pantalla Vigilancia de Aplicaciones).

No es un antivirus por firmas. Es un modelo de puntuación basado en cómo opera el malware
móvil real en la región (troyanos bancarios, robo de OTP por SMS, stalkerware):

* Permisos peligrosos ponderados por abuso conocido.
* COMBINACIONES de permisos (la señal fuerte): Accesibilidad + superposición de pantalla es
  el patrón clásico de troyano bancario; SMS + Internet es robo de códigos de verificación.
* Procedencia: instalada fuera de Google Play.
* Comportamiento: transmisión de datos de madrugada y subida desproporcionada.
* Listas de certificados maliciosos conocidos (inteligencia de amenazas).

Cada punto suma una razón legible: la persona entiende POR QUÉ se marca una app.
"""
from __future__ import annotations

from dataclasses import dataclass, field

ENGINE_VERSION = "apprisk-1.3.0"
TRUSTED_INSTALLERS = {"com.android.vending", "com.google.android.feedback", "com.sec.android.app.samsungapps",
                      "com.huawei.appmarket"}

P = "android.permission."
PERMISSION_WEIGHTS: dict[str, tuple[int, str]] = {
    P + "BIND_ACCESSIBILITY_SERVICE": (22, "Puede leer y controlar todo lo que aparece en pantalla"),
    P + "BIND_DEVICE_ADMIN": (18, "Pide ser administrador del dispositivo (dificulta desinstalarla)"),
    P + "SYSTEM_ALERT_WINDOW": (12, "Puede dibujar ventanas encima de otras apps"),
    P + "REQUEST_INSTALL_PACKAGES": (12, "Puede instalar otras aplicaciones"),
    P + "READ_SMS": (14, "Lee sus mensajes SMS"),
    P + "RECEIVE_SMS": (10, "Recibe SMS entrantes (códigos de verificación)"),
    P + "SEND_SMS": (10, "Puede enviar SMS con costo"),
    P + "READ_CALL_LOG": (9, "Lee el historial de llamadas"),
    P + "PROCESS_OUTGOING_CALLS": (9, "Intercepta llamadas salientes"),
    P + "READ_CONTACTS": (6, "Lee sus contactos"),
    P + "RECORD_AUDIO": (8, "Usa el micrófono"),
    P + "CAMERA": (5, "Usa la cámara"),
    P + "ACCESS_BACKGROUND_LOCATION": (9, "Conoce su ubicación incluso sin usar la app"),
    P + "ACCESS_FINE_LOCATION": (4, "Conoce su ubicación precisa"),
    P + "QUERY_ALL_PACKAGES": (5, "Ve todas las apps instaladas (p. ej. bancos)"),
    P + "MANAGE_EXTERNAL_STORAGE": (8, "Acceso completo a sus archivos"),
    P + "BIND_NOTIFICATION_LISTENER_SERVICE": (12, "Lee todas sus notificaciones"),
    P + "PACKAGE_USAGE_STATS": (5, "Sabe qué apps usa y cuándo"),
    P + "READ_PHONE_STATE": (4, "Lee identificadores del teléfono"),
}

COMBOS: list[tuple[set[str], int, str]] = [
    ({P + "BIND_ACCESSIBILITY_SERVICE", P + "SYSTEM_ALERT_WINDOW"}, 25,
     "Patrón de troyano bancario: controla la pantalla y superpone formularios falsos"),
    ({P + "READ_SMS", P + "INTERNET"}, 15, "Puede leer códigos de verificación y enviarlos a internet"),
    ({P + "BIND_NOTIFICATION_LISTENER_SERVICE", P + "INTERNET"}, 10,
     "Puede extraer códigos de las notificaciones"),
    ({P + "RECORD_AUDIO", P + "ACCESS_BACKGROUND_LOCATION", P + "READ_SMS"}, 20,
     "Patrón de stalkerware: micrófono, ubicación y mensajes a la vez"),
    ({P + "REQUEST_INSTALL_PACKAGES", P + "BIND_ACCESSIBILITY_SERVICE"}, 15,
     "Patrón de «dropper»: instala otras apps y se da permisos a sí misma"),
]

# Apps donde ciertos permisos son esperables (reduce falsos positivos).
EXPECTED_BY_CATEGORY = {
    "messaging": {P + "READ_SMS", P + "RECEIVE_SMS", P + "SEND_SMS", P + "READ_CONTACTS", P + "RECORD_AUDIO",
                  P + "CAMERA"},
    "navigation": {P + "ACCESS_FINE_LOCATION", P + "ACCESS_BACKGROUND_LOCATION"},
    "accessibility": {P + "BIND_ACCESSIBILITY_SERVICE"},
    "security": {P + "BIND_DEVICE_ADMIN", P + "QUERY_ALL_PACKAGES", P + "PACKAGE_USAGE_STATS"},
}


@dataclass
class AppSample:
    package: str
    label: str
    permissions: list[str]
    installer: str | None = None
    cert_sha256: str | None = None
    category: str | None = None
    bytes_rx: int = 0
    bytes_tx: int = 0
    night_tx_ratio: float = 0.0  # fracción de bytes subidos entre 00:00 y 05:00
    target_sdk: int | None = None


@dataclass
class AppVerdict:
    score: int
    verdict: str
    reasons: list[dict] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    engine_version: str = ENGINE_VERSION


def assess_app(app: AppSample, known_bad_certs: set[str] | None = None) -> AppVerdict:
    reasons: list[dict] = []
    score = 0
    perms = set(app.permissions)
    expected = EXPECTED_BY_CATEGORY.get(app.category or "", set())

    if app.cert_sha256 and known_bad_certs and app.cert_sha256.lower() in known_bad_certs:
        return AppVerdict(100, "peligrosa", [{"puntos": 100, "motivo": "Firma digital de malware conocido"}],
                          ["eliminar", "cambiar_contrasenas"])

    for perm in sorted(perms):
        if perm in PERMISSION_WEIGHTS and perm not in expected:
            pts, why = PERMISSION_WEIGHTS[perm]
            score += pts
            reasons.append({"puntos": pts, "motivo": why})

    for combo, pts, why in COMBOS:
        if combo <= perms and not combo <= (expected | {P + "INTERNET"}):
            score += pts
            reasons.append({"puntos": pts, "motivo": why})

    sideloaded = app.installer not in TRUSTED_INSTALLERS
    if sideloaded:
        pts = 15 if score >= 20 else 6
        score += pts
        reasons.append({"puntos": pts, "motivo": "Instalada fuera de una tienda oficial"})

    if app.target_sdk is not None and app.target_sdk < 26:
        score += 8
        reasons.append({"puntos": 8, "motivo": "Diseñada para Android antiguo y así esquiva protecciones modernas"})

    total = app.bytes_rx + app.bytes_tx
    if app.night_tx_ratio >= 0.4 and app.bytes_tx > 5_000_000:
        score += 15
        reasons.append({"puntos": 15, "motivo": "Envía datos principalmente de madrugada"})
    if total > 10_000_000 and app.bytes_tx / max(total, 1) > 0.6 and app.category not in ("backup", "media"):
        score += 12
        reasons.append({"puntos": 12, "motivo": "Sube mucha más información de la que descarga"})

    score = min(100, score)
    if score >= 60:
        verdict, actions = "peligrosa", ["cuarentena", "eliminar", "revisar_cuentas_bancarias"]
    elif score >= 30:
        verdict, actions = "sospechosa", ["revisar_permisos", "restringir"]
    else:
        verdict, actions = "segura", []
    reasons.sort(key=lambda r: -r["puntos"])
    return AppVerdict(score, verdict, reasons, actions)


def permission_distribution(assessments: list[tuple[list[str], str]]) -> dict:
    """Resumen «Distribución de permisos» + «Permisos críticos detectados»."""
    critical_keys = {
        "acceso_pantalla": {P + "BIND_ACCESSIBILITY_SERVICE"},
        "ubicacion_segundo_plano": {P + "ACCESS_BACKGROUND_LOCATION"},
        "camara_y_microfono": {P + "CAMERA", P + "RECORD_AUDIO"},
        "sms": {P + "READ_SMS"},
    }
    buckets = {"seguros": 0, "medios": 0, "criticos": 0}
    critical_counts = {k: 0 for k in critical_keys}
    for perms, verdict in assessments:
        buckets[{"segura": "seguros", "sospechosa": "medios", "peligrosa": "criticos"}[verdict]] += 1
        s = set(perms)
        for k, needed in critical_keys.items():
            if needed <= s:
                critical_counts[k] += 1
    n = max(1, len(assessments))
    return {"porcentajes": {k: round(100 * v / n) for k, v in buckets.items()}, "apps_con_permiso_critico":
            critical_counts, "total_apps": len(assessments)}
