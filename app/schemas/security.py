from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import Out


# ---------------------------------------------------------------- antivirus
class FileScanIn(BaseModel):
    name: str = Field(min_length=1, max_length=260)
    size: int = Field(ge=0, le=5_000_000_000)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    kind: Literal["pe", "apk", "elf", "pdf", "office", "script", "zip", "unknown"] = "unknown"
    header_hex: str = Field("", max_length=256)
    strings: list[str] = Field(default_factory=list, max_length=400)
    entropy: float | None = Field(None, ge=0, le=8)
    imports: list[str] = Field(default_factory=list, max_length=400)
    yara_hits: list[str] = Field(default_factory=list, max_length=50)
    is_signed: bool = False
    signer: str | None = Field(None, max_length=120)


class BehaviorIn(BaseModel):
    contacted_hosts: list[str] = Field(default_factory=list, max_length=100)
    dns_queries: list[str] = Field(default_factory=list, max_length=100)
    files_written: list[str] = Field(default_factory=list, max_length=200)
    files_encrypted: int = Field(0, ge=0)
    processes_spawned: list[str] = Field(default_factory=list, max_length=100)
    persistence: list[str] = Field(default_factory=list, max_length=50)
    requested_admin: bool = False
    reads_sms: bool = False
    keylogging_api: bool = False
    screen_capture: bool = False


class ScanIn(BaseModel):
    file: FileScanIn
    behavior: BehaviorIn | None = None
    device_id: str | None = Field(None, max_length=80)


class AiPayloadIn(BaseModel):
    text: str = Field(min_length=1, max_length=20000)


class ScanOut(BaseModel):
    resultado: dict
    alerta_generada: bool


# --------------------------------------------------------------- app vigilancia
class PermissionScanIn(BaseModel):
    device_id: str | None = Field(None, max_length=80)
    package: str = Field(min_length=1, max_length=200)
    label: str = Field(min_length=1, max_length=120)
    version: str | None = Field(None, max_length=40)
    installer: str | None = Field(None, max_length=120)
    cert_sha256: str | None = Field(None, max_length=64)
    category: str | None = Field(None, max_length=30)
    target_sdk: int | None = Field(None, ge=1, le=40)
    permissions: list[str] = Field(default_factory=list, max_length=200)
    bytes_rx: int = Field(0, ge=0)
    bytes_tx: int = Field(0, ge=0)
    night_tx_ratio: float = Field(0.0, ge=0, le=1)


class AppScanBatchIn(BaseModel):
    device_id: str | None = None
    apps: list[PermissionScanIn] = Field(min_length=1, max_length=500)


class AppAssessmentOut(Out):
    id: str
    package: str
    label: str
    verdict: str
    score: int
    reasons: list[dict]
    user_action: str | None
    scanned_at: datetime


class AppOverview(BaseModel):
    total: int
    seguras: int
    sospechosas: int
    peligrosas: int
    distribucion_permisos: dict
    apps: list[AppAssessmentOut]


class AppActionIn(BaseModel):
    action: Literal["allowed", "restricted", "quarantined", "removed"]


# ----------------------------------------------------------------- escudo web
class UrlCheckIn(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class UrlCheckOut(BaseModel):
    host: str
    dominio: str
    veredicto: str
    puntaje: int
    categoria: str | None
    motivos: list[dict]


class WebRuleIn(BaseModel):
    kind: Literal["allow", "block"]
    domain: str = Field(min_length=3, max_length=253)


class WebRuleOut(Out):
    id: str
    kind: str
    domain: str
    created_at: datetime


class CategoryPolicyIn(BaseModel):
    category: Literal["adultos", "apuestas", "juegos", "redes_sociales", "phishing"]
    action: Literal["block", "allow", "schedule"]
    schedule: dict = Field(default_factory=dict)


# ------------------------------------------------------------------- chat IA
class ChatIn(BaseModel):
    """Mensaje al asistente. `crear_archivos` permite que genere documentos cuando se los piden."""
    message: str = Field(min_length=1, max_length=60000)
    conversation_id: str | None = None
    allow_web: bool = True
    crear_archivos: bool = True


class SourceOut(BaseModel):
    titulo: str
    url: str
    fragmento: str = ""


class ChatOut(BaseModel):
    conversation_id: str
    respuesta: str
    proveedor: str
    busco_en_web: bool
    fuentes: list[SourceOut]
    acciones_sugeridas: list[dict]
    seguridad: dict


class ConversationOut(Out):
    id: str
    title: str
    created_at: datetime


class ChatMessageOut(BaseModel):
    role: str
    content: str
    created_at: datetime
    id: str | None = None
    files: list[dict] = Field(default_factory=list)      # archivos creados en este mensaje (con su descarga)
    sources: list[dict] = Field(default_factory=list)


class PersonalityIO(BaseModel):
    friendliness: int = Field(70, ge=0, le=100)
    protection: int = Field(70, ge=0, le=100)
    proactivity: int = Field(50, ge=0, le=100)
    verbosity: int = Field(90, ge=0, le=100)
    humor: int = Field(30, ge=0, le=100)
    mode: Literal["home", "work", "emergency"] = "home"
    assistant_name: str = Field("Asistente AI", min_length=1, max_length=30)


# ---------------------------------------------------------------------- VPN
class VpnServerOut(BaseModel):
    id: str
    country: str
    city: str
    host: str
    port: int
    protocol: str
    is_premium: bool
    load: float
    latency_ms: int


class VpnRecommendIn(BaseModel):
    purpose: Literal["general", "streaming", "gaming", "privacy", "download", "anonimato"] = "general"
    user_country: str | None = Field(None, min_length=2, max_length=2)
    target_country: str | None = Field(None, min_length=2, max_length=2)


class VpnRecommendationOut(BaseModel):
    servidor: VpnServerOut
    puntaje: float
    latencia_estimada_ms: int
    motivos: list[str]
    alternativas: list[dict]
    engine_version: str


class VpnPingIn(BaseModel):
    server_id: str
    latency_ms: float = Field(ge=0, le=10000)

