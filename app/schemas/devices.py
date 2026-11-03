from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import Out


class DeviceRegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    platform: Literal["android", "ios", "windows", "other"] = "android"
    model: str | None = Field(None, max_length=80)
    os_version: str | None = Field(None, max_length=20)


class DeviceRegisterOut(BaseModel):
    id: str
    device_token: str = Field(description="Guárdelo: autentica al dispositivo en /telemetry y comandos")


class DeviceOut(Out):
    id: str
    name: str
    platform: str
    model: str | None
    os_version: str | None = None
    status: str
    battery: int | None
    charging: bool | None = None
    last_lat: float | None
    last_lon: float | None
    last_accuracy_m: float | None = None
    last_fix_at: datetime | None = None
    last_seen_at: datetime | None
    created_at: datetime | None = None
    tracking_enabled: bool = True
    gps_status: str | None = None
    report_interval_s: int | None = None
    device_info: dict | None = None
    en_linea: bool = False
    canal_en_vivo: bool = False
    tiene_identificacion: bool = False


class DeviceInfoIn(BaseModel):
    """Datos que el navegador del equipo conoce de sí mismo. Campos fijos y acotados: el servidor no
    guarda un JSON arbitrario que un cliente malicioso pudiera inflar."""
    model_config = {"extra": "ignore"}
    modelo: str | None = Field(None, max_length=80)
    sistema: str | None = Field(None, max_length=40)
    version_sistema: str | None = Field(None, max_length=20)
    navegador: str | None = Field(None, max_length=60)
    pantalla: str | None = Field(None, max_length=20)
    idioma: str | None = Field(None, max_length=20)
    zona_horaria: str | None = Field(None, max_length=60)
    red: str | None = Field(None, max_length=20)             # wifi | cellular | …
    red_calidad: str | None = Field(None, max_length=10)     # 4g | 3g | 2g | slow-2g
    red_mbps: float | None = Field(None, ge=0, le=10000)
    memoria_gb: float | None = Field(None, ge=0, le=1024)
    nucleos: int | None = Field(None, ge=0, le=512)
    pestana_visible: bool | None = None
    pantalla_activa: bool | None = None                      # Wake Lock concedido


class TelemetryIn(BaseModel):
    device_token: str = Field(min_length=20)
    battery: int | None = Field(None, ge=0, le=100)
    charging: bool | None = None
    lat: float | None = Field(None, ge=-90, le=90)
    lon: float | None = Field(None, ge=-180, le=180)
    accuracy_m: float | None = Field(None, ge=0)
    speed_ms: float | None = Field(None, ge=0, le=400)
    gps: Literal["ok", "https_required", "denied", "unavailable", "paused", "waiting"] | None = None
    info: DeviceInfoIn | None = None


class TrackingIn(BaseModel):
    activo: bool


class DeviceCommandIn(BaseModel):
    kind: Literal["ring", "lock", "locate", "message", "wipe", "photo", "sos"]
    message: str | None = Field(None, max_length=200)
    confirm_wipe: bool = False
    # SOS remoto: el teléfono enviará SMS de emergencia a los contactos con SU SIM. Exige confirmación.
    confirm_sos: bool = False


class DeviceCommandOut(Out):
    id: str
    kind: str
    status: str
    created_at: datetime


class PendingCommandOut(BaseModel):
    id: str
    kind: str
    payload: dict
    signature: str


class LostModeIn(BaseModel):
    status: Literal["lost", "stolen", "ok"]
    message: str | None = Field(None, max_length=200)


def _luhn_ok(n: str) -> bool:
    total = 0
    for i, c in enumerate(reversed(n)):
        d = int(c)
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


class IdentificacionIn(BaseModel):
    """Datos para denunciar y bloquear el equipo. Los escribe el dueño: marcando *#06# el teléfono
    muestra su IMEI; ninguna app ni página web puede leerlo por su cuenta en Android 10 o superior."""
    imei: str = Field(description="15 dígitos, lo muestra *#06#")
    imei2: str | None = Field(None, description="Segundo IMEI en teléfonos con doble SIM")
    numero: str | None = Field(None, max_length=20)
    operador: Literal["Claro", "Movistar", "Tigo", "WOM", "ETB", "Virgin", "Otro"] | None = None
    color: str | None = Field(None, max_length=40)
    senas: str | None = Field(None, max_length=200, description="Forro, rayones, stickers: ayuda a reconocerlo")

    @field_validator("imei", "imei2")
    @classmethod
    def _imei(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        n = "".join(ch for ch in v if ch.isdigit())
        if len(n) != 15 or not _luhn_ok(n):
            raise ValueError("El IMEI son 15 dígitos (márquelo con *#06#); este no es válido, revise que esté completo")
        return n

    @field_validator("numero")
    @classmethod
    def _numero(cls, v: str | None) -> str | None:
        if not v:
            return None
        n = "".join(ch for ch in v if ch.isdigit())
        if n.startswith("57") and len(n) == 12:
            n = n[2:]
        if len(n) != 10 or not n.startswith("3"):
            raise ValueError("Escriba el celular colombiano de 10 dígitos (ej. 3001234567)")
        return "+57" + n
