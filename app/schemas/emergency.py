from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import Out

Relation = Literal["family", "friends", "work", "other"]


def normalize_phone(raw: str) -> str:
    """Normaliza a E.164. Números colombianos de 10 dígitos (3xx / 60x) reciben +57."""
    digits = re.sub(r"[^\d+]", "", raw)
    if digits.startswith("00"):
        digits = "+" + digits[2:]
    if not digits.startswith("+"):
        if len(digits) == 10 and digits[0] in "36":
            digits = "+57" + digits
        elif digits.startswith("57") and len(digits) == 12:
            digits = "+" + digits
        else:
            raise ValueError("Número inválido: use formato internacional, p. ej. +57 300 123 4567")
    if not re.fullmatch(r"\+[1-9]\d{7,14}", digits):
        raise ValueError("Número inválido")
    return digits


class ContactIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    phone: str = Field(min_length=7, max_length=25)
    relation: Relation = "family"
    priority: int = Field(1, ge=1, le=20)
    notify_sms: bool = True
    notify_call: bool = True

    @field_validator("phone")
    @classmethod
    def _phone(cls, v: str) -> str:
        return normalize_phone(v)


class ContactPatch(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=100)
    phone: str | None = None
    relation: Relation | None = None
    priority: int | None = Field(None, ge=1, le=20)
    notify_sms: bool | None = None
    notify_call: bool | None = None

    @field_validator("phone")
    @classmethod
    def _phone(cls, v: str | None) -> str | None:
        return normalize_phone(v) if v else v


class ContactOut(Out):
    id: str
    name: str
    phone_e164: str
    relation: str
    priority: int
    notify_sms: bool
    notify_call: bool
    last_test_at: datetime | None
    last_test_status: str | None


class ContactsSummary(BaseModel):
    """Cabecera de activity_main: tv_total_contacts, tv_avg_response_time, tv_last_test."""
    total: int
    por_relacion: dict[str, int]
    tiempo_total_escalamiento_min: int
    ultima_prueba: datetime | None
    contactos: list[ContactOut]


class EmergencySettingsIO(BaseModel):
    auto_police: bool
    auto_call: bool
    live_location: bool
    wait_minutes: int = Field(ge=1, le=10)
    cancel_window_seconds: int = Field(30, ge=10, le=120)
    message_template: str = Field(max_length=300)

    @field_validator("message_template")
    @classmethod
    def _tpl(cls, v: str) -> str:
        allowed = {"nombre", "mapa"}
        used = set(re.findall(r"{(\w*)}", v))
        if not used <= allowed or "{mapa}" not in v:
            raise ValueError("Use solo {nombre} y {mapa}; {mapa} es obligatorio")
        return v


class ImportIn(BaseModel):
    contacts: list[ContactIn] = Field(max_length=50)


class ImportOut(BaseModel):
    creados: int
    omitidos_duplicados: int


class SosIn(BaseModel):
    lat: float | None = Field(None, ge=-90, le=90)
    lon: float | None = Field(None, ge=-180, le=180)
    kind: Literal["sos", "fall", "theft"] = "sos"
    note: str | None = Field(None, max_length=200)
    silent: bool = False
    # Contactos a los que el TELÉFONO ya les mandó el SMS desde su propia SIM (sin internet).
    # El servidor no se los repite: ni el SOS ni luego el «estoy bien».
    sms_desde_telefono: list[str] = Field(default_factory=list, max_length=20)


class IncidentOut(Out):
    id: str
    kind: str
    severity: str
    status: str
    summary: str
    lat: float | None
    lon: float | None
    plan: list[dict]
    timeline: list[dict]
    cancel_deadline: datetime | None
    created_at: datetime


class LocationPing(BaseModel):
    lat: float = Field(ge=-90, le=90)
    lon: float = Field(ge=-180, le=180)
