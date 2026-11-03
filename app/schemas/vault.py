from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import Out


class VaultFileOut(Out):
    id: str
    category: str
    filename: str
    mime: str
    size_bytes: int
    created_at: datetime


class VaultOverview(BaseModel):
    total_archivos: int
    por_categoria: dict[str, int]
    espacio_usado_mb: float
    archivos: list[VaultFileOut]


class SecretIn(BaseModel):
    """Cifrado de extremo a extremo: el cliente envía el blob ya cifrado; el servidor no ve el contenido."""
    ciphertext: str = Field(min_length=1, max_length=100000)
    strength: Literal["fuerte", "media", "debil"] | None = None
    breached: bool = False


class SecretOut(Out):
    id: str
    ciphertext: str
    strength: str | None
    breached: bool
    updated_at: datetime


class PasswordGenIn(BaseModel):
    length: int = Field(20, ge=8, le=64)
    symbols: bool = True


class PasswordGenOut(BaseModel):
    password: str
    entropy_bits: float
    fortaleza: str


class PasswordAuditOut(BaseModel):
    total: int
    fuertes: int
    medias: int
    debiles: int
    comprometidas: int
