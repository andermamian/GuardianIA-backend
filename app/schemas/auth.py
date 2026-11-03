from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.common import Out


class UserOut(Out):
    id: str
    email: EmailStr
    full_name: str
    role: str
    plan: str
    totp_enabled: bool
    timezone: str
    created_at: datetime


class GeoHint(BaseModel):
    lat: float | None = Field(None, ge=-90, le=90)
    lon: float | None = Field(None, ge=-180, le=180)
    country: str | None = Field(None, min_length=2, max_length=2)


class RegisterIn(GeoHint):
    email: EmailStr
    full_name: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=1, max_length=128)
    phone: str | None = Field(None, max_length=20)
    birth_year: int | None = Field(None, ge=1900, le=2026)
    accept_terms: bool
    accept_health_data: bool = False
    device_id: str | None = Field(None, max_length=80)
    device_label: str | None = Field(None, max_length=120)

    @field_validator("accept_terms")
    @classmethod
    def _terms(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Debe aceptar los términos y la política de tratamiento de datos")
        return v


class LoginIn(GeoHint):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    device_id: str | None = Field(None, max_length=80)
    device_label: str | None = Field(None, max_length=120)


class AdminLoginIn(LoginIn):
    authorization_level: Literal["supervisor", "admin", "super_admin"]
    remember_session: bool = False


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str | None = Field(None, description="null en una renovación concurrente: conserve el refresh token vigente")
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class MfaChallengeOut(BaseModel):
    mfa_required: bool = True
    challenge_id: str
    expires_in: int
    motivo: str


class MfaVerifyIn(BaseModel):
    challenge_id: str
    code: str = Field(min_length=6, max_length=13)


class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=200)


class RecoveryIn(BaseModel):
    email: EmailStr


class ResetIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=1, max_length=128)


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=1, max_length=128)


class TotpSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class TotpEnableIn(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]
    aviso: str = "Guárdelos en un lugar seguro: solo se muestran una vez"


class BiometricRegisterIn(BaseModel):
    device_id: str = Field(min_length=4, max_length=80)
    label: str = Field(min_length=1, max_length=80)
    public_key: str = Field(min_length=40, max_length=2000, description="PEM o DER base64 de clave EC P-256")


class BiometricChallengeIn(BaseModel):
    email: EmailStr
    device_id: str = Field(min_length=4, max_length=80)


class BiometricChallengeOut(BaseModel):
    challenge_id: str
    challenge: str
    expires_in: int


class BiometricVerifyIn(BaseModel):
    challenge_id: str
    signature: str = Field(description="Firma ECDSA-SHA256 (DER, base64) del reto")
    device_label: str | None = None


class SessionOut(Out):
    id: str
    audience: str
    device_label: str | None
    ip: str | None
    country: str | None
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    actual: bool = False
