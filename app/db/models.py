"""Modelo de datos.

Principios aplicados:
* Identificadores UUID (no enumerables): impide adivinar recursos ajenos.
* Minimización de datos (Ley 1581 de 2012): se guarda lo necesario y lo sensible va cifrado.
* Nada de contraseñas en claro (el volcado original sí las tenía).
* Toda tabla de usuario lleva user_id indexado para aplicar propiedad en cada consulta.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, LargeBinary, DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint,
                        Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from app.db.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class UTC(TypeDecorator):
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value


def pk() -> Mapped[str]:
    return mapped_column(String(36), primary_key=True, default=_uuid)


def owner() -> Mapped[str]:
    return mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)


def created() -> Mapped[datetime]:
    return mapped_column(UTC, default=_now, index=True)


# ============================================================ identidad y acceso
class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = pk()
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120))
    phone_e164: Mapped[str | None] = mapped_column(String(20))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="user", index=True)  # user|supervisor|admin|super_admin
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)  # active|suspended
    plan: Mapped[str] = mapped_column(String(20), default="BASIC")  # BASIC|PREMIUM|ENTERPRISE
    plan_expires_at: Mapped[datetime | None] = mapped_column(UTC)
    birth_year: Mapped[int | None] = mapped_column(Integer)
    timezone: Mapped[str] = mapped_column(String(40), default="America/Bogota")
    totp_secret_enc: Mapped[str | None] = mapped_column(Text)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    recovery_code_hashes: Mapped[list] = mapped_column(JSON, default=list)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTC)
    last_login_at: Mapped[datetime | None] = mapped_column(UTC)
    password_changed_at: Mapped[datetime] = mapped_column(UTC, default=_now)
    created_at: Mapped[datetime] = created()


class AuthSession(Base):
    """Sesión = familia de refresh tokens. Reutilizar un token viejo revoca la familia entera."""
    __tablename__ = "auth_sessions"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    audience: Mapped[str] = mapped_column(String(20))
    refresh_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    previous_hashes: Mapped[list] = mapped_column(JSON, default=list)
    device_label: Mapped[str | None] = mapped_column(String(120))
    ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(300))
    country: Mapped[str | None] = mapped_column(String(2))
    lat: Mapped[float | None] = mapped_column(Float)
    lon: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = created()
    last_seen_at: Mapped[datetime] = mapped_column(UTC, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTC)
    revoked_at: Mapped[datetime | None] = mapped_column(UTC)
    revoke_reason: Mapped[str | None] = mapped_column(String(60))


class LoginEvent(Base):
    __tablename__ = "login_events"
    id: Mapped[str] = pk()
    user_id: Mapped[str | None] = mapped_column(String(36), index=True)
    audience: Mapped[str] = mapped_column(String(20))
    ip: Mapped[str | None] = mapped_column(String(45), index=True)
    success: Mapped[bool] = mapped_column(Boolean)
    reason: Mapped[str] = mapped_column(String(40))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_reasons: Mapped[list] = mapped_column(JSON, default=list)
    device_id: Mapped[str | None] = mapped_column(String(80))
    country: Mapped[str | None] = mapped_column(String(2))
    lat: Mapped[float | None] = mapped_column(Float)
    lon: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = created()


class DeviceKey(Base):
    """Clave pública del Android Keystore para inicio de sesión biométrico."""
    __tablename__ = "device_keys"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    device_id: Mapped[str] = mapped_column(String(80))
    label: Mapped[str] = mapped_column(String(80))
    public_key: Mapped[str] = mapped_column(Text)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    last_used_at: Mapped[datetime | None] = mapped_column(UTC)
    created_at: Mapped[datetime] = created()
    __table_args__ = (UniqueConstraint("user_id", "device_id"),)


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    purpose: Mapped[str] = mapped_column(String(20))  # biometric|admin_mfa
    value: Mapped[str] = mapped_column(String(128))
    audience: Mapped[str] = mapped_column(String(20), default="guardian-app")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(UTC)
    used_at: Mapped[datetime | None] = mapped_column(UTC)


class PasswordReset(Base):
    __tablename__ = "password_resets"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(UTC)
    used_at: Mapped[datetime | None] = mapped_column(UTC)


class AuditLog(Base):
    """Bitácora encadenada por hash: alterar o borrar una fila rompe la cadena y se detecta."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(UTC, default=_now, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), index=True)
    actor_role: Mapped[str | None] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(60), index=True)
    level: Mapped[str] = mapped_column(String(10), default="info", index=True)  # info|warning|error|security
    target_type: Mapped[str | None] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(45))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


# ============================================================ alertas y avisos
class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    id: Mapped[str] = pk()
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    category: Mapped[str] = mapped_column(String(20), index=True)  # auth|device|app|web|vitals|system
    severity: Mapped[str] = mapped_column(String(10), index=True)  # info|low|medium|high|critical
    title: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    engine: Mapped[str | None] = mapped_column(String(40))
    engine_version: Mapped[str | None] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open|acknowledged|resolved
    feedback: Mapped[str | None] = mapped_column(String(20))  # true_positive|false_positive
    resolved_by: Mapped[str | None] = mapped_column(String(36))
    resolved_at: Mapped[datetime | None] = mapped_column(UTC)
    created_at: Mapped[datetime] = created()


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    kind: Mapped[str] = mapped_column(String(30))
    severity: Mapped[str] = mapped_column(String(10), default="info", index=True)
    title: Mapped[str] = mapped_column(String(160))
    body: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    read_at: Mapped[datetime | None] = mapped_column(UTC)
    created_at: Mapped[datetime] = created()


class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    reason: Mapped[str] = mapped_column(String(160))
    blocked_by: Mapped[str | None] = mapped_column(String(36))
    expires_at: Mapped[datetime | None] = mapped_column(UTC)
    created_at: Mapped[datetime] = created()


# ============================================================ emergencias
class EmergencyContact(Base):
    __tablename__ = "emergency_contacts"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    name: Mapped[str] = mapped_column(String(100))
    phone_e164: Mapped[str] = mapped_column(String(20))
    relation: Mapped[str] = mapped_column(String(20), default="family")  # family|friends|work|other
    priority: Mapped[int] = mapped_column(Integer, default=1)
    notify_sms: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_call: Mapped[bool] = mapped_column(Boolean, default=True)
    last_test_at: Mapped[datetime | None] = mapped_column(UTC)
    last_test_status: Mapped[str | None] = mapped_column(String(20))
    created_at: Mapped[datetime] = created()
    __table_args__ = (UniqueConstraint("user_id", "phone_e164"),)


class EmergencySettings(Base):
    __tablename__ = "emergency_settings"
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    auto_police: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_call: Mapped[bool] = mapped_column(Boolean, default=True)
    live_location: Mapped[bool] = mapped_column(Boolean, default=True)
    wait_minutes: Mapped[int] = mapped_column(Integer, default=5)
    cancel_window_seconds: Mapped[int] = mapped_column(Integer, default=30)
    message_template: Mapped[str] = mapped_column(
        Text, default="{nombre} activó una alerta de GuardianIA. Ubicación: {mapa}. Por favor comuníquese.")


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    kind: Mapped[str] = mapped_column(String(20), index=True)  # sos|fall|vitals|theft
    severity: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(20), default="pending_cancel", index=True)
    # pending_cancel → escalating → resolved | cancelled
    lat: Mapped[float | None] = mapped_column(Float)
    lon: Mapped[float | None] = mapped_column(Float)
    summary: Mapped[str] = mapped_column(Text)
    plan: Mapped[list] = mapped_column(JSON, default=list)
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    cancel_deadline: Mapped[datetime | None] = mapped_column(UTC)
    assigned_to: Mapped[str | None] = mapped_column(String(36))
    resolved_at: Mapped[datetime | None] = mapped_column(UTC)
    created_at: Mapped[datetime] = created()


# ============================================================ salud (wearables)
class HealthProfile(Base):
    """Umbrales clínicos por persona. Solo un administrador puede cambiarlos (con revisión humana)."""
    __tablename__ = "health_profiles"
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    hr_min: Mapped[int | None] = mapped_column(Integer)
    hr_max: Mapped[int | None] = mapped_column(Integer)
    spo2_min: Mapped[int | None] = mapped_column(Integer)
    takes_beta_blockers: Mapped[bool] = mapped_column(Boolean, default=False)
    has_chronic_lung_disease: Mapped[bool] = mapped_column(Boolean, default=False)
    notes_enc: Mapped[str | None] = mapped_column(Text)
    consent_health_data: Mapped[bool] = mapped_column(Boolean, default=False)
    consent_at: Mapped[datetime | None] = mapped_column(UTC)
    updated_at: Mapped[datetime] = mapped_column(UTC, default=_now, onupdate=_now)


class Wearable(Base):
    __tablename__ = "wearables"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    vendor: Mapped[str] = mapped_column(String(40))
    model: Mapped[str] = mapped_column(String(60))
    transport: Mapped[str] = mapped_column(String(20), default="ble")  # ble|health_connect
    battery: Mapped[int | None] = mapped_column(Integer)
    last_sync_at: Mapped[datetime | None] = mapped_column(UTC)
    created_at: Mapped[datetime] = created()


class VitalReading(Base):
    __tablename__ = "vital_readings"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    wearable_id: Mapped[str | None] = mapped_column(String(36))
    measured_at: Mapped[datetime] = mapped_column(UTC)
    heart_rate: Mapped[int | None] = mapped_column(Integer)
    spo2: Mapped[int | None] = mapped_column(Integer)
    hrv_rmssd: Mapped[float | None] = mapped_column(Float)
    resp_rate: Mapped[int | None] = mapped_column(Integer)
    skin_temp: Mapped[float | None] = mapped_column(Float)
    steps: Mapped[int | None] = mapped_column(Integer)
    sleep_minutes: Mapped[int | None] = mapped_column(Integer)
    activity: Mapped[str] = mapped_column(String(10), default="rest")  # rest|walk|run|sleep
    signal_quality: Mapped[float] = mapped_column(Float, default=1.0)
    fall_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = created()
    __table_args__ = (Index("ix_vitals_user_time", "user_id", "measured_at"),
                      UniqueConstraint("user_id", "measured_at", name="uq_vital_instant"))


class WellbeingCheckin(Base):
    """Autorreporte emocional: la emoción la declara la persona; el reloj no la adivina."""
    __tablename__ = "wellbeing_checkins"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    mood: Mapped[str] = mapped_column(String(20))  # stressed|sad|happy|energetic|relaxed|anxious
    intensity: Mapped[int] = mapped_column(Integer)
    note_enc: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created()


class MusicSession(Base):
    __tablename__ = "music_sessions"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    mood_before: Mapped[str] = mapped_column(String(20))
    plan: Mapped[dict] = mapped_column(JSON)
    rating: Mapped[int | None] = mapped_column(Integer)
    mood_after: Mapped[str | None] = mapped_column(String(20))
    created_at: Mapped[datetime] = created()


# ============================================================ dispositivos / antirrobo
class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    name: Mapped[str] = mapped_column(String(80))
    platform: Mapped[str] = mapped_column(String(20), default="android")
    model: Mapped[str | None] = mapped_column(String(80))
    os_version: Mapped[str | None] = mapped_column(String(20))
    device_token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(20), default="ok", index=True)  # ok|lost|stolen|wiped
    battery: Mapped[int | None] = mapped_column(Integer)
    last_lat: Mapped[float | None] = mapped_column(Float)
    last_lon: Mapped[float | None] = mapped_column(Float)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTC)
    created_at: Mapped[datetime] = created()
    # ── Estado en vivo que reporta el propio equipo (todo real: nada se inventa en el servidor).
    # «Conectar / desconectar»: el dueño pausa o reanuda el envío de GPS desde el PC. El equipo
    # sigue mandando un latido liviano para poder recibir la orden de reanudar.
    tracking_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    charging: Mapped[bool | None] = mapped_column(Boolean)
    last_accuracy_m: Mapped[float | None] = mapped_column(Float)
    last_fix_at: Mapped[datetime | None] = mapped_column(UTC)       # hora de la última posición GPS
    gps_status: Mapped[str | None] = mapped_column(String(20))      # ok|https_required|denied|unavailable|paused
    report_interval_s: Mapped[int | None] = mapped_column(Integer)  # cada cuánto promete reportar
    device_info: Mapped[dict | None] = mapped_column(JSON)          # navegador, pantalla, red, idioma…
    # IMEI, número y operador: los escribe el dueño (ni una página web ni una app normal pueden leer
    # el IMEI desde Android 10). Se guardan CIFRADOS con AES-256-GCM, atados a este equipo.
    ident_key_version: Mapped[str | None] = mapped_column(String(20))
    ident_wrapped_dek: Mapped[str | None] = mapped_column(String(200))
    ident_blob: Mapped[bytes | None] = mapped_column(LargeBinary)

    # En línea = reportó dentro de 2,5 intervalos (tolera un latido perdido por la red móvil).
    @property
    def en_linea(self) -> bool:
        if self.last_seen_at is None:
            return False
        visto = self.last_seen_at if self.last_seen_at.tzinfo else self.last_seen_at.replace(tzinfo=timezone.utc)
        return (_now() - visto).total_seconds() <= max(45, 2.5 * (self.report_interval_s or 30))


    @property
    def tiene_identificacion(self) -> bool:
        return self.ident_blob is not None

    @property
    def canal_en_vivo(self) -> bool:
        from app.services.realtime import device_channel, hub
        return hub.escuchando(device_channel(self.id))


class DeviceLocation(Base):
    __tablename__ = "device_locations"
    id: Mapped[str] = pk()
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    lat: Mapped[float] = mapped_column(Float)
    lon: Mapped[float] = mapped_column(Float)
    accuracy_m: Mapped[float | None] = mapped_column(Float)
    recorded_at: Mapped[datetime] = mapped_column(UTC, index=True)
    battery: Mapped[int | None] = mapped_column(Integer)          # para estimar el consumo de batería
    speed_ms: Mapped[float | None] = mapped_column(Float)         # velocidad que reporta el GPS (m/s)


class DevicePhoto(Base):
    """Foto de la cámara frontal que envía la app Android con el equipo reportado. Va cifrada."""
    __tablename__ = "device_photos"
    id: Mapped[str] = pk()
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = owner()
    motivo: Mapped[str] = mapped_column(String(40), default="comando")
    lat: Mapped[float | None] = mapped_column(Float)
    lon: Mapped[float | None] = mapped_column(Float)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    key_version: Mapped[str] = mapped_column(String(20))
    wrapped_dek: Mapped[str] = mapped_column(String(200))
    blob: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = created()


class DeviceCommand(Base):
    __tablename__ = "device_commands"
    id: Mapped[str] = pk()
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # ring|lock|locate|message|wipe|photo|sos
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    signature: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    requested_by: Mapped[str] = mapped_column(String(36))
    expires_at: Mapped[datetime] = mapped_column(UTC)
    delivered_at: Mapped[datetime | None] = mapped_column(UTC)
    completed_at: Mapped[datetime | None] = mapped_column(UTC)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = created()


# ============================================================ apps / web
class AppAssessment(Base):
    __tablename__ = "app_assessments"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    device_id: Mapped[str | None] = mapped_column(String(36), index=True)
    package: Mapped[str] = mapped_column(String(200), index=True)
    label: Mapped[str] = mapped_column(String(120))
    version: Mapped[str | None] = mapped_column(String(40))
    installer: Mapped[str | None] = mapped_column(String(120))
    cert_sha256: Mapped[str | None] = mapped_column(String(64))
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    bytes_rx: Mapped[int] = mapped_column(Integer, default=0)
    bytes_tx: Mapped[int] = mapped_column(Integer, default=0)
    night_tx_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    score: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(20), index=True)  # segura|sospechosa|peligrosa
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    user_action: Mapped[str | None] = mapped_column(String(20))  # allowed|restricted|quarantined|removed
    scanned_at: Mapped[datetime] = created()
    __table_args__ = (UniqueConstraint("user_id", "device_id", "package"),)


class WebRule(Base):
    __tablename__ = "web_rules"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    kind: Mapped[str] = mapped_column(String(10))  # allow|block
    domain: Mapped[str] = mapped_column(String(253))
    created_at: Mapped[datetime] = created()
    __table_args__ = (UniqueConstraint("user_id", "domain"),)


class WebCategoryPolicy(Base):
    __tablename__ = "web_category_policies"
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    category: Mapped[str] = mapped_column(String(30), primary_key=True)
    action: Mapped[str] = mapped_column(String(10), default="block")  # block|allow|schedule
    schedule: Mapped[dict] = mapped_column(JSON, default=dict)  # {"desde":"21:00","hasta":"06:00"}


class WebEvent(Base):
    """Solo se guarda el dominio, nunca la URL completa (privacidad de navegación)."""
    __tablename__ = "web_events"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    host: Mapped[str] = mapped_column(String(253))
    score: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(10), index=True)
    category: Mapped[str | None] = mapped_column(String(30))
    created_at: Mapped[datetime] = created()


class VpnServer(Base):
    __tablename__ = "vpn_servers"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    country: Mapped[str] = mapped_column(String(60))
    city: Mapped[str] = mapped_column(String(60))
    host: Mapped[str] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(20), default="wireguard")
    is_premium: Mapped[bool] = mapped_column(Boolean, default=False)
    load: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Datos reales del túnel. Vacíos = servidor de ejemplo, sin túnel posible.
    public_key: Mapped[str | None] = mapped_column(String(64))
    endpoint: Mapped[str | None] = mapped_column(String(120))   # host:puerto que anuncia el servidor
    subred: Mapped[str] = mapped_column(String(20), default="10.66.0.0/24")
    dns: Mapped[str] = mapped_column(String(60), default="1.1.1.1, 9.9.9.9")
    ip_salida: Mapped[str | None] = mapped_column(String(45))   # IP publica esperada al salir por el


# ============================================================ bóveda
class VaultFile(Base):
    __tablename__ = "vault_files"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    category: Mapped[str] = mapped_column(String(20), index=True)  # photos|documents|videos|financial|evidence
    filename_enc: Mapped[str] = mapped_column(Text)
    mime: Mapped[str] = mapped_column(String(100))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    key_version: Mapped[str] = mapped_column(String(10))
    wrapped_dek: Mapped[str] = mapped_column(Text)
    storage_name: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = created()


class VaultSecret(Base):
    """Cifrado de extremo a extremo: el servidor guarda un blob que no puede leer."""
    __tablename__ = "vault_secrets"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    ciphertext: Mapped[str] = mapped_column(Text)
    strength: Mapped[str | None] = mapped_column(String(10))  # fuerte|media|debil (lo calcula el cliente)
    breached: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = created()
    updated_at: Mapped[datetime] = mapped_column(UTC, default=_now, onupdate=_now)


# ============================================================ asistente IA
class PersonalityProfile(Base):
    __tablename__ = "personality_profiles"
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    friendliness: Mapped[int] = mapped_column(Integer, default=70)
    protection: Mapped[int] = mapped_column(Integer, default=70)
    proactivity: Mapped[int] = mapped_column(Integer, default=50)
    verbosity: Mapped[int] = mapped_column(Integer, default=90)
    humor: Mapped[int] = mapped_column(Integer, default=30)
    mode: Mapped[str] = mapped_column(String(20), default="home")  # home|work|emergency
    assistant_name: Mapped[str] = mapped_column(String(30), default="Asistente AI")
    updated_at: Mapped[datetime] = mapped_column(UTC, default=_now, onupdate=_now)


class Conversation(Base):
    __tablename__ = "conversations"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    title: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = created()
    messages: Mapped[list["Message"]] = relationship(back_populates="conversation", cascade="all, delete-orphan",
                                                     order_by="Message.created_at")


class VpnPeer(Base):
    """Par criptográfico de un dispositivo dentro de la VPN (WireGuard).

    La clave privada NUNCA llega aquí: se genera en el equipo y no sale de él. El servidor solo
    conoce la pública y la IP que le asignó dentro del túnel. Si esta base se filtrara, nadie podría
    hacerse pasar por su dispositivo ni descifrar su tráfico.
    """
    __tablename__ = "vpn_peers"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    device_id: Mapped[str] = mapped_column(String(36), index=True)
    server_id: Mapped[str] = mapped_column(String(40), index=True)
    public_key: Mapped[str] = mapped_column(String(64))
    ip_tunel: Mapped[str] = mapped_column(String(20))
    activo: Mapped[bool] = mapped_column(Boolean, default=True)
    ultimo_handshake: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created()
    __table_args__ = (UniqueConstraint("server_id", "ip_tunel", name="uq_peer_ip"),)


class VpnSession(Base):
    """Una conexión de VPN: cuándo empezó, cuánto duró y por qué servidor salió.

    El túnel lo levanta el agente o la app; aquí queda el registro para poder decir «lleva 42
    minutos conectado» y para que la persona vea su propio historial.
    """
    __tablename__ = "vpn_sessions"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    server_id: Mapped[str] = mapped_column(String(40), index=True)
    device_id: Mapped[str | None] = mapped_column(String(36), index=True)
    proposito: Mapped[str] = mapped_column(String(20), default="general")
    estado: Mapped[str] = mapped_column(String(20), default="conectando", index=True)  # conectando|conectada|cerrada|error
    ip_salida: Mapped[str | None] = mapped_column(String(45))
    ip_previa: Mapped[str | None] = mapped_column(String(45))
    # Solo es True si se comprobó que la IP pública cambió. Sin eso, la interfaz NO puede decir
    # «conectada»: afirmar que el tráfico va cifrado cuando no lo está es peor que no tener VPN.
    verificada: Mapped[bool] = mapped_column(Boolean, default=False)
    latencia_ms: Mapped[int] = mapped_column(Integer, default=0)
    bytes_subida: Mapped[int] = mapped_column(Integer, default=0)
    bytes_bajada: Mapped[int] = mapped_column(Integer, default=0)
    motivo_cierre: Mapped[str | None] = mapped_column(String(60))
    iniciada_at: Mapped[datetime] = created()
    cerrada_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PairingCode(Base):
    """Código corto para vincular un equipo sin copiar tokens a mano.

    Pedirle a una persona que copie un token de 43 caracteres entre el navegador y una terminal es
    una forma segura de perder usuarios. El código de 6 dígitos hace lo mismo con dos defensas:
    vence a los 10 minutos y se quema al primer uso o al quinto intento fallido.
    """
    __tablename__ = "pairing_codes"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    nombre_sugerido: Mapped[str | None] = mapped_column(String(80))
    intentos: Mapped[int] = mapped_column(Integer, default=0)
    usado_por: Mapped[str | None] = mapped_column(String(36))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = created()


class Agent(Base):
    """Agente instalado en un equipo. Es quien sí puede tocar el disco.

    Se autentica con el token del dispositivo (ver Device), no con la sesión del usuario: un servicio
    del sistema no puede depender de que alguien tenga la sesión abierta.
    """
    __tablename__ = "agents"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id", ondelete="CASCADE"),
                                           unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(120), default="")
    so: Mapped[str] = mapped_column(String(60), default="")
    version: Mapped[str] = mapped_column(String(20), default="")
    tiempo_real: Mapped[bool] = mapped_column(Boolean, default=True)
    cuarentena_automatica: Mapped[bool] = mapped_column(Boolean, default=True)
    escaneo_pedido: Mapped[str | None] = mapped_column(String(20))      # rapido|completo|personalizado
    # Análisis automáticos: el agente los ejecuta solo, sin que nadie abra nada.
    auto_rapido_horas: Mapped[int] = mapped_column(Integer, default=6)
    auto_completo_dias: Mapped[int] = mapped_column(Integer, default=7)
    ultimo_rapido: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ultimo_completo: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    progreso: Mapped[dict] = mapped_column(JSON, default=dict)          # análisis en curso
    ruta_pedida: Mapped[str | None] = mapped_column(String(400))
    ultimo_latido: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ultimo_escaneo: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    archivos_protegidos: Mapped[int] = mapped_column(Integer, default=0)
    amenazas_totales: Mapped[int] = mapped_column(Integer, default=0)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = created()


class QuarantineItem(Base):
    """Archivo aislado por el agente.

    El archivo no se sube: queda cifrado en la cuarentena del propio equipo. Aquí solo vive el
    registro, para que la persona decida desde la web y el agente ejecute esa decisión.
    """
    __tablename__ = "quarantine_items"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    device_id: Mapped[str] = mapped_column(String(36), index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    filename: Mapped[str] = mapped_column(String(200))
    ruta_original: Mapped[str] = mapped_column(String(400), default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    nivel: Mapped[str] = mapped_column(String(20), default="sospechoso")
    familia: Mapped[str | None] = mapped_column(String(60))
    motivos: Mapped[list] = mapped_column(JSON, default=list)
    # en_cuarentena | pendiente_restaurar | pendiente_eliminar | restaurado | eliminado | error
    estado: Mapped[str] = mapped_column(String(24), default="en_cuarentena", index=True)
    detalle_error: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = created()
    resuelto_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanRun(Base):
    """Resumen de un análisis del equipo: qué se revisó, qué se encontró y cuánto tardó."""
    __tablename__ = "scan_runs"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    origen: Mapped[str] = mapped_column(String(30), default="carpeta")  # carpeta|archivo|apps|agente
    device_id: Mapped[str | None] = mapped_column(String(36), index=True)
    tipo: Mapped[str] = mapped_column(String(20), default="manual")     # rapido|completo|personalizado|manual|tiempo_real
    en_cuarentena: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer, default=0)
    limpios: Mapped[int] = mapped_column(Integer, default=0)
    sospechosos: Mapped[int] = mapped_column(Integer, default=0)
    maliciosos: Mapped[int] = mapped_column(Integer, default=0)
    omitidos: Mapped[int] = mapped_column(Integer, default=0)
    duracion_ms: Mapped[int] = mapped_column(Integer, default=0)
    hallazgos: Mapped[list] = mapped_column(JSON, default=list)   # solo lo relevante, sin rutas completas
    created_at: Mapped[datetime] = created()


class ExposureCheck(Base):
    """Revisión de filtraciones de datos. Se guarda el hash del correo, no el correo.

    Así el historial sirve (se sabe si el mismo correo ya se revisó y cuándo) sin acumular una lista
    de correos en claro que sería, ella misma, un objetivo atractivo.
    """
    __tablename__ = "exposure_checks"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    email_hash: Mapped[str] = mapped_column(String(64), index=True)
    proveedor: Mapped[str] = mapped_column(String(30), default="")
    filtraciones: Mapped[int] = mapped_column(Integer, default=0)
    detalle: Mapped[list] = mapped_column(JSON, default=list)
    riesgo: Mapped[str] = mapped_column(String(20), default="bajo")
    created_at: Mapped[datetime] = created()


class Attachment(Base):
    """Archivo que la persona adjuntó a una conversación para que el asistente lo lea.

    Se guarda el texto extraído (cifrado), no el archivo original: es lo único que el asistente
    necesita, ocupa mucho menos y reduce lo que habría que proteger. Si la persona quiere conservar
    el archivo, para eso está la bóveda.
    """
    __tablename__ = "attachments"
    id: Mapped[str] = pk()
    conversation_id: Mapped[str] = mapped_column(String(36), ForeignKey("conversations.id", ondelete="CASCADE"),
                                                 index=True)
    user_id: Mapped[str] = owner()
    filename: Mapped[str] = mapped_column(String(200))
    mime: Mapped[str] = mapped_column(String(120))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    pages: Mapped[int] = mapped_column(Integer, default=0)
    method: Mapped[str] = mapped_column(String(60), default="")
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    chars: Mapped[int] = mapped_column(Integer, default=0)
    text_enc: Mapped[str] = mapped_column(Text, default="")
    image_enc: Mapped[str] = mapped_column(Text, default="")   # solo imágenes, para modelos de visión
    created_at: Mapped[datetime] = created()


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[str] = pk()
    conversation_id: Mapped[str] = mapped_column(String(36), ForeignKey("conversations.id", ondelete="CASCADE"),
                                                 index=True)
    role: Mapped[str] = mapped_column(String(10))  # user|assistant
    content_enc: Mapped[str] = mapped_column(Text)
    safety: Mapped[dict] = mapped_column(JSON, default=dict)
    provider: Mapped[str | None] = mapped_column(String(20))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    # Archivos que el asistente creó EN este mensaje (nombre, id en la bóveda, descarga…) y las fuentes web
    # citadas. Antes solo viajaban como eventos en vivo: al reabrir el chat la tarjeta de descarga se perdía.
    files: Mapped[list] = mapped_column(JSON, default=list)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = created()
    conversation: Mapped[Conversation] = relationship(back_populates="messages")


# ============================================================ membresía
class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    plan: Mapped[str] = mapped_column(String(20))
    provider: Mapped[str] = mapped_column(String(20), default="google_play")
    product_id: Mapped[str] = mapped_column(String(80))
    purchase_token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    starts_at: Mapped[datetime] = mapped_column(UTC, default=_now)
    ends_at: Mapped[datetime | None] = mapped_column(UTC)
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=True)


# ============================================================ operación / soporte
class Ticket(Base):
    __tablename__ = "tickets"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = owner()
    subject: Mapped[str] = mapped_column(String(160))
    category: Mapped[str] = mapped_column(String(20))  # cuenta|seguridad|salud|pagos|otro
    priority: Mapped[str] = mapped_column(String(10), default="media")
    status: Mapped[str] = mapped_column(String(20), default="abierto", index=True)
    assigned_to: Mapped[str | None] = mapped_column(String(36))
    sla_due_at: Mapped[datetime] = mapped_column(UTC)
    created_at: Mapped[datetime] = created()
    updated_at: Mapped[datetime] = mapped_column(UTC, default=_now, onupdate=_now)


class TicketMessage(Base):
    __tablename__ = "ticket_messages"
    id: Mapped[str] = pk()
    ticket_id: Mapped[str] = mapped_column(String(36), ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[str] = mapped_column(String(36))
    body: Mapped[str] = mapped_column(Text)
    internal: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = created()


class ConfigSetting(Base):
    __tablename__ = "config_settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    area: Mapped[str] = mapped_column(String(20))  # medical|security|system
    value: Mapped[dict] = mapped_column(JSON)
    updated_by: Mapped[str | None] = mapped_column(String(36))
    updated_at: Mapped[datetime] = mapped_column(UTC, default=_now, onupdate=_now)


class Recommendation(Base):
    """Flujo de la pantalla Configuration Center: la IA propone, un humano decide."""
    __tablename__ = "recommendations"
    id: Mapped[str] = pk()
    area: Mapped[str] = mapped_column(String(20), index=True)
    setting_key: Mapped[str] = mapped_column(String(80))
    current_value: Mapped[dict] = mapped_column(JSON)
    proposed_value: Mapped[dict] = mapped_column(JSON)
    rationale: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(30))
    expert_review: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    decided_by: Mapped[str | None] = mapped_column(String(36))
    decided_at: Mapped[datetime | None] = mapped_column(UTC)
    decision_note: Mapped[str | None] = mapped_column(Text)
    final_value: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = created()


class Backup(Base):
    __tablename__ = "backups"
    id: Mapped[str] = pk()
    filename: Mapped[str] = mapped_column(String(120))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="running")  # running|completed|failed|verified
    error: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(36))
    verified_at: Mapped[datetime | None] = mapped_column(UTC)
    created_at: Mapped[datetime] = created()


class EngineMetric(Base):
    """Latencias de los motores de IA para el monitor de modelos (reemplaza el 'monitor de consciencia')."""
    __tablename__ = "engine_metrics"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    engine: Mapped[str] = mapped_column(String(40), index=True)
    latency_ms: Mapped[float] = mapped_column(Float)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = created()


class Leccion(Base):
    """Algo que la persona le enseñó al asistente («cuando pida X, haz Y»). Cifrado como los mensajes."""
    __tablename__ = "lecciones_asistente"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    cuando_enc: Mapped[str] = mapped_column(Text)
    haz_enc: Mapped[str] = mapped_column(Text)
    usos: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = created()


class AssistantSkill(Base):
    """Skill de la persona (propia) o marca de que apagó una integrada (``builtin_ref`` = nombre del archivo).

    Ver app/ai/skills.py. El contenido es texto de método, no se ejecuta nunca.
    """
    __tablename__ = "assistant_skills"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    builtin_ref: Mapped[str | None] = mapped_column(String(80), nullable=True)
    name: Mapped[str] = mapped_column(String(60), default="")
    description: Mapped[str] = mapped_column(String(300), default="")
    content: Mapped[str] = mapped_column(Text, default="")
    triggers: Mapped[list] = mapped_column(JSON, default=list)
    tipos: Mapped[list] = mapped_column(JSON, default=list)
    always: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = created()
    updated_at: Mapped[datetime] = mapped_column(UTC, default=_now, onupdate=_now)
    __table_args__ = (UniqueConstraint("user_id", "name", name="uq_skill_usuario_nombre"),)
