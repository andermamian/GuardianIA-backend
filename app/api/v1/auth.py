"""Autenticación.

Dos puertas separadas, como pidió el proyecto:
* /v1/auth/*        → app de usuario (audiencia guardian-app).
* /v1/admin/auth/*  → consola administrativa (audiencia guardian-admin), 2FA obligatorio,
                      tokens más cortos. Un token de usuario jamás abre un endpoint de admin.
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Request, status
from sqlalchemy import select

from app.api.deps import DB, CurrentStaff, CurrentUser, client_ip
from app.core import audit, rbac
from app.core.config import get_settings
from app.core.crypto import open_text, seal_text
from app.core.errors import ApiError, conflict
from app.core.ratelimit import limiter
from app.core.security import (AUD_ADMIN, AUD_APP, hash_password, load_device_public_key, new_opaque_token,
                               new_totp_secret, password_problems, recovery_codes, token_hash, totp_uri, utcnow,
                               verify_device_signature, verify_password, verify_totp)
from app.db.models import AuthSession, DeviceKey, EmergencySettings, HealthProfile, PasswordReset, User
from app.schemas.auth import (AdminLoginIn, BiometricChallengeIn, BiometricChallengeOut, BiometricRegisterIn,
                              BiometricVerifyIn, ChangePasswordIn, LoginIn, MfaChallengeOut, MfaVerifyIn,
                              RecoveryCodesOut, RecoveryIn, RefreshIn, RegisterIn, ResetIn, SessionOut,
                              TokenOut, TotpEnableIn, TotpSetupOut, UserOut)
from app.schemas.common import Msg
from app.services import auth as svc
from app.services.alerts import raise_alert

router = APIRouter(prefix="/auth", tags=["Autenticación (app)"])
admin_router = APIRouter(prefix="/admin/auth", tags=["Autenticación (consola admin)"])


def _limit_login(ip: str, email: str) -> None:
    s = get_settings()
    limiter.hit(f"login-ip:{ip}", s.rate_limit_login_per_minute * 3)
    limiter.hit(f"login:{ip}:{svc.email_norm(email)}", s.rate_limit_login_per_minute)


# ============================================================== usuarios (app)
@router.post("/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterIn, request: Request, db: DB):
    ip = client_ip(request)
    limiter.hit(f"register:{ip}", 5, 3600)
    email = svc.email_norm(body.email)
    issues = password_problems(body.password, email=email, name=body.full_name)
    if issues:
        raise ApiError(422, "weak_password", "La contraseña no cumple la política", {"problemas": issues})
    if db.execute(select(User.id).where(User.email == email)).scalar():
        # Mensaje neutro para no confirmar qué correos están registrados.
        raise conflict("registration_failed", "No fue posible crear la cuenta con esos datos")
    user = User(email=email, full_name=body.full_name.strip(), phone_e164=body.phone, birth_year=body.birth_year,
                password_hash=hash_password(body.password))
    db.add(user)
    db.flush()
    db.add(EmergencySettings(user_id=user.id))
    db.add(HealthProfile(user_id=user.id, consent_health_data=body.accept_health_data,
                         consent_at=utcnow() if body.accept_health_data else None))
    audit.record(db, "user.registered", actor_id=user.id, actor_role="user", target_type="user",
                 target_id=user.id, ip=ip, commit=False)
    risk = svc.assess_risk(db, user, ip, body.device_id, body.country, body.lat, body.lon)
    svc.record_success(db, user, AUD_APP, ip, risk, body.device_id, body.country, body.lat, body.lon)
    return svc.issue_tokens(db, user, AUD_APP, request, ip=ip, device_label=body.device_label,
                            lat=body.lat, lon=body.lon, country=body.country)


@router.post("/login", response_model=TokenOut | MfaChallengeOut)
def login(body: LoginIn, request: Request, db: DB):
    ip = client_ip(request)
    _limit_login(ip, body.email)
    user = svc.check_password(db, body.email, body.password, AUD_APP, ip, body.device_id)
    if user.role in rbac.STAFF_ROLES:
        # El personal entra solo por la consola. Respuesta genérica: no se revela que la clave era correcta.
        audit.record(db, "admin.login_via_app_blocked", actor_id=user.id, actor_role=user.role, ip=ip,
                     level="security")
        raise svc.INVALID
    risk = svc.assess_risk(db, user, ip, body.device_id, body.country, body.lat, body.lon)
    if risk.decision == "deny":
        svc._register_failure(db, user, AUD_APP, ip, "risk_denied", body.device_id)
        raise ApiError(403, "login_blocked", "Bloqueamos este acceso por seguridad. Revise su correo.")
    if risk.decision == "step_up" and user.totp_enabled:
        ch = svc.new_challenge(db, user, "login_mfa", AUD_APP)
        db.commit()
        return MfaChallengeOut(challenge_id=ch.id, expires_in=300, motivo="; ".join(risk.reasons))
    svc.record_success(db, user, AUD_APP, ip, risk, body.device_id, body.country, body.lat, body.lon)
    return svc.issue_tokens(db, user, AUD_APP, request, ip=ip, device_label=body.device_label,
                            lat=body.lat, lon=body.lon, country=body.country)


@router.post("/login/mfa", response_model=TokenOut)
def login_mfa(body: MfaVerifyIn, request: Request, db: DB):
    ip = client_ip(request)
    limiter.hit(f"mfa:{ip}", 10)
    ch, user = svc.consume_challenge(db, body.challenge_id, "login_mfa")
    if not svc.verify_second_factor(user, body.code):
        db.commit()
        raise ApiError(401, "invalid_code", "Código incorrecto")
    ch.used_at = utcnow()
    risk = svc.assess_risk(db, user, ip, None, None, None, None)
    svc.record_success(db, user, AUD_APP, ip, risk, None, None, None, None)
    return svc.issue_tokens(db, user, AUD_APP, request, ip=ip, device_label=None)


@router.post("/refresh", response_model=TokenOut)
def refresh(body: RefreshIn, request: Request, db: DB):
    limiter.hit(f"refresh:{client_ip(request)}", 30)
    return svc.rotate_refresh(db, body.refresh_token, AUD_APP, client_ip(request))


@router.post("/logout", response_model=Msg)
def logout(p: CurrentUser, db: DB):
    s = db.get(AuthSession, p.session_id)
    s.revoked_at, s.revoke_reason = utcnow(), "logout"
    db.commit()
    return Msg(mensaje="Sesión cerrada")


@router.get("/me", response_model=UserOut)
def me(p: CurrentUser):
    return p.user


@router.post("/password/change", response_model=Msg)
def change_password(body: ChangePasswordIn, request: Request, p: CurrentUser, db: DB):
    if not verify_password(body.current_password, p.user.password_hash):
        raise ApiError(401, "invalid_credentials", "La contraseña actual no es correcta")
    issues = password_problems(body.new_password, email=p.user.email, name=p.user.full_name)
    if issues:
        raise ApiError(422, "weak_password", "La contraseña no cumple la política", {"problemas": issues})
    p.user.password_hash = hash_password(body.new_password)
    p.user.password_changed_at = utcnow()
    closed = svc.revoke_all(db, p.user.id, "password_changed", except_session=p.session_id)
    audit.record(db, "user.password_changed", actor_id=p.user.id, ip=client_ip(request), commit=False)
    db.commit()
    return Msg(mensaje=f"Contraseña actualizada; se cerraron {closed} sesiones en otros dispositivos")


@router.post("/password/recovery", response_model=Msg, status_code=202)
def recovery(body: RecoveryIn, request: Request, db: DB):
    limiter.hit(f"recovery:{client_ip(request)}", 5, 3600)
    user = db.execute(select(User).where(User.email == svc.email_norm(body.email))).scalar()
    if user and user.status == "active":
        raw = new_opaque_token()
        db.add(PasswordReset(user_id=user.id, token_hash=token_hash(raw), expires_at=utcnow() + timedelta(minutes=30)))
        db.commit()
        # Aquí se envía `raw` por correo mediante el proveedor transaccional (nunca en la respuesta HTTP).
    return Msg(mensaje="Si el correo está registrado, recibirá instrucciones en unos minutos")


@router.post("/password/reset", response_model=Msg)
def reset_password(body: ResetIn, request: Request, db: DB):
    limiter.hit(f"reset:{client_ip(request)}", 10, 3600)
    pr = db.execute(select(PasswordReset).where(PasswordReset.token_hash == token_hash(body.token))).scalar()
    if pr is None or pr.used_at or pr.expires_at < utcnow():
        raise ApiError(400, "invalid_token", "El enlace expiró o ya fue usado")
    user = db.get(User, pr.user_id)
    issues = password_problems(body.new_password, email=user.email, name=user.full_name)
    if issues:
        raise ApiError(422, "weak_password", "La contraseña no cumple la política", {"problemas": issues})
    user.password_hash, user.password_changed_at = hash_password(body.new_password), utcnow()
    user.failed_logins, user.locked_until, pr.used_at = 0, None, utcnow()
    svc.revoke_all(db, user.id, "password_reset")
    audit.record(db, "user.password_reset", actor_id=user.id, ip=client_ip(request), level="security", commit=False)
    db.commit()
    return Msg(mensaje="Contraseña restablecida")


# ------------------------------------------------------------------- 2FA app
@router.post("/2fa/setup", response_model=TotpSetupOut)
def totp_setup(p: CurrentUser, db: DB):
    if p.user.totp_enabled:
        raise conflict("mfa_already_enabled", "La verificación en dos pasos ya está activa")
    secret = new_totp_secret()
    p.user.totp_secret_enc = seal_text(secret, f"totp:{p.user.id}")
    db.commit()
    return TotpSetupOut(secret=secret, otpauth_uri=totp_uri(secret, p.user.email))


@router.post("/2fa/enable", response_model=RecoveryCodesOut)
def totp_enable(body: TotpEnableIn, p: CurrentUser, db: DB):
    if not verify_totp(open_text(p.user.totp_secret_enc, f"totp:{p.user.id}"), body.code):
        raise ApiError(401, "invalid_code", "Código incorrecto")
    codes = recovery_codes()
    p.user.totp_enabled = True
    p.user.recovery_code_hashes = [token_hash(c) for c in codes]
    audit.record(db, "user.mfa_enabled", actor_id=p.user.id, commit=False)
    db.commit()
    return RecoveryCodesOut(recovery_codes=codes)


# ---------------------------------------------------------------- biometría
@router.post("/biometric/register", response_model=Msg, status_code=201)
def biometric_register(body: BiometricRegisterIn, p: CurrentUser, db: DB):
    load_device_public_key(body.public_key)
    existing = db.execute(select(DeviceKey).where(DeviceKey.user_id == p.user.id,
                                                  DeviceKey.device_id == body.device_id)).scalar()
    if existing:
        existing.public_key, existing.label, existing.revoked = body.public_key, body.label, False
    else:
        db.add(DeviceKey(user_id=p.user.id, device_id=body.device_id, label=body.label, public_key=body.public_key))
    audit.record(db, "user.biometric_registered", actor_id=p.user.id, detail={"device": body.label}, commit=False)
    db.commit()
    return Msg(mensaje="Huella/rostro vinculado a este dispositivo")


@router.post("/biometric/challenge", response_model=BiometricChallengeOut)
def biometric_challenge(body: BiometricChallengeIn, request: Request, db: DB):
    limiter.hit(f"bio:{client_ip(request)}", 20)
    user = db.execute(select(User).where(User.email == svc.email_norm(body.email))).scalar()
    key = user and db.execute(select(DeviceKey).where(DeviceKey.user_id == user.id,
                                                      DeviceKey.device_id == body.device_id,
                                                      DeviceKey.revoked.is_(False))).scalar()
    if not user or not key or user.status != "active" or user.role in rbac.STAFF_ROLES:
        raise ApiError(401, "biometric_unavailable", "Inicie sesión con contraseña en este dispositivo")
    ch = svc.new_challenge(db, user, "biometric", AUD_APP, seconds=120)
    ch.value = f"{ch.value}|{body.device_id}"
    db.commit()
    return BiometricChallengeOut(challenge_id=ch.id, challenge=ch.value, expires_in=120)


@router.post("/biometric/verify", response_model=TokenOut)
def biometric_verify(body: BiometricVerifyIn, request: Request, db: DB):
    ip = client_ip(request)
    ch, user = svc.consume_challenge(db, body.challenge_id, "biometric")
    device_id = ch.value.rsplit("|", 1)[1]
    key = db.execute(select(DeviceKey).where(DeviceKey.user_id == user.id, DeviceKey.device_id == device_id,
                                             DeviceKey.revoked.is_(False))).scalar()
    if key is None or not verify_device_signature(key.public_key, ch.value, body.signature):
        db.commit()
        raise ApiError(401, "invalid_signature", "No se pudo verificar la biometría")
    ch.used_at, key.last_used_at = utcnow(), utcnow()
    risk = svc.assess_risk(db, user, ip, device_id, None, None, None)
    svc.record_success(db, user, AUD_APP, ip, risk, device_id, None, None, None)
    return svc.issue_tokens(db, user, AUD_APP, request, ip=ip, device_label=body.device_label or key.label)


# ------------------------------------------------------------------ sesiones
@router.get("/sessions", response_model=list[SessionOut])
def my_sessions(p: CurrentUser, db: DB):
    rows = db.execute(select(AuthSession).where(AuthSession.user_id == p.user.id, AuthSession.revoked_at.is_(None),
                                                AuthSession.expires_at > utcnow())
                      .order_by(AuthSession.last_seen_at.desc())).scalars().all()
    return [SessionOut.model_validate(r).model_copy(update={"actual": r.id == p.session_id}) for r in rows]


@router.delete("/sessions/{session_id}", response_model=Msg)
def revoke_my_session(session_id: str, p: CurrentUser, db: DB):
    s = db.get(AuthSession, session_id)
    if s is None or s.user_id != p.user.id:
        raise ApiError(404, "not_found", "No se encontró la sesión")
    s.revoked_at, s.revoke_reason = utcnow(), "user_revoked"
    db.commit()
    return Msg(mensaje="Sesión cerrada")


# ========================================================= consola de admin
@admin_router.post("/login", response_model=MfaChallengeOut)
def admin_login(body: AdminLoginIn, request: Request, db: DB):
    """Paso 1 (pantalla activity_admin_login): nivel de autorización + credenciales."""
    ip = client_ip(request)
    _limit_login(ip, body.email)
    user = svc.check_password(db, body.email, body.password, AUD_ADMIN, ip, body.device_id)
    if user.role != body.authorization_level:
        svc._register_failure(db, user, AUD_ADMIN, ip, "level_mismatch", body.device_id)
        raise svc.INVALID
    if not user.totp_enabled:
        raise ApiError(403, "mfa_not_configured",
                       "La cuenta administrativa no tiene 2FA. Configúrelo con: python -m app.cli enroll-mfa")
    ch = svc.new_challenge(db, user, "admin_mfa", AUD_ADMIN, seconds=300)
    ch.value = "remember" if body.remember_session else "short"
    db.commit()
    return MfaChallengeOut(challenge_id=ch.id, expires_in=300, motivo="Ingrese el código de su app autenticadora")


@admin_router.post("/mfa", response_model=TokenOut)
def admin_mfa(body: MfaVerifyIn, request: Request, db: DB):
    """Paso 2: código TOTP (et_2fa_verification con tv_2fa_countdown)."""
    ip = client_ip(request)
    limiter.hit(f"admin-mfa:{ip}", 10)
    ch, user = svc.consume_challenge(db, body.challenge_id, "admin_mfa")
    if not svc.verify_second_factor(user, body.code):
        audit.record(db, "admin.mfa_failed", actor_id=user.id, actor_role=user.role, ip=ip, level="security",
                     commit=False)
        db.commit()
        raise ApiError(401, "invalid_code", "Código incorrecto")
    ch.used_at = utcnow()
    risk = svc.assess_risk(db, user, ip, None, None, None, None)
    svc.record_success(db, user, AUD_ADMIN, ip, risk, None, None, None, None)
    if risk.reasons:
        raise_alert(db, user_id=None, category="auth", severity="high", title="Acceso administrativo atípico",
                    description=f"{user.email}: " + "; ".join(risk.reasons), source_ip=ip, engine="loginrisk")
    audit.record(db, "admin.login", actor_id=user.id, actor_role=user.role, ip=ip, level="security",
                 detail={"riesgo": risk.score}, commit=False)
    return svc.issue_tokens(db, user, AUD_ADMIN, request, ip=ip, device_label=None,
                            long_lived=ch.value == "remember")


@admin_router.post("/refresh", response_model=TokenOut)
def admin_refresh(body: RefreshIn, request: Request, db: DB):
    limiter.hit(f"admin-refresh:{client_ip(request)}", 30)
    return svc.rotate_refresh(db, body.refresh_token, AUD_ADMIN, client_ip(request))


@admin_router.post("/logout", response_model=Msg)
def admin_logout(staff: CurrentStaff, request: Request, db: DB):
    s = db.get(AuthSession, staff.session_id)
    s.revoked_at, s.revoke_reason = utcnow(), "logout"
    audit.record(db, "admin.logout", actor_id=staff.user.id, actor_role=staff.role, ip=client_ip(request),
                 commit=False)
    db.commit()
    return Msg(mensaje="Sesión administrativa cerrada")


@admin_router.post("/recovery", response_model=Msg, status_code=202)
def admin_recovery(body: RecoveryIn, request: Request, db: DB):
    """Botón «recuperar acceso»: nunca restablece en línea; abre un proceso verificado por otro super_admin."""
    limiter.hit(f"admin-recovery:{client_ip(request)}", 3, 3600)
    user = db.execute(select(User).where(User.email == svc.email_norm(body.email))).scalar()
    if user and user.role in rbac.STAFF_ROLES:
        audit.record(db, "admin.recovery_requested", actor_id=user.id, actor_role=user.role,
                     ip=client_ip(request), level="security")
    return Msg(mensaje="Solicitud registrada. Un super administrador validará su identidad por un canal verificado.")


@admin_router.get("/me", response_model=UserOut)
def admin_me(staff: CurrentStaff):
    return staff.user
