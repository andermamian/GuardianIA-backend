from __future__ import annotations

import hmac
import secrets
from datetime import timedelta

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai import login_risk
from app.core import audit
from app.core.config import get_settings
from app.core.crypto import open_text
from app.core.errors import ApiError
from app.core.tz import zone as tz_zone
from app.core.security import (AUD_ADMIN, AUD_APP, create_access_token, hash_password, needs_rehash,
                               new_opaque_token, token_hash, utcnow, verify_password, verify_totp)
from app.db.models import AuthChallenge, AuthSession, LoginEvent, User
from app.services.alerts import notify, raise_alert

INVALID = ApiError(401, "invalid_credentials", "Correo o contraseña incorrectos")
REUSE_GRACE_SECONDS = 20


def email_norm(email: str) -> str:
    return email.strip().lower()


def ua(request: Request) -> str:
    return (request.headers.get("user-agent") or "")[:300]


# ------------------------------------------------------------------- sesiones
def issue_tokens(db: Session, user: User, audience: str, request: Request, *, ip: str, device_label: str | None,
                 lat: float | None = None, lon: float | None = None, country: str | None = None,
                 long_lived: bool = True) -> dict:
    s = get_settings()
    if audience == AUD_ADMIN:
        ttl = timedelta(hours=s.admin_refresh_token_hours if long_lived else 1)
        minutes = s.admin_access_token_minutes
    else:
        ttl, minutes = timedelta(days=s.refresh_token_days), s.access_token_minutes
    session = AuthSession(user_id=user.id, audience=audience, refresh_hash="pending", device_label=device_label,
                          ip=ip, user_agent=ua(request), country=country, lat=lat, lon=lon,
                          expires_at=utcnow() + ttl)
    db.add(session)
    db.flush()
    refresh = f"{session.id}.{new_opaque_token()}"
    session.refresh_hash = token_hash(refresh)
    user.last_login_at = utcnow()
    access = create_access_token(subject=user.id, audience=audience, role=user.role, session_id=session.id,
                                 minutes=minutes, extra={"plan": user.plan})
    db.commit()
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer",
            "expires_in": minutes * 60, "user": user}


def rotate_refresh(db: Session, raw: str, audience: str, ip: str) -> dict:
    sid = raw.split(".", 1)[0]
    session = db.get(AuthSession, sid)
    digest = token_hash(raw)
    if session is None or session.audience != audience:
        raise ApiError(401, "invalid_token", "Credenciales inválidas")
    if (session.previous_hashes and hmac.compare_digest(digest, session.previous_hashes[-1])
            and session.revoked_at is None and (utcnow() - session.last_seen_at).total_seconds() <= REUSE_GRACE_SECONDS):
        # Carrera benigna: dos pestañas (o un reintento de red) renovaron casi a la vez con el mismo token.
        # Se entrega un access token nuevo SIN rotar otra vez; el refresh vigente ya lo tiene el cliente.
        # Pasada la ventana de gracia, reutilizar un token viejo sí se trata como robo (abajo).
        user = db.get(User, session.user_id)
        if user is None or user.status != "active":
            raise ApiError(401, "account_inactive", "La cuenta no está activa")
        s = get_settings()
        minutes = s.admin_access_token_minutes if audience == AUD_ADMIN else s.access_token_minutes
        access = create_access_token(subject=user.id, audience=audience, role=user.role, session_id=session.id,
                                     minutes=minutes, extra={"plan": user.plan})
        return {"access_token": access, "refresh_token": None, "token_type": "bearer", "expires_in": minutes * 60,
                "user": user}
    if digest in session.previous_hashes:
        # Un token ya usado reaparece: alguien lo robó. Se corta la sesión completa.
        session.revoked_at, session.revoke_reason = utcnow(), "refresh_reuse"
        raise_alert(db, user_id=session.user_id, category="auth", severity="high",
                    title="Posible robo de sesión",
                    description="Se reutilizó un token de sesión antiguo; la sesión fue cerrada por seguridad.",
                    source_ip=ip, engine="auth")
        audit.record(db, "auth.refresh_reuse", actor_id=session.user_id, target_type="session",
                     target_id=session.id, ip=ip, level="security", commit=False)
        db.commit()
        raise ApiError(401, "session_revoked", "La sesión fue cerrada por seguridad")
    if (not hmac.compare_digest(digest, session.refresh_hash) or session.revoked_at is not None
            or session.expires_at < utcnow()):
        raise ApiError(401, "invalid_token", "Credenciales inválidas")
    user = db.get(User, session.user_id)
    if user is None or user.status != "active":
        raise ApiError(401, "account_inactive", "La cuenta no está activa")
    new_raw = f"{session.id}.{new_opaque_token()}"
    session.previous_hashes = [*session.previous_hashes[-20:], session.refresh_hash]
    session.refresh_hash = token_hash(new_raw)
    session.last_seen_at, session.ip = utcnow(), ip
    s = get_settings()
    minutes = s.admin_access_token_minutes if audience == AUD_ADMIN else s.access_token_minutes
    access = create_access_token(subject=user.id, audience=audience, role=user.role, session_id=session.id,
                                 minutes=minutes, extra={"plan": user.plan})
    db.commit()
    return {"access_token": access, "refresh_token": new_raw, "token_type": "bearer", "expires_in": minutes * 60,
            "user": user}


def revoke_all(db: Session, user_id: str, reason: str, except_session: str | None = None) -> int:
    rows = db.execute(select(AuthSession).where(AuthSession.user_id == user_id,
                                                AuthSession.revoked_at.is_(None))).scalars().all()
    n = 0
    for r in rows:
        if r.id != except_session:
            r.revoked_at, r.revoke_reason = utcnow(), reason
            n += 1
    return n


# ------------------------------------------------------------ verificación
def _register_failure(db: Session, user: User | None, audience: str, ip: str, reason: str, device_id: str | None):
    s = get_settings()
    db.add(LoginEvent(user_id=user.id if user else None, audience=audience, ip=ip, success=False, reason=reason,
                      device_id=device_id))
    if user is not None:
        user.failed_logins += 1
        if user.failed_logins >= s.max_failed_logins:
            extra = user.failed_logins - s.max_failed_logins
            user.locked_until = utcnow() + timedelta(seconds=min(s.lockout_base_seconds * 2 ** extra, 3600))
            if user.failed_logins == s.max_failed_logins:
                raise_alert(db, user_id=user.id, category="auth", severity="medium",
                            title="Intentos fallidos de acceso a su cuenta",
                            description="Bloqueamos temporalmente el acceso. Si no fue usted, cambie su contraseña.",
                            source_ip=ip, engine="auth")
    db.commit()


def check_password(db: Session, email: str, password: str, audience: str, ip: str,
                   device_id: str | None) -> User:
    user = db.execute(select(User).where(User.email == email_norm(email))).scalar()
    ok = verify_password(password, user.password_hash if user else None)  # tiempo constante exista o no
    if user is None:
        _register_failure(db, None, audience, ip, "unknown_user", device_id)
        raise INVALID
    if user.locked_until and user.locked_until > utcnow():
        _register_failure(db, user, audience, ip, "locked", device_id)
        raise INVALID
    if not ok:
        _register_failure(db, user, audience, ip, "bad_password", device_id)
        raise INVALID
    if user.status != "active":
        _register_failure(db, user, audience, ip, "inactive", device_id)
        raise INVALID
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    return user


def assess_risk(db: Session, user: User, ip: str, device_id: str | None, country: str | None,
                lat: float | None, lon: float | None) -> login_risk.LoginRisk:
    now = utcnow()
    tz = tz_zone(user.timezone)
    hist = db.execute(select(LoginEvent).where(LoginEvent.user_id == user.id, LoginEvent.success.is_(True))
                      .order_by(LoginEvent.created_at.desc()).limit(50)).scalars().all()
    failures = db.execute(select(func.count()).select_from(LoginEvent).where(
        LoginEvent.ip == ip, LoginEvent.success.is_(False),
        LoginEvent.created_at >= now - timedelta(minutes=15))).scalar_one()
    ctx = login_risk.LoginContext(now, ip, device_id, country, lat, lon, now.astimezone(tz).hour)
    past = [login_risk.PastLogin(h.created_at, h.device_id, h.country, h.lat, h.lon,
                                 h.created_at.astimezone(tz).hour) for h in hist]
    return login_risk.assess_login(ctx, past, failures)


def record_success(db: Session, user: User, audience: str, ip: str, risk: login_risk.LoginRisk,
                   device_id: str | None, country: str | None, lat: float | None, lon: float | None) -> None:
    user.failed_logins, user.locked_until = 0, None
    db.add(LoginEvent(user_id=user.id, audience=audience, ip=ip, success=True, reason="ok", risk_score=risk.score,
                      risk_reasons=risk.reasons, device_id=device_id, country=country, lat=lat, lon=lon))
    if risk.reasons and audience == AUD_APP:
        notify(db, user.id, "Nuevo inicio de sesión", "Detectamos un acceso con: " + "; ".join(risk.reasons)
               + ". Si no fue usted, cierre las sesiones y cambie su contraseña.", kind="auth", severity="medium")


def new_challenge(db: Session, user: User, purpose: str, audience: str, seconds: int = 300) -> AuthChallenge:
    ch = AuthChallenge(user_id=user.id, purpose=purpose, audience=audience, value=secrets.token_urlsafe(32),
                       expires_at=utcnow() + timedelta(seconds=seconds))
    db.add(ch)
    db.flush()
    return ch


def consume_challenge(db: Session, challenge_id: str, purpose: str) -> tuple[AuthChallenge, User]:
    ch = db.get(AuthChallenge, challenge_id)
    if ch is None or ch.purpose != purpose or ch.used_at or ch.expires_at < utcnow() or ch.attempts >= 5:
        raise ApiError(401, "challenge_invalid", "El código expiró; inicie sesión de nuevo")
    ch.attempts += 1
    return ch, db.get(User, ch.user_id)


def verify_second_factor(user: User, code: str) -> bool:
    secret = open_text(user.totp_secret_enc, f"totp:{user.id}")
    if verify_totp(secret, code):
        return True
    digest = token_hash(code.strip().lower())
    if digest in user.recovery_code_hashes:
        user.recovery_code_hashes = [h for h in user.recovery_code_hashes if h != digest]
        return True
    return False
