from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core import rbac
from app.core.errors import ApiError, forbidden
from app.core.plans import features_for
from app.core.security import AUD_ADMIN, AUD_APP, decode_access_token, utcnow
from app.db.models import AuthSession, User
from app.db.session import get_db

DB = Annotated[Session, Depends(get_db)]
_bearer = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> str:
    # Solo se confía en X-Forwarded-For si el proxy de confianza lo reescribe (ver uvicorn --proxy-headers).
    return request.client.host if request.client else "0.0.0.0"


@dataclass
class Principal:
    user: User
    session_id: str
    audience: str

    @property
    def role(self) -> str:
        return self.user.role


def _authenticate(db: Session, creds: HTTPAuthorizationCredentials | None, audience: str) -> Principal:
    if creds is None or creds.scheme.lower() != "bearer":
        raise ApiError(401, "not_authenticated", "Debe iniciar sesión")
    claims = decode_access_token(creds.credentials, audience)
    session = db.get(AuthSession, claims["sid"])
    if session is None or session.revoked_at is not None or session.expires_at < utcnow():
        raise ApiError(401, "session_revoked", "La sesión fue cerrada")
    user = db.get(User, claims["sub"])
    if user is None or user.status != "active":
        raise ApiError(401, "account_inactive", "La cuenta no está activa")
    if int(user.password_changed_at.timestamp()) > claims["iat"] + 1:
        raise ApiError(401, "session_revoked", "La contraseña cambió; inicie sesión de nuevo")
    return Principal(user=user, session_id=session.id, audience=audience)


def current_user(db: DB, creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]) -> Principal:
    return _authenticate(db, creds, AUD_APP)


def current_staff(db: DB, creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]) -> Principal:
    p = _authenticate(db, creds, AUD_ADMIN)
    if p.role not in rbac.STAFF_ROLES:
        raise forbidden()
    return p


CurrentUser = Annotated[Principal, Depends(current_user)]
CurrentStaff = Annotated[Principal, Depends(current_staff)]


def require(perm: str):
    def _dep(staff: CurrentStaff) -> Principal:
        if not rbac.has_permission(staff.role, perm):
            raise forbidden(f"Se requiere el permiso «{perm}»")
        return staff
    return Depends(_dep)


def require_feature(feature: str):
    def _dep(p: CurrentUser) -> Principal:
        if feature not in features_for(p.user.plan):
            raise ApiError(402, "plan_required", "Esta función requiere mejorar su plan",
                           {"funcionalidad": feature})
        return p
    return Depends(_dep)
