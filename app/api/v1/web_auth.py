"""Sesión para los clientes web (/app y /consola).

La app Android guarda el refresh token en el Keystore. Un navegador no tiene equivalente seguro:
localStorage y sessionStorage son legibles por cualquier script, así que un solo XSS robaría la
sesión de 30 días. Aquí el refresh token viaja en una cookie:

* HttpOnly  → JavaScript no puede leerla.
* SameSite=Strict + cabecera obligatoria X-Guardian-Web → otro sitio no puede usarla (CSRF).
* Path limitado a /v1/web/... → no acompaña a cada petición de la API.
* Secure en HTTPS.

El access token (15 min) vive solo en memoria de la pestaña y se renueva con la cookie.
Estos endpoints reutilizan la misma lógica de autenticación: no hay una segunda implementación
que pueda divergir.
"""
from __future__ import annotations

from fastapi import APIRouter, Request, Response

from app.api.deps import DB, CurrentStaff, CurrentUser
from app.api.v1 import auth as core
from app.core.errors import ApiError
from app.core.security import AUD_ADMIN, AUD_APP, utcnow
from app.db.models import AuthSession
from app.schemas.auth import AdminLoginIn, LoginIn, MfaVerifyIn, RefreshIn, RegisterIn
from app.schemas.common import Msg

APP_COOKIE, APP_PATH = "gi_app_rt", "/v1/web/auth"
# Indicador sin secretos, legible por JS: evita intentar renovar (y un 401 en consola) cuando no hay sesión.
HINT = {"gi_app_rt": "gi_app_s", "gi_admin_rt": "gi_admin_s"}
ADMIN_COOKIE, ADMIN_PATH = "gi_admin_rt", "/v1/web/admin/auth"

router = APIRouter(prefix="/web", tags=["Sesión web (cookies)"])


def _require_web_header(request: Request) -> None:
    # Una cabecera personalizada obliga a una verificación CORS previa: un formulario o <img> de otro
    # sitio no puede enviarla, así que la cookie nunca se usa desde un origen ajeno.
    if request.headers.get("x-guardian-web") != "1":
        raise ApiError(403, "web_header_required", "Solicitud no válida")


def _deliver(request: Request, response: Response, result, cookie: str, path: str):
    if isinstance(result, dict) and "access_token" in result:
        if result.get("refresh_token"):
            response.set_cookie(cookie, result["refresh_token"], httponly=True, samesite="strict", path=path,
                                secure=request.url.scheme == "https", max_age=30 * 24 * 3600)
            response.set_cookie(HINT[cookie], "1", samesite="strict", path="/", secure=request.url.scheme == "https",
                                max_age=30 * 24 * 3600)
        user = result["user"]
        return {"access_token": result["access_token"], "expires_in": result["expires_in"],
                "user": core.UserOut.model_validate(user).model_dump(mode="json")}
    return result  # reto de 2FA: no hay tokens todavía


def _clear(response: Response, cookie: str, path: str) -> None:
    response.delete_cookie(cookie, path=path)
    response.delete_cookie(HINT[cookie], path="/")


def _cookie_refresh(request: Request, db, cookie: str, path: str, audience: str, response: Response):
    _require_web_header(request)
    raw = request.cookies.get(cookie)
    if not raw:
        raise ApiError(401, "no_session", "Inicie sesión")
    try:
        fn = core.refresh if audience == AUD_APP else core.admin_refresh
        result = fn(RefreshIn(refresh_token=raw), request, db)
    except ApiError:
        _clear(response, cookie, path)
        raise
    return _deliver(request, response, result, cookie, path)


# ------------------------------------------------------------------- app
@router.post("/auth/register", status_code=201)
def web_register(body: RegisterIn, request: Request, response: Response, db: DB):
    _require_web_header(request)
    return _deliver(request, response, core.register(body, request, db), APP_COOKIE, APP_PATH)


@router.post("/auth/login")
def web_login(body: LoginIn, request: Request, response: Response, db: DB):
    _require_web_header(request)
    return _deliver(request, response, core.login(body, request, db), APP_COOKIE, APP_PATH)


@router.post("/auth/login/mfa")
def web_login_mfa(body: MfaVerifyIn, request: Request, response: Response, db: DB):
    _require_web_header(request)
    return _deliver(request, response, core.login_mfa(body, request, db), APP_COOKIE, APP_PATH)


@router.post("/auth/refresh")
def web_refresh(request: Request, response: Response, db: DB):
    return _cookie_refresh(request, db, APP_COOKIE, APP_PATH, AUD_APP, response)


@router.post("/auth/logout", response_model=Msg)
def web_logout(request: Request, response: Response, p: CurrentUser, db: DB):
    _require_web_header(request)
    s = db.get(AuthSession, p.session_id)
    s.revoked_at, s.revoke_reason = utcnow(), "logout"
    db.commit()
    _clear(response, APP_COOKIE, APP_PATH)
    return Msg(mensaje="Sesión cerrada")


# --------------------------------------------------------------- consola
@router.post("/admin/auth/login")
def web_admin_login(body: AdminLoginIn, request: Request, db: DB):
    _require_web_header(request)
    return core.admin_login(body, request, db)


@router.post("/admin/auth/mfa")
def web_admin_mfa(body: MfaVerifyIn, request: Request, response: Response, db: DB):
    _require_web_header(request)
    return _deliver(request, response, core.admin_mfa(body, request, db), ADMIN_COOKIE, ADMIN_PATH)


@router.post("/admin/auth/refresh")
def web_admin_refresh(request: Request, response: Response, db: DB):
    return _cookie_refresh(request, db, ADMIN_COOKIE, ADMIN_PATH, AUD_ADMIN, response)


@router.post("/admin/auth/logout", response_model=Msg)
def web_admin_logout(request: Request, response: Response, staff: CurrentStaff, db: DB):
    _require_web_header(request)
    core.admin_logout(staff, request, db)
    _clear(response, ADMIN_COOKIE, ADMIN_PATH)
    return Msg(mensaje="Sesión administrativa cerrada")
