"""Sesión web por cookies, CSP del frontend y notificaciones."""
from datetime import timedelta

from app.core.security import utcnow

H = {"X-Guardian-Web": "1"}
USER = {"email": "web@example.com", "full_name": "Web Uno", "password": "Frase larga de prueba 2026",
        "accept_terms": True}


def _register(client):
    r = client.post("/v1/web/auth/register", json=USER, headers=H)
    assert r.status_code == 201, r.text
    return r


def test_web_register_sets_httponly_cookie_and_hides_refresh(client):
    r = _register(client)
    body = r.json()
    assert "refresh_token" not in body and body["access_token"]
    cookies = r.headers.get_list("set-cookie")
    rt = next(c for c in cookies if c.startswith("gi_app_rt="))
    assert "HttpOnly" in rt and "SameSite=strict" in rt and "Path=/v1/web/auth" in rt
    hint = next(c for c in cookies if c.startswith("gi_app_s="))
    assert "HttpOnly" not in hint  # el indicador no lleva secretos


def test_web_endpoints_require_csrf_header(client):
    _register(client)
    assert client.post("/v1/web/auth/refresh").status_code == 403
    assert client.post("/v1/web/auth/login", json={"email": USER["email"], "password": USER["password"]}).status_code == 403


def test_cookie_refresh_rotates(client):
    _register(client)
    first = client.cookies.get("gi_app_rt")
    r = client.post("/v1/web/auth/refresh", headers=H)
    assert r.status_code == 200 and r.json()["access_token"]
    assert client.cookies.get("gi_app_rt") != first


def test_concurrent_refresh_within_grace_does_not_kill_session(client):
    _register(client)
    old = client.cookies.get("gi_app_rt")
    assert client.post("/v1/web/auth/refresh", headers=H).status_code == 200  # pestaña A rota
    new = client.cookies.get("gi_app_rt")
    client.cookies.set("gi_app_rt", old, path="/v1/web/auth")                  # pestaña B llega tarde con el viejo
    r = client.post("/v1/web/auth/refresh", headers=H)
    assert r.status_code == 200, r.text
    client.cookies.set("gi_app_rt", new, path="/v1/web/auth")
    assert client.post("/v1/web/auth/refresh", headers=H).status_code == 200  # la sesión sigue viva


def test_reuse_after_grace_revokes_session(client):
    from app.db.models import AuthSession
    from app.db.session import SessionLocal
    _register(client)
    old = client.cookies.get("gi_app_rt")
    client.post("/v1/web/auth/refresh", headers=H)
    db = SessionLocal()
    s = db.query(AuthSession).first()
    s.last_seen_at = utcnow() - timedelta(minutes=5)
    db.commit()
    db.close()
    client.cookies.set("gi_app_rt", old, path="/v1/web/auth")
    r = client.post("/v1/web/auth/refresh", headers=H)
    assert r.status_code == 401 and r.json()["code"] == "session_revoked"


def test_logout_clears_cookie(client):
    token = _register(client).json()["access_token"]
    r = client.post("/v1/web/auth/logout", headers={**H, "Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert any(c.startswith("gi_app_rt=") and "Max-Age=0" in c for c in r.headers.get_list("set-cookie"))


def test_frontend_served_with_strict_csp(client):
    for path in ("/app/", "/consola/", "/static/app/main.js"):
        r = client.get(path)
        assert r.status_code == 200, path
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert "default-src 'none'" in client.get("/health").headers["content-security-policy"]


def test_notifications_flow(client, auth):
    from app.db.models import Notification, User
    from app.db.session import SessionLocal
    db = SessionLocal()
    uid = db.query(User).first().id
    db.add_all([Notification(user_id=uid, kind="info", title=f"Aviso {i}", body="x") for i in range(3)])
    db.commit()
    db.close()
    r = client.get("/v1/notifications", headers=auth).json()
    assert r["sin_leer"] == 3
    client.post(f"/v1/notifications/{r['items'][0]['id']}/read", headers=auth)
    assert client.get("/v1/notifications", headers=auth).json()["sin_leer"] == 2
    client.post("/v1/notifications/read-all", headers=auth)
    assert client.get("/v1/notifications", headers=auth).json()["sin_leer"] == 0


def test_admin_permissions_endpoint(client):
    from tests.test_devices_vault_admin import _staff_login
    sup = _staff_login(client, "sup2@guardian.co", "supervisor")
    perms = client.get("/v1/admin/permissions", headers=sup).json()
    assert perms["rol"] == "supervisor" and "users:write" not in perms["permisos"]


def test_dev_genera_claves_si_faltan_y_produccion_no(monkeypatch):
    """Sin claves en .env la app debe seguir usable en desarrollo (con aviso), nunca fallar al firmar
    el primer token con «Error interno», y en producción debe negarse a arrancar."""
    from app.core.config import Settings
    dev = Settings(env="development", jwt_secret="", keyring="")
    assert dev.ensure_dev_secrets() == ["GUARDIAN_JWT_SECRET", "GUARDIAN_KEYRING"]
    assert len(dev.jwt_secret) >= 48 and dev.active_key_version in dev.keys()
    dev.validate_for_runtime()  # ya no hay problemas
    assert dev.ensure_dev_secrets() == []  # idempotente

    prod = Settings(env="production", jwt_secret="", keyring="")
    assert prod.ensure_dev_secrets() == []
    try:
        prod.validate_for_runtime()
        raise AssertionError("producción debía rechazar la configuración vacía")
    except RuntimeError as e:
        assert "GUARDIAN_JWT_SECRET" in str(e)


def test_cli_exige_claves_reales(monkeypatch, capsys):
    """El CLI no debe inventar claves: cifraría el secreto 2FA con una clave que el servidor no tiene."""
    import app.cli as cli
    import app.core.config as config
    from app.core.config import Settings
    monkeypatch.setattr(config, "get_settings", lambda: Settings(env="development", jwt_secret="", keyring=""))
    try:
        cli._require_keys()
        raise AssertionError("debía abortar")
    except SystemExit as e:
        assert e.code == 1
        assert "generate-keys" in capsys.readouterr().err


def test_env_se_busca_junto_al_proyecto(tmp_path, monkeypatch):
    """Arrancar el servidor desde otra carpeta no debe ignorar el .env del proyecto: antes eso dejaba
    la app sin claves y todo terminaba en «Error interno» al firmar el primer token."""
    from app.core.config import PROJECT_ROOT, Settings
    monkeypatch.chdir(tmp_path)
    assert str(PROJECT_ROOT / ".env") in Settings.model_config["env_file"]
    s = Settings(env="development")
    assert s.env_file_in_use() in (None, PROJECT_ROOT / ".env")


def test_doctor_detecta_configuracion_incompleta(monkeypatch, capsys):
    import app.cli as cli
    import app.core.config as config
    from app.core.config import Settings
    monkeypatch.setattr(config, "get_settings", lambda: Settings(env="development", jwt_secret="", keyring=""))
    try:
        cli.doctor(None)
        raise AssertionError("debía terminar con error")
    except SystemExit as e:
        salida = capsys.readouterr().out
        assert e.code == 1
        assert "GUARDIAN_JWT_SECRET" in salida and "python -m app.cli setup" in salida


def test_error_500_muestra_la_causa_en_desarrollo_y_la_oculta_en_produccion(client, monkeypatch):
    """Un «Error interno» sin más deja al desarrollador adivinando; la traza en producción, en cambio,
    revela rutas y estructura interna."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.core import errors
    from app.core.config import Settings

    def build(env: str) -> TestClient:
        app = FastAPI()
        monkeypatch.setattr(errors, "get_settings", lambda: Settings(env=env, jwt_secret="x" * 48))
        errors.install(app)

        @app.get("/boom")
        def boom():
            raise ValueError("fallo simulado")

        return TestClient(app, raise_server_exceptions=False)

    dev = build("development").get("/boom").json()
    assert dev["code"] == "internal_error" and "fallo simulado" in dev["detalle"]
    assert "doctor" in dev["ayuda"]  # el mensaje dice qué ejecutar
    prod = build("production").get("/boom").json()
    assert prod["code"] == "internal_error" and "detalle" not in prod and "fallo simulado" not in str(prod)


def test_zona_horaria_ausente_no_rompe_el_registro(monkeypatch):
    """En Windows sin `tzdata`, ZoneInfo lanza ZoneInfoNotFoundError. Eso no puede impedir que alguien
    cree su cuenta: se avisa en el log y se sigue con UTC."""
    import zoneinfo
    from datetime import timezone

    import app.core.tz as tz

    def explota(*a, **k):
        raise zoneinfo.ZoneInfoNotFoundError("No time zone found with key America/Bogota")

    monkeypatch.setattr(tz, "ZoneInfo", explota)
    tz._avisadas.clear()
    assert tz.zone("America/Bogota") is timezone.utc
    assert tz.zone(None) is timezone.utc


def test_registro_funciona_sin_base_de_zonas(client, monkeypatch):
    import zoneinfo

    import app.core.tz as tz
    monkeypatch.setattr(tz, "ZoneInfo", lambda *a, **k: (_ for _ in ()).throw(
        zoneinfo.ZoneInfoNotFoundError("sin tzdata")))
    tz._avisadas.clear()
    r = client.post("/v1/auth/register", json={
        "email": "sinzona@example.com", "full_name": "Sin Zona", "password": "Zorro montaña bici 4471",
        "accept_terms": True})
    assert r.status_code == 201, r.text
