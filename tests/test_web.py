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


def test_raiz_lleva_a_la_app_en_navegador_y_mantiene_json_para_la_api(client):
    """Escribir 127.0.0.1:8000/#/asistente mostraba el JSON de la API. Un navegador debe terminar en
    la app; un cliente de API debe seguir recibiendo JSON."""
    html = client.get("/", headers={"Accept": "text/html"})
    assert html.status_code == 200 and "ir-a-la-app.js" in html.text
    api = client.get("/", headers={"Accept": "application/json"})
    assert api.json()["servicio"] == "GuardianIA API"
    assert client.get("/static/shared/ir-a-la-app.js").status_code == 200


def _fake_client(handler):
    import httpx
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_asistente_con_anthropic_y_con_modelo_compatible_openai(monkeypatch):
    """El asistente debe funcionar igual con Anthropic o con un modelo compatible con OpenAI
    (Ollama local, Groq, OpenRouter): el resto del sistema no debe notar la diferencia."""
    import httpx

    from app.ai import assistant
    from app.core.config import Settings

    persona = assistant.Persona(name="Guardian")
    vistos = {}

    def anthropic_handler(request: httpx.Request) -> httpx.Response:
        vistos["url"] = str(request.url)
        return httpx.Response(200, json={"content": [{"type": "text", "text": "Respuesta del modelo"}]})

    s = Settings(env="test", anthropic_api_key="sk-ant-prueba", web_browsing_enabled=False)
    monkeypatch.setattr(assistant, "get_settings", lambda: s)
    r = assistant.respond("¿qué es el phishing?", [], persona, client=_fake_client(anthropic_handler))
    assert r.provider == "anthropic" and r.text == "Respuesta del modelo"
    assert "api.anthropic.com" in vistos["url"]

    def openai_handler(request: httpx.Request) -> httpx.Response:
        vistos["url"] = str(request.url)
        vistos["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"choices": [{"message": {"content": "Respuesta local"}}]})

    s2 = Settings(env="test", llm_provider="openai", llm_base_url="http://localhost:11434/v1",
                  llm_model="llama3.1:8b", web_browsing_enabled=False)
    monkeypatch.setattr(assistant, "get_settings", lambda: s2)
    r2 = assistant.respond("¿qué es el phishing?", [], persona, client=_fake_client(openai_handler))
    assert r2.provider == "openai" and r2.text == "Respuesta local"
    assert vistos["url"] == "http://localhost:11434/v1/chat/completions"
    assert vistos["auth"] is None  # Ollama local no lleva clave


def test_asistente_cae_a_modo_local_si_el_proveedor_falla(monkeypatch):
    """Si el modelo no responde, el asistente sigue sirviendo: no puede quedarse mudo."""
    import httpx

    from app.ai import assistant
    from app.core.config import Settings

    s = Settings(env="test", anthropic_api_key="sk-ant-prueba", web_browsing_enabled=False)
    monkeypatch.setattr(assistant, "get_settings", lambda: s)
    r = assistant.respond("hola", [], assistant.Persona(name="Guardian"),
                          client=_fake_client(lambda req: httpx.Response(401, json={"error": "clave inválida"})))
    assert r.provider == "local_fallback" and r.text


def test_modo_local_responde_con_conocimiento_propio(monkeypatch):
    """Sin modelo, el asistente debe seguir sirviendo: antes solo se presentaba."""
    from app.ai import assistant
    from app.core.config import Settings
    monkeypatch.setattr(assistant, "get_settings", lambda: Settings(env="test", web_browsing_enabled=False))
    persona = assistant.Persona(name="Guardian")
    r = assistant.respond("¿qué es el phishing?", [], persona)
    assert r.provider == "local" and "phishing" in r.text.lower() and len(r.text) > 200
    r2 = assistant.respond("me robaron el celular", [], persona)
    assert "123" in r2.text and "IMEI" in r2.text
    # Lo que no sabe, no lo inventa.
    r3 = assistant.respond("¿cuántos habitantes tiene Ulán Bator?", [], persona)
    assert "no inventar" in r3.text or "No tengo una respuesta verificada" in r3.text


def test_modo_local_resume_lo_que_encuentra_en_la_web(monkeypatch):
    """Con búsqueda activa y sin modelo, responde extrayendo frases de las fuentes y citándolas."""
    from app.ai import assistant
    from app.ai import web_browser
    from app.core.config import Settings
    monkeypatch.setattr(assistant, "get_settings", lambda: Settings(env="test", web_browsing_enabled=True))
    monkeypatch.setattr(assistant, "wants_web", lambda _t: True)
    monkeypatch.setattr(web_browser, "search", lambda q, client, limit=4: [
        web_browser.SearchHit("Ransomware - CCB", "https://ejemplo.co/ransomware", "resumen")])
    monkeypatch.setattr(web_browser, "fetch", lambda url, client, max_chars=3500: web_browser.Page(
        url=url, title="Ransomware",
        text=("El ransomware es un programa que cifra los archivos del equipo y exige un pago para "
              "devolverlos. Las empresas colombianas reportaron un aumento de casos en el último año. "
              "Pagar el rescate no garantiza recuperar la información."),
        truncated=False))
    r = assistant.respond("qué es el ransomware", [], assistant.Persona(name="Guardian"))
    assert r.provider == "local" and r.searched_web
    assert "cifra los archivos" in r.text
    assert "https://ejemplo.co/ransomware" in r.text  # cita la fuente, no inventa


def test_chat_transmite_en_vivo_y_guarda_la_respuesta(client, auth, monkeypatch):
    """Con un modelo local lento, el texto debe llegar por trozos (si no, el navegador corta a los
    60 s) y la respuesta completa debe quedar guardada en la conversación."""
    from app.ai import assistant
    from app.core.config import Settings

    s = Settings(env="test", llm_provider="openai", llm_base_url="http://localhost:11434/v1",
                 llm_model="llama3", web_browsing_enabled=False)
    monkeypatch.setattr(assistant, "get_settings", lambda: s)
    import app.api.v1.assistant as api_asistente
    monkeypatch.setattr(api_asistente, "get_settings", lambda: s)
    monkeypatch.setattr(assistant, "_stream_llm", lambda *a, **k: iter(["Para ", "protegerse ", "del phishing…"]))

    trozos, final = [], None
    with client.stream("POST", "/v1/assistant/chat/stream", headers=auth,
                       json={"message": "consejos contra phishing", "allow_web": False}) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        for linea in r.iter_lines():
            if not linea.startswith("data:"):
                continue
            import json as _json
            evento = _json.loads(linea[5:])
            if evento["tipo"] == "texto":
                trozos.append(evento["texto"])
            elif evento["tipo"] == "fin":
                final = evento

    assert trozos == ["Para ", "protegerse ", "del phishing…"]  # llegó por partes, no de golpe
    assert final and final["proveedor"] == "openai"
    mensajes = client.get(f"/v1/assistant/conversations/{final['conversation_id']}", headers=auth).json()
    assert [m["role"] for m in mensajes] == ["user", "assistant"]
    assert mensajes[1]["content"] == "Para protegerse del phishing…"


def test_stream_cae_a_modo_local_si_el_modelo_no_responde(client, auth, monkeypatch):
    import httpx

    from app.ai import assistant
    from app.core.config import Settings
    s = Settings(env="test", llm_provider="openai", llm_base_url="http://localhost:11434/v1",
                 llm_model="llama3", web_browsing_enabled=False)
    monkeypatch.setattr(assistant, "get_settings", lambda: s)
    import app.api.v1.assistant as api_asistente
    monkeypatch.setattr(api_asistente, "get_settings", lambda: s)

    def cae(*a, **k):
        raise httpx.ConnectError("Ollama apagado")
        yield  # pragma: no cover

    monkeypatch.setattr(assistant, "_stream_llm", cae)
    texto = ""
    with client.stream("POST", "/v1/assistant/chat/stream", headers=auth,
                       json={"message": "¿qué es el phishing?", "allow_web": False}) as r:
        for linea in r.iter_lines():
            if linea.startswith("data:"):
                import json as _json
                evento = _json.loads(linea[5:])
                if evento["tipo"] == "texto":
                    texto += evento["texto"]
    assert "phishing" in texto.lower() and len(texto) > 150  # respondió igual, con el modo local


def test_el_asistente_se_llama_asistente_ai_y_no_se_limita_a_seguridad():
    """El prompt debe habilitar cualquier tema y la programación, sin perder las reglas de seguridad."""
    from app.ai import assistant
    p = assistant.Persona()
    assert p.name == "Asistente AI"
    prompt = assistant.system_prompt(p)
    for esperado in ["cualquier oficio", "Programación", "no tu límite", "no inventas datos"]:
        assert esperado in prompt
    assert "no escribes código ni instrucciones para dañar" in prompt.lower()


def test_modo_local_ofrece_todos_los_servicios(monkeypatch):
    from app.ai import assistant
    from app.core.config import Settings
    monkeypatch.setattr(assistant, "get_settings", lambda: Settings(env="test", web_browsing_enabled=False))
    r = assistant.respond("¿cuántos habitantes tiene Ulán Bator?", [], assistant.Persona())
    assert "cualquier tema" in r.text and "usar-ollama" in r.text  # dice qué falta, no se limita al tema


def test_migracion_del_nombre_respeta_lo_personalizado():
    """Al arrancar, las cuentas con el nombre anterior por defecto pasan a «Asistente AI»; quien
    eligió su propio nombre no se toca."""
    from app.db.models import PersonalityProfile, User
    from app.db.session import SessionLocal
    from app.main import migrar_nombre_asistente

    db = SessionLocal()
    try:
        u1, u2 = db.query(User).limit(2).all() if db.query(User).count() >= 2 else (None, None)
        if u1 is None:  # la suite crea usuarios en otras pruebas; si no hay, se omite
            return
        db.merge(PersonalityProfile(user_id=u1.id, assistant_name="Guardian"))
        db.merge(PersonalityProfile(user_id=u2.id, assistant_name="Jarvis"))
        db.commit()
    finally:
        db.close()

    migrar_nombre_asistente()

    db = SessionLocal()
    try:
        assert db.get(PersonalityProfile, u1.id).assistant_name == "Asistente AI"
        assert db.get(PersonalityProfile, u2.id).assistant_name == "Jarvis"  # elección propia intacta
    finally:
        db.close()
