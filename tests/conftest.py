import base64
import os

os.environ.update({
    "GUARDIAN_ENV": "test",
    "GUARDIAN_JWT_SECRET": "test-secret-" + "x" * 50,
    "GUARDIAN_KEYRING": "v1:" + base64.b64encode(b"0" * 32).decode(),
    "GUARDIAN_ACTIVE_KEY_VERSION": "v1",
    "GUARDIAN_DATABASE_URL": "sqlite://",
    "GUARDIAN_ANTHROPIC_API_KEY": "",
    # Las pruebas no deben depender del .env de quien las corre (p. ej. un Ollama local): sin esto,
    # cualquier prueba del asistente intentaba hablar con el modelo real de la persona.
    "GUARDIAN_LLM_PROVIDER": "auto",
    "GUARDIAN_LLM_BASE_URL": "",
    "GUARDIAN_LLM_MODEL": "",
    "GUARDIAN_WEB_BROWSING_ENABLED": "false",
})

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
get_settings.cache_clear()
from app.db.session import init_db
from app.core.ratelimit import limiter
from app.main import app


@pytest.fixture(autouse=True)
def _fresh():
    from app.db.session import Base, engine
    Base.metadata.drop_all(engine)
    init_db()
    limiter.reset()
    yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def user_token(client):
    r = client.post("/v1/auth/register", json={
        "email": "ana@example.com", "full_name": "Ana Pérez", "password": "MiClaveSegura2026!",
        "accept_terms": True, "accept_health_data": True})
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


@pytest.fixture
def auth(user_token):
    return {"Authorization": f"Bearer {user_token}"}
