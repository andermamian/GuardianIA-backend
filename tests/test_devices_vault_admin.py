"""Pruebas de los módulos de antirrobo, bóveda y consola — con énfasis en los casos de abuso."""
import os
import tempfile

import pyotp
import pytest

from app.core.config import get_settings

_tmp = tempfile.mkdtemp()
os.environ["GUARDIAN_VAULT_DIR"] = os.path.join(_tmp, "vault")
os.environ["GUARDIAN_BACKUP_DIR"] = os.path.join(_tmp, "backups")
get_settings.cache_clear()

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100


# ------------------------------------------------------------------ fixtures
def _make_staff(email: str, role: str) -> str:
    from app.core.crypto import seal_text
    from app.core.security import hash_password, new_totp_secret
    from app.db.models import User
    from app.db.session import SessionLocal
    secret = new_totp_secret()
    db = SessionLocal()
    u = User(email=email, full_name=f"Staff {role}", password_hash=hash_password("ClaveAdmin#2026Segura"),
             role=role, totp_enabled=True)
    db.add(u)
    db.flush()
    u.totp_secret_enc = seal_text(secret, f"totp:{u.id}")
    db.commit()
    db.close()
    return secret


def _staff_login(client, email: str, role: str) -> dict:
    secret = _make_staff(email, role)
    r = client.post("/v1/admin/auth/login", json={"email": email, "password": "ClaveAdmin#2026Segura",
                                                   "authorization_level": role})
    assert r.status_code == 200, r.text
    r = client.post("/v1/admin/auth/mfa", json={"challenge_id": r.json()["challenge_id"],
                                                 "code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def admin(client):
    return _staff_login(client, "admin@guardian.co", "admin")


@pytest.fixture
def device(client, auth):
    r = client.post("/v1/devices", headers=auth, json={"name": "Moto G", "platform": "android"})
    assert r.status_code == 201, r.text
    return r.json()


def _second_user(client) -> dict:
    r = client.post("/v1/auth/register", json={"email": "luis@example.com", "full_name": "Luis Gómez",
                                               "password": "OtraClaveMuyLarga#99", "accept_terms": True})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ================================================================ antirrobo
def test_device_register_and_telemetry(client, auth, device):
    r = client.post("/v1/devices/telemetry", json={"device_token": device["device_token"], "battery": 80,
                                                   "lat": 7.98, "lon": -72.47})
    assert r.status_code == 200 and r.json()["estado"] == "ok"
    listed = client.get("/v1/devices", headers=auth).json()
    assert listed[0]["battery"] == 80 and listed[0]["last_lat"] == 7.98


def test_device_token_is_not_user_token(client, auth, device):
    bad = client.post("/v1/devices/telemetry", json={"device_token": "x" * 40, "battery": 10})
    assert bad.status_code == 401


def test_other_user_cannot_see_or_command_device(client, auth, device):
    other = _second_user(client)
    assert client.get(f"/v1/devices/{device['id']}/locations", headers=other).status_code == 404
    r = client.post(f"/v1/devices/{device['id']}/commands", headers=other, json={"kind": "ring"})
    assert r.status_code == 404  # 404 y no 403: no se confirma que el recurso exista


def test_lost_mode_queues_lock_and_command_ack_flow(client, auth, device):
    r = client.put(f"/v1/devices/{device['id']}/status", headers=auth, json={"status": "lost"})
    assert r.status_code == 200 and r.json()["status"] == "lost"
    pending = client.post("/v1/devices/commands/pending", json={"device_token": device["device_token"]}).json()
    assert {c["kind"] for c in pending} == {"lock", "locate"}
    cmd = pending[0]
    tampered = client.post(f"/v1/devices/commands/{cmd['id']}/ack", json={
        "device_token": device["device_token"], "signature": "0" * 64, "status": "completed"})
    assert tampered.status_code == 409
    ok = client.post(f"/v1/devices/commands/{cmd['id']}/ack", json={
        "device_token": device["device_token"], "signature": cmd["signature"], "status": "completed"})
    assert ok.status_code == 200


def test_cannot_remove_reported_device(client, auth, device):
    client.put(f"/v1/devices/{device['id']}/status", headers=auth, json={"status": "stolen"})
    assert client.delete(f"/v1/devices/{device['id']}", headers=auth).status_code == 409


def test_wipe_requires_confirmation_and_report(client, auth, device):
    url = f"/v1/devices/{device['id']}/commands"
    assert client.post(url, headers=auth, json={"kind": "wipe"}).status_code == 422
    assert client.post(url, headers=auth, json={"kind": "wipe", "confirm_wipe": True}).status_code == 409
    client.put(f"/v1/devices/{device['id']}/status", headers=auth, json={"status": "stolen"})
    assert client.post(url, headers=auth, json={"kind": "wipe", "confirm_wipe": True}).status_code == 201


def test_wipe_completion_kills_device_token(client, auth, device):
    client.put(f"/v1/devices/{device['id']}/status", headers=auth, json={"status": "stolen"})
    client.post(f"/v1/devices/{device['id']}/commands", headers=auth, json={"kind": "wipe", "confirm_wipe": True})
    tok = device["device_token"]
    wipe = next(c for c in client.post("/v1/devices/commands/pending", json={"device_token": tok}).json()
                if c["kind"] == "wipe")
    client.post(f"/v1/devices/commands/{wipe['id']}/ack",
                json={"device_token": tok, "signature": wipe["signature"], "status": "completed"})
    assert client.post("/v1/devices/telemetry", json={"device_token": tok}).status_code == 401


# ==================================================================== bóveda
def test_vault_upload_download_roundtrip_encrypted_on_disk(client, auth):
    r = client.post("/v1/vault/files", headers=auth, data={"category": "photos"},
                    files={"file": ("../../etc/mi foto.png", PNG, "image/png")})
    assert r.status_code == 201, r.text
    f = r.json()
    assert f["filename"] == "mi foto.png" and f["mime"] == "image/png"  # ruta saneada
    stored = os.listdir(get_settings().vault_dir)
    raw = open(os.path.join(get_settings().vault_dir, stored[0]), "rb").read()
    assert PNG not in raw and b"PNG" not in raw  # cifrado en reposo
    d = client.get(f"/v1/vault/files/{f['id']}/download", headers=auth)
    assert d.status_code == 200 and d.content == PNG
    assert "attachment" in d.headers["content-disposition"]


def test_vault_rejects_disguised_executable(client, auth):
    r = client.post("/v1/vault/files", headers=auth, data={"category": "photos"},
                    files={"file": ("foto.jpg", b"MZ\x90\x00" + b"\x00" * 60, "image/jpeg")})
    assert r.status_code == 415


def test_vault_rejects_svg_and_html(client, auth):
    for name, data in (("a.svg", b"<svg onload=alert(1)>"), ("a.html", b"<script>alert(1)</script>")):
        r = client.post("/v1/vault/files", headers=auth, data={"category": "documents"},
                        files={"file": (name, data, "text/plain")})
        assert r.status_code == 415


def test_vault_isolation_between_users(client, auth):
    f = client.post("/v1/vault/files", headers=auth, data={"category": "documents"},
                    files={"file": ("x.pdf", b"%PDF-1.7 hola", "application/pdf")}).json()
    other = _second_user(client)
    assert client.get(f"/v1/vault/files/{f['id']}/download", headers=other).status_code == 404
    assert client.delete(f"/v1/vault/files/{f['id']}", headers=other).status_code == 404


def test_vault_secrets_e2e_and_audit(client, auth):
    for strength, breached in (("fuerte", False), ("debil", True)):
        r = client.post("/v1/vault/secrets", headers=auth,
                        json={"ciphertext": "base64-cifrado-en-el-telefono", "strength": strength,
                              "breached": breached})
        assert r.status_code == 201
    a = client.get("/v1/vault/secrets/audit", headers=auth).json()
    assert a == {"total": 2, "fuertes": 1, "medias": 0, "debiles": 1, "comprometidas": 1}


def test_password_generator(client, auth):
    r = client.post("/v1/vault/passwords/generate", headers=auth, json={"length": 24}).json()
    assert len(r["password"]) == 24 and r["fortaleza"] == "fuerte"


def test_breach_prefix_validated(client, auth):
    assert client.get("/v1/vault/passwords/breach-range/ZZZZZ", headers=auth).status_code == 422
    assert client.get("/v1/vault/passwords/breach-range/ABCDE", headers=auth).status_code == 503  # deshabilitado


# ==================================================================== admin
def test_user_token_cannot_use_admin_api(client, auth):
    assert client.get("/v1/admin/dashboard", headers=auth).status_code == 401


def test_admin_dashboard(client, auth, admin):
    r = client.get("/v1/admin/dashboard", headers=admin)
    assert r.status_code == 200
    assert r.json()["usuarios"]["total"] >= 2


def test_supervisor_lacks_write_permissions(client, auth):
    sup = _staff_login(client, "sup@guardian.co", "supervisor")
    assert client.get("/v1/admin/users", headers=sup).status_code == 200
    uid = client.get("/v1/auth/me", headers=auth).json()["id"]
    r = client.put(f"/v1/admin/users/{uid}/status", headers=sup, json={"status": "suspended", "reason": "prueba"})
    assert r.status_code == 403


def test_suspend_user_revokes_sessions(client, auth, admin):
    uid = client.get("/v1/auth/me", headers=auth).json()["id"]
    r = client.put(f"/v1/admin/users/{uid}/status", headers=admin,
                   json={"status": "suspended", "reason": "Actividad fraudulenta"})
    assert r.status_code == 200 and r.json()["status"] == "suspended"
    assert client.get("/v1/auth/me", headers=auth).status_code == 401


def test_admin_cannot_manage_peer_or_self(client, admin):
    _make_staff("otro@guardian.co", "admin")
    users = client.get("/v1/admin/users", headers=admin, params={"role": "admin"}).json()["items"]
    me = client.get("/v1/admin/auth/me", headers=admin).json()["id"]
    peer = next(u for u in users if u["id"] != me)
    body = {"status": "suspended", "reason": "intento"}
    assert client.put(f"/v1/admin/users/{peer['id']}/status", headers=admin, json=body).status_code == 403
    assert client.put(f"/v1/admin/users/{me}/status", headers=admin, json=body).status_code == 403


def test_role_promotion_requires_super_admin_and_mfa(client, auth, admin):
    uid = client.get("/v1/auth/me", headers=auth).json()["id"]
    r = client.put(f"/v1/admin/users/{uid}/role", headers=admin, json={"role": "supervisor", "reason": "x" * 5})
    assert r.status_code == 403  # admin no tiene users:roles
    root = _staff_login(client, "root@guardian.co", "super_admin")
    r = client.put(f"/v1/admin/users/{uid}/role", headers=root, json={"role": "supervisor", "reason": "x" * 5})
    assert r.status_code == 409 and r.json()["code"] == "mfa_required"


def test_block_ip_rules(client, admin):
    assert client.post("/v1/admin/blocked-ips", headers=admin,
                       json={"ip": "10.0.0.5", "reason": "prueba"}).status_code == 409
    assert client.post("/v1/admin/blocked-ips", headers=admin,
                       json={"ip": "no-es-ip", "reason": "prueba"}).status_code == 422
    assert client.post("/v1/admin/blocked-ips", headers=admin,
                       json={"ip": "185.220.101.4", "reason": "fuerza bruta", "hours": 24}).status_code == 201


def test_blocked_ip_is_enforced(client, admin):
    from app.core.blocklist import blocklist
    from app.db.models import BlockedIP
    from app.db.session import SessionLocal
    db = SessionLocal()
    db.add(BlockedIP(ip="testclient", reason="prueba de middleware"))  # TestClient usa este host
    db.commit()
    db.close()
    blocklist.invalidate()
    assert client.get("/health").status_code == 403
    blocklist._ips.clear()
    blocklist.invalidate()


def test_audit_chain_detects_tampering(client, auth, admin):
    from app.db.models import AuditLog
    from app.db.session import SessionLocal
    assert client.get("/v1/admin/audit/verify", headers=admin).json()["integra"] is True
    db = SessionLocal()
    row = db.query(AuditLog).order_by(AuditLog.id).first()
    row.action = "borrado.encubierto"
    db.commit()
    db.close()
    r = client.get("/v1/admin/audit/verify", headers=admin).json()
    assert r["integra"] is False


def test_medical_recommendation_needs_expert_review(client, admin):
    from app.db.models import Recommendation
    from app.db.session import SessionLocal
    db = SessionLocal()
    rec = Recommendation(area="medical", setting_key="vitals.hr_max_default", current_value={"v": 120},
                         proposed_value={"v": 110}, rationale="Menos falsos negativos", source="vitals_engine")
    db.add(rec)
    db.commit()
    rid = rec.id
    db.close()
    r = client.post(f"/v1/admin/recommendations/{rid}/decision", headers=admin, json={"decision": "approve"})
    assert r.status_code == 409 and r.json()["code"] == "expert_review_required"


def test_diagnostics(client, admin):
    r = client.get("/v1/admin/diagnostics", headers=admin)
    assert r.status_code == 200 and r.json()["comprobaciones"]["cifrado"]["ok"] is True


# ───────────────────────── vinculación por código (sin copiar tokens)
def test_vinculacion_por_codigo(client, auth):
    """Una persona sin experiencia no debería copiar un token de 43 caracteres entre ventanas."""
    r = client.post("/v1/devices/vinculacion", headers=auth, json={"nombre_sugerido": "HP de Anderson"})
    assert r.status_code == 201
    datos = r.json()
    assert len(datos["codigo"]) == 6 and datos["codigo"].isdigit()
    assert datos["qr"].startswith("data:image/png;base64,")   # para escanear desde el celular

    # El equipo nuevo canjea el código sin estar autenticado: el código es el secreto.
    canje = client.post("/v1/devices/vinculacion/canjear",
                        json={"codigo": datos["codigo"], "nombre": "HP de Anderson",
                              "platform": "windows", "model": "Ryzen 7 7730U"})
    assert canje.status_code == 201
    assert len(canje.json()["device_token"]) > 30

    # Un solo uso: el segundo intento falla.
    repetido = client.post("/v1/devices/vinculacion/canjear",
                           json={"codigo": datos["codigo"], "nombre": "Otro", "platform": "windows"})
    assert repetido.status_code == 400 and repetido.json()["code"] == "codigo_invalido"

    # Y el dispositivo aparece en la cuenta correcta.
    equipos = client.get("/v1/devices", headers=auth).json()
    assert any(e["name"] == "HP de Anderson" for e in equipos)


def test_codigo_vencido_no_sirve(client, auth):
    from datetime import timedelta

    from app.core.security import utcnow
    from app.db.models import PairingCode
    from app.db.session import SessionLocal
    codigo = client.post("/v1/devices/vinculacion", headers=auth, json={}).json()["codigo"]
    db = SessionLocal()
    try:
        fila = db.query(PairingCode).order_by(PairingCode.created_at.desc()).first()
        fila.expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()
    r = client.post("/v1/devices/vinculacion/canjear",
                    json={"codigo": codigo, "nombre": "Tarde", "platform": "windows"})
    assert r.status_code == 400 and "venció" in r.json()["title"]


def test_codigo_equivocado_no_revela_nada_y_se_bloquea(client, auth):
    client.post("/v1/devices/vinculacion", headers=auth, json={})
    for _ in range(5):
        fallo = client.post("/v1/devices/vinculacion/canjear",
                            json={"codigo": "000000", "nombre": "Intruso", "platform": "windows"})
        assert fallo.status_code == 400
    # Tras 5 intentos fallidos el código vivo queda quemado, aunque el atacante acierte después.
    from app.db.models import PairingCode
    from app.db.session import SessionLocal
    db = SessionLocal()
    try:
        assert db.query(PairingCode).order_by(PairingCode.created_at.desc()).first().intentos >= 5
    finally:
        db.close()
