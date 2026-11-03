"""Backend que necesita la app Android v2: foto del intruso, pausa desde el teléfono y red de intención."""
import base64

JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 400 + b"\xff\xd9"


def _vincular(client, auth):
    cod = client.post("/v1/devices/vinculacion", headers=auth, json={}).json()["codigo"]
    r = client.post("/v1/devices/vinculacion/canjear", json={"codigo": cod, "nombre": "Redmi", "platform": "android"})
    assert r.status_code == 201
    return r.json()["device_id"], r.json()["device_token"]


def test_foto_solo_con_equipo_reportado(client, auth):
    did, tk = _vincular(client, auth)
    r = client.post(f"/v1/devices/{did}/commands", headers=auth, json={"kind": "photo"})
    assert r.status_code == 409                       # sin reportar no se puede pedir la foto
    r = client.post("/v1/devices/self/foto", json={"device_token": tk, "imagen_b64": base64.b64encode(JPEG).decode()})
    assert r.status_code == 409                       # ni subirla por cuenta propia


def test_flujo_completo_de_foto_cifrada(client, auth):
    did, tk = _vincular(client, auth)
    client.put(f"/v1/devices/{did}/status", headers=auth, json={"status": "stolen"})
    assert client.post(f"/v1/devices/{did}/commands", headers=auth, json={"kind": "photo"}).status_code == 201
    pend = client.post("/v1/devices/commands/pending", json={"device_token": tk}).json()
    pend = [c for c in pend if c["kind"] == "photo"]    # reportarlo ya encola «lock» y «locate»
    assert len(pend) == 1
    r = client.post("/v1/devices/self/foto", json={"device_token": tk, "imagen_b64": base64.b64encode(JPEG).decode(),
                                                    "motivo": "comando", "lat": 8.3, "lon": -72.4})
    assert r.status_code == 201, r.text
    fotos = client.get(f"/v1/devices/{did}/fotos", headers=auth).json()
    assert len(fotos) == 1 and fotos[0]["lat"] == 8.3
    img = client.get(fotos[0]["url"], headers=auth)
    assert img.status_code == 200 and img.content == JPEG and img.headers["content-type"] == "image/jpeg"
    # En la base de datos va cifrada, nunca en claro.
    from app.db.models import DevicePhoto
    from app.db.session import SessionLocal
    with SessionLocal() as db:
        assert JPEG not in db.get(DevicePhoto, fotos[0]["id"]).blob
    ack = client.post(f"/v1/devices/commands/{pend[0]['id']}/ack",
                      json={"device_token": tk, "signature": pend[0]["signature"], "status": "completed",
                            "result": {"capturada": True}})
    assert ack.status_code == 200
    assert client.delete(f"/v1/devices/{did}/fotos/{fotos[0]['id']}", headers=auth).status_code == 200


def test_foto_rechaza_lo_que_no_es_jpeg(client, auth):
    did, tk = _vincular(client, auth)
    client.put(f"/v1/devices/{did}/status", headers=auth, json={"status": "lost"})
    falso = base64.b64encode(b"<script>" + b"x" * 200).decode()
    assert client.post("/v1/devices/self/foto", json={"device_token": tk, "imagen_b64": falso}).status_code == 422


def test_otro_usuario_no_ve_las_fotos(client, auth):
    did, tk = _vincular(client, auth)
    client.put(f"/v1/devices/{did}/status", headers=auth, json={"status": "stolen"})
    client.post("/v1/devices/self/foto", json={"device_token": tk, "imagen_b64": base64.b64encode(JPEG).decode()})
    otro = client.post("/v1/auth/register", json={"email": "luis@example.com", "full_name": "Luis Díaz",
                                                   "password": "OtraClaveSegura2026!", "accept_terms": True}).json()
    r = client.get(f"/v1/devices/{did}/fotos", headers={"Authorization": f"Bearer {otro['access_token']}"})
    assert r.status_code == 404


def test_telefono_pausa_y_reanuda_su_seguimiento(client, auth):
    did, tk = _vincular(client, auth)
    r = client.post("/v1/devices/self/seguimiento", json={"device_token": tk, "activo": False})
    assert r.status_code == 200 and r.json()["seguimiento"] is False
    client.put(f"/v1/devices/{did}/status", headers=auth, json={"status": "stolen"})
    r = client.post("/v1/devices/self/seguimiento", json={"device_token": tk, "activo": False})
    assert r.status_code == 409


def test_red_de_intencion_exportable_al_movil(client, auth, tmp_path, monkeypatch):
    from app.ml import asistente, entrenamiento
    monkeypatch.setattr(entrenamiento, "carpeta_modelos", lambda: tmp_path)
    entrenamiento.limpiar_cache()
    assert client.get("/v1/ml/intencion/movil", headers=auth).status_code == 409
    asistente.entrenar(tmp_path, epocas=40)
    entrenamiento.limpiar_cache()
    r = client.get("/v1/ml/intencion/movil", headers=auth)
    assert r.status_code == 200, r.text
    m = r.json()
    assert m["formato"] == "guardian-mlp-1" and m["intenciones"] == asistente.INTENCIONES
    assert len(m["W"]) == len(m["capas"]) - 1 and len(m["mu"]) == m["dimensiones"]
    assert client.get("/v1/ml/intencion/movil").status_code == 401


def test_sos_no_repite_sms_enviado_por_la_sim(client, auth):
    """El teléfono ya avisó por SMS desde su SIM: el servidor no repite ese SMS (ni el «estoy bien»)."""
    from app.services import emergency as svc
    a = client.post("/v1/emergency/contacts", json={"name": "Ana", "phone": "3001234567"}, headers=auth).json()
    svc.messenger.sent.clear()
    r = client.post("/v1/emergency/sos", json={"lat": 4.6, "lon": -74.08, "sms_desde_telefono": [a["id"]]},
                    headers=auth)
    assert r.status_code == 201, r.text
    assert [x for x in svc.messenger.sent if x[0] == "sms"] == []      # Ana ya lo recibió por la SIM
    assert [x[0] for x in svc.messenger.sent] == ["call"]             # la llamada del plan sí sigue
    linea = r.json()["timeline"]
    assert any(e.get("ref") == "sim_telefono" and e.get("contacto") == "Ana" for e in linea)
    svc.messenger.sent.clear()
    assert client.post(f"/v1/emergency/incidents/{r.json()['id']}/cancel", headers=auth).status_code == 200
    # Ana recibió la llamada del servidor, así que el servidor sí le confirma que está bien…
    assert [x[0] for x in svc.messenger.sent] == ["sms"]


def test_sos_sin_sim_el_servidor_avisa(client, auth):
    """Sin SMS desde el teléfono, el servidor sigue avisando como siempre."""
    from app.services import emergency as svc
    client.post("/v1/emergency/contacts", json={"name": "Luis", "phone": "3109876543", "notify_call": False},
                headers=auth)
    svc.messenger.sent.clear()
    r = client.post("/v1/emergency/sos", json={"lat": 4.6, "lon": -74.08}, headers=auth)
    assert r.status_code == 201
    assert [(x[0], x[1]) for x in svc.messenger.sent] == [("sms", "+573109876543")]
    assert "maps.google.com/?q=4.60000%2C-74.08000" in svc.messenger.sent[0][2]   # un solo enlace, sin coma


def test_estoy_bien_no_duplica_si_solo_fue_por_sim(client, auth):
    """Si al contacto solo le escribió la SIM, el «estoy bien» también lo manda el teléfono, no el servidor."""
    from app.services import emergency as svc
    a = client.post("/v1/emergency/contacts", json={"name": "Eva", "phone": "3155551234", "notify_call": False},
                    headers=auth).json()
    r = client.post("/v1/emergency/sos", json={"sms_desde_telefono": [a["id"]]}, headers=auth)
    svc.messenger.sent.clear()
    client.post(f"/v1/emergency/incidents/{r.json()['id']}/cancel", headers=auth)
    assert svc.messenger.sent == []


def test_boton_conectar_y_latido_informa_canal(client, auth):
    """El PC puede pedir al teléfono que se reconecte; el latido le dice si su canal en vivo está abierto."""
    did, tk = _vincular(client, auth)
    r = client.post("/v1/devices/telemetry", json={"device_token": tk, "battery": 50})
    assert r.status_code == 200 and r.json()["canal_vivo"] is False     # sin WebSocket abierto
    r = client.post(f"/v1/devices/{did}/conectar", headers=auth)
    assert r.status_code == 200, r.text
    assert r.json()["en_vivo"] is False and "próximo reporte" in r.json()["mensaje"]
    r = client.post("/v1/devices/telemetry", json={"device_token": tk})
    assert r.json()["comandos_pendientes"] >= 1                          # el «Localizar» espera al teléfono
    pend = client.post("/v1/devices/commands/pending", json={"device_token": tk}).json()
    assert any(c["kind"] == "locate" and c["payload"].get("motivo") == "conectar" for c in pend)


def test_sos_remoto_exige_confirmacion_y_llega_al_telefono(client, auth):
    """El PC puede pedir al teléfono que envíe el SOS con su SIM, solo con confirmación explícita."""
    did, tk = _vincular(client, auth)
    r = client.post(f"/v1/devices/{did}/commands", headers=auth, json={"kind": "sos"})
    assert r.status_code == 422 and r.json()["code"] == "sos_not_confirmed"
    r = client.post(f"/v1/devices/{did}/commands", headers=auth, json={"kind": "sos", "confirm_sos": True})
    assert r.status_code == 201, r.text
    pend = client.post("/v1/devices/commands/pending", json={"device_token": tk}).json()
    sos = [c for c in pend if c["kind"] == "sos"]
    assert len(sos) == 1 and sos[0]["payload"]["origen"] == "pc" and sos[0]["signature"]
    notas = client.get("/v1/notifications", headers=auth).json()
    lista = notas["items"] if isinstance(notas, dict) and "items" in notas else notas
    assert any("SOS remoto" in (n.get("title") or "") for n in lista)
