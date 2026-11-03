"""Dispositivos en vivo: latidos sin GPS, conectar/desconectar, comandos por navegador y análisis."""
from datetime import datetime, timedelta, timezone

from app.ai import device_insights as di


def _vincular(client, auth, nombre="Redmi Note 13 pro"):
    cod = client.post("/v1/devices/vinculacion", headers=auth, json={}).json()["codigo"]
    r = client.post("/v1/devices/vinculacion/canjear", json={"codigo": cod, "nombre": nombre, "platform": "android"})
    assert r.status_code == 201
    return r.json()["device_id"], r.json()["device_token"]


def _equipo(client, auth, did):
    return next(d for d in client.get("/v1/devices", headers=auth).json() if d["id"] == did)


def test_latido_sin_gps_marca_en_linea_y_guarda_datos_reales(client, auth):
    """Antes, sin GPS el teléfono no mandaba nada y el PC decía «Último reporte: nunca»."""
    did, tk = _vincular(client, auth)
    r = client.post("/v1/devices/telemetry", json={
        "device_token": tk, "battery": 57, "charging": True, "gps": "https_required",
        "info": {"modelo": "23117RA68G", "sistema": "Android", "version_sistema": "14", "navegador": "Chrome 140",
                 "red": "wifi", "red_calidad": "4g", "pantalla": "1080x2400", "campo_raro": "x" * 5000}})
    assert r.status_code == 200 and r.json()["seguimiento"] is True
    d = _equipo(client, auth, did)
    assert d["en_linea"] and d["last_seen_at"] and d["battery"] == 57 and d["charging"] is True
    assert d["gps_status"] == "https_required" and d["last_lat"] is None
    assert d["device_info"]["navegador"] == "Chrome 140" and "campo_raro" not in d["device_info"]
    assert d["model"] == "23117RA68G" and d["os_version"] == "14"


def test_gps_real_actualiza_posicion_y_precision(client, auth):
    did, tk = _vincular(client, auth)
    client.post("/v1/devices/telemetry", json={"device_token": tk, "lat": 8.36, "lon": -72.41,
                                               "accuracy_m": 12, "battery": 80, "gps": "ok"})
    d = _equipo(client, auth, did)
    assert d["last_lat"] == 8.36 and d["last_accuracy_m"] == 12 and d["gps_status"] == "ok" and d["last_fix_at"]


def test_desconectar_pausa_el_gps_y_conectar_lo_reanuda(client, auth):
    did, tk = _vincular(client, auth)
    r = client.put(f"/v1/devices/{did}/seguimiento", headers=auth, json={"activo": False})
    assert r.status_code == 200 and r.json()["tracking_enabled"] is False
    tel = client.post("/v1/devices/telemetry", json={"device_token": tk, "lat": 8.3, "lon": -72.4, "battery": 50}).json()
    assert tel["seguimiento"] is False and tel["siguiente_reporte_s"] == 60
    d = _equipo(client, auth, did)
    assert d["last_lat"] is None and d["gps_status"] == "paused"      # pausado: la posición NO se guarda
    assert d["en_linea"] and d["battery"] == 50                        # pero el latido sí llega
    client.put(f"/v1/devices/{did}/seguimiento", headers=auth, json={"activo": True})
    assert client.post("/v1/devices/telemetry", json={"device_token": tk, "lat": 8.3, "lon": -72.4}).json()["seguimiento"]
    assert _equipo(client, auth, did)["last_lat"] == 8.3


def test_equipo_reportado_no_se_puede_desconectar(client, auth):
    did, _ = _vincular(client, auth)
    client.put(f"/v1/devices/{did}/seguimiento", headers=auth, json={"activo": False})
    client.put(f"/v1/devices/{did}/status", headers=auth, json={"status": "stolen"})
    assert _equipo(client, auth, did)["tracking_enabled"] is True     # reportarlo lo reconecta
    r = client.put(f"/v1/devices/{did}/seguimiento", headers=auth, json={"activo": False})
    assert r.status_code == 409


def test_comando_de_navegador_se_entrega_y_se_confirma(client, auth):
    did, tk = _vincular(client, auth)
    client.post(f"/v1/devices/{did}/commands", headers=auth, json={"kind": "ring"})
    assert client.post("/v1/devices/telemetry", json={"device_token": tk}).json()["comandos_pendientes"] == 1
    cmds = client.post("/v1/devices/commands/pending", json={"device_token": tk}).json()
    assert cmds[0]["kind"] == "ring"
    ack = client.post(f"/v1/devices/commands/{cmds[0]['id']}/ack", json={
        "device_token": tk, "signature": cmds[0]["signature"], "status": "completed", "result": {"sonido": True}})
    assert ack.status_code == 200
    hist = client.get(f"/v1/devices/{did}/commands", headers=auth).json()
    assert hist[0]["status"] == "completed"


def test_no_guarda_ruido_del_gps(client, auth):
    """Un equipo quieto reporta cada pocos segundos: no debe llenar la base con el mismo punto."""
    did, tk = _vincular(client, auth)
    for i in range(4):
        client.post("/v1/devices/telemetry", json={"device_token": tk, "lat": 8.36 + i * 1e-6, "lon": -72.41,
                                                   "accuracy_m": 10})
    assert len(client.get(f"/v1/devices/{did}/locations", headers=auth).json()["puntos"]) == 1
    client.post("/v1/devices/telemetry", json={"device_token": tk, "lat": 8.3610, "lon": -72.41, "accuracy_m": 10})
    assert len(client.get(f"/v1/devices/{did}/locations", headers=auth).json()["puntos"]) == 2


def test_endpoint_de_analisis(client, auth):
    did, tk = _vincular(client, auth)
    client.post("/v1/devices/telemetry", json={"device_token": tk, "gps": "https_required", "battery": 40})
    a = client.get(f"/v1/devices/{did}/analisis", headers=auth).json()
    assert a["gps"]["nivel"] == "sin_gps"
    assert any("HTTPS" in r for r in a["recomendaciones"])
    assert a["zona_habitual"]["conocida"] is False


# ─────────────────────────────── motor de análisis (puro)
AHORA = datetime(2026, 9, 22, 18, 0, tzinfo=timezone.utc)


def _p(minutos_atras, lat, lon, bat=None, acc=10, vel=None):
    return di.Punto(lat=lat, lon=lon, t=AHORA - timedelta(minutes=minutos_atras), precision_m=acc,
                    bateria=bat, velocidad_ms=vel)


def _analizar(**kw):
    base = dict(estado="ok", en_linea=True, visto=AHORA, bateria=None, cargando=False, lat=None, lon=None,
                precision_m=10, gps_status="ok", seguimiento=True, puntos_24h=[], historial_30d=[], ahora=AHORA)
    return di.analizar(**{**base, **kw})


def test_movimiento_quieto_caminando_vehiculo():
    assert _analizar(puntos_24h=[_p(1, 8.36, -72.41, vel=0.2)])["movimiento"]["estado"] == "quieto"
    assert _analizar(puntos_24h=[_p(1, 8.36, -72.41, vel=1.3)])["movimiento"]["estado"] == "caminando"
    assert _analizar(puntos_24h=[_p(1, 8.36, -72.41, vel=12)])["movimiento"]["estado"] == "en_vehiculo"


def test_estima_consumo_de_bateria():
    pts = [_p(120, 8.36, -72.41, bat=80), _p(60, 8.36, -72.41, bat=70), _p(0, 8.36, -72.41, bat=60)]
    b = _analizar(puntos_24h=pts, bateria=60)["bateria"]
    assert b["consumo_por_hora"] == 10.0 and b["horas_restantes"] == 6.0


def test_zona_habitual_y_fuera_de_zona():
    casa = [_p(i * 60, 8.3600, -72.4100) for i in range(15)]
    a = _analizar(historial_30d=casa, lat=8.40, lon=-72.41)        # ~4,4 km al norte
    assert a["zona_habitual"]["conocida"] and a["zona_habitual"]["fuera"] is True
    assert a["riesgo"]["puntaje"] > 0
    assert _analizar(historial_30d=casa, lat=8.3601, lon=-72.4101)["zona_habitual"]["fuera"] is False


def test_robado_en_vehiculo_es_riesgo_alto():
    a = _analizar(estado="stolen", puntos_24h=[_p(1, 8.36, -72.41, vel=15)], en_linea=True)
    assert a["riesgo"]["nivel"] in ("medio", "alto") and any("123" in r for r in a["recomendaciones"])


def test_canal_en_vivo_del_equipo_recibe_ordenes_al_instante(client, auth):
    """Sin canal, «Sonar alarma» esperaba el siguiente latido (hasta 30 s)."""
    did, tk = _vincular(client, auth)
    with client.websocket_connect("/v1/ws/equipo") as ws:
        ws.send_json({"device_token": tk})
        assert ws.receive_json()["tipo"] == "conectado"
        client.post(f"/v1/devices/{did}/commands", headers=auth, json={"kind": "ring"})
        orden = ws.receive_json()
        assert orden["tipo"] == "orden" and orden["comandos"] is True
        client.put(f"/v1/devices/{did}/seguimiento", headers=auth, json={"activo": False})
        assert ws.receive_json()["seguimiento"] is False


def test_canal_del_equipo_rechaza_token_falso(client):
    import pytest
    from starlette.websockets import WebSocketDisconnect
    with client.websocket_connect("/v1/ws/equipo") as ws:
        ws.send_json({"device_token": "x" * 43})
        with pytest.raises(WebSocketDisconnect) as e:
            ws.receive_json()
        assert e.value.code == 4401


# ─────────────────────────────── IMEI, número y denuncia
IMEI_OK = "490154203237518"   # IMEI de ejemplo con dígito de control (Luhn) válido


def test_identificacion_se_guarda_cifrada_y_solo_la_ve_el_dueno(client, auth):
    did, _ = _vincular(client, auth)
    r = client.put(f"/v1/devices/{did}/identificacion", headers=auth, json={
        "imei": "49-015420-323751-8", "numero": "300 123 4567", "operador": "Claro", "color": "Negro"})
    assert r.status_code == 200 and r.json()["imei"] == IMEI_OK and r.json()["numero"] == "+573001234567"
    assert _equipo(client, auth, did)["tiene_identificacion"] is True
    assert client.get(f"/v1/devices/{did}/identificacion", headers=auth).json()["imei"] == IMEI_OK
    # En la base NO está en claro.
    from app.db.models import Device
    from app.db.session import SessionLocal
    with SessionLocal() as db:
        fila = db.get(Device, did)
        assert IMEI_OK.encode() not in fila.ident_blob and b"3001234567" not in fila.ident_blob
    # Otro usuario no puede leerlo.
    otro = client.post("/v1/auth/register", json={"email": "otro@example.com", "full_name": "Otro", "password":
                       "MiClaveSegura2026!", "accept_terms": True, "accept_health_data": True}).json()["access_token"]
    assert client.get(f"/v1/devices/{did}/identificacion",
                      headers={"Authorization": f"Bearer {otro}"}).status_code == 404


def test_imei_invalido_se_rechaza(client, auth):
    did, _ = _vincular(client, auth)
    assert client.put(f"/v1/devices/{did}/identificacion", headers=auth, json={"imei": "490154203237519"}).status_code == 422
    assert client.put(f"/v1/devices/{did}/identificacion", headers=auth, json={"imei": "12345"}).status_code == 422
    assert client.put(f"/v1/devices/{did}/identificacion", headers=auth,
                      json={"imei": IMEI_OK, "numero": "12345"}).status_code == 422


def test_expediente_de_denuncia_con_ubicacion(client, auth):
    did, tk = _vincular(client, auth)
    client.put(f"/v1/devices/{did}/identificacion", headers=auth, json={"imei": IMEI_OK, "numero": "3001234567",
                                                                       "operador": "Tigo"})
    client.post("/v1/devices/telemetry", json={"device_token": tk, "lat": 8.36389, "lon": -72.40722, "accuracy_m": 9})
    client.put(f"/v1/devices/{did}/status", headers=auth, json={"status": "stolen"})
    x = client.get(f"/v1/devices/{did}/denuncia", headers=auth).json()
    assert x["faltan"] == [] and IMEI_OK in x["texto"] and "Hurtado" in x["texto"]
    assert "google.com/maps?q=8.36389,-72.40722" in x["texto"]
    assert x["ultima_ubicacion"]["precision_m"] == 9 and any("Tigo" in p["titulo"] for p in x["pasos"])


def test_expediente_avisa_lo_que_falta(client, auth):
    did, _ = _vincular(client, auth)
    x = client.get(f"/v1/devices/{did}/denuncia", headers=auth).json()
    assert set(x["faltan"]) == {"IMEI", "número", "operador"} and "NO REGISTRADO" in x["texto"]


def test_csp_permite_mosaicos_del_mapa_y_nada_mas_externo(client):
    csp = client.get("/app/").headers["content-security-policy"]
    assert "img-src 'self' data: blob: https://tile.openstreetmap.org" in csp
    assert "script-src 'self';" in csp
    assert client.get("/static/shared/vendor/leaflet/leaflet.js").status_code == 200
