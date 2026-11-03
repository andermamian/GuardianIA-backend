"""Túnel WireGuard: configuración, verificación honesta y entrega de la tarea al agente."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agente"))

CLAVE_SERVIDOR = "kZx1YQ0bR7uJ8lN3vF6dP2sA9tE4wC5xH7yL0mB1nQ="
CLAVE_EQUIPO = "aBc1YQ0bR7uJ8lN3vF6dP2sA9tE4wC5xH7yL0mB1nQ="


@pytest.fixture
def entorno(client, auth):
    """Un servidor real (con túnel), uno de ejemplo (sin túnel) y la cuenta en plan Enterprise."""
    from app.db.models import User, VpnServer
    from app.db.session import SessionLocal
    db = SessionLocal()
    try:
        db.merge(VpnServer(id="co-real", country="CO", city="Bogotá", host="45.33.10.2", port=51820,
                           protocol="wireguard", active=True, is_premium=False,
                           public_key=CLAVE_SERVIDOR, endpoint="45.33.10.2:51820",
                           ip_salida="45.33.10.2", subred="10.66.0.0/24", dns="1.1.1.1"))
        db.merge(VpnServer(id="co-ejemplo", country="CO", city="Medellín", host="mde.example.dev",
                           port=51820, protocol="wireguard", active=True))
        for u in db.query(User).all():
            u.plan = "ENTERPRISE"
        db.commit()
    finally:
        db.close()
    device = client.post("/v1/devices", headers=auth, json={"name": "HP", "platform": "windows"}).json()
    return device


def test_servidor_de_ejemplo_no_entrega_configuracion(client, auth, entorno):
    """Antes se podía «conectar» a un servidor inexistente. Ahora se dice que es de ejemplo."""
    r = client.post("/v1/vpn/peer", headers=auth,
                    json={"server_id": "co-ejemplo", "device_id": entorno["id"], "public_key": CLAVE_EQUIPO})
    assert r.status_code == 409 and r.json()["code"] == "servidor_sin_tunel"
    assert "ejemplo" in r.json()["title"]


def test_peer_recibe_ip_fija_y_configuracion_sin_clave_privada(client, auth, entorno):
    r = client.post("/v1/vpn/peer", headers=auth,
                    json={"server_id": "co-real", "device_id": entorno["id"], "public_key": CLAVE_EQUIPO})
    assert r.status_code == 201, r.text
    config = r.json()
    assert config["interfaz"]["Address"].startswith("10.66.0.") and config["interfaz"]["Address"].endswith("/32")
    assert config["par"]["PublicKey"] == CLAVE_SERVIDOR
    assert config["par"]["AllowedIPs"].startswith("0.0.0.0/0")   # todo el tráfico por el túnel
    # La clave privada jamás viaja: eso es lo que hace que ni el operador pueda descifrar el tráfico.
    assert CLAVE_EQUIPO not in config["archivo"]
    assert "no sale de él" in config["archivo"]

    # El mismo dispositivo conserva su IP; otro recibe una distinta.
    igual = client.post("/v1/vpn/peer", headers=auth,
                        json={"server_id": "co-real", "device_id": entorno["id"], "public_key": CLAVE_EQUIPO})
    assert igual.json()["interfaz"]["Address"] == config["interfaz"]["Address"]
    otro = client.post("/v1/devices", headers=auth, json={"name": "Otro", "platform": "android"}).json()
    distinta = client.post("/v1/vpn/peer", headers=auth,
                           json={"server_id": "co-real", "device_id": otro["id"], "public_key": CLAVE_EQUIPO})
    assert distinta.json()["interfaz"]["Address"] != config["interfaz"]["Address"]


def test_la_verificacion_detecta_que_la_ip_no_cambio(client, auth, entorno):
    """El caso que vio el usuario: decía «conectada» pero la IP era la misma. Ya no pasa."""
    sesion = client.post("/v1/vpn/conectar", headers=auth,
                         json={"server_id": "co-real", "device_id": entorno["id"]}).json()
    r = client.post("/v1/vpn/verificar", headers=auth,
                    json={"sesion_id": sesion["id"], "ip_observada": "191.156.228.127"})  # su IP de casa
    assert r.json()["verificada"] is False
    assert "NO va por el túnel" in r.json()["mensaje"]
    assert client.get("/v1/vpn/sesion", headers=auth).json()["estado"] == "sin_verificar"

    # Y aunque el cliente insista en marcarla conectada sin demostrar el cambio de IP, no se le cree.
    client.post("/v1/vpn/tunel", headers=auth,
                json={"sesion_id": sesion["id"], "estado": "conectada",
                      "ip_salida": "191.156.228.127", "ip_previa": "191.156.228.127"})
    final = client.get("/v1/vpn/sesion", headers=auth).json()
    assert final["estado"] == "sin_verificar" and final["verificada"] is False


def test_la_verificacion_confirma_cuando_la_ip_es_la_del_servidor(client, auth, entorno):
    sesion = client.post("/v1/vpn/conectar", headers=auth,
                         json={"server_id": "co-real", "device_id": entorno["id"]}).json()
    r = client.post("/v1/vpn/verificar", headers=auth,
                    json={"sesion_id": sesion["id"], "ip_observada": "45.33.10.2"})
    assert r.json()["verificada"] is True and "confirmado" in r.json()["mensaje"]
    actual = client.get("/v1/vpn/sesion", headers=auth).json()
    assert actual["estado"] == "conectada" and actual["ip_salida"] == "45.33.10.2"


def test_el_agente_recibe_la_configuracion_del_tunel(client, auth, entorno):
    token = entorno["device_token"]
    client.post("/v1/agente/registrar", json={"device_token": token, "hostname": "HP", "so": "Windows 11",
                                              "version": "1.0.0", "privilegios": True})
    client.post("/v1/vpn/peer", headers=auth,
                json={"server_id": "co-real", "device_id": entorno["id"], "public_key": CLAVE_EQUIPO})
    client.post("/v1/vpn/conectar", headers=auth, json={"server_id": "co-real", "device_id": entorno["id"]})

    tareas = client.post("/v1/agente/latido", json={"device_token": token}).json()["tareas"]
    vpn = next(t for t in tareas if t["tipo"] == "vpn_conectar")
    assert vpn["config"]["par"]["Endpoint"] == "45.33.10.2:51820"
    assert vpn["config"]["interfaz"]["Address"].startswith("10.66.0.")


# ─────────────────────────── lado del agente
def test_el_agente_genera_claves_y_nunca_envia_la_privada(tmp_path, monkeypatch):
    import guardian_agent as ga
    monkeypatch.setattr(ga, "carpeta_datos", lambda: tmp_path)
    tunel = ga.Tunel()
    privada, publica = tunel._claves()
    assert len(privada) == 44 and len(publica) == 44 and privada != publica
    # Se reutilizan entre llamadas: la IP dentro del túnel se mantiene estable.
    assert tunel._claves() == (privada, publica)
    guardadas = (tmp_path / "vpn" / "claves.json").read_text()
    assert privada in guardadas    # la privada solo vive aquí, en el equipo


def test_el_agente_avisa_si_falta_wireguard(tmp_path, monkeypatch):
    import guardian_agent as ga
    monkeypatch.setattr(ga, "carpeta_datos", lambda: tmp_path)
    monkeypatch.setattr(ga.Tunel, "disponible", staticmethod(lambda: None))
    ok, detalle = ga.Tunel().conectar({"interfaz": {"Address": "10.66.0.2/32", "DNS": "1.1.1.1"},
                                       "par": {"PublicKey": CLAVE_SERVIDOR, "Endpoint": "1.2.3.4:51820",
                                               "AllowedIPs": "0.0.0.0/0", "PersistentKeepalive": "25"}})
    assert ok is False and "wireguard.com/install" in detalle


def test_el_archivo_de_configuracion_queda_protegido(tmp_path, monkeypatch):
    import os
    import guardian_agent as ga
    monkeypatch.setattr(ga, "carpeta_datos", lambda: tmp_path)
    monkeypatch.setattr(ga.Tunel, "disponible", staticmethod(lambda: "/usr/bin/wg-quick"))
    monkeypatch.setattr(ga.subprocess, "run",
                        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    monkeypatch.setattr(ga.os, "geteuid", lambda: 0, raising=False)
    ok, _ = ga.Tunel().conectar({"interfaz": {"Address": "10.66.0.2/32", "DNS": "1.1.1.1"},
                                 "par": {"PublicKey": CLAVE_SERVIDOR, "Endpoint": "1.2.3.4:51820",
                                         "AllowedIPs": "0.0.0.0/0, ::/0", "PersistentKeepalive": "25"}})
    conf = tmp_path / "vpn" / "guardiania.conf"
    assert ok and conf.exists()
    assert "PrivateKey" in conf.read_text() and "0.0.0.0/0" in conf.read_text()
    assert oct(os.stat(conf).st_mode)[-3:] == "600"   # contiene la clave privada


def test_el_agente_registra_su_clave_y_recibe_configuracion(client, auth, entorno):
    """El agente debe poder preparar el túnel sin que nadie abra la web."""
    token = entorno["device_token"]
    client.post("/v1/agente/registrar", json={"device_token": token, "hostname": "HP", "so": "Windows 11",
                                              "version": "1.0.0", "privilegios": True})
    r = client.post("/v1/agente/vpn/peer", json={"device_token": token, "server_id": "co-real",
                                                 "public_key": CLAVE_EQUIPO})
    assert r.status_code == 201
    config = r.json()
    assert config["par"]["Endpoint"] == "45.33.10.2:51820"
    assert config["interfaz"]["Address"].startswith("10.66.0.")
    assert config["ip_salida_esperada"] == "45.33.10.2"

    # Contra un servidor de ejemplo, se niega con una explicación.
    malo = client.post("/v1/agente/vpn/peer", json={"device_token": token, "server_id": "co-ejemplo",
                                                    "public_key": CLAVE_EQUIPO})
    assert malo.status_code == 409 and "ejemplo" in malo.json()["title"]


def test_el_agente_no_puede_declarar_tunel_sin_cambio_de_ip(client, auth, entorno):
    """Ni el propio agente puede marcar «conectada» si la IP pública siguió igual."""
    token = entorno["device_token"]
    client.post("/v1/agente/registrar", json={"device_token": token, "hostname": "HP", "so": "Windows",
                                              "version": "1.0.0", "privilegios": True})
    sesion = client.post("/v1/vpn/conectar", headers=auth,
                         json={"server_id": "co-real", "device_id": entorno["id"]}).json()
    igual = client.post("/v1/agente/vpn/estado", json={
        "device_token": token, "sesion_id": sesion["id"], "estado": "conectada",
        "ip_salida": "191.156.228.127", "ip_previa": "191.156.228.127"}).json()
    assert igual == {"estado": "sin_verificar", "verificada": False}

    cambio = client.post("/v1/agente/vpn/estado", json={
        "device_token": token, "sesion_id": sesion["id"], "estado": "conectada",
        "ip_salida": "45.33.10.2", "ip_previa": "191.156.228.127"}).json()
    assert cambio == {"estado": "conectada", "verificada": True}


def test_el_latido_pide_registrar_la_clave_si_falta(client, auth, entorno):
    token = entorno["device_token"]
    client.post("/v1/agente/registrar", json={"device_token": token, "hostname": "HP", "so": "Windows",
                                              "version": "1.0.0", "privilegios": True})
    client.post("/v1/vpn/conectar", headers=auth, json={"server_id": "co-real", "device_id": entorno["id"]})
    tareas = client.post("/v1/agente/latido", json={"device_token": token}).json()["tareas"]
    vpn = next(t for t in tareas if t["tipo"] == "vpn_conectar")
    assert vpn["registrar_en"] == "co-real"   # aún no hay clave: se le pide al agente que la genere
