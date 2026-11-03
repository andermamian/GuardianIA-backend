"""Servidor VPN propio conectado a GuardianIA, con TLS REAL y anclaje de certificado.

Se levanta el agente real (vpn_servidor/agente.py) con un certificado generado con el MISMO comando openssl
del instalador, y se comprueba que la ficha secreta nunca sale hacia un servidor que no sea el anclado.
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

from app.local import vpn, vpn_propio as vp
from vpn_servidor import agente as ag

FICHA = "FichaSecretaDePrueba0123456789abcdefXYZ"
pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="requiere openssl")


class SistemaFalso(ag.Sistema):
    def __init__(self):
        self.peers = []

    def agregar_peer(self, c, v4, v6):
        self.peers.append(c)

    def quitar_peer(self, c):
        pass

    def bytes_transferidos(self):
        return 0

    def reenvio(self, activo):
        pass


def _certificado(d):
    # Mismo comando que vpn_servidor/instalar.sh (EC P-256, autofirmado, CN=guardian-vpn).
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-days", "3650", "-subj", "/CN=guardian-vpn", "-keyout", str(d / "api.key"),
                    "-out", str(d / "api.crt")], check=True, capture_output=True)
    huella = subprocess.run(["openssl", "x509", "-in", str(d / "api.crt"), "-noout", "-fingerprint", "-sha256"],
                            check=True, capture_output=True, text=True).stdout.strip().split("=", 1)[1]
    return huella                                     # formato «AB:CD:…», tal como lo muestra el instalador


def _servidor(d, region="us-central1"):
    """Agente real por HTTPS en un puerto libre. Devuelve (url, huella, contador de peticiones, parar)."""
    import uvicorn
    huella = _certificado(d)
    a = ag.Agente(sistema=SistemaFalso(), dir=d)
    a._escribir("config.json", {"ficha_sha256": ag.huella_ficha(FICHA), "region": region,
                                "clave_publica": base64.b64encode(os.urandom(32)).decode(),
                                "endpoint": "34.1.2.3:51820"})
    app = ag.crear_app(a)
    contador = {"n": 0, "auth": []}

    @app.middleware("http")
    async def contar(request, call_next):
        contador["n"] += 1
        contador["auth"].append(request.headers.get("authorization"))
        return await call_next(request)

    s = socket.socket(); s.bind(("127.0.0.1", 0)); puerto = s.getsockname()[1]; s.close()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=puerto, log_level="error",
                                        ssl_certfile=str(d / "api.crt"), ssl_keyfile=str(d / "api.key")))
    hilo = threading.Thread(target=srv.run, daemon=True)
    hilo.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    def parar():
        srv.should_exit = True
        hilo.join(5)
    return f"https://127.0.0.1:{puerto}", huella, contador, a, parar


@pytest.fixture
def entorno(tmp_path, monkeypatch):
    monkeypatch.setattr(vpn, "_dir", lambda: tmp_path / "pc")
    (tmp_path / "pc").mkdir()
    (tmp_path / "srv").mkdir()
    (tmp_path / "falso").mkdir()
    url, huella, contador, agente, parar = _servidor(tmp_path / "srv")
    yield tmp_path, url, huella, contador, agente
    parar()


def test_configurar_con_la_huella_correcta_da_de_alta_el_pc(entorno):
    tmp, url, huella, contador, agente = entorno
    r = vp.configurar(url, huella, FICHA, "usuario-1")
    assert r["configurado"] and r["region"] == "us-central1" and r["pais"] == "US"
    u = [x for x in vpn.ubicaciones() if x["propio"]]
    assert len(u) == 1 and u[0]["pais"] == "US" and u[0]["endpoint"] == "34.1.2.3:51820"
    p, privada = vpn._ubicacion(u[0]["id"])
    assert p["interfaz"]["Address"] == "10.66.0.2/32, fd66::2/128" and p["proveedor"] == "servidor"
    # La clave privada del PC nunca viajó: el servidor solo tiene la pública, que corresponde a ella.
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub = base64.b64encode(X25519PrivateKey.from_private_bytes(base64.b64decode(privada)).public_key()
                           .public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    assert agente.sistema.peers == [pub]
    # La ficha queda cifrada en disco, nunca en claro.
    guardado = (tmp / "pc" / "propio.json").read_text()
    assert FICHA not in guardado and "BEGIN CERTIFICATE" in guardado
    # Reconfigurar no duplica la ubicación propia y da de baja la clave vieja en el servidor.
    vp.configurar(url, huella, FICHA, "usuario-1")
    assert len([x for x in vpn.ubicaciones() if x["propio"]]) == 1
    assert pub not in agente.peers() and len(agente.peers()) == 1
    # Desconectar el servidor también retira la clave del PC allá.
    vp.quitar()
    assert agente.peers() == {} and not vp.configurado()


def test_huella_equivocada_no_envia_la_ficha(entorno):
    tmp, url, huella, contador, _ = entorno
    otra = "AA:" * 31 + "AA"
    with pytest.raises(vp.ErrorPropio, match="NO coincide"):
        vp.configurar(url, otra, FICHA, "usuario-1")
    assert contador["n"] == 0                              # ni una petición HTTP: la ficha no salió
    assert not vp.configurado()


def test_servidor_impostor_no_recibe_la_ficha(entorno):
    """Tras configurar, alguien pone otro servidor en esa dirección (otro certificado): la conexión se
    corta en el apretón TLS, antes de enviar la ficha."""
    tmp, url, huella, contador, _ = entorno
    vp.configurar(url, huella, FICHA, "usuario-1")
    url2, _, contador2, _, parar2 = _servidor(tmp / "falso")
    try:
        cfg = json.loads((tmp / "pc" / "propio.json").read_text())
        cfg["url"] = url2                                  # la dirección ahora lleva al impostor
        vpn._escribir_privado(tmp / "pc" / "propio.json", json.dumps(cfg))
        with pytest.raises(vp.ErrorPropio, match="suplantación"):
            vp.alta_dispositivo(base64.b64encode(os.urandom(32)).decode(), "celular")
        assert contador2["n"] == 0
    finally:
        parar2()


def test_ficha_incorrecta(entorno):
    _, url, huella, _, _ = entorno
    with pytest.raises(vp.ErrorPropio, match="ficha"):
        vp.configurar(url, huella, "FichaEquivocada000000000000000000000000", "usuario-1")
    assert not vp.configurado()


def test_entradas_invalidas():
    for url in ["http://1.2.3.4:8844", "https://1.2.3.4:8844/x?y=1", "ftp://x", "https://a b"]:
        with pytest.raises(vp.ErrorPropio):
            vp.separar_url(url)
    for h in ["abc", "ZZ" * 32, "AB:" * 10]:
        with pytest.raises(vp.ErrorPropio):
            vp.normalizar_huella(h)
    assert vp.normalizar_huella("AB:" * 31 + "AB") == "ab" * 32
    assert vp.pais_de_region("us-central1") == "US" and vp.pais_de_region("europe-west6") == "CH"
    assert vp.pais_de_region("southamerica-east1") == "BR" and vp.pais_de_region("marte-1") is None


def test_rutas_pc_y_celular(entorno, client, auth):
    tmp, url, huella, _, _ = entorno
    r = client.put("/v1/local/vpn/propio", headers=auth, json={"url": url, "huella": huella, "ficha": FICHA})
    assert r.status_code == 200, r.text
    # El celular (misma cuenta) pide su alta: recibe su configuración, nunca la ficha.
    assert client.get("/v1/vpn/propio", headers=auth).json() == {"configurado": True, "region": "us-central1",
                                                                "pais": "US"}
    clave = base64.b64encode(os.urandom(32)).decode()
    a = client.post("/v1/vpn/propio/alta", headers=auth, json={"clave_publica": clave, "nombre": "Redmi"})
    assert a.status_code == 200 and a.json()["direccion"].startswith("10.66.0.3/32")
    assert FICHA not in a.text and "ficha" not in a.text.lower()
    # Otra cuenta del mismo PC no puede usar el servidor de otra persona.
    otro = client.post("/v1/auth/register", json={"email": "luis@example.com", "full_name": "Luis Gómez",
                                                  "password": "OtraClaveSegura2026!", "accept_terms": True})
    h2 = {"Authorization": f"Bearer {otro.json()['access_token']}"}
    assert client.get("/v1/vpn/propio", headers=h2).json() == {"configurado": False}
    assert client.post("/v1/vpn/propio/alta", headers=h2, json={"clave_publica": clave}).status_code == 403
    assert client.post("/v1/vpn/propio/alta", headers=auth, json={"clave_publica": "A" * 44}).status_code == 502
