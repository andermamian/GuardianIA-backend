"""Servidor VPN propio (WireGuard): altas, sin registros, ficha protegida y freno de consumo."""
import base64
import os

import pytest

from vpn_servidor import agente as ag

CLAVE = base64.b64encode(os.urandom(32)).decode()
CLAVE2 = base64.b64encode(os.urandom(32)).decode()
FICHA = "ficha-secreta-de-prueba-" + "x" * 20


class Falso(ag.Sistema):
    def __init__(self):
        self.comandos, self.bytes, self.frenado = [], 0, False

    def agregar_peer(self, c, v4, v6):
        self.comandos.append(("alta", c, v4, v6))

    def quitar_peer(self, c):
        self.comandos.append(("baja", c))

    def bytes_transferidos(self):
        return self.bytes

    def reenvio(self, activo):
        self.frenado = not activo
        self.comandos.append(("reenvio", activo))


@pytest.fixture
def a(tmp_path):
    x = ag.Agente(sistema=Falso(), dir=tmp_path, limite_gb=1.0)
    x._escribir("config.json", {"ficha_sha256": ag.huella_ficha(FICHA), "clave_publica": "S" * 43 + "=",
                                "endpoint": "34.1.2.3:51820", "region": "us-central1"})
    return x


def test_claves_validas_y_sin_inyeccion():
    assert ag.clave_valida(CLAVE)
    for mala in ["", "abc", "A" * 44, CLAVE[:-1] + "!", CLAVE + " remove", "x; rm -rf /" + "a" * 33]:
        assert not ag.clave_valida(mala), mala


def test_alta_asigna_direcciones_y_es_idempotente(a):
    r = a.alta(CLAVE, "celular de Anderson")
    assert r["direccion"] == "10.66.0.2/32, fd66::2/128" and r["endpoint"] == "34.1.2.3:51820"
    assert r["allowed_ips"] == "0.0.0.0/0, ::/0" and r["dns"].startswith("10.66.0.1")
    assert a.alta(CLAVE, "otro nombre")["direccion"] == r["direccion"]     # misma clave, misma dirección
    assert a.alta(CLAVE2, "PC")["direccion"].startswith("10.66.0.3/32")
    guardado = a.peers()
    assert set(guardado) == {CLAVE, CLAVE2}
    # Sin registros: no hay IPs de origen, horas de conexión ni tráfico por dispositivo.
    assert set(guardado[CLAVE]) == {"v4", "v6", "nombre", "alta"}


def test_baja(a):
    a.alta(CLAVE, "x")
    a.baja(CLAVE)
    assert a.peers() == {} and ("baja", CLAVE) in a.sistema.comandos
    with pytest.raises(ag.ErrorVpn):
        a.baja(CLAVE)


def test_ficha_solo_se_guarda_su_huella_y_bloquea_fuerza_bruta(a, tmp_path):
    assert FICHA not in (tmp_path / "config.json").read_text()
    a.autorizar(FICHA, "1.1.1.1")
    for _ in range(ag.FALLOS_MAX):
        with pytest.raises(ag.ErrorVpn) as e:
            a.autorizar("mala", "6.6.6.6")
        assert e.value.codigo == 401
    with pytest.raises(ag.ErrorVpn) as e:
        a.autorizar(FICHA, "6.6.6.6")                  # bloqueado aunque ahora acierte
    assert e.value.codigo == 429
    a.autorizar(FICHA, "1.1.1.1")                      # otro origen no se ve afectado


def test_freno_de_consumo(a):
    a.sistema.bytes = 400_000_000
    r = a.medir_consumo()
    assert r["frenado"] is False and r["usado_gb"] == 0.4        # la primera medición SÍ cuenta
    a.sistema.bytes = 1_100_000_000                    # pasa el límite (1 GB en la prueba)
    r = a.medir_consumo()
    assert r["frenado"] is True and a.sistema.frenado is True and r["usado_gb"] == 1.1
    a.sistema.bytes = 200                              # el servidor se reinició: el contador vuelve a 0
    assert a.medir_consumo()["usado_gb"] == 1.1         # lo acumulado del mes no se pierde


def test_api(a):
    from fastapi.testclient import TestClient
    c = TestClient(ag.crear_app(a))
    h = {"Authorization": f"Bearer {FICHA}"}
    assert c.get("/salud").status_code == 401
    assert c.get("/salud", headers=h).json()["region"] == "us-central1"
    r = c.post("/dispositivos", headers=h, json={"clave_publica": CLAVE, "nombre": "PC"})
    assert r.status_code == 200 and r.json()["direccion"].startswith("10.66.0.2")
    assert c.post("/dispositivos", headers=h, json={"clave_publica": "A" * 44}).status_code == 422
    assert c.get("/docs").status_code == 404           # sin documentación pública expuesta
