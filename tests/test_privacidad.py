"""Pasarela de privacidad v3.8: solo su servidor GuardianIA VPN y Tor, un botón, IA y respaldo automático."""
import pytest

from app.ai import cerebro_vpn
from app.core import red
from app.local import privacidad as pv, tor, vpn


@pytest.fixture
def entorno(monkeypatch, tmp_path):
    """Simula WireGuard, Tor y su servidor sin tocar la red real."""
    e = {"vpn": False, "tor": False, "tor_inicios": 0, "conexiones": 0, "servidor_falla": False,
         "en_linea": True, "consumo": 0.1, "tor_instalado": True, "red_insegura": False}
    monkeypatch.setattr(vpn, "_dir", lambda: tmp_path)
    monkeypatch.setattr(vpn, "ubicaciones", lambda: [{"id": "aaaaaaaa", "propio": True, "pais": "US",
                                                     "endpoint": "34.1.2.3:51820", "en_uso": e["vpn"]}])
    monkeypatch.setattr(vpn, "usar_ubicacion", lambda i: None)
    monkeypatch.setattr(vpn, "wireguard", lambda: "wg")
    monkeypatch.setattr(vpn, "activo", lambda: e["vpn"])

    def conectar():
        e["conexiones"] += 1
        if e["servidor_falla"]:
            raise vpn.ErrorVpn("WireGuard terminó con el código 1")
        e["vpn"] = True
        return {"verificado": True}
    monkeypatch.setattr(vpn, "conectar", conectar)
    monkeypatch.setattr(vpn, "desconectar", lambda: e.update(vpn=False) or {})
    monkeypatch.setattr(vpn, "purgar_terceros", lambda: {"ubicaciones_borradas": 0, "perfil_quitado": False})
    monkeypatch.setattr(vpn, "estadisticas", lambda **k: {})
    monkeypatch.setattr(vpn, "anonimato", lambda **k: {"nivel": "medio", "puntaje": 70})

    def t_iniciar():
        if not e["tor_instalado"]:
            raise tor.ErrorTor("No encontré Tor")
        e.update(tor=True, tor_inicios=e["tor_inicios"] + 1)
        return {}
    monkeypatch.setattr(tor, "iniciar", t_iniciar)
    monkeypatch.setattr(tor, "detener", lambda: e.update(tor=False) or {})
    monkeypatch.setattr(tor, "estado", lambda **k: {"activo": e["tor"], "listo": e["tor"],
                                                    "instalado": e["tor_instalado"]})
    monkeypatch.setattr(pv, "_circuito", lambda: {})
    monkeypatch.setattr(pv, "_asegurar_vigilante", lambda: None)
    monkeypatch.setattr(pv.sistema, "red_publica", lambda: e["red_insegura"])
    from app.local import vpn_propio, warp
    monkeypatch.setattr(warp, "registrado", lambda: True)
    monkeypatch.setattr(vpn_propio, "configurado", lambda: True)
    monkeypatch.setattr(vpn_propio, "estado", lambda consultar=True: {
        "configurado": True, "region": "us-central1", "pais": "US", "en_linea": e["en_linea"],
        "consumo": {"usado_gb": e["consumo"] * 190, "limite_gb": 190}} if consultar else
        {"configurado": True, "region": "us-central1", "pais": "US"})
    pv._senales_cache.update(cuando=0.0, senales=None)
    yield e
    pv.ajustes.guardar({"privacidad_modo": "apagado", "privacidad_efectivo": "apagado", "tor_aislamiento": False,
                        "privacidad_respaldo": False, "tor_pais": None})
    red.fijar_modo("apagado")
    pv._senales_cache.update(cuando=0.0, senales=None)


def test_auto_elige_servidor_en_equilibrio(entorno):
    r = pv.activar("auto", "equilibrio")
    assert r["efectivo"] == "servidor" and entorno["vpn"] and not entorno["tor"] and r["protegido"]
    assert r["ia"]["decision"]["modo"] == "servidor" and r["ia"]["senales"]["servidor_en_linea"] is True
    assert "servidor" in r["razon"].lower()


def test_auto_en_anonimato_pone_tor_dentro_del_servidor_y_endurece(entorno):
    r = pv.activar("auto", "anonimato")
    assert r["efectivo"] == "servidor_tor" and entorno["vpn"] and entorno["tor"]
    assert tor.aislamiento() is True and red.modo() == "estricto"


def test_auto_si_el_servidor_falla_aprende_y_usa_tor(entorno):
    entorno["servidor_falla"] = True
    r = pv.activar("auto", "equilibrio")
    assert r["efectivo"] == "tor" and entorno["tor"] and not entorno["vpn"]
    assert entorno["conexiones"] == 1                     # no insiste con servidor+Tor: comparte la pieza rota
    assert pv.memoria()["servidor"]["intentos"] == 1 and pv.memoria()["servidor"]["fiabilidad"] < 0.8


def test_auto_registra_warp_solo_si_no_habia_ubicacion(entorno, monkeypatch):
    """El botón de un solo toque: sin ubicación guardada, WARP se registra solo (antes quedaba solo Tor)."""
    ubicaciones = []
    registros = []
    monkeypatch.setattr(vpn, "ubicaciones", lambda: list(ubicaciones))

    def registrar():
        registros.append(1)
        ubicaciones.append({"id": "bbbbbbbb", "propio": True, "pais": "US"})
    monkeypatch.setattr(vpn, "configurar_warp", registrar)
    r = pv.activar("auto", "equilibrio")
    assert registros == [1] and r["efectivo"] == "servidor" and entorno["vpn"]


def test_si_warp_no_puede_registrarse_queda_tor_y_se_explica(entorno, monkeypatch):
    from app.local import warp
    monkeypatch.setattr(vpn, "ubicaciones", lambda: [])

    def falla():
        raise warp.ErrorWarp("Cloudflare no respondió al registro gratuito de WARP")
    monkeypatch.setattr(vpn, "configurar_warp", falla)
    r = pv.activar("servidor", "equilibrio")
    assert r["efectivo"] == "tor" and entorno["tor"] and not entorno["vpn"]
    assert "Cloudflare" in r["aviso"]


def test_tunel_sin_verificar_se_baja_y_dice_por_que(entorno, monkeypatch):
    """Nunca un túnel encendido que no protege, y el motivo real llega hasta la pantalla."""
    monkeypatch.setattr(vpn, "conectar", lambda: {"verificado": False, "motivo": "sin apretón de manos (UDP 2408)"})
    r = pv.activar("servidor", "equilibrio")
    assert r["efectivo"] == "tor" and "UDP 2408" in r["aviso"] and not entorno["vpn"]


def test_manual_servidor_cae_a_tor_y_vuelve_solo(entorno):
    entorno["servidor_falla"] = True
    r = pv.activar("servidor", "equilibrio")
    assert r["efectivo"] == "tor" and r["respaldo"] is True and "Tor" in r["aviso"]
    # El servidor vuelve: el vigilante regresa a él y apaga Tor.
    entorno["servidor_falla"] = False
    pv._senales_cache.update(cuando=0.0)
    assert pv.revisar_una_vez() == "restaurado"
    c = pv.config()
    assert c["efectivo"] == "servidor" and c["respaldo"] is False and entorno["vpn"] and not entorno["tor"]


def test_manual_tor_sin_tor_instalado_no_miente(entorno):
    entorno["tor_instalado"] = False
    with pytest.raises(pv.ErrorPrivacidad, match="Tor"):
        pv.activar("tor", "anonimato")


def test_modos_excluyentes_y_legado(entorno):
    pv.activar("proton_tor", "anonimato")                  # nombre viejo = servidor + Tor
    assert pv.config()["modo"] == "servidor_tor" and entorno["vpn"] and entorno["tor"]
    pv.activar("tor", "velocidad")
    assert entorno["tor"] and not entorno["vpn"] and red.modo() == "preferir"
    pv.activar("servidor", "velocidad")
    assert entorno["vpn"] and not entorno["tor"] and red.modo() == "apagado"
    r = pv.activar("apagado")
    assert not entorno["vpn"] and not entorno["tor"] and r["protegido"] is False


def test_vigilante_repara_lo_caido(entorno):
    pv.activar("servidor_tor", "anonimato")
    entorno["vpn"] = False
    assert pv.revisar_una_vez() == "reconectado" and entorno["vpn"]
    entorno["tor"] = False
    assert pv.revisar_una_vez() == "tor_reiniciado" and entorno["tor"]
    assert pv.revisar_una_vez() is None


def test_vigilante_auto_cambia_con_histeresis(entorno, monkeypatch):
    entorno["servidor_falla"] = True
    pv.activar("auto", "equilibrio")                        # queda en Tor
    entorno["servidor_falla"] = False
    # Aún dentro de los 5 min del fallo y de los 10 min entre cambios: se queda en Tor.
    assert pv.revisar_una_vez() is None and pv.config()["efectivo"] == "tor"
    # Pasado el tiempo, la IA vuelve al servidor.
    import time as _t
    futuro = _t.time() + 3600
    monkeypatch.setattr(cerebro_vpn.time, "time", lambda: futuro)
    monkeypatch.setattr(pv.time, "time", lambda: futuro)
    pv._senales_cache.update(cuando=0.0)
    assert pv.revisar_una_vez() == "cambio_ia" and pv.config()["efectivo"] == "servidor"


def test_entradas_invalidas(entorno):
    for modo, obj, pais in [("warp", "equilibrio", None), ("auto", "streaming", None), ("tor", "anonimato", "XX")]:
        with pytest.raises(pv.ErrorPrivacidad):
            pv.activar(modo, obj, pais)


def test_rutas(client, auth, entorno):
    r = client.put("/v1/local/privacidad", headers=auth, json={"modo": "auto", "objetivo": "anonimato"})
    assert r.status_code == 200, r.text
    assert r.json()["efectivo"] == "servidor_tor"
    assert client.get("/v1/local/privacidad", headers=auth).json()["modo"] == "auto"
    assert client.put("/v1/local/privacidad", headers=auth, json={"modo": "warp"}).status_code == 422
    assert client.put("/v1/local/privacidad", headers=auth, json={"modo": "apagado"}).status_code == 200
    # El celular recibe las señales para su propia IA (solo el dueño; sin claves ni direcciones).
    from app.local import vpn_propio
    import app.api.v1.vpn as api_vpn  # noqa: F401
    monkeypatch_dueno = vpn_propio.dueno
    try:
        vpn_propio.dueno = lambda: client.get("/v1/auth/me", headers=auth).json()["id"]
        s = client.get("/v1/vpn/propio/salud", headers=auth).json()
        assert s["configurado"] is True and s["en_linea"] is True and "ficha" not in str(s)
    finally:
        vpn_propio.dueno = monkeypatch_dueno
