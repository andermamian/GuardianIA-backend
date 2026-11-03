"""v3.8: la única ubicación VPN es su servidor GuardianIA VPN. Lo de terceros (ProtonVPN, WARP, .conf
importados) se purga y nunca se usa, aunque quede en disco de una versión anterior."""
import json

import pytest

from app.local import vpn

K = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="


@pytest.fixture(autouse=True)
def _dir_temporal(monkeypatch, tmp_path):
    monkeypatch.setattr(vpn, "_dir", lambda: tmp_path / "vpn")
    (tmp_path / "vpn").mkdir()


def _ubic(id_, propio, endpoint):
    p = {"id": id_, "nombre": "GuardianIA VPN (us-central1)" if propio else "wg-CH-FREE-2", "pais": "US",
         "proveedor": "servidor" if propio else "importado", "propio": propio,
         "interfaz": {"Address": "10.66.0.2/32", "DNS": "10.66.0.1"},
         "peer": {"PublicKey": K, "Endpoint": endpoint, "AllowedIPs": "0.0.0.0/0, ::/0"}}
    vpn._guardar_ubicacion(p, "privada-" + id_)
    return p


def test_solo_se_listan_las_propias():
    _ubic("aaaaaaaa", False, "185.2.2.2:51820")
    _ubic("bbbbbbbb", True, "34.1.2.3:51820")
    assert [u["id"] for u in vpn.ubicaciones()] == ["bbbbbbbb"]


def test_purga_proton_y_perfil_ajeno_sin_tocar_el_propio(monkeypatch):
    _ubic("aaaaaaaa", False, "185.2.2.2:51820")
    _ubic("bbbbbbbb", True, "34.1.2.3:51820")
    vpn._guardar_perfil({"proveedor": "importado", "nombre": "ProtonVPN CH", "peer": {}, "interfaz": {}})
    vpn._escribir_privado(vpn._dir() / "importada.key", "clave-de-proton")
    bajado = []
    monkeypatch.setattr(vpn, "wireguard", lambda: "wg")
    monkeypatch.setattr(vpn, "activo", lambda: True)
    monkeypatch.setattr(vpn, "desconectar", lambda: bajado.append(1) or {})
    r = vpn.purgar_terceros()
    assert r == {"ubicaciones_borradas": 1, "perfil_quitado": True}
    assert bajado == [1]                                   # el túnel ajeno se bajó antes de borrarlo
    assert vpn.perfil() is None and not (vpn._dir() / "importada.key").exists()
    assert (vpn._dir() / "ubicaciones" / "bbbbbbbb" / "perfil.json").exists()
    # Con el perfil propio activo, la purga no lo toca.
    monkeypatch.setattr(vpn, "activo", lambda: False)
    vpn.usar_ubicacion("bbbbbbbb")
    assert vpn.purgar_terceros() == {"ubicaciones_borradas": 0, "perfil_quitado": False}
    assert vpn.perfil()["proveedor"] == "servidor"


def test_conectar_se_niega_con_un_perfil_ajeno(monkeypatch):
    vpn._guardar_perfil({"proveedor": "importado", "nombre": "ProtonVPN", "peer": {}, "interfaz": {}})
    monkeypatch.setattr(vpn, "wireguard", lambda: "wg")
    with pytest.raises(vpn.ErrorVpn, match="WARP"):
        vpn.conectar()


def test_id_malicioso_no_toca_archivos():
    for malo in ["../../etc", "..", "ZZZZZZZZ", ""]:
        with pytest.raises(vpn.ErrorVpn):
            vpn.usar_ubicacion(malo)


def test_ninguna_clave_privada_en_la_lista():
    _ubic("bbbbbbbb", True, "34.1.2.3:51820")
    assert "privada-" not in json.dumps(vpn.ubicaciones())


# ───────────────────────────── WARP robusto (v4.1)
def test_perfil_warp_lleva_mtu_1280():
    from app.local import warp
    cfg = {"direccion_v4": "172.16.0.2", "direccion_v6": "fd01::2", "registrado": 1.0, "clave_publica": "k",
           "clave_publica_servidor": "s", "endpoint": "engage.cloudflareclient.com:2408"}
    assert warp.perfil_wireguard(cfg)["interfaz"]["MTU"] == "1280"


def test_perfil_warp_viejo_sin_mtu_lo_recibe_al_escribir_el_conf(monkeypatch, tmp_path):
    monkeypatch.setattr(vpn, "_dir", lambda: tmp_path)
    p = {"proveedor": "warp", "nombre": "Cloudflare WARP", "privada_propia": True,
         "interfaz": {"Address": "172.16.0.2/32", "DNS": "1.1.1.1"},
         "peer": {"PublicKey": "x", "Endpoint": "e:2408", "AllowedIPs": "0.0.0.0/0, ::/0"}}
    assert "MTU = 1280" in vpn._texto_conf(p)


def test_endpoint_de_warp_siempre_trae_puerto():
    from app.local import warp
    assert warp._endpoint({"endpoint": {"host": "engage.cloudflareclient.com:2408"}}) == "engage.cloudflareclient.com:2408"
    assert warp._endpoint({"endpoint": {"host": "engage.cloudflareclient.com"}}) == "engage.cloudflareclient.com:2408"
    assert warp._endpoint({"endpoint": {"host": "engage.cloudflareclient.com:0"}}) == "engage.cloudflareclient.com:2408"
    assert warp._endpoint({}) == ""


def test_registro_warp_prueba_la_siguiente_version_si_una_ya_no_existe(monkeypatch, tmp_path):
    import httpx
    from app.local import warp
    monkeypatch.setattr(vpn, "_dir", lambda: tmp_path)
    monkeypatch.setattr(warp.time, "sleep", lambda _s: None)
    visitadas = []

    def manejador(request: httpx.Request) -> httpx.Response:
        visitadas.append(request.url.path)
        if request.method == "PATCH":
            return httpx.Response(200, json={})
        if "/v0a2158/" in request.url.path:
            return httpx.Response(404)
        return httpx.Response(200, json={"id": "i", "token": "t", "config": {
            "peers": [{"public_key": "PK", "endpoint": {"host": "engage.cloudflareclient.com:2408"}}],
            "interface": {"addresses": {"v4": "172.16.0.2", "v6": "fd01::2"}}}})

    real = httpx.Client
    monkeypatch.setattr(warp.httpx, "Client", lambda **k: real(transport=httpx.MockTransport(manejador), **k))
    cfg = warp.registrar()
    assert cfg["api"] == "v0a1922" and cfg["endpoint"].endswith(":2408")
    assert any(v.endswith("/v0a2158/reg") for v in visitadas) and any(v.endswith("/v0a1922/reg") for v in visitadas)
    assert any(m for m in visitadas if m.startswith("/v0a1922/reg/i"))      # warp_enabled


def test_conectar_acepta_warp_on_aunque_la_ip_no_cambie(monkeypatch, tmp_path):
    monkeypatch.setattr(vpn, "_dir", lambda: tmp_path)
    monkeypatch.setattr(vpn, "wireguard", lambda: "wg")
    monkeypatch.setattr(vpn.sistema, "ejecutar_elevado", lambda *a, **k: 0)
    monkeypatch.setattr(vpn, "activo", lambda: True)
    monkeypatch.setattr(vpn, "tunel_instalado", lambda: False)
    monkeypatch.setattr(vpn.time, "sleep", lambda _s: None)
    monkeypatch.setattr(vpn, "ipv6_publica", lambda *a, **k: None)
    monkeypatch.setattr(vpn, "resolutor_dns", lambda: "1.1.1.1")
    monkeypatch.setattr(vpn, "trace", lambda timeout=6.0: {"ip": "203.0.113.9", "pais": "CO", "warp": "on", "colo": "BOG"})
    vpn._guardar_perfil({"proveedor": "warp", "nombre": "Cloudflare WARP", "privada_propia": True,
                         "interfaz": {"Address": "172.16.0.2/32"}, "peer": {"PublicKey": "x", "Endpoint": "e:2408",
                                                                             "AllowedIPs": "0.0.0.0/0"}})
    assert vpn.conectar()["verificado"] is True


def test_conectar_explica_la_falta_de_apreton_de_manos(monkeypatch, tmp_path):
    monkeypatch.setattr(vpn, "_dir", lambda: tmp_path)
    monkeypatch.setattr(vpn, "wireguard", lambda: "wg")
    monkeypatch.setattr(vpn.sistema, "ejecutar_elevado", lambda *a, **k: 0)
    monkeypatch.setattr(vpn, "activo", lambda: True)
    monkeypatch.setattr(vpn, "tunel_instalado", lambda: False)
    monkeypatch.setattr(vpn.time, "sleep", lambda _s: None)
    monkeypatch.setattr(vpn, "trace", lambda timeout=6.0: {"ip": "198.51.100.7", "pais": "CO", "warp": "off", "colo": None})
    monkeypatch.setattr(vpn, "_wg_show", lambda permitir_elevacion=False: {"recibidos": 0, "enviados": 148})
    vpn._guardar_perfil({"proveedor": "warp", "nombre": "Cloudflare WARP", "privada_propia": True,
                         "interfaz": {"Address": "172.16.0.2/32"}, "peer": {"PublicKey": "x", "Endpoint": "e:2408",
                                                                             "AllowedIPs": "0.0.0.0/0"}})
    r = vpn.conectar()
    assert r["verificado"] is False and "UDP 2408" in r["motivo"]
