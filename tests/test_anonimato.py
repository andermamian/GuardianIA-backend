"""Motor de anonimato de la VPN (mismo que usa la app Android)."""
from app.ai import anonimato as an


def test_jurisdiccion_alianzas():
    assert an.jurisdiccion("US")["alianza"] == "5 Ojos"
    assert an.jurisdiccion("fr")["alianza"] == "9 Ojos"
    assert an.jurisdiccion("SE")["alianza"] == "14 Ojos"
    assert an.jurisdiccion("CH")["alianza"] == "ninguna" and an.jurisdiccion("CH")["puntaje"] == 1.0
    assert an.jurisdiccion(None)["alianza"] == "desconocida"


def test_endurecer_cierra_fugas():
    interfaz, peer = {"Address": "10.2.0.2/32"}, {"AllowedIPs": "0.0.0.0/0"}
    assert an.endurecer(interfaz, peer) == ["dns_privado", "ipv6_por_tunel"]
    assert interfaz["DNS"] == an.DNS_PRIVADO and peer["AllowedIPs"] == "0.0.0.0/0, ::/0"
    # Un archivo ya correcto no se toca.
    assert an.endurecer({"DNS": "10.2.0.1"}, {"AllowedIPs": "0.0.0.0/0, ::/0"}) == []


def test_proton_suiza_sin_fugas_es_alto():
    r = an.evaluar(ip_oculta=True, ipv6_fuga=False, dns_fuga=False, kill_switch=True,
                   proveedor="importado", nombre="ProtonVPN CH-12", pais_salida="CH")
    assert r["puntaje"] == 100 and r["nivel"] == "alto" and r["consejos"] == []


def test_warp_es_privacidad_no_anonimato():
    r = an.evaluar(ip_oculta=True, ipv6_fuga=False, dns_fuga=False, kill_switch=None,
                   proveedor="warp", pais_salida="CO")
    assert r["nivel"] != "alto"
    assert any("Cloudflare conoce su IP real" in c for c in r["consejos"])


def test_sin_ip_oculta_no_hay_anonimato():
    r = an.evaluar(ip_oculta=False, ipv6_fuga=False, dns_fuga=False, kill_switch=True,
                   proveedor="importado", nombre="Proton", pais_salida="CH")
    assert r["puntaje"] <= 10 and r["nivel"] == "bajo"


def test_fugas_bajan_el_nivel():
    limpio = an.evaluar(ip_oculta=True, ipv6_fuga=False, dns_fuga=False, kill_switch=True,
                        proveedor="importado", nombre="Proton", pais_salida="CH")["puntaje"]
    fugas = an.evaluar(ip_oculta=True, ipv6_fuga=True, dns_fuga=True, kill_switch=True,
                       proveedor="importado", nombre="Proton", pais_salida="CH")["puntaje"]
    assert fugas == limpio - 30



def test_ia_anonimato_prefiere_fuera_de_las_alianzas():
    from app.ai import vpn_ai
    S = [vpn_ai.Server("mia", "US", "Miami", "h", 51820, load=0.1, latency_ms=40),
         vpn_ai.Server("bog", "CO", "Bogotá", "h", 51820, load=0.1, latency_ms=20),
         vpn_ai.Server("zrh", "CH", "Zúrich", "h", 51820, load=0.4, latency_ms=190)]
    r = vpn_ai.recommend(S, purpose="anonimato", user_country="CO")
    assert r.server.id == "zrh"                       # lento pero fuera de 5/9/14 Ojos
    assert any("5/9/14 Ojos" in m for m in r.reasons)
    assert not any("Cercano" in m for m in r.reasons)
    # En «general» manda la velocidad: sale por Bogotá.
    assert vpn_ai.recommend(S, purpose="general", user_country="CO").server.id == "bog"


def test_vpn_pc_deja_pasar_la_red_local():
    """Con la red local permitida (por defecto) no hay rutas «/0»: WireGuard para Windows no bloquea la
    red de la casa y el celular sigue llegando al PC; lo público sigue por el túnel."""
    import ipaddress
    from app.local import vpn
    r = vpn.rutas_para("0.0.0.0/0, ::/0", lan=True)
    redes = [ipaddress.ip_network(x.strip()) for x in r.split(",")]
    assert "0.0.0.0/0" not in r and "::/0" not in r and "2000::/3" in r
    def cubre(ip): return any(ipaddress.ip_address(ip) in n for n in redes)
    assert cubre("8.8.8.8") and cubre("1.1.1.1") and cubre("2001:4860:4860::8888")   # internet por el túnel
    assert not cubre("10.234.28.243") and not cubre("192.168.1.5") and not cubre("172.16.0.9")  # casa fuera
    assert vpn.rutas_para("0.0.0.0/0, ::/0", lan=False) == "0.0.0.0/0, ::/0"             # kill switch si se pide


def test_conectar_no_desinstala_un_tunel_que_no_existe(monkeypatch, tmp_path):
    """Antes se pedía desinstalar siempre: WireGuard mostraba «El servicio especificado no existe» y el
    primer intento fallaba. Ahora solo se desinstala si el túnel existe (un solo permiso de administrador)."""
    from app.local import vpn, sistema
    llamadas = []
    monkeypatch.setattr(sistema, "ES_WINDOWS", True)
    monkeypatch.setattr(vpn, "tunel_instalado", lambda: False)
    monkeypatch.setattr(vpn, "wireguard", lambda: "wireguard.exe")
    monkeypatch.setattr(sistema, "ejecutar_elevado", lambda exe, args: llamadas.append(args[0]) or 0)
    monkeypatch.setattr(vpn, "_estado_archivo", lambda: {})
    monkeypatch.setattr(vpn, "_guardar_estado", lambda e: e)
    vpn.desconectar()
    assert "/uninstalltunnelservice" not in llamadas
