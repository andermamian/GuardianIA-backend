"""Salida a internet por Tor: sin filtrar la IP real (modo estricto) y sin pasar por Tor lo local."""
import pytest

from app.core import red
from app.local import tor


@pytest.fixture(autouse=True)
def _modo_limpio():
    red.fijar_modo("apagado")
    yield
    red.fijar_modo("apagado")


def _clientes(monkeypatch):
    creados = []

    class Cliente:
        def __init__(self, proxy=None, timeout=None, **k): creados.append(proxy)
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url, **k): return url
        def close(self): pass
    monkeypatch.setattr(red.httpx, "Client", Cliente)
    monkeypatch.setattr(red.httpx, "get", lambda url, **k: creados.append(None) or url)   # salida directa
    return creados


def test_apagado_sale_directo(monkeypatch):
    c = _clientes(monkeypatch)
    monkeypatch.setattr(tor, "puerto_activo", lambda: 9050)
    red.get("https://ejemplo.org")
    assert c == [None]


def test_preferir_usa_tor_con_dns_dentro(monkeypatch):
    c = _clientes(monkeypatch)
    red.fijar_modo("preferir")
    monkeypatch.setattr(tor, "puerto_activo", lambda: 9150)
    red.get("https://ejemplo.org")
    assert c == ["socks5h://127.0.0.1:9150"]           # socks5h: el DNS lo resuelve Tor, no un DoH externo
    monkeypatch.setattr(tor, "puerto_activo", lambda: None)
    red.get("https://ejemplo.org")
    assert c[-1] is None                                 # preferir: sin Tor, sale directo


def test_estricto_sin_tor_no_sale(monkeypatch):
    c = _clientes(monkeypatch)
    red.fijar_modo("estricto")
    monkeypatch.setattr(tor, "puerto_activo", lambda: None)
    with pytest.raises(red.SinTor):
        red.get("https://ejemplo.org")
    assert c == []                                       # ni siquiera se creó un cliente: la IP no se expuso
    assert red.estado()["bloqueado"] is True


def test_busqueda_web_estricta_sin_tor_no_busca(monkeypatch):
    from app.ai import assistant, web_browser
    red.fijar_modo("estricto")
    monkeypatch.setattr(tor, "puerto_activo", lambda: None)
    llamado = []
    monkeypatch.setattr(web_browser, "search", lambda *a, **k: llamado.append(1) or [])
    import httpx
    with httpx.Client() as local:
        assert assistant.gather_web_context("noticias de hoy", local) == ("", [])
    assert llamado == []                                 # no hubo búsqueda por la conexión normal


def test_rutas_locales_de_modo(client, auth):
    assert client.get("/v1/local/tor/red", headers=auth).json()["modo"] == "apagado"
    r = client.put("/v1/local/tor/red", headers=auth, json={"modo": "estricto"})
    assert r.status_code == 200 and r.json()["modo"] == "estricto"
    assert client.put("/v1/local/tor/red", headers=auth, json={"modo": "todo"}).status_code == 422
