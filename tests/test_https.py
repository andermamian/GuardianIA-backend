"""HTTPS de punta a punta: CA local restringida, renovación por cambio de IP, redirección http→https
y migración del agente."""
import importlib.util
import ipaddress
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from starlette.testclient import TestClient

from app import tls
from app.servidor import app_redireccion

IPS = ["127.0.0.1", "10.234.28.243"]


def _verificar(r, ip):
    ca = x509.load_pem_x509_certificate(r.ca_crt.read_bytes())
    hoja = x509.load_pem_x509_certificates(r.crt.read_bytes())[0]
    PolicyBuilder().store(Store([ca])).build_server_verifier(x509.IPAddress(ipaddress.ip_address(ip))).verify(hoja, [])


def test_crea_ca_y_certificado_valido_para_cada_ip(tmp_path):
    r, hecho = tls.asegurar(tmp_path, ips=IPS)
    assert "CA local creada" in hecho
    for ip in IPS:
        _verificar(r, ip)                               # un navegador que confíe en la CA lo acepta
    assert (r.ca_key.stat().st_mode & 0o077) == 0 or __import__("os").name == "nt"   # clave privada


def test_la_ca_no_puede_firmar_sitios_de_internet(tmp_path):
    """Name Constraints: aunque roben la clave de la CA, no sirve para suplantar google.com."""
    import datetime as dt
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    r, _ = tls.asegurar(tmp_path, ips=IPS)
    ca = x509.load_pem_x509_certificate(r.ca_crt.read_bytes())
    clave_ca = serialization.load_pem_private_key(r.ca_key.read_bytes(), None)
    k, ahora = ec.generate_private_key(ec.SECP256R1()), dt.datetime.now(dt.timezone.utc)
    falso = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "google.com")]))
             .issuer_name(ca.subject).public_key(k.public_key()).serial_number(7)
             .not_valid_before(ahora).not_valid_after(ahora + dt.timedelta(days=5))
             .add_extension(x509.SubjectAlternativeName([x509.DNSName("google.com")]), False)
             .sign(clave_ca, hashes.SHA256()))
    with pytest.raises(VerificationError):
        PolicyBuilder().store(Store([ca])).build_server_verifier(x509.DNSName("google.com")).verify(falso, [])


def test_si_cambia_la_ip_renueva_el_certificado_y_conserva_la_ca(tmp_path):
    r, _ = tls.asegurar(tmp_path, ips=IPS)
    ca_antes = r.ca_crt.read_bytes()
    assert tls.asegurar(tmp_path, ips=IPS)[1] == "certificados vigentes"          # nada que hacer
    r, hecho = tls.asegurar(tmp_path, ips=["127.0.0.1", "192.168.1.50"])
    assert "la IP cambió" in hecho and r.ca_crt.read_bytes() == ca_antes            # misma CA
    _verificar(r, "192.168.1.50")


def test_ip_publica_no_se_mete_en_el_certificado(tmp_path):
    r, _ = tls.asegurar(tmp_path, ips=["127.0.0.1", "181.50.1.2"])
    san = x509.load_pem_x509_certificates(r.crt.read_bytes())[0].extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    assert "181.50.1.2" not in {str(i) for i in san.get_values_for_type(x509.IPAddress)}


# ─────────────────────────────── servidor de redirección (puerto 8000)
@pytest.fixture
def redir(tmp_path):
    r, _ = tls.asegurar(tmp_path, ips=IPS)
    app = app_redireccion(8443, r.ca_crt, tls.huella_ca(tmp_path), {"127.0.0.1", "localhost", "10.234.28.243"})
    with TestClient(app, base_url="http://10.234.28.243:8000") as c:
        yield c, r


def test_http_redirige_a_https_conservando_ruta_y_metodo(redir):
    c, _ = redir
    g = c.get("/app/#/dispositivos", follow_redirects=False)
    assert g.status_code == 308 and g.headers["location"] == "https://10.234.28.243:8443/app/"
    q = c.get("/vincular?codigo=123456", follow_redirects=False)
    assert q.headers["location"] == "https://10.234.28.243:8443/vincular?codigo=123456"
    p = c.post("/v1/devices/telemetry", json={}, follow_redirects=False)
    assert p.status_code == 308          # 308: el POST sigue siendo POST al llegar a https


def test_no_es_redireccion_abierta(redir):
    c, _ = redir
    r = c.get("/app/", headers={"host": "sitio-malo.com"}, follow_redirects=False)
    assert r.headers["location"].startswith("https://127.0.0.1:8443/")


def test_entrega_la_ca_y_la_guia(redir):
    c, r = redir
    ca = c.get("/ca.crt")
    assert ca.status_code == 200 and ca.content == r.ca_crt.read_bytes()
    assert b"PRIVATE" not in ca.content                   # nunca la clave
    guia = c.get("/certificado")
    assert guia.status_code == 200 and tls.huella_ca(r.ca_crt.parent) in guia.text


def test_app_https_ofrece_la_ca(client, tmp_path, monkeypatch):
    monkeypatch.setattr(tls, "CARPETA", tmp_path)
    r, _ = tls.asegurar(tmp_path, ips=IPS)
    assert client.get("/ca.crt").content == r.ca_crt.read_bytes()


# ─────────────────────────────── agente
def _agente():
    ruta = Path(__file__).resolve().parents[1] / "agente" / "guardian_agent.py"
    spec = importlib.util.spec_from_file_location("guardian_agent_test", ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_agente_registrado_con_http_migra_solo_a_https(tmp_path, monkeypatch):
    ag = _agente()
    monkeypatch.setattr(ag, "carpeta_datos", lambda: tmp_path)
    monkeypatch.setattr(ag, "buscar_ca", lambda: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n")
    (tmp_path / "agente.json").write_text(json.dumps({"servidor": "http://127.0.0.1:8000", "token": "t"}))
    config = ag.cargar_config()
    assert config["servidor"] == "https://127.0.0.1:8443" and config["ca_pem"].startswith("-----BEGIN")
    assert json.loads((tmp_path / "agente.json").read_text())["servidor"] == "https://127.0.0.1:8443"


def test_agente_confia_solo_en_la_ca_de_guardiania(tmp_path):
    ag = _agente()
    r, _ = tls.asegurar(tmp_path, ips=IPS)
    ctx = ag.contexto_tls(r.ca_crt.read_text())
    assert len(ctx.get_ca_certs()) == 1 and ctx.get_ca_certs()[0]["subject"][0][0][1] == "GuardianIA"
