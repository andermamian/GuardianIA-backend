"""HTTPS local para GuardianIA: autoridad certificadora propia + certificado del servidor.

Por qué una CA y no un certificado autofirmado suelto (lo mismo que hace `mkcert`):
* Se instala la CA UNA vez en el PC y en el celular, y desaparece el aviso «conexión no privada».
* Cuando cambia la IP del PC (pasa a menudo en redes con DHCP), se genera un certificado nuevo del
  servidor firmado por la MISMA CA: los dispositivos siguen confiando sin reinstalar nada.

Seguridad de la CA:
* Tiene *Name Constraints*: solo puede firmar para IP privadas (10/8, 172.16/12, 192.168/16,
  127/8, ::1) y para «localhost». Si alguien robara su clave, NO podría falsificar google.com ni el
  banco en los equipos que la instalaron; los navegadores rechazan lo que salga de esos límites.
* La clave de la CA vive solo en data/certs/ca.key (permisos 600) y nunca se sirve por la red. Lo
  único público es ca.crt, que es seguro compartir.

Uso:
    python -m app.tls              estado de los certificados (y huella de la CA)
    python -m app.tls confiar      instala la CA en Windows (usuario actual) para no ver avisos
    python -m app.tls nuevo        regenera el certificado del servidor (la CA se conserva)
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RAIZ = Path(__file__).resolve().parents[1]
CARPETA = Path(os.environ.get("GUARDIAN_CERTS_DIR", RAIZ / "data" / "certs"))

VIGENCIA_CA_DIAS = 3650
VIGENCIA_SERVIDOR_DIAS = 397      # tope que exigen los navegadores a certificados de servidor
RENOVAR_ANTES_DIAS = 30

REDES_PERMITIDAS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                    "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10"]


@dataclass(frozen=True)
class Rutas:
    ca_crt: Path
    ca_key: Path
    crt: Path
    key: Path


def rutas(carpeta: Path | None = None) -> Rutas:
    c = Path(carpeta or CARPETA)
    return Rutas(c / "ca.crt", c / "ca.key", c / "servidor.crt", c / "servidor.key")


def ips_locales() -> list[str]:
    """IP de este PC en todas sus interfaces (sin enlace-local: no se usan para conectarse)."""
    ips = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))       # no envía nada: solo pregunta qué interfaz se usaría
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return sorted(ip for ip in ips if not ip.startswith("169.254."))


def _escribir_clave(ruta: Path, clave) -> None:
    ruta.write_bytes(clave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    try:
        os.chmod(ruta, 0o600)
    except OSError:
        pass


def _ahora() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _crear_ca(r: Rutas) -> None:
    clave = ec.generate_private_key(ec.SECP256R1())
    nombre = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GuardianIA"),
                        x509.NameAttribute(NameOID.COMMON_NAME,
                                           f"GuardianIA CA local ({socket.gethostname()[:30]})")])
    permitidos = [x509.DNSName("localhost")] + [x509.IPAddress(ipaddress.ip_network(n)) for n in REDES_PERMITIDAS]
    ahora = _ahora()
    cert = (x509.CertificateBuilder()
            .subject_name(nombre).issuer_name(nombre)
            .public_key(clave.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(ahora - dt.timedelta(minutes=5))
            .not_valid_after(ahora + dt.timedelta(days=VIGENCIA_CA_DIAS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.NameConstraints(permitted_subtrees=permitidos, excluded_subtrees=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(clave.public_key()), critical=False)
            .sign(clave, hashes.SHA256()))
    _escribir_clave(r.ca_key, clave)
    r.ca_crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _cargar_ca(r: Rutas):
    cert = x509.load_pem_x509_certificate(r.ca_crt.read_bytes())
    clave = serialization.load_pem_private_key(r.ca_key.read_bytes(), password=None)
    return cert, clave


def _crear_servidor(r: Rutas, ips: list[str]) -> None:
    ca, ca_clave = _cargar_ca(r)
    clave = ec.generate_private_key(ec.SECP256R1())
    ahora = _ahora()
    san = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("::1"))]
    san += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips if _ip_permitida(ip)]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GuardianIA servidor local")]))
            .issuer_name(ca.subject)
            .public_key(clave.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(ahora - dt.timedelta(minutes=5))
            .not_valid_after(ahora + dt.timedelta(days=VIGENCIA_SERVIDOR_DIAS))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=True, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_clave.public_key()), critical=False)
            .sign(ca_clave, hashes.SHA256()))
    _escribir_clave(r.key, clave)
    # Cadena completa (servidor + CA): algunos clientes no la arman solos.
    r.crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM))


def _ip_permitida(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(n) for n in REDES_PERMITIDAS if a.version == ipaddress.ip_network(n).version)


def motivo_para_renovar(r: Rutas, ips: list[str]) -> str | None:
    """Por qué hay que regenerar el certificado del servidor, o None si sirve tal cual."""
    if not (r.crt.exists() and r.key.exists()):
        return "no existe"
    try:
        cert = x509.load_pem_x509_certificate(r.crt.read_bytes())
        ca = x509.load_pem_x509_certificate(r.ca_crt.read_bytes())
    except ValueError:
        return "archivo dañado"
    if cert.issuer != ca.subject:
        return "lo firmó otra CA"
    if cert.not_valid_after_utc - _ahora() < dt.timedelta(days=RENOVAR_ANTES_DIAS):
        return "está por vencer"
    try:
        nombres = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        cubiertas = {str(i) for i in nombres.get_values_for_type(x509.IPAddress)}
    except x509.ExtensionNotFound:
        return "sin nombres alternativos"
    faltan = [ip for ip in ips if _ip_permitida(ip) and ip not in cubiertas]
    return f"la IP cambió ({', '.join(faltan)})" if faltan else None


def asegurar(carpeta: Path | None = None, *, forzar: bool = False, ips: list[str] | None = None) -> tuple[Rutas, str]:
    """Deja listos CA y certificado del servidor. Devuelve las rutas y qué se hizo (para el log)."""
    r = rutas(carpeta)
    r.ca_crt.parent.mkdir(parents=True, exist_ok=True)
    ips = ips if ips is not None else ips_locales()
    hecho = []
    if not (r.ca_crt.exists() and r.ca_key.exists()):
        _crear_ca(r)
        hecho.append("CA local creada")
        forzar = True
    motivo = "regeneración pedida" if forzar else motivo_para_renovar(r, ips)
    if motivo:
        _crear_servidor(r, ips)
        hecho.append(f"certificado del servidor renovado: {motivo}")
    return r, "; ".join(hecho) or "certificados vigentes"


def huella_ca(carpeta: Path | None = None) -> str:
    """SHA-256 de la CA, para comprobar en el celular que se instaló la correcta y no una cambiada."""
    cert = x509.load_pem_x509_certificate(rutas(carpeta).ca_crt.read_bytes())
    h = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def confiar_en_windows(carpeta: Path | None = None) -> tuple[bool, str]:
    """Agrega la CA al almacén «Raíz de confianza» del USUARIO actual (no requiere administrador).

    Windows muestra un aviso de seguridad pidiendo confirmar: es a propósito, nadie puede instalar
    una CA sin que usted lo apruebe. Chrome, Edge y Opera usan ese almacén; Firefox tiene el suyo.
    """
    if os.name != "nt":
        return False, "Solo aplica en Windows."
    r = rutas(carpeta)
    try:
        p = subprocess.run(["certutil", "-user", "-addstore", "Root", str(r.ca_crt)],
                           capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    return p.returncode == 0, (p.stdout or p.stderr).strip()[-300:]


def _main(argv: list[str]) -> None:
    orden = argv[0] if argv else "estado"
    if orden == "nuevo":
        r, hecho = asegurar(forzar=True)
    else:
        r, hecho = asegurar()
    print(f"Certificados: {hecho}")
    print(f"  CA (pública, se puede compartir): {r.ca_crt}")
    print(f"  Huella SHA-256 de la CA: {huella_ca()}")
    print(f"  IP cubiertas: {', '.join(ip for ip in ips_locales() if _ip_permitida(ip))}")
    if orden == "confiar":
        ok, salida = confiar_en_windows()
        print("✓ CA instalada en Windows: cierre y abra el navegador." if ok else f"✗ No se instaló: {salida}")


if __name__ == "__main__":
    _main(sys.argv[1:])
