"""Cliente del servidor VPN propio de GuardianIA (vpn_servidor/agente.py en su máquina de Google Cloud).

Se configura UNA vez en el PC con los tres datos que mostró el instalador: dirección de la API, huella
del certificado y ficha secreta. Desde entonces el PC y el celular se dan de alta solos: nada de .conf.

Seguridad:
* **Anclaje del certificado.** Antes de enviar la ficha se descarga el certificado del servidor y se
  compara su SHA-256 con la huella que usted copió del instalador. Si no coincide, NO se envía nada
  (alguien podría estar suplantando el servidor). Después, cada conexión confía SOLO en ese certificado:
  un atacante con otro certificado corta el apretón TLS antes de que salga la ficha.
* **La ficha no sale de este PC.** Se guarda cifrada (clave maestra del servidor GuardianIA) y el
  celular nunca la recibe: le pide el alta al PC con su sesión, y el PC habla con el servidor VPN.
* **Cada dispositivo tiene su propia clave** WireGuard; la privada nunca sale de él.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import ssl
import time
import uuid
from urllib.parse import quote, urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from app.core.crypto import open_text, seal_text
from app.local import vpn

ARCHIVO = "propio.json"
TIMEOUT = 15.0

# Región de Google Cloud → país que verán los sitios.
REGIONES = {
    "us-": "US", "northamerica-northeast": "CA", "northamerica-south": "MX", "southamerica-east": "BR",
    "southamerica-west": "CL", "europe-west1": "BE", "europe-west2": "GB", "europe-west3": "DE",
    "europe-west4": "NL", "europe-west6": "CH", "europe-west8": "IT", "europe-west9": "FR",
    "europe-southwest": "ES", "europe-north": "FI", "europe-central": "PL", "asia-northeast1": "JP",
    "asia-northeast3": "KR", "asia-southeast1": "SG", "asia-east1": "TW", "asia-east2": "HK",
    "asia-south": "IN", "australia-": "AU", "me-west": "IL", "africa-south": "ZA",
}


class ErrorPropio(Exception):
    pass


# ─────────────────────────── validaciones
def pais_de_region(region: str | None) -> str | None:
    r = (region or "").lower()
    for prefijo, pais in sorted(REGIONES.items(), key=lambda x: -len(x[0])):
        if r.startswith(prefijo):
            return pais
    return None


def normalizar_huella(h: str) -> str:
    """«AB:CD:…» (openssl) o «abcd…» → 64 hexadecimales en minúscula."""
    limpio = re.sub(r"[\s:]", "", h or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", limpio):
        raise ErrorPropio("La huella no tiene el formato correcto (64 caracteres hexadecimales, con o sin «:»)")
    return limpio


def separar_url(url: str) -> tuple[str, int]:
    u = urlsplit((url or "").strip())
    if u.scheme != "https" or not u.hostname or u.path not in ("", "/") or u.query or u.username:
        raise ErrorPropio("La dirección debe ser como https://34.123.45.67:8844")
    host = u.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
            raise ErrorPropio("Dirección no válida") from None
    return host, u.port or 8844


def huella_de(pem: str) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def contexto_anclado(pem: str) -> ssl.SSLContext:
    """Contexto TLS que confía SOLO en ese certificado (sin CAs del sistema)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cadata=pem)
    ctx.check_hostname = False              # certificado propio por IP: el anclaje sustituye al nombre
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)   # Python 3.13+: el anclaje manda
    return ctx


# ─────────────────────────── almacenamiento
def _cfg() -> dict:
    try:
        return json.loads((vpn._dir() / ARCHIVO).read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def configurado() -> bool:
    return bool(_cfg().get("url"))


def dueno() -> str | None:
    return _cfg().get("dueno")


def _cliente(cfg: dict) -> httpx.Client:
    return httpx.Client(base_url=cfg["url"], verify=contexto_anclado(cfg["pem"]), timeout=TIMEOUT,
                        headers={"Authorization": f"Bearer {open_text(cfg['ficha'], 'vpn_propio:ficha')}"})


def _llamar(cfg: dict, metodo: str, ruta: str, cuerpo: dict | None = None) -> dict:
    try:
        with _cliente(cfg) as c:
            r = c.request(metodo, ruta, json=cuerpo)
    except ssl.SSLError as e:
        raise ErrorPropio("El certificado del servidor ya no coincide con la huella guardada: posible "
                          "suplantación. No se envió nada.") from e
    except httpx.ConnectError as e:
        if isinstance(e.__cause__, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(e):
            raise ErrorPropio("El certificado del servidor ya no coincide con la huella guardada: posible "
                              "suplantación. No se envió nada.") from e
        raise ErrorPropio("Su servidor VPN no respondió. Revise que la máquina esté encendida y que exista la "
                          "regla de firewall «guardian-vpn-api» (tcp:8844).") from e
    except httpx.HTTPError as e:
        raise ErrorPropio(f"Su servidor VPN no respondió ({type(e).__name__}).") from e
    if r.status_code == 401:
        raise ErrorPropio("La ficha secreta no es correcta.")
    if r.status_code == 429:
        raise ErrorPropio("Demasiados intentos fallidos: el servidor se bloqueó 15 minutos.")
    if r.status_code >= 400:
        raise ErrorPropio(f"El servidor VPN rechazó la petición: {r.json().get('error', r.status_code)}")
    return r.json()


# ─────────────────────────── configurar / estado / quitar
def configurar(url: str, huella: str, ficha: str, dueno_id: str, nombre_pc: str = "PC GuardianIA") -> dict:
    """Verifica el servidor (huella), guarda la configuración cifrada y da de alta este PC."""
    host, puerto = separar_url(url)
    esperada = normalizar_huella(huella)
    ficha = (ficha or "").strip()
    if not 20 <= len(ficha) <= 200 or not re.fullmatch(r"[A-Za-z0-9._~-]+", ficha):
        raise ErrorPropio("La ficha secreta no tiene el formato esperado.")
    try:
        pem = ssl.get_server_certificate((host, puerto), timeout=TIMEOUT)
    except (OSError, ssl.SSLError) as e:
        raise ErrorPropio("No pude conectar con su servidor VPN. Revise la dirección, que la máquina esté "
                          "encendida y la regla de firewall «guardian-vpn-api» (tcp:8844).") from e
    real = huella_de(pem)
    if real != esperada:
        raise ErrorPropio("La huella del certificado NO coincide con la que copió del instalador: podría ser "
                          "una suplantación. No se envió la ficha ni se guardó nada.")
    cfg = {"url": f"https://{host}:{puerto}", "pem": pem, "huella": real,
           "ficha": seal_text(ficha, "vpn_propio:ficha"), "dueno": dueno_id, "configurado": time.time()}
    salud = _llamar(cfg, "GET", "/salud")                       # también comprueba la ficha
    cfg.update(region=salud.get("region"), endpoint=salud.get("endpoint"),
               clave_publica_servidor=salud.get("clave_publica_servidor"))
    vpn._escribir_privado(vpn._dir() / ARCHIVO, json.dumps(cfg, ensure_ascii=False))
    ubic = _alta_este_pc(cfg, nombre_pc)
    return {**estado(consultar=False), "ubicacion_id": ubic}


def _alta_este_pc(cfg: dict, nombre: str) -> str:
    privada = X25519PrivateKey.generate()
    priv_b64 = base64.b64encode(privada.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    pub_b64 = base64.b64encode(privada.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    r = _llamar(cfg, "POST", "/dispositivos", {"clave_publica": pub_b64, "nombre": nombre[:40]})
    # Una sola ubicación «propia» en este PC: si se reconfigura, reemplaza la anterior y da de baja su
    # clave en el servidor (una clave vieja que nadie usa no debe seguir autorizada).
    for clave in _quitar_propias():
        _baja_silenciosa(cfg, clave)
    pais = pais_de_region(r.get("region") or cfg.get("region"))
    p = {"proveedor": "servidor", "propio": True, "id": uuid.uuid4().hex[:8], "creado": time.time(),
         "nombre": f"GuardianIA VPN ({r.get('region') or cfg.get('region') or 'propio'})", "pais": pais,
         "clave_publica_equipo": pub_b64, "privada_propia": False, "endurecido": [],
         "interfaz": {"Address": r["direccion"], "DNS": r["dns"]},
         "peer": {"PublicKey": r["clave_publica_servidor"], "Endpoint": r["endpoint"],
                  "AllowedIPs": r.get("allowed_ips", "0.0.0.0/0, ::/0"),
                  "PersistentKeepalive": str(r.get("keepalive", 25))}}
    vpn._guardar_ubicacion(p, priv_b64)
    return p["id"]


def alta_dispositivo(clave_publica: str, nombre: str | None) -> dict:
    """Alta de OTRO dispositivo (el celular): el PC habla con el servidor; la ficha no sale de aquí."""
    cfg = _cfg()
    if not cfg:
        raise ErrorPropio("Su servidor GuardianIA VPN aún no está conectado en el PC.")
    try:
        if len(base64.b64decode(clave_publica, validate=True)) != 32:
            raise ValueError
    except ValueError:
        raise ErrorPropio("Clave pública inválida") from None
    r = _llamar(cfg, "POST", "/dispositivos", {"clave_publica": clave_publica, "nombre": (nombre or "celular")[:40]})
    region = r.get("region") or cfg.get("region")
    return {**r, "region": region, "pais": pais_de_region(region), "nombre": f"GuardianIA VPN ({region})"}


def estado(consultar: bool = True) -> dict:
    cfg = _cfg()
    if not cfg:
        return {"configurado": False}
    r = {"configurado": True, "url": cfg["url"], "region": cfg.get("region"), "pais": pais_de_region(cfg.get("region")),
         "endpoint": cfg.get("endpoint"), "huella": cfg.get("huella")}
    if consultar:
        try:
            s = _llamar(cfg, "GET", "/salud")
            r.update(en_linea=True, dispositivos=s.get("dispositivos"), consumo=s.get("consumo"))
        except ErrorPropio as e:
            r.update(en_linea=False, error=str(e))
    return r


def _quitar_propias() -> list[str]:
    """Borra las ubicaciones propias de este PC y devuelve sus claves públicas."""
    claves = []
    for u in vpn.ubicaciones():
        if u.get("propio"):
            try:
                clave = vpn._ubicacion(u["id"])[0].get("clave_publica_equipo")
            except Exception:  # noqa: BLE001 - ubicación dañada: se borra igual
                clave = None
            vpn.eliminar_ubicacion(u["id"])
            if clave:
                claves.append(clave)
    return claves


def _baja_silenciosa(cfg: dict, clave: str) -> None:
    try:
        _llamar(cfg, "DELETE", "/dispositivos/" + quote(clave, safe=""))
    except ErrorPropio:
        pass                                    # ya no estaba, o el servidor no responde: no bloquea


def quitar() -> dict:
    cfg = _cfg()
    for clave in _quitar_propias():
        if cfg:
            _baja_silenciosa(cfg, clave)
    try:
        (vpn._dir() / ARCHIVO).unlink()
    except OSError:
        pass
    return {"configurado": False}
