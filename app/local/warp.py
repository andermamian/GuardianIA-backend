"""Registro gratuito con Cloudflare WARP: sin cuenta, sin servidor propio, sin costo para nadie.

Usa la misma API pública (no oficial, pero estable y usada por clientes como wgcf) que usa la app
oficial de WARP para darse de alta gratis. GuardianIA nunca administra ni ve ese tráfico: lo opera
Cloudflare, igual que si la persona instalara la app oficial de WARP. Cada equipo se registra UNA
vez y guarda su propia clave; nadie comparte servidor con nadie.

Límite honesto (documentado también en la interfaz): WARP protege el tráfico frente al operador o al
WiFi público, pero Cloudflare sí conoce la IP real de quien se conecta. Para anonimato frente a
Cloudflare también, se combina con Tor (modo "WARP + Tor" en el panel).
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from datetime import datetime, timezone

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from app.local import vpn

# Cloudflare va cambiando la versión de su API de registro. Se prueban de la más nueva a la más vieja
# y se usa la primera que responda: antes una sola versión fija hacía que WARP "dejara de funcionar"
# de un día para otro sin que el código tuviera ningún error.
API_BASE = "https://api.cloudflareclient.com"
VERSIONES_API = ("v0a2158", "v0a1922", "v0a884")
CABECERAS = {"Content-Type": "application/json; charset=UTF-8", "User-Agent": "okhttp/3.12.1",
             "CF-Client-Version": "a-6.3-1922"}
TIMEOUT = 20.0
INTENTOS = 2                  # por versión: una red móvil o un Wi-Fi saturado pierde alguna petición
ARCHIVO = "warp.json"
PUERTO_WARP = "2408"
MTU = "1280"                  # el valor que usa Cloudflare; con 1420 muchas páginas se quedan cargando


class ErrorWarp(Exception):
    pass


def _archivo():
    return vpn._dir() / ARCHIVO


def _cfg() -> dict | None:
    try:
        return json.loads(_archivo().read_text("utf-8"))
    except (OSError, ValueError):
        return None


def registrado() -> bool:
    return _cfg() is not None


def _registrar_en_cloudflare(cuerpo: dict) -> tuple[dict, str]:
    """POST /reg probando las versiones de la API. Devuelve (respuesta, versión que funcionó)."""
    ultimo: Exception | None = None
    with httpx.Client(timeout=TIMEOUT) as c:
        for version in VERSIONES_API:
            for intento in range(INTENTOS):
                try:
                    r = c.post(f"{API_BASE}/{version}/reg", headers=CABECERAS, json=cuerpo)
                    if r.status_code == 404:          # esa versión ya no existe: pasar a la siguiente
                        break
                    r.raise_for_status()
                    return r.json(), version
                except (httpx.HTTPError, ValueError) as e:
                    ultimo = e
                    time.sleep(0.6 * (intento + 1))
    raise ErrorWarp("Cloudflare no respondió al registro gratuito de WARP"
                    + (f" ({type(ultimo).__name__})" if ultimo else "")
                    + ". Revise que esta red no bloquee cloudflareclient.com y vuelva a intentar.") from ultimo


def _habilitar(datos: dict, version: str) -> None:
    """Pide a Cloudflare que deje el registro «encendido» (warp_enabled). Sin esto algunos registros
    nuevos hacen el apretón de manos pero no pasan tráfico. Si falla no es grave: se ignora."""
    try:
        token, id_ = datos.get("token"), datos.get("id")
        if not token or not id_:
            return
        with httpx.Client(timeout=TIMEOUT) as c:
            c.patch(f"{API_BASE}/{version}/reg/{id_}", json={"warp_enabled": True},
                    headers={**CABECERAS, "Authorization": f"Bearer {token}"})
    except httpx.HTTPError:
        pass


def _endpoint(peer: dict) -> str:
    """host:puerto del servidor WARP. La API a veces devuelve el host sin puerto (o con puerto 0)."""
    ep = peer.get("endpoint") or {}
    host = (ep.get("host") or "").strip()
    if not host:
        return ""
    nombre, _, puerto = host.rpartition(":")
    if not nombre or not puerto.isdigit() or int(puerto) == 0:
        return f"{(nombre or host)}:{PUERTO_WARP}"
    return host


def registrar() -> dict:
    """Alta gratuita en Cloudflare WARP: genera un par de claves propio y lo registra. No pide nada
    a la persona (ni cuenta, ni tarjeta, ni datos)."""
    priv = X25519PrivateKey.generate()
    privada = base64.b64encode(priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    publica = base64.b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()

    cuerpo = {"key": publica, "install_id": "", "fcm_token": "",
              "tos": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
              "type": "PC", "model": "PC", "locale": "es_CO"}
    datos, version = _registrar_en_cloudflare(cuerpo)

    cfg_remota = datos.get("config", {})
    peers = cfg_remota.get("peers") or [{}]
    peer = peers[0]
    endpoint = _endpoint(peer)
    direccion = cfg_remota.get("interface", {}).get("addresses", {})
    if not (peer.get("public_key") and endpoint and direccion.get("v4")):
        raise ErrorWarp("Cloudflare respondió, pero sin los datos del túnel (puede que cambiaran su API). "
                        "Intente de nuevo en unos minutos.")
    _habilitar(datos, version)

    perfil = {"clave_privada": privada, "clave_publica": publica,
              "endpoint": endpoint, "clave_publica_servidor": peer.get("public_key"),
              "direccion_v4": direccion.get("v4"), "direccion_v6": direccion.get("v6"),
              "ubicacion_id": uuid.uuid4().hex[:8], "registrado": time.time(), "api": version}
    vpn._escribir_privado(_archivo(), json.dumps(perfil, ensure_ascii=False))
    return perfil


def olvidar() -> None:
    try:
        _archivo().unlink()
    except OSError:
        pass


def perfil_wireguard(cfg: dict) -> dict:
    """Perfil en el mismo formato que usa vpn.py (proveedor/interfaz/peer): listo para conectar()."""
    direccion = cfg["direccion_v4"] + "/32"
    if cfg.get("direccion_v6"):
        direccion += f", {cfg['direccion_v6']}/128"
    return {"proveedor": "warp", "nombre": "Cloudflare WARP", "creado": cfg["registrado"],
            "clave_publica_equipo": cfg["clave_publica"], "privada_propia": False,
            "interfaz": {"Address": direccion, "DNS": "1.1.1.1, 2606:4700:4700::1111", "MTU": MTU},
            "peer": {"PublicKey": cfg["clave_publica_servidor"], "Endpoint": cfg["endpoint"],
                     "AllowedIPs": "0.0.0.0/0, ::/0", "PersistentKeepalive": "25"}}
