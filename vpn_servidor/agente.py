"""Agente del servidor VPN propio de GuardianIA (WireGuard) para una máquina Linux (Google Cloud e2-micro).

Independiente de Proton, Tor y Cloudflare: el servidor es suyo. Protocolo WireGuard (estándar abierto y
auditado, dentro del núcleo de Linux): NO se inventa criptografía propia — ese es el error más grave que
se puede cometer en una VPN.

Qué hace:
* Da de alta dispositivos: cada celular/PC genera SU clave; aquí solo llega la PÚBLICA (la privada nunca
  sale del dispositivo). Se le asigna una dirección interna 10.66.0.x y fd66::x.
* Sin registros: no se guardan IPs de origen ni actividad; solo «clave pública → dirección interna».
* Freno de consumo: Google Cloud da 200 GB/mes gratis en red Standard. Al llegar al límite (190 GB por
  defecto) se deja de reenviar tráfico hasta el mes siguiente: nunca llega una factura por sorpresa.
* API protegida con una ficha secreta (en disco solo se guarda su SHA-256) y bloqueo tras fallos.

Los comandos del sistema pasan por ``Sistema`` para poder probar toda la lógica sin ser administrador.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "1.0.0"
RED_V4 = ipaddress.ip_network("10.66.0.0/24")
RED_V6 = ipaddress.ip_network("fd66::/64")
INTERFAZ = "wg0"
DIR = Path(os.environ.get("GUARDIAN_VPN_DIR", "/etc/guardian-vpn"))
LIMITE_GB = float(os.environ.get("GUARDIAN_VPN_LIMITE_GB", "190"))
MAX_DISPOSITIVOS = 50
FALLOS_MAX, BLOQUEO_S = 10, 900


class ErrorVpn(Exception):
    def __init__(self, codigo: int, mensaje: str):
        super().__init__(mensaje)
        self.codigo = codigo


# ─────────────────────────── validación
def clave_valida(clave: str) -> bool:
    """Clave pública de WireGuard: 32 bytes en base64 (44 caracteres). Nada de texto libre hacia «wg»."""
    if not isinstance(clave, str) or len(clave) != 44:
        return False
    try:
        return len(base64.b64decode(clave, validate=True)) == 32
    except ValueError:
        return False


def nombre_limpio(nombre: str | None) -> str:
    n = "".join(c for c in (nombre or "dispositivo") if c.isalnum() or c in " -_.")[:40].strip()
    return n or "dispositivo"


def huella_ficha(ficha: str) -> str:
    return hashlib.sha256(ficha.encode()).hexdigest()


# ─────────────────────────── sistema (se sustituye en las pruebas)
class Sistema:
    def ejecutar(self, args: list[str], entrada: str | None = None) -> str:
        r = subprocess.run(args, input=entrada, capture_output=True, text=True, timeout=15, check=True)
        return r.stdout

    def agregar_peer(self, clave: str, v4: str, v6: str) -> None:
        self.ejecutar(["wg", "set", INTERFAZ, "peer", clave, "allowed-ips", f"{v4}/32,{v6}/128"])

    def quitar_peer(self, clave: str) -> None:
        self.ejecutar(["wg", "set", INTERFAZ, "peer", clave, "remove"])

    def bytes_transferidos(self) -> int:
        """Suma de recibidos+enviados de todos los peers (contadores del núcleo, desde el arranque)."""
        total = 0
        for linea in self.ejecutar(["wg", "show", INTERFAZ, "transfer"]).splitlines():
            partes = linea.split()
            if len(partes) == 3:
                total += int(partes[1]) + int(partes[2])
        return total

    def reenvio(self, activo: bool) -> None:
        """Freno de consumo: con False, nftables descarta lo que el túnel reenvía a internet."""
        self.ejecutar(["nft", "flush", "chain", "inet", "guardian", "freno"])
        if not activo:
            self.ejecutar(["nft", "add", "rule", "inet", "guardian", "freno", "iifname", INTERFAZ, "drop"])


# ─────────────────────────── estado persistente (sin registros de actividad)
@dataclass
class Agente:
    sistema: Sistema = field(default_factory=Sistema)
    dir: Path = DIR
    limite_gb: float = LIMITE_GB
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _fallos: dict = field(default_factory=dict, repr=False)

    # archivos
    def _leer(self, nombre: str, defecto):
        try:
            return json.loads((self.dir / nombre).read_text("utf-8"))
        except (OSError, ValueError):
            return defecto

    def _escribir(self, nombre: str, datos) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.dir / (nombre + ".tmp")
        tmp.write_text(json.dumps(datos, ensure_ascii=False, indent=1), "utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.dir / nombre)

    def config(self) -> dict:
        return self._leer("config.json", {})

    def peers(self) -> dict:
        return self._leer("peers.json", {})

    # autenticación
    def autorizar(self, ficha: str | None, origen: str = "") -> None:
        ahora = time.time()
        f = self._fallos.get(origen, [0, 0.0])
        if f[0] >= FALLOS_MAX and ahora - f[1] < BLOQUEO_S:
            raise ErrorVpn(429, "Demasiados intentos fallidos: espere 15 minutos")
        esperado = self.config().get("ficha_sha256", "")
        dada = huella_ficha(ficha or "")
        if not esperado or not hmac.compare_digest(dada, esperado):
            self._fallos[origen] = [f[0] + 1, ahora]
            raise ErrorVpn(401, "Ficha inválida")
        self._fallos.pop(origen, None)

    # dispositivos
    def _libres(self, usados: set[str]):
        for i, ip in enumerate(RED_V4.hosts()):
            if i == 0:
                continue                                   # .1 es el servidor
            if str(ip) not in usados:
                return str(ip), str(RED_V6.network_address + int(ip) - int(RED_V4.network_address))
        raise ErrorVpn(507, "No quedan direcciones libres")

    def alta(self, clave: str, nombre: str | None) -> dict:
        if not clave_valida(clave):
            raise ErrorVpn(422, "Clave pública inválida")
        with self._lock:
            peers = self.peers()
            if clave in peers:
                p = peers[clave]                           # alta repetida: misma dirección (idempotente)
            else:
                if len(peers) >= MAX_DISPOSITIVOS:
                    raise ErrorVpn(507, "Límite de dispositivos alcanzado")
                v4, v6 = self._libres({x["v4"] for x in peers.values()})
                p = {"v4": v4, "v6": v6, "nombre": nombre_limpio(nombre), "alta": int(time.time())}
                peers[clave] = p
                self._escribir("peers.json", peers)
            self.sistema.agregar_peer(clave, p["v4"], p["v6"])
        cfg = self.config()
        return {"direccion": f"{p['v4']}/32, {p['v6']}/128", "dns": "10.66.0.1, fd66::1",
                "clave_publica_servidor": cfg.get("clave_publica"), "endpoint": cfg.get("endpoint"),
                "allowed_ips": "0.0.0.0/0, ::/0", "keepalive": 25, "region": cfg.get("region")}

    def baja(self, clave: str) -> None:
        if not clave_valida(clave):
            raise ErrorVpn(422, "Clave pública inválida")
        with self._lock:
            peers = self.peers()
            if clave not in peers:
                raise ErrorVpn(404, "Ese dispositivo no está dado de alta")
            del peers[clave]
            self._escribir("peers.json", peers)
            self.sistema.quitar_peer(clave)

    def restaurar(self) -> None:
        """Al arrancar: vuelve a cargar los peers guardados en la interfaz."""
        for clave, p in self.peers().items():
            self.sistema.agregar_peer(clave, p["v4"], p["v6"])

    # freno de consumo
    def medir_consumo(self) -> dict:
        """Acumula el consumo del mes con los contadores del núcleo (que se reinician si el servidor
        se reinicia) y aplica el freno. Solo cuenta bytes: nunca a dónde ni de quién."""
        with self._lock:
            u = self._leer("uso.json", {})
            mes = time.strftime("%Y-%m")
            actual = self.sistema.bytes_transferidos()
            if not u:
                # Primera medición: lo que marcan los contadores ya es consumo de este mes.
                u = {"mes": mes, "acumulado": 0, "ultimo": 0, "frenado": False}
            elif u.get("mes") != mes:
                # Mes nuevo: se parte de lo que marcan ahora (lo anterior era del mes pasado).
                u = {"mes": mes, "acumulado": 0, "ultimo": actual, "frenado": False}
            delta = actual - u.get("ultimo", 0)
            u["acumulado"] += delta if delta >= 0 else actual   # contador reiniciado: se suma lo nuevo
            u["ultimo"] = actual
            gb = u["acumulado"] / 1e9
            debe_frenar = gb >= self.limite_gb
            if debe_frenar != u.get("frenado", False):
                self.sistema.reenvio(not debe_frenar)
                u["frenado"] = debe_frenar
            self._escribir("uso.json", u)
        return {"mes": u["mes"], "usado_gb": round(gb, 2), "limite_gb": self.limite_gb, "frenado": u["frenado"]}

    def salud(self) -> dict:
        cfg = self.config()
        return {"ok": True, "version": VERSION, "region": cfg.get("region"), "endpoint": cfg.get("endpoint"),
                "clave_publica_servidor": cfg.get("clave_publica"), "dispositivos": len(self.peers()),
                "consumo": self.medir_consumo()}


# ─────────────────────────── API HTTPS (FastAPI)
try:  # FastAPI solo hace falta para servir la API (las pruebas de la lógica no lo necesitan)
    from fastapi import FastAPI, Header, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field

    class AltaIn(BaseModel):
        clave_publica: str = Field(min_length=44, max_length=44)
        nombre: str | None = Field(None, max_length=40)
except ImportError:  # pragma: no cover
    FastAPI = None


def crear_app(agente: Agente | None = None):
    ag = agente or Agente()
    app = FastAPI(title="GuardianIA VPN", docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(ErrorVpn)
    def _err(_: Request, e: ErrorVpn):
        return JSONResponse({"error": str(e)}, status_code=e.codigo)

    def _auth(request: Request, authorization: str | None):
        ficha = authorization[7:] if authorization and authorization.startswith("Bearer ") else None
        ag.autorizar(ficha, request.client.host if request.client else "")

    @app.get("/salud")
    def salud(request: Request, authorization: str | None = Header(None)):
        _auth(request, authorization)
        return ag.salud()

    @app.post("/dispositivos")
    def alta(body: AltaIn, request: Request, authorization: str | None = Header(None)):
        _auth(request, authorization)
        return ag.alta(body.clave_publica, body.nombre)

    @app.delete("/dispositivos/{clave:path}")
    def baja(clave: str, request: Request, authorization: str | None = Header(None)):
        _auth(request, authorization)
        ag.baja(clave)
        return {"ok": True}

    @app.on_event("startup")
    def _inicio():
        try:
            ag.restaurar()
        except Exception:  # noqa: BLE001 - sin wg (pruebas) no hay nada que restaurar
            pass

        def vigilar():
            while True:
                try:
                    ag.medir_consumo()
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(300)
        threading.Thread(target=vigilar, daemon=True).start()

    return app


if __name__ == "__main__":
    import uvicorn
    cfg = Agente().config()
    # Sin registro de accesos: ni IPs ni rutas (política sin registros).
    uvicorn.run(crear_app(), host="0.0.0.0", port=int(cfg.get("puerto_api", 8844)), access_log=False,
                log_level="warning", ssl_certfile=str(DIR / "api.crt"), ssl_keyfile=str(DIR / "api.key"))
