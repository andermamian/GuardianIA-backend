#!/usr/bin/env python3
"""GuardianIA â€” Agente de protecciÃ³n del equipo.

Es el componente que sÃ­ puede tocar el disco: analiza unidades completas, vigila en tiempo real y
pone en cuarentena. Corre como servicio del sistema (SYSTEM en Windows, root en Linux).

    python guardian_agent.py registrar --servidor https://127.0.0.1:8443 --token <token-del-dispositivo>
    python guardian_agent.py escanear --modo completo
    python guardian_agent.py servicio          # vigilancia en tiempo real + tareas del servidor
    python guardian_agent.py estado

Sin dependencias externas: solo biblioteca estÃ¡ndar. Un antivirus que exige instalar medio ecosistema
para arrancar es un antivirus que nadie instala.

â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Decisiones de seguridad â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

* **Lista cerrada de tareas.** Del servidor solo se aceptan: escanear, restaurar y eliminar de la
  cuarentena. Cualquier otra cosa se descarta y se registra. No existe Â«ejecuta este comandoÂ»: si
  alguien compromete el servidor, no obtiene ejecuciÃ³n remota en los equipos.
* **La cuarentena no es una carpeta con los virus dentro.** Cada archivo se cifra con XOR de clave
  larga derivada del equipo y se guarda con extensiÃ³n inerte, permisos 600 y sin bit de ejecuciÃ³n.
  No es criptografÃ­a fuerte y no pretende serlo: su objetivo es que ningÃºn otro antivirus, indexador
  o doble clic pueda ejecutar o restaurar eso por accidente.
* **Nunca se toca el sistema operativo.** Hay una lista de rutas prohibidas (Windows\\System32,
  /boot, /procâ€¦) que el agente se niega a aislar aunque el servidor lo pida: un falso positivo sobre
  un archivo del sistema deja el equipo sin arrancar, y eso es peor que el malware.
* **Solo se aÃ­sla lo malicioso.** Lo sospechoso se reporta y se deja quieto.
* **Rendimiento primero.** Prioriza por riesgo, salta lo que no cambiÃ³ desde el Ãºltimo anÃ¡lisis y
  cede CPU: un antivirus que vuelve lento el equipo termina desinstalado, y entonces no protege nada.
"""
from __future__ import annotations

import argparse
import ctypes
import getpass
import hashlib
import json
import math
import os
import platform
import shutil
import socket
import stat
import subprocess
import sys
import time
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
TAREAS_PERMITIDAS = {"escanear", "restaurar", "eliminar", "vpn_conectar", "vpn_desconectar"}

# Rutas que el agente no toca jamÃ¡s: aislar algo de aquÃ­ deja el equipo sin arrancar.
INTOCABLES = [
    "c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\winsxs", "c:\\windows\\boot",
    "c:\\program files\\windowsapps", "/boot", "/proc", "/sys", "/dev", "/bin", "/sbin", "/usr/bin",
    "/usr/sbin", "/lib", "/usr/lib", "/system", "/etc/passwd", "/etc/shadow",
]
# Lo que un atacante necesita que se ejecute. Se revisa primero: el orden importa cuando hay prisa.
EXT_RIESGO = {".exe": 10, ".dll": 9, ".scr": 10, ".com": 9, ".pif": 9, ".bat": 8, ".cmd": 8, ".ps1": 8,
              ".vbs": 8, ".js": 7, ".jse": 8, ".wsf": 8, ".hta": 9, ".jar": 7, ".apk": 7, ".msi": 7,
              ".lnk": 6, ".docm": 6, ".xlsm": 6, ".pptm": 6, ".iso": 5, ".img": 5, ".zip": 4,
              ".rar": 4, ".7z": 4, ".pdf": 3, ".doc": 3, ".xls": 3}
CARPETAS_CALIENTES = ("downloads", "descargas", "temp", "tmp", "appdata\\local\\temp", "desktop",
                      "escritorio", "documents", "documentos", "startup", "inicio")
MAX_BYTES = 256 * 1024 * 1024
LOTE = 200


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• utilidades
def es_administrador() -> bool:
    """Â¿Tenemos privilegios para leer todo el disco y escribir en la cuarentena del sistema?"""
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


def carpeta_datos() -> Path:
    """Cuarentena y estado. Con privilegios va a una ruta del sistema que el usuario no puede alterar."""
    if os.name == "nt":
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "GuardianIA"
    else:
        base = Path("/var/lib/guardiania") if es_administrador() else Path.home() / ".guardiania"
    base.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    return base


def _clave_equipo() -> bytes:
    """Clave local para la cuarentena. No protege del dueÃ±o del equipo (no puede), sino de que el
    archivo sea ejecutable o lo restaure otro programa por accidente."""
    semilla = f"{platform.node()}|{platform.machine()}|guardiania-cuarentena-v1"
    return hashlib.sha256(semilla.encode()).digest()


def _cifrar(datos: bytes) -> bytes:
    clave = _clave_equipo()
    largo = len(clave)
    return bytes(b ^ clave[i % largo] for i, b in enumerate(datos))


_descifrar = _cifrar   # XOR es simÃ©trico


def unidades() -> list[Path]:
    """Discos y memorias conectadas, incluidas las USB."""
    encontradas: list[Path] = []
    if os.name == "nt":
        import string
        bits = ctypes.windll.kernel32.GetLogicalDrives()
        for i, letra in enumerate(string.ascii_uppercase):
            if bits & (1 << i):
                raiz = Path(f"{letra}:\\")
                tipo = ctypes.windll.kernel32.GetDriveTypeW(str(raiz))
                if tipo in (2, 3, 6):   # extraÃ­ble, fijo, disco RAM; se excluyen CD y unidades de red
                    encontradas.append(raiz)
    else:
        encontradas.append(Path("/"))
        for punto in ("/media", "/mnt", "/run/media", "/Volumes"):
            p = Path(punto)
            if p.exists():
                encontradas.extend(x for x in p.iterdir() if x.is_dir())
    return encontradas


def carpetas_rapidas() -> list[Path]:
    """DÃ³nde aparece el malware en la prÃ¡ctica: descargas, temporales, escritorio y arranque."""
    casa = Path.home()
    candidatas = [casa / "Downloads", casa / "Descargas", casa / "Desktop", casa / "Escritorio",
                  casa / "Documents", casa / "Documentos", Path(os.environ.get("TEMP", "/tmp"))]
    if os.name == "nt":
        appdata = Path(os.environ.get("APPDATA", ""))
        if appdata.name:
            candidatas += [appdata / "Microsoft/Windows/Start Menu/Programs/Startup",
                           appdata.parent / "Local/Temp"]
    return [c for c in candidatas if c.exists()]


def intocable(ruta: Path) -> bool:
    texto = str(ruta).lower().replace("/", os.sep).replace("\\", os.sep)
    return any(texto.startswith(p.replace("/", os.sep).replace("\\", os.sep)) for p in INTOCABLES)


def prioridad(ruta: Path, tamano: int) -> int:
    """Riesgo a priori del archivo. Con esto se revisa primero lo que mÃ¡s importa.

    No es un modelo entrenado: es conocimiento del dominio puesto en nÃºmeros. Lo ejecutable pesa mÃ¡s
    que un documento, lo que estÃ¡ en Descargas mÃ¡s que lo que lleva aÃ±os en una carpeta de fotos, y
    lo reciÃ©n modificado mÃ¡s que lo antiguo. AsÃ­, aunque el anÃ¡lisis se corte, ya revisÃ³ lo crÃ­tico.
    """
    puntos = EXT_RIESGO.get(ruta.suffix.lower(), 1)
    padre = str(ruta.parent).lower()
    if any(c in padre for c in CARPETAS_CALIENTES):
        puntos += 4
    try:
        edad_dias = (time.time() - ruta.stat().st_mtime) / 86400
        if edad_dias < 7:
            puntos += 3
        elif edad_dias < 30:
            puntos += 1
    except OSError:
        pass
    if tamano < 8 * 1024 * 1024:     # el malware suele ser pequeÃ±o
        puntos += 1
    return puntos


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• rasgos del archivo
MAGIC = [(b"MZ", "pe"), (b"\x7fELF", "elf"), (b"%PDF", "pdf"), (b"PK\x03\x04", "zip"),
         (b"\xd0\xcf\x11\xe0", "office")]


def entropia(datos: bytes) -> float:
    if not datos:
        return 0.0
    conteo = [0] * 256
    for b in datos:
        conteo[b] += 1
    total = len(datos)
    return min(8.0, round(-sum((c / total) * math.log2(c / total) for c in conteo if c), 3))


def cadenas(datos: bytes, minimo: int = 6, maximo: int = 300) -> list[str]:
    salida, actual = [], bytearray()
    for b in datos:
        if 32 <= b < 127:
            actual.append(b)
            continue
        if len(actual) >= minimo:
            salida.append(actual.decode("ascii", "ignore")[:200])
            if len(salida) >= maximo:
                return salida
        actual.clear()
    if len(actual) >= minimo and len(salida) < maximo:
        salida.append(actual.decode("ascii", "ignore")[:200])
    return salida


def rasgos(ruta: Path) -> dict | None:
    """Extrae del archivo lo que el motor necesita. El archivo nunca sale del equipo."""
    try:
        tamano = ruta.stat().st_size
        if tamano == 0 or tamano > MAX_BYTES:
            return None
        sha = hashlib.sha256()
        with open(ruta, "rb") as fh:
            cabecera = fh.read(65536)
            sha.update(cabecera)
            while bloque := fh.read(1024 * 1024):
                sha.update(bloque)
        clase = "unknown"
        for firma, nombre in MAGIC:
            if cabecera.startswith(firma):
                clase = nombre
                break
        if clase == "zip" and ruta.suffix.lower() == ".apk":
            clase = "apk"
        if clase == "unknown" and ruta.suffix.lower() in (".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh"):
            clase = "script"
        return {"name": ruta.name[:260], "size": tamano, "sha256": sha.hexdigest(), "kind": clase,
                "header_hex": cabecera[:64].hex(), "strings": cadenas(cabecera[:262144]),
                "entropy": entropia(cabecera[:262144])}
    except (OSError, PermissionError):
        return None


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• cliente HTTP
SERVIDOR_POR_DEFECTO = "https://127.0.0.1:8443"
# Direcciones con las que se registraban los agentes antes de pasar a HTTPS.
_ANTIGUOS = ("http://127.0.0.1:8000", "http://localhost:8000")


def buscar_ca() -> str | None:
    """CA local de GuardianIA (data/certs/ca.crt del proyecto), si el agente corre junto al servidor."""
    for base in (Path(__file__).resolve().parent.parent, Path.cwd()):
        ruta = base / "data" / "certs" / "ca.crt"
        if ruta.is_file():
            return ruta.read_text("ascii")
    return None


def contexto_tls(ca_pem: str | None) -> ssl.SSLContext:
    """Con la CA de GuardianIA: se confÃ­a SOLO en ella (pinning). Un certificado falso emitido por
    cualquier otra autoridad, aunque el sistema confÃ­e en ella, se rechaza. Sin CA: las del sistema."""
    ctx = ssl.create_default_context(cadata=ca_pem) if ca_pem else ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class Servidor:
    def __init__(self, base: str, token: str, timeout: float = 45.0, ca_pem: str | None = None,
                 al_mudarse=None):
        self.base = base.rstrip("/")
        u = urllib.parse.urlsplit(self.base)
        # El token del dispositivo viaja en cada peticiÃ³n: por http solo se permite dentro del propio PC.
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("DirecciÃ³n del servidor no vÃ¡lida (use https://IP:8443)")
        if u.scheme == "http" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("Por http el token viajarÃ­a sin cifrar por la red: use https://")
        self.token = token
        self.timeout = timeout
        self.ca_pem = ca_pem
        self.al_mudarse = al_mudarse        # se llama con la nueva base si el servidor redirige a https
        self._ctx = contexto_tls(ca_pem)

    def post(self, ruta: str, cuerpo: dict, _intentos: int = 2) -> dict:
        datos = json.dumps({**cuerpo, "device_token": self.token}).encode()
        pedido = urllib.request.Request(f"{self.base}/v1{ruta}", data=datos, method="POST",
                                        headers={"Content-Type": "application/json",
                                                 "User-Agent": f"GuardianIA-Agent/{VERSION}"})
        try:
            with urllib.request.urlopen(pedido, timeout=self.timeout,
                                        context=self._ctx if self.base.startswith("https") else None) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            destino = e.headers.get("Location", "") if e.code in (301, 307, 308) else ""
            if destino.startswith("https://") and _intentos > 0:
                # El servidor pasÃ³ a HTTPS: urllib no reenvÃ­a un POST redirigido, asÃ­ que se hace aquÃ­,
                # solo hacia https y solo al mismo equipo, y se recuerda la direcciÃ³n nueva.
                nuevo = urllib.parse.urlsplit(destino)
                viejo = urllib.parse.urlsplit(self.base)
                if nuevo.hostname == viejo.hostname:
                    self.base = f"https://{nuevo.netloc}"
                    if self.al_mudarse:
                        self.al_mudarse(self.base)
                    return self.post(ruta, cuerpo, _intentos - 1)
            try:
                detalle = json.loads(e.read() or b"{}")
            except ValueError:
                detalle = {}
            raise RuntimeError(f"{e.code} {detalle.get('title', '')} {detalle.get('code', '')}".strip()) from e
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                raise RuntimeError("El certificado del servidor no es el de GuardianIA de este equipo. Si "
                                   "regenerÃ³ la CA, registre de nuevo el agente.") from e
            raise RuntimeError(f"Sin conexiÃ³n con el servidor: {e.reason}") from e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• tÃºnel VPN
class Tunel:
    """Levanta y baja el tÃºnel WireGuard con privilegios.

    La clave privada se genera aquÃ­ y NUNCA sale del equipo: al servidor solo va la pÃºblica. Eso es
    lo que hace que ni siquiera quien opere GuardianIA pueda descifrar el trÃ¡fico de un usuario.
    """

    INTERFAZ = "guardiania"

    def __init__(self):
        self.dir = carpeta_datos() / "vpn"
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    # WireGuard para Windows no agrega su carpeta al PATH. Trae dos programas: wireguard.exe, que
    # gestiona los tÃºneles como servicio, y wg.exe, con las utilidades (entre ellas generar claves).
    # Usar wg.exe evita depender de la librerÃ­a Â«cryptographyÂ», que tarda en tener versiÃ³n para los
    # Python mÃ¡s nuevos: con Python 3.14 todavÃ­a no la hay.
    CARPETAS_WINDOWS = (r"C:\Program Files\WireGuard", r"C:\Program Files (x86)\WireGuard")

    @staticmethod
    def _buscar(nombre: str) -> str | None:
        ruta = shutil.which(nombre)
        if ruta:
            return ruta
        if os.name == "nt":
            # os.path y no pathlib: pathlib elige la clase segÃºn el sistema y aquÃ­ solo se arma
            # una ruta de texto.
            for carpeta in Tunel.CARPETAS_WINDOWS:
                candidato = os.path.join(carpeta, f"{nombre}.exe")
                if os.path.exists(candidato):
                    return candidato
        return None

    @staticmethod
    def disponible() -> str | None:
        """Programa que levanta tÃºneles: wg-quick en Linux/Mac, wireguard.exe en Windows."""
        return Tunel._buscar("wg-quick") or Tunel._buscar("wireguard") or Tunel._buscar("wg")

    def _claves(self) -> tuple[str, str]:
        """Devuelve (privada, pÃºblica). Se reutilizan entre conexiones: la IP del tÃºnel es estable."""
        archivo = self.dir / "claves.json"
        if archivo.exists():
            datos = json.loads(archivo.read_text("utf-8"))
            return datos["privada"], datos["publica"]
        wg = Tunel._buscar("wg")
        if wg:
            privada = subprocess.run([wg, "genkey"], capture_output=True, text=True, check=True).stdout.strip()
            publica = subprocess.run([wg, "pubkey"], input=privada, capture_output=True, text=True,
                                     check=True).stdout.strip()
        else:
            # Sin el binario wg (caso tÃ­pico en Windows antes de instalarlo): se generan con la
            # misma curva (X25519) usando la biblioteca estÃ¡ndar del sistema si estÃ¡ disponible.
            privada, publica = _claves_x25519()
        archivo.write_text(json.dumps({"privada": privada, "publica": publica}), "utf-8")
        try:
            os.chmod(archivo, 0o600)
        except OSError:
            pass
        return privada, publica

    @property
    def publica(self) -> str:
        return self._claves()[1]

    def conectar(self, config: dict) -> tuple[bool, str]:
        programa = self.disponible()
        if not programa:
            return False, ("WireGuard no estÃ¡ instalado. DescÃ¡rguelo de https://www.wireguard.com/install/ "
                           "(en Windows queda en C:\\Program Files\\WireGuard).")
        privada, _ = self._claves()
        interfaz, par = config["interfaz"], config["par"]
        texto = ("[Interface]\n"
                 f"PrivateKey = {privada}\n"
                 f"Address = {interfaz['Address']}\n"
                 f"DNS = {interfaz['DNS']}\n\n"
                 "[Peer]\n"
                 f"PublicKey = {par['PublicKey']}\n"
                 f"Endpoint = {par['Endpoint']}\n"
                 f"AllowedIPs = {par['AllowedIPs']}\n"
                 f"PersistentKeepalive = {par['PersistentKeepalive']}\n")
        archivo = self.dir / f"{self.INTERFAZ}.conf"
        archivo.write_text(texto, "utf-8")
        try:
            os.chmod(archivo, 0o600)   # la clave privada estÃ¡ dentro: nadie mÃ¡s debe leerla
        except OSError:
            pass
        try:
            if programa.endswith("wireguard.exe"):
                cmd = [programa, "/installtunnelservice", str(archivo)]
            else:
                cmd = ["sudo", "-n", programa, "up", str(archivo)] if os.geteuid() != 0 else [programa, "up", str(archivo)]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if r.returncode:
                return False, (r.stderr or r.stdout)[-200:]
        except (OSError, subprocess.SubprocessError) as e:
            return False, str(e)[:200]
        return True, "TÃºnel levantado"

    def desconectar(self) -> tuple[bool, str]:
        programa = self.disponible()
        if not programa:
            return False, "WireGuard no estÃ¡ instalado"
        archivo = self.dir / f"{self.INTERFAZ}.conf"
        try:
            if programa.endswith("wireguard.exe"):
                cmd = [programa, "/uninstalltunnelservice", self.INTERFAZ]
            else:
                cmd = ["sudo", "-n", programa, "down", str(archivo)] if os.geteuid() != 0 else [programa, "down", str(archivo)]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return r.returncode == 0, (r.stderr or "TÃºnel cerrado")[-200:]
        except (OSError, subprocess.SubprocessError) as e:
            return False, str(e)[:200]

    @staticmethod
    def ip_publica() -> str | None:
        """La prueba de fuego: con el tÃºnel arriba, esta IP debe ser la del servidor."""
        for servicio in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
            try:
                with urllib.request.urlopen(servicio, timeout=8) as r:
                    ip = r.read().decode().strip()
                    if ip.count(".") == 3 or ":" in ip:
                        return ip
            except Exception:  # noqa: BLE001 - se prueba el siguiente servicio
                continue
        return None


def _claves_x25519() -> tuple[str, str]:
    """Genera un par WireGuard sin el binario wg, usando la curva X25519."""
    import base64
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (Encoding, NoEncryption, PrivateFormat,
                                                                  PublicFormat)
    except ImportError as e:
        raise RuntimeError(
            "No encontrÃ© wg.exe ni la librerÃ­a Â«cryptographyÂ» para generar las claves.\n"
            "  OpciÃ³n 1 (recomendada): instale WireGuard desde https://www.wireguard.com/install/\n"
            "    Trae wg.exe y no hace falta nada mÃ¡s.\n"
            f"  OpciÃ³n 2: {sys.executable} -m pip install cryptography") from e
    priv = X25519PrivateKey.generate()
    privada = base64.b64encode(priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    publica = base64.b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    return privada, publica


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• cuarentena
class Cuarentena:
    def __init__(self):
        self.dir = carpeta_datos() / "cuarentena"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.indice = carpeta_datos() / "cuarentena.json"

    def _leer(self) -> dict:
        try:
            return json.loads(self.indice.read_text("utf-8"))
        except (OSError, ValueError):
            return {}

    def _guardar(self, datos: dict) -> None:
        tmp = self.indice.with_suffix(".tmp")
        tmp.write_text(json.dumps(datos, ensure_ascii=False, indent=1), "utf-8")
        os.replace(tmp, self.indice)

    def aislar(self, ruta: Path, sha: str) -> dict | None:
        """Mueve el archivo a la cuarentena, cifrado e inerte. Devuelve el registro o None."""
        if intocable(ruta):
            print(f"  [!] {ruta} estÃ¡ en una ruta protegida del sistema: NO se aÃ­sla")
            return None
        try:
            datos = ruta.read_bytes()
            destino = self.dir / f"{sha}.qtn"
            destino.write_bytes(_cifrar(datos))
            os.chmod(destino, stat.S_IRUSR | stat.S_IWUSR)   # 600: ni ejecuciÃ³n ni acceso de otros
            ruta.unlink()
        except (OSError, PermissionError) as e:
            print(f"  [!] No se pudo aislar {ruta}: {e}")
            return None
        indice = self._leer()
        indice[sha] = {"archivo": ruta.name, "ruta_original": str(ruta), "bytes": len(datos),
                       "aislado": datetime.now(timezone.utc).isoformat()}
        self._guardar(indice)
        return indice[sha]

    def restaurar(self, sha: str) -> tuple[bool, str]:
        indice = self._leer()
        registro = indice.get(sha)
        if not registro:
            return False, "No estÃ¡ en la cuarentena de este equipo"
        origen = self.dir / f"{sha}.qtn"
        destino = Path(registro["ruta_original"])
        try:
            destino.parent.mkdir(parents=True, exist_ok=True)
            destino.write_bytes(_descifrar(origen.read_bytes()))
            origen.unlink(missing_ok=True)
        except (OSError, PermissionError) as e:
            return False, str(e)[:180]
        indice.pop(sha, None)
        self._guardar(indice)
        return True, f"Restaurado en {destino}"

    def eliminar(self, sha: str) -> tuple[bool, str]:
        indice = self._leer()
        archivo = self.dir / f"{sha}.qtn"
        try:
            if archivo.exists():
                # Se sobrescribe antes de borrar: en discos mecÃ¡nicos evita recuperaciones triviales.
                tamano = archivo.stat().st_size
                with open(archivo, "r+b") as fh:
                    fh.write(os.urandom(min(tamano, 1024 * 1024)))
                    fh.flush()
                    os.fsync(fh.fileno())
                archivo.unlink()
        except (OSError, PermissionError) as e:
            return False, str(e)[:180]
        indice.pop(sha, None)
        self._guardar(indice)
        return True, "Eliminado definitivamente"

    def listar(self) -> dict:
        return self._leer()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• el agente
class Agente:
    def __init__(self, config: dict, modo_rendimiento: str = "auto"):
        self.config = config
        self.servidor = Servidor(config["servidor"], config["token"], ca_pem=config.get("ca_pem"),
                                 al_mudarse=lambda base: guardar_servidor(config, base))
        self.cuarentena = Cuarentena()
        self.politica = config.get("politica", {})
        self.cache = self._cargar_cache()
        self.ritmo = Ritmo(modo_rendimiento)
        self.progreso: dict = {}

    # â”€â”€ memoria de lo ya analizado: lo que no cambiÃ³ no se vuelve a leer
    def _cargar_cache(self) -> dict:
        try:
            return json.loads((carpeta_datos() / "analizados.json").read_text("utf-8"))
        except (OSError, ValueError):
            return {}

    def _guardar_cache(self) -> None:
        try:
            recorte = dict(list(self.cache.items())[-200000:])   # no crecer sin lÃ­mite
            (carpeta_datos() / "analizados.json").write_text(json.dumps(recorte), "utf-8")
        except OSError:
            pass

    def _sin_cambios(self, ruta: Path) -> bool:
        try:
            st = ruta.stat()
            huella = f"{st.st_mtime_ns}:{st.st_size}"
        except OSError:
            return False
        return self.cache.get(str(ruta)) == huella

    def _marcar(self, ruta: Path) -> None:
        try:
            st = ruta.stat()
            self.cache[str(ruta)] = f"{st.st_mtime_ns}:{st.st_size}"
        except OSError:
            pass

    # â”€â”€ recorrido
    def recolectar(self, raices: list[Path], limite: int) -> list[tuple[int, Path]]:
        """Recorre y ordena por riesgo. Devuelve los mÃ¡s prioritarios hasta el lÃ­mite."""
        candidatos: list[tuple[int, Path]] = []
        vistos = 0
        for raiz in raices:
            for carpeta, subcarpetas, archivos in os.walk(raiz, onerror=lambda e: None):
                if intocable(Path(carpeta)):
                    subcarpetas[:] = []
                    continue
                subcarpetas[:] = [s for s in subcarpetas if not intocable(Path(carpeta) / s)]
                for nombre in archivos:
                    ruta = Path(carpeta) / nombre
                    vistos += 1
                    if self._sin_cambios(ruta):
                        continue
                    try:
                        tamano = ruta.stat().st_size
                    except OSError:
                        continue
                    if tamano == 0 or tamano > MAX_BYTES:
                        continue
                    candidatos.append((prioridad(ruta, tamano), ruta))
                if vistos > 400000:
                    break
        candidatos.sort(key=lambda x: -x[0])
        return candidatos[:limite]

    # â”€â”€ anÃ¡lisis
    def escanear(self, modo: str = "rapido", ruta: str | None = None, limite: int = 4000) -> dict:
        inicio = time.perf_counter()
        if modo == "completo":
            raices = unidades()
        elif modo == "personalizado" and ruta:
            raices = [Path(ruta)]
        else:
            raices = carpetas_rapidas()
        print(f"AnÃ¡lisis {modo} en: {', '.join(str(r) for r in raices)}")
        if modo == "completo" and not es_administrador():
            print("[!] Sin privilegios de administrador: se omitirÃ¡n carpetas de otros usuarios y del sistema.")

        candidatos = self.recolectar(raices, limite)
        print(f"{len(candidatos)} archivos por revisar (los de mayor riesgo primero)")

        revisados = omitidos = aislados = 0
        amenazas: list[dict] = []
        lote: list[dict] = []
        rutas: dict[str, Path] = {}

        print(f"Ritmo: {self.ritmo.modo} Â· {self.ritmo.hilos} hilos de {self.ritmo.nucleos} disponibles")
        with ThreadPoolExecutor(max_workers=self.ritmo.hilos) as pool:
            for (_, archivo), datos in zip(candidatos, pool.map(rasgos, [c[1] for c in candidatos])):
                if datos is None:
                    omitidos += 1
                    continue
                revisados += 1
                rutas[datos["sha256"]] = archivo
                lote.append({"archivo": datos, "ruta": str(archivo)[:400]})
                self._marcar(archivo)
                if len(lote) >= LOTE:
                    aislados += self._enviar(lote, rutas, modo, amenazas, revisados, omitidos, inicio)
                    lote = []
                if revisados % 100 == 0:
                    # El progreso viaja en el siguiente latido: la web lo muestra sin que nadie mire
                    # la terminal.
                    self.progreso = {"modo": modo, "revisados": revisados, "total": len(candidatos),
                                     "actual": archivo.name[:60], "estado": "analizando"}
                    if revisados % 500 == 0:
                        print(f"  â€¦ {revisados} revisados")
                self.ritmo.ajustar()
                if self.ritmo.pausa:
                    time.sleep(self.ritmo.pausa)   # el equipo sigue usable durante el anÃ¡lisis

        if lote:
            aislados += self._enviar(lote, rutas, modo, amenazas, revisados, omitidos, inicio, final=True)
        else:
            self._enviar([], rutas, modo, amenazas, revisados, omitidos, inicio, final=True)
        self._guardar_cache()
        self.progreso = {}
        duracion = time.perf_counter() - inicio
        print(f"\nListo: {revisados} archivos en {duracion:.1f} s Â· {len(amenazas)} amenazas Â· "
              f"{aislados} en cuarentena")
        for a in amenazas[:10]:
            print(f"  - {a['nivel'].upper()}: {rutas.get(a['sha256'], a['sha256'])} ({a.get('familia') or 'sin familia'})")
        return {"revisados": revisados, "amenazas": len(amenazas), "aislados": aislados,
                "duracion_s": round(duracion, 1)}

    def _enviar(self, lote: list[dict], rutas: dict, modo: str, amenazas: list, revisados: int,
                omitidos: int, inicio: float, final: bool = False) -> int:
        try:
            respuesta = self.servidor.post("/agente/escaneo", {
                "tipo": modo if modo in ("rapido", "completo", "personalizado") else "tiempo_real",
                "final": final,
                "archivos_revisados": revisados, "archivos_omitidos": omitidos,
                "duracion_ms": int((time.perf_counter() - inicio) * 1000), "candidatos": lote})
        except RuntimeError as e:
            print(f"  [!] No se pudo consultar al servidor: {e}")
            return 0
        aislados = 0
        pendientes = []
        for v in respuesta.get("veredictos", []):
            amenazas.append(v)
            archivo = rutas.get(v["sha256"])
            if v.get("accion") == "aislar" and archivo and archivo.exists():
                registro = self.cuarentena.aislar(archivo, v["sha256"])
                if registro:
                    aislados += 1
                    pendientes.append({"sha256": v["sha256"], "filename": registro["archivo"],
                                       "ruta_original": registro["ruta_original"][:400],
                                       "size_bytes": registro["bytes"], "nivel": v["nivel"],
                                       "familia": v.get("familia"), "motivos": v.get("motivos", [])[:6]})
        if pendientes:
            try:
                self.servidor.post("/agente/cuarentena", {"items": pendientes})
            except RuntimeError as e:
                print(f"  [!] Aislado localmente, pero no se pudo informar al servidor: {e}")
        return aislados

    # â”€â”€ tareas del servidor (lista cerrada)
    def ejecutar_tarea(self, tarea: dict) -> None:
        tipo = tarea.get("tipo")
        if tipo not in TAREAS_PERMITIDAS:
            print(f"[!] Tarea no permitida, ignorada: {tipo!r}")   # aquÃ­ se corta cualquier abuso
            return
        if tipo == "escanear":
            self.escanear(tarea.get("modo", "rapido"), tarea.get("ruta"))
            return
        if tipo in ("vpn_conectar", "vpn_desconectar"):
            self._tarea_vpn(tipo, tarea)
            return
        sha, id_ = tarea.get("sha256", ""), tarea.get("cuarentena_id", "")
        ok, detalle = (self.cuarentena.restaurar(sha) if tipo == "restaurar"
                       else self.cuarentena.eliminar(sha))
        print(f"{'âœ“' if ok else 'âœ—'} {tipo}: {detalle}")
        estado = {"restaurar": "restaurado", "eliminar": "eliminado"}[tipo] if ok else "error"
        try:
            self.servidor.post("/agente/cuarentena/resultado",
                               {"cuarentena_id": id_, "estado": estado, "detalle": None if ok else detalle})
        except RuntimeError as e:
            print(f"  [!] No se pudo informar el resultado: {e}")

    # â”€â”€ tÃºnel VPN
    def _tarea_vpn(self, tipo: str, tarea: dict) -> None:
        tunel = Tunel()
        if tipo == "vpn_desconectar":
            ok, detalle = tunel.desconectar()
            print(f"{'âœ“' if ok else 'âœ—'} VPN desconectada: {detalle}")
            return
        config = tarea.get("config")
        if not config and tarea.get("registrar_en"):
            # Primera vez con este servidor: se genera el par de claves aquÃ­ y se registra la pÃºblica.
            try:
                config = self.servidor.post("/agente/vpn/peer", {"server_id": tarea["registrar_en"],
                                                                 "public_key": tunel.publica})
                print(f"  Clave pÃºblica registrada Â· IP en el tÃºnel: {config['interfaz']['Address']}")
            except RuntimeError as e:
                print(f"[!] No se pudo registrar la clave: {e}")
                return
        if not config:
            print("[!] El servidor no enviÃ³ configuraciÃ³n de tÃºnel")
            return
        previa = tunel.ip_publica()
        ok, detalle = tunel.conectar(config)
        print(f"{'âœ“' if ok else 'âœ—'} VPN: {detalle}")
        if not ok:
            return
        time.sleep(3)   # el handshake tarda un momento
        ip = tunel.ip_publica()
        cambio = bool(ip and previa and ip != previa)
        print(f"  IP pÃºblica: {previa or '?'} â†’ {ip or '?'}"
              + ("  âœ“ el trÃ¡fico sale por el tÃºnel" if cambio else "  âœ— NO cambiÃ³: el tÃºnel no estÃ¡ enrutando"))
        if tarea.get("sesion_id"):
            try:
                self.servidor.post("/agente/vpn/estado", {
                    "sesion_id": tarea["sesion_id"], "ip_salida": ip, "ip_previa": previa,
                    "estado": "conectada" if cambio else "error",
                    "motivo": None if cambio else "la IP pÃºblica no cambiÃ³"})
            except RuntimeError as e:
                print(f"  [!] No se pudo informar el estado: {e}")

    # â”€â”€ vigilancia en tiempo real
    def servicio(self) -> None:
        """Vigilancia continua, anÃ¡lisis programados y tareas del servidor.

        AsÃ­ funciona un antivirus de verdad: nadie ejecuta nada. El servicio arranca con Windows,
        vigila los archivos nuevos, hace un anÃ¡lisis rÃ¡pido cada pocas horas y uno completo cada
        semana, en momentos en que el equipo estÃ¡ ocioso para no molestar.
        """
        print(f"Servicio activo. Latido cada {self.config.get('latido', 60)} s. Ctrl+C para detener.")
        vigiladas = carpetas_rapidas()
        conocidos: dict[str, float] = {}
        for carpeta in vigiladas:
            for ruta in carpeta.glob("*"):
                if ruta.is_file():
                    conocidos[str(ruta)] = ruta.stat().st_mtime
        siguiente_latido = 0.0
        while True:
            try:
                if time.time() >= siguiente_latido:
                    siguiente_latido = time.time() + self._latido()
                self._programados()
                if self.politica.get("tiempo_real", True):
                    nuevos = []
                    for carpeta in vigiladas:
                        for ruta in carpeta.glob("*"):
                            if not ruta.is_file():
                                continue
                            try:
                                m = ruta.stat().st_mtime
                            except OSError:
                                continue
                            if conocidos.get(str(ruta)) != m:
                                conocidos[str(ruta)] = m
                                nuevos.append(ruta)
                    if nuevos:
                        print(f"[tiempo real] {len(nuevos)} archivo(s) nuevo(s) o modificado(s)")
                        self._revisar_ahora(nuevos[:50])
                time.sleep(5)
            except KeyboardInterrupt:
                print("\nServicio detenido.")
                return
            except Exception as e:  # noqa: BLE001 - un servicio no se cae por un error puntual
                print(f"[!] {type(e).__name__}: {e}")
                time.sleep(15)

    def _programados(self) -> None:
        """Â¿Toca anÃ¡lisis? Lo decide el agente con la polÃ­tica que trae del servidor."""
        ahora = time.time()
        horas = int(self.politica.get("auto_rapido_horas", 6) or 0)
        dias = int(self.politica.get("auto_completo_dias", 7) or 0)
        marcas = self._marcas()
        if "completo" not in marcas:
            # ReciÃ©n instalado: el rÃ¡pido corre enseguida, pero el completo se agenda para dentro de
            # un ciclo. Encadenar los dos el primer dÃ­a deja el equipo lento justo cuando la persona
            # acaba de instalar, y esa es la razÃ³n por la que la gente desinstala antivirus.
            marcas["completo"] = ahora
            self._marcas(marcas)
        if horas and ahora - marcas.get("rapido", 0) > horas * 3600:
            if _cpu() > 70:
                return          # el equipo estÃ¡ ocupado: se pospone al siguiente ciclo
            print("[automÃ¡tico] anÃ¡lisis rÃ¡pido programado")
            self.escanear("rapido", limite=1500)
            marcas["rapido"] = ahora
            self._marcas(marcas)
        elif dias and ahora - marcas.get("completo", 0) > dias * 86400:
            if _cpu() > 50:
                return          # el completo es largo: solo con el equipo tranquilo
            print("[automÃ¡tico] anÃ¡lisis completo programado")
            self.escanear("completo", limite=8000)
            marcas["completo"] = ahora
            self._marcas(marcas)

    def _marcas(self, nuevas: dict | None = None) -> dict:
        """CuÃ¡ndo se hizo cada anÃ¡lisis. En disco, para que sobreviva a un reinicio."""
        archivo = carpeta_datos() / "programados.json"
        if nuevas is not None:
            archivo.write_text(json.dumps(nuevas), "utf-8")
            return nuevas
        try:
            return json.loads(archivo.read_text("utf-8"))
        except (OSError, ValueError):
            return {}

    def _revisar_ahora(self, archivos: list[Path]) -> None:
        inicio = time.perf_counter()
        lote, rutas, amenazas = [], {}, []
        for archivo in archivos:
            datos = rasgos(archivo)
            if datos:
                rutas[datos["sha256"]] = archivo
                lote.append({"archivo": datos, "ruta": str(archivo)[:400]})
        if lote:
            self._enviar(lote, rutas, "tiempo_real", amenazas, len(lote), 0, inicio)

    def _latido(self) -> int:
        try:
            r = self.servidor.post("/agente/latido", {
                "cpu_percent": _cpu(), "archivos_protegidos": len(self.cache),
                "tiempo_real_activo": bool(self.politica.get("tiempo_real", True)),
                "progreso": self.progreso})
        except RuntimeError as e:
            print(f"[!] Latido fallido: {e}")
            return 60
        self.politica = r.get("politica", self.politica)
        for tarea in r.get("tareas", []):
            self.ejecutar_tarea(tarea)
        return int(r.get("intervalo_latido_s", 60))


def _cpu() -> float:
    """Uso de CPU del equipo, sin depender de psutil."""
    if os.name == "nt":
        try:
            salida = os.popen("wmic cpu get loadpercentage /value").read()
            for linea in salida.splitlines():
                if "LoadPercentage=" in linea:
                    return float(linea.split("=")[1])
        except Exception:  # noqa: BLE001
            return 0.0
        return 0.0
    try:
        return round(os.getloadavg()[0] / (os.cpu_count() or 1) * 100, 1)
    except (AttributeError, OSError):
        return 0.0


class Ritmo:
    """Adapta el esfuerzo a lo que estÃ© haciendo la persona.

    Un antivirus que vuelve lento el equipo termina desinstalado, y entonces no protege nada. AsÃ­
    que el agente mide la CPU cada pocos segundos y ajusta dos cosas: cuÃ¡ntos hilos usa y cuÃ¡nto
    descansa entre archivos. En un equipo ocioso aprovecha casi todos los nÃºcleos; si usted empieza
    a trabajar, se aparta solo.

    En su portÃ¡til (8 nÃºcleos / 16 hilos) eso significa hasta 8 hilos en reposo y 2 cuando estÃ¡
    ocupado, con pausas proporcionales.
    """

    def __init__(self, modo: str = "auto"):
        self.nucleos = os.cpu_count() or 4
        self.modo = modo
        self.hilos = self._hilos_base()
        self.pausa = 0.0
        self._ultima_medicion = 0.0

    def _hilos_base(self) -> int:
        if self.modo == "turbo":
            return max(2, self.nucleos - 1)       # el usuario pidiÃ³ velocidad: se le da
        if self.modo == "silencioso":
            return 2
        return max(2, self.nucleos // 2)

    def ajustar(self) -> None:
        if self.modo != "auto" or time.time() - self._ultima_medicion < 5:
            return
        self._ultima_medicion = time.time()
        uso = _cpu()
        if uso > 75:            # la persona estÃ¡ trabajando: apartarse
            self.hilos, self.pausa = 2, 0.02
        elif uso > 45:
            self.hilos, self.pausa = max(2, self.nucleos // 4), 0.005
        else:                   # equipo ocioso: aprovechar
            self.hilos, self.pausa = max(2, self.nucleos // 2), 0.0


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• CLI
def _fail(mensaje: str) -> None:
    """Termina con un mensaje entendible. Una traza de Python no le dice nada a quien instala."""
    print(f"âœ— {mensaje}", file=sys.stderr)
    sys.exit(1)


def ruta_config() -> Path:
    return carpeta_datos() / "agente.json"


def _escribir_config(config: dict) -> None:
    ruta_config().write_text(json.dumps(config, indent=1), "utf-8")
    try:
        os.chmod(ruta_config(), 0o600)   # el token es una credencial: no legible por otros usuarios
    except OSError:
        pass


def guardar_servidor(config: dict, base: str) -> None:
    config["servidor"] = base
    _escribir_config(config)
    print(f"  [i] Servidor actualizado a {base}")


def cargar_config() -> dict:
    try:
        config = json.loads(ruta_config().read_text("utf-8"))
    except (OSError, ValueError):
        print("El agente no estÃ¡ registrado. Ejecute primero:\n"
              f"  python guardian_agent.py registrar --servidor {SERVIDOR_POR_DEFECTO} --token <token>")
        sys.exit(1)
    # MigraciÃ³n a HTTPS: los agentes registrados contra http://127.0.0.1:8000 pasan solos al nuevo
    # puerto seguro y guardan la CA local para verificar el certificado.
    cambios = False
    if config.get("servidor", "").rstrip("/") in _ANTIGUOS:
        config["servidor"] = SERVIDOR_POR_DEFECTO
        cambios = True
    if config.get("servidor", "").startswith("https") and not config.get("ca_pem"):
        ca = buscar_ca()
        if ca:
            config["ca_pem"], cambios = ca, True
    if cambios:
        _escribir_config(config)
    return config


def _ca_de_args(args) -> str | None:
    """CA para verificar el HTTPS: la indicada con --ca, o la del proyecto si el agente estÃ¡ al lado."""
    if getattr(args, "ca", None):
        try:
            return Path(args.ca).read_text("ascii")
        except OSError as e:
            _fail(f"No se pudo leer la CA {args.ca}: {e}")
    return buscar_ca() if args.servidor.startswith("https") else None


def cmd_vincular(args) -> None:
    """Vincula este equipo con el cÃ³digo de 6 dÃ­gitos que muestra la app. Sin copiar tokens."""
    codigo = (args.codigo or input("CÃ³digo de 6 dÃ­gitos que muestra la app: ")).strip().replace(" ", "")
    if not (len(codigo) == 6 and codigo.isdigit()):
        _fail("El cÃ³digo son 6 dÃ­gitos. Lo genera en la app web, secciÃ³n Dispositivos.")
    servidor = Servidor(args.servidor, "", ca_pem=_ca_de_args(args))
    plataforma = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(platform.system(), "other")
    try:
        r = servidor.post("/devices/vinculacion/canjear", {
            "codigo": codigo, "nombre": args.nombre or socket.gethostname()[:80],
            "platform": plataforma, "model": platform.machine()[:80], "os_version": platform.release()[:40]})
    except RuntimeError as e:
        _fail(f"No se pudo vincular: {e}\n  El cÃ³digo vence a los 10 minutos: genere uno nuevo en la app.")
    print(f"âœ“ Equipo vinculado a la cuenta {r['usuario']} como Â«{r['nombre']}Â»")
    # Ya con el token, el agente se registra solo: la persona no vuelve a copiar nada.
    args.token = r["device_token"]
    cmd_registrar(args)


def cmd_registrar(args) -> None:
    token = args.token or getpass.getpass("Token del dispositivo (no se muestra): ").strip()
    ca_pem = _ca_de_args(args)
    servidor = Servidor(args.servidor, token, ca_pem=ca_pem,
                        al_mudarse=lambda base: setattr(args, "servidor", base))
    admin = es_administrador()
    try:
        r = servidor.post("/agente/registrar", {
            "hostname": socket.gethostname()[:120], "so": f"{platform.system()} {platform.release()}"[:60],
            "version": VERSION, "privilegios": admin})
    except RuntimeError as e:
        print(f"âœ— No se pudo registrar: {e}")
        sys.exit(1)
    config = {"servidor": args.servidor.rstrip("/"), "token": token, "agente_id": r["agente_id"],
              "politica": r.get("politica", {}), "latido": r.get("intervalo_latido_s", 60)}
    if ca_pem:
        config["ca_pem"] = ca_pem
    _escribir_config(config)
    print(f"âœ“ Agente registrado ({r['agente_id']})")
    print(f"  Privilegios de administrador: {'sÃ­' if admin else 'NO'}")
    if not admin:
        print("  â†’ Sin administrador solo se revisan sus carpetas. Para el disco completo, abra la"
              "\n    terminal como administrador y repita el registro.")
    print(f"  Datos y cuarentena en: {carpeta_datos()}")


def cmd_escanear(args) -> None:
    agente = Agente(cargar_config(), args.rendimiento)
    agente.escanear(args.modo, args.ruta, args.limite)


def cmd_servicio(args) -> None:
    Agente(cargar_config()).servicio()


def cmd_vpn(args) -> None:
    """Estado o desconexiÃ³n del tÃºnel desde la lÃ­nea de comandos."""
    cargar_config()   # valida que el agente estÃ© registrado
    tunel = Tunel()
    if args.accion == "estado":
        print(f"WireGuard instalado: {Tunel.disponible() or 'NO'}")
        print(f"Clave pÃºblica de este equipo: {tunel.publica}")
        print(f"IP pÃºblica actual: {Tunel.ip_publica() or 'no se pudo consultar'}")
        return
    if args.accion == "desconectar":
        ok, detalle = tunel.desconectar()
        print(f"{'âœ“' if ok else 'âœ—'} {detalle}")
        return
    print("Use la app web para elegir servidor y conectar: el agente recibe la orden en su latido.")


def cmd_estado(args) -> None:
    config = cargar_config()
    cuarentena = Cuarentena().listar()
    print(f"Servidor:     {config['servidor']}")
    print(f"Equipo:       {socket.gethostname()} Â· {platform.system()} {platform.release()}")
    print(f"Privilegios:  {'administrador' if es_administrador() else 'usuario normal'}")
    print(f"Unidades:     {', '.join(str(u) for u in unidades())}")
    print(f"Cuarentena:   {len(cuarentena)} archivo(s) en {carpeta_datos() / 'cuarentena'}")
    for sha, datos in list(cuarentena.items())[:10]:
        print(f"  - {datos['archivo']} ({datos['bytes']} bytes) desde {datos['ruta_original']}")
    libre = shutil.disk_usage(carpeta_datos()).free // (1024 ** 3)
    print(f"Espacio libre: {libre} GB")
    ritmo = Ritmo()
    print(f"Rendimiento:  {ritmo.nucleos} nÃºcleos Â· {ritmo.hilos} hilos en modo auto Â· CPU ahora {_cpu()} %")


def main() -> None:
    parser = argparse.ArgumentParser(prog="guardian_agent", description="Agente de protecciÃ³n GuardianIA")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("vincular", help="vincula este equipo con el cÃ³digo de 6 dÃ­gitos de la app")
    p.add_argument("--servidor", default=SERVIDOR_POR_DEFECTO)
    p.add_argument("--ca", help="ruta a ca.crt de GuardianIA (si el agente no estÃ¡ junto al servidor)")
    p.add_argument("--codigo", help="si se omite, se pide por pantalla")
    p.add_argument("--nombre", help="nombre del equipo (por defecto, el del sistema)")
    p.set_defaults(fn=cmd_vincular)

    p = sub.add_parser("registrar", help="vincula este equipo con su cuenta")
    p.add_argument("--servidor", default=SERVIDOR_POR_DEFECTO, help=SERVIDOR_POR_DEFECTO)
    p.add_argument("--ca", help="ruta a ca.crt de GuardianIA (si el agente no estÃ¡ junto al servidor)")
    p.add_argument("--token", help="token del dispositivo (si se omite, se pide sin mostrarlo)")
    p.set_defaults(fn=cmd_registrar)

    p = sub.add_parser("escanear", help="analiza el equipo")
    p.add_argument("--modo", choices=["rapido", "completo", "personalizado"], default="rapido")
    p.add_argument("--ruta", help="carpeta o unidad para el modo personalizado")
    p.add_argument("--limite", type=int, default=4000, help="mÃ¡ximo de archivos a revisar")
    p.add_argument("--rendimiento", choices=["auto", "turbo", "silencioso"], default="auto",
                   help="auto se adapta a la carga; turbo usa casi todos los nÃºcleos; silencioso solo 2")
    p.set_defaults(fn=cmd_escanear)

    sub.add_parser("servicio", help="vigilancia en tiempo real y tareas del servidor").set_defaults(fn=cmd_servicio)
    p = sub.add_parser("vpn", help="estado o desconexiÃ³n del tÃºnel")
    p.add_argument("accion", choices=["estado", "desconectar", "conectar"], default="estado", nargs="?")
    p.set_defaults(fn=cmd_vpn)
    sub.add_parser("estado", help="muestra el estado local").set_defaults(fn=cmd_estado)

    args = parser.parse_args()
    try:
        args.fn(args)
    except ValueError as e:
        sys.exit(f"âœ— {e}")


if __name__ == "__main__":
    main()



