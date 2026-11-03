"""Acceso al sistema operativo sin PowerShell.

Todo lo que el antivirus necesita del sistema se pide directamente a la API de Windows con ctypes
(o a psutil si está instalado). No se lanza PowerShell ni wmic en ningún momento, por tres razones:

* **Seguridad.** Un antivirus que invoca PowerShell se parece demasiado al malware que persigue, y
  las reglas de Defender/ASR lo tratan con sospecha.
* **Velocidad.** Arrancar PowerShell cuesta cientos de milisegundos; una llamada a la API, microsegundos.
* **Vigencia.** wmic ya no viene en Windows 11 24H2: el agente anterior medía la CPU con él y en su
  equipo siempre leía 0 %.

En Linux/macOS cada función degrada con elegancia (devuelve None o una lista vacía), así el backend y
las pruebas corren en cualquier sistema.
"""
from __future__ import annotations

import ctypes
import os
import sys
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

ES_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000

try:  # opcional: más preciso y portable, pero el antivirus no depende de él
    import psutil  # type: ignore
except Exception:  # noqa: BLE001
    psutil = None


# ══════════════════════════════════════════════════════════ privilegios
def es_admin() -> bool:
    try:
        if ES_WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


# ══════════════════════════════════════════════════════════════ CPU
class _MedidorCpu:
    """Uso total de CPU entre dos lecturas. GetSystemTimes en Windows, /proc/stat en Linux."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._previo: tuple[int, int] | None = None
        self._ultimo = 0.0
        self._momento = 0.0

    def _tiempos(self) -> tuple[int, int] | None:
        if ES_WINDOWS:
            from ctypes import wintypes
            ocioso, kernel, usuario = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
            if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(ocioso), ctypes.byref(kernel),
                                                         ctypes.byref(usuario)):
                return None
            a_int = lambda ft: (ft.dwHighDateTime << 32) | ft.dwLowDateTime  # noqa: E731
            # En Windows el tiempo de kernel ya incluye el ocioso.
            return a_int(ocioso), a_int(kernel) + a_int(usuario)
        try:
            with open("/proc/stat", encoding="ascii") as fh:
                campos = [int(x) for x in fh.readline().split()[1:]]
            return campos[3] + campos[4], sum(campos)
        except (OSError, ValueError, IndexError):
            return None

    def leer(self) -> float:
        if psutil is not None:
            try:
                return float(psutil.cpu_percent(interval=None))
            except Exception:  # noqa: BLE001
                pass
        with self._lock:
            if time.monotonic() - self._momento < 0.5:
                return self._ultimo
            actual = self._tiempos()
            if actual is None:
                return 0.0
            if self._previo is not None:
                ocioso = actual[0] - self._previo[0]
                total = actual[1] - self._previo[1]
                if total > 0:
                    self._ultimo = round(max(0.0, min(100.0, 100.0 * (1 - ocioso / total))), 1)
            self._previo = actual
            self._momento = time.monotonic()
            return self._ultimo


_cpu = _MedidorCpu()


def cpu_percent() -> float:
    return _cpu.leer()


def nucleos() -> int:
    return os.cpu_count() or 4


# ════════════════════════════════════════════════ prioridad de los hilos
def hilo_en_segundo_plano() -> None:
    """Pone el hilo actual en modo «background»: baja su prioridad de CPU y de disco.

    Es lo que hacen los antivirus comerciales para que un análisis completo no se note: Windows le
    da el disco a lo que usted esté usando y al escáner lo que sobre.
    """
    if not ES_WINDOWS:
        return
    try:
        k32 = ctypes.windll.kernel32
        k32.GetCurrentThread.restype = ctypes.c_void_p
        k32.SetThreadPriority.argtypes = [ctypes.c_void_p, ctypes.c_int]
        THREAD_MODE_BACKGROUND_BEGIN = 0x00010000
        if not k32.SetThreadPriority(k32.GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN):
            k32.SetThreadPriority(k32.GetCurrentThread(), -1)   # BELOW_NORMAL como respaldo
    except Exception:  # noqa: BLE001
        pass


# ══════════════════════════════════════════════════════ rutas del equipo
INTOCABLES = [
    "c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\winsxs", "c:\\windows\\boot",
    "c:\\windows\\servicing", "c:\\program files\\windowsapps", "c:\\programdata\\microsoft\\windows defender",
    "/boot", "/proc", "/sys", "/dev", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/usr/lib",
    "/system", "/etc/passwd", "/etc/shadow",
]
# No se recorren nunca: o son enormes y sin valor para el análisis, o no son legibles.
OMITIR_RECORRIDO = [
    "c:\\windows\\winsxs", "c:\\windows\\servicing", "c:\\windows\\softwaredistribution\\download",
    "c:\\system volume information", "c:\\$winreagent", "c:\\windows\\installer\\$patchcache$",
    "/proc", "/sys", "/dev", "/run", "/snap",
]
OMITIR_NOMBRES = {".git", "__pycache__", "node_modules", ".venv", "venv", "$WinREAgent"}


def _normal(ruta: str | Path) -> str:
    return str(ruta).lower().replace("/", "\\") if ES_WINDOWS else str(ruta)


def _empieza(ruta: str | Path, lista: list[str]) -> bool:
    texto = _normal(ruta).rstrip("\\/")
    for p in lista:
        base = p.replace("/", "\\") if ES_WINDOWS else p
        if texto == base or texto.startswith(base + ("\\" if ES_WINDOWS else "/")):
            return True
    return False


# Código propio de GuardianIA. El motor contiene, a propósito, las cadenas que buscan las reglas
# («CreateRemoteThread», «your files encrypted»…): analizarse a sí mismo lo aislaba y la app no
# arrancaba. Solo se exime el CÓDIGO (no las carpetas de datos ni lo que alguien suelte en la raíz):
# una lista blanca amplia sería el escondite perfecto para un malware.
CODIGO_PROPIO = ("app", "web", "agente", "vpn_servidor", "tests", ".venv", "venv")


def _carpeta_guardian() -> str:
    return _normal(Path(__file__).resolve().parents[2])


def _rutas_propias() -> list[str]:
    raiz = _carpeta_guardian().rstrip("\\/")
    sep = "\\" if ES_WINDOWS else "/"
    propias = [raiz + sep + c for c in CODIGO_PROPIO]
    # El intérprete que ejecuta GuardianIA: aislar python.exe también la tumbaría.
    propias.append(_normal(Path(sys.executable).resolve()))
    if ES_WINDOWS or sys.prefix != sys.base_prefix:      # en Linux /usr no se exime entero
        propias.append(_normal(Path(sys.prefix).resolve()))
    return propias


def intocable(ruta: str | Path) -> bool:
    """Rutas que jamás se aíslan: las del sistema (un falso positivo deja el equipo sin arrancar)
    y el código de la propia GuardianIA."""
    return _empieza(ruta, INTOCABLES) or _empieza(ruta, _rutas_propias())


def omitir_recorrido(ruta: str | Path) -> bool:
    return _empieza(ruta, OMITIR_RECORRIDO) or _empieza(ruta, _rutas_propias())


def unidades() -> list[Path]:
    """Discos fijos y memorias extraíbles. Se excluyen CD y unidades de red."""
    salida: list[Path] = []
    if ES_WINDOWS:
        import string
        k32 = ctypes.windll.kernel32
        bits = k32.GetLogicalDrives()
        for i, letra in enumerate(string.ascii_uppercase):
            if bits & (1 << i):
                raiz = f"{letra}:\\"
                if k32.GetDriveTypeW(raiz) in (2, 3):   # 2 = extraíble, 3 = fijo
                    salida.append(Path(raiz))
        return salida
    salida.append(Path("/"))
    for punto in ("/media", "/mnt", "/run/media", "/Volumes"):
        p = Path(punto)
        if p.is_dir():
            try:
                salida.extend(x for x in p.iterdir() if x.is_dir())
            except OSError:
                pass
    return salida


def unidades_extraibles() -> set[str]:
    if not ES_WINDOWS:
        return {str(u) for u in unidades() if str(u) != "/"}
    k32 = ctypes.windll.kernel32
    return {str(u) for u in unidades() if k32.GetDriveTypeW(str(u)) == 2}


def carpetas_calientes() -> list[Path]:
    """Dónde aparece el malware en la práctica: descargas, escritorio, temporales y arranque."""
    casa = Path.home()
    candidatas = [casa / "Downloads", casa / "Descargas", casa / "Desktop", casa / "Escritorio",
                  Path(os.environ.get("TEMP", "/tmp"))]
    # OneDrive redirige el escritorio y a veces las descargas.
    for od in (os.environ.get("OneDrive"), os.environ.get("OneDriveConsumer")):
        if od:
            candidatas += [Path(od) / "Desktop", Path(od) / "Escritorio"]
    candidatas += carpetas_inicio()
    vistas, salida = set(), []
    for c in candidatas:
        try:
            clave = _normal(c.resolve())
        except OSError:
            continue
        if c.is_dir() and clave not in vistas:
            vistas.add(clave)
            salida.append(c)
    return salida


def carpetas_inicio() -> list[Path]:
    if not ES_WINDOWS:
        return [p for p in (Path.home() / ".config/autostart",) if p.is_dir()]
    salida = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        salida.append(Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup")
    programdata = os.environ.get("ProgramData", r"C:\ProgramData")
    salida.append(Path(programdata) / "Microsoft/Windows/Start Menu/Programs/StartUp")
    return [p for p in salida if p.is_dir()]


# ══════════════════════════════════════════════ objetos de inicio (autorun)
_CLAVES_RUN = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
]
_EJECUTABLE = re.compile(r"^(.+?\.(?:exe|dll|scr|com|bat|cmd|vbs|js|hta|ps1|jar|pif|cpl))(?:\s|$|,)", re.I)


def ruta_de_comando(comando: str) -> Path | None:
    """Extrae el ejecutable de una línea de comandos del registro («"C:\\x.exe" /min», «rundll32 y.dll,F»)."""
    texto = os.path.expandvars(comando.strip())
    if not texto:
        return None
    if texto.startswith('"'):
        fin = texto.find('"', 1)
        candidato = texto[1:fin] if fin > 0 else texto[1:]
        resto = texto[fin + 1:] if fin > 0 else ""
    else:
        m = _EJECUTABLE.match(texto)
        candidato = m.group(1) if m else texto.split(" ")[0]
        resto = texto[len(candidato):]
    nombre = Path(candidato).name.lower()
    # rundll32/regsvr32/mshta/wscript ejecutan OTRO archivo: ese es el que importa.
    if nombre in ("rundll32.exe", "rundll32", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe"):
        m = re.search(r'"?([a-z]:\\[^",]+\.(?:dll|hta|vbs|js|ocx|cpl))', resto, re.I)
        if m:
            candidato = m.group(1)
    ruta = Path(candidato)
    if not ruta.is_absolute():
        encontrado = shutil.which(candidato)
        if not encontrado:
            return None
        ruta = Path(encontrado)
    return ruta if ruta.is_file() else None


def objetos_inicio() -> list[tuple[str, Path]]:
    """Programas que arrancan solos con Windows: registro Run/RunOnce y carpetas de inicio."""
    salida: list[tuple[str, Path]] = []
    if ES_WINDOWS:
        import winreg
        for colmena, nombre_colmena in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            for subclave in _CLAVES_RUN:
                try:
                    with winreg.OpenKey(colmena, subclave) as k:
                        i = 0
                        while True:
                            try:
                                nombre, valor, _ = winreg.EnumValue(k, i)
                            except OSError:
                                break
                            i += 1
                            if isinstance(valor, str):
                                ruta = ruta_de_comando(valor)
                                if ruta:
                                    salida.append((f"{nombre_colmena}\\{subclave.split(chr(92))[-1]}: {nombre}", ruta))
                except OSError:
                    continue
    for carpeta in carpetas_inicio():
        try:
            for x in carpeta.iterdir():
                if x.is_file():
                    salida.append((f"Carpeta de inicio: {x.name}", x))
        except OSError:
            continue
    return salida


# ══════════════════════════════════════════════════════ procesos
def procesos() -> list[tuple[int, str, Path]]:
    """(pid, nombre, ejecutable) de lo que está corriendo ahora. Es el «análisis de memoria»."""
    salida: list[tuple[int, str, Path]] = []
    if psutil is not None:
        for p in psutil.process_iter(["pid", "name", "exe"]):
            try:
                exe = p.info.get("exe")
                if exe:
                    salida.append((p.info["pid"], p.info.get("name") or Path(exe).name, Path(exe)))
            except Exception:  # noqa: BLE001 - procesos protegidos o que terminaron
                continue
        return salida
    if not ES_WINDOWS:
        for d in Path("/proc").glob("[0-9]*"):
            try:
                exe = Path(os.readlink(d / "exe"))
                salida.append((int(d.name), exe.name, exe))
            except OSError:
                continue
        return salida
    from ctypes import wintypes
    psapi, k32 = ctypes.windll.psapi, ctypes.windll.kernel32
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                               ctypes.POINTER(wintypes.DWORD)]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    arreglo = (wintypes.DWORD * 4096)()
    usados = wintypes.DWORD()
    if not psapi.EnumProcesses(ctypes.byref(arreglo), ctypes.sizeof(arreglo), ctypes.byref(usados)):
        return salida
    for pid in list(arreglo)[: usados.value // ctypes.sizeof(wintypes.DWORD)]:
        if not pid:
            continue
        h = k32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            continue
        try:
            buf = ctypes.create_unicode_buffer(1024)
            tam = wintypes.DWORD(1024)
            if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(tam)):
                exe = Path(buf.value)
                salida.append((pid, exe.name, exe))
        finally:
            k32.CloseHandle(h)
    return salida


def terminar_proceso(pid: int) -> bool:
    try:
        if psutil is not None:
            psutil.Process(pid).kill()
            return True
        if ES_WINDOWS:
            k32 = ctypes.windll.kernel32
            k32.OpenProcess.restype = ctypes.c_void_p
            h = k32.OpenProcess(0x0001, False, pid)   # PROCESS_TERMINATE
            if not h:
                return False
            try:
                return bool(k32.TerminateProcess(ctypes.c_void_p(h), 1))
            finally:
                k32.CloseHandle(ctypes.c_void_p(h))
        os.kill(pid, 9)
        return True
    except Exception:  # noqa: BLE001
        return False


# ═════════════════════════════════════════ firma digital (Authenticode)
TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_BAD_DIGEST = 0x80096010


def verificar_firma(ruta: Path) -> tuple[bool | None, str]:
    """Verifica la firma Authenticode con WinVerifyTrust, igual que el Explorador de Windows.

    Devuelve (True, «válida»), (False, motivo) o (None, «no disponible») fuera de Windows. No
    consulta internet (solo caché de revocación): un análisis de miles de archivos no puede esperar
    a la red por cada uno.
    """
    if not ES_WINDOWS:
        return None, "no disponible"
    try:
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                        ("Data4", ctypes.c_ubyte * 8)]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                        ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.POINTER(GUID))]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                        ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                        ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
                        ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                        ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                        ("pSignatureSettings", ctypes.c_void_p)]

        accion = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
        info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), str(ruta), None, None)
        datos = WINTRUST_DATA()
        datos.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        datos.dwUIChoice = 2              # WTD_UI_NONE
        datos.fdwRevocationChecks = 0     # WTD_REVOKE_NONE
        datos.dwUnionChoice = 1           # WTD_CHOICE_FILE
        datos.pFile = ctypes.pointer(info)
        datos.dwStateAction = 1           # WTD_STATEACTION_VERIFY
        datos.dwProvFlags = 0x1000 | 0x10  # solo caché de URL, sin comprobar revocación

        wvt = ctypes.windll.wintrust.WinVerifyTrust
        wvt.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
        wvt.restype = wintypes.LONG
        resultado = wvt(None, ctypes.byref(accion), ctypes.byref(datos)) & 0xFFFFFFFF
        datos.dwStateAction = 2           # WTD_STATEACTION_CLOSE: libera el estado
        wvt(None, ctypes.byref(accion), ctypes.byref(datos))
    except Exception as e:  # noqa: BLE001
        return None, f"no se pudo verificar ({type(e).__name__})"
    if resultado == 0:
        return True, "válida"
    if resultado == TRUST_E_NOSIGNATURE:
        return False, "sin firma"
    if resultado == TRUST_E_BAD_DIGEST:
        return False, "firma alterada"
    return False, f"firma no confiable (0x{resultado:08X})"


# ═══════════════════════════════════════════ Windows Defender (segunda opinión)
def defender_disponible() -> str | None:
    """Ruta de MpCmdRun.exe, el motor de línea de comandos de Defender (no es PowerShell)."""
    if not ES_WINDOWS:
        return None
    candidatos = []
    plataforma = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft/Windows Defender/Platform"
    try:
        candidatos += sorted(plataforma.glob("*/MpCmdRun.exe"), reverse=True)
    except OSError:
        pass
    candidatos.append(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender/MpCmdRun.exe")
    return next((str(c) for c in candidatos if c.is_file()), None)


def defender_escanear(ruta: Path, timeout: int = 90) -> tuple[bool | None, str]:
    """(True si Defender lo detecta, detalle). -DisableRemediation: Defender solo opina, no borra."""
    mp = defender_disponible()
    if not mp:
        return None, "Defender no disponible"
    try:
        r = subprocess.run([mp, "-Scan", "-ScanType", "3", "-File", str(ruta), "-DisableRemediation"],
                           capture_output=True, text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"Defender no respondió ({type(e).__name__})"
    if r.returncode == 2:
        amenaza = re.search(r"Threat\s+:\s*(.+)", r.stdout or "")
        return True, amenaza.group(1).strip() if amenaza else "amenaza detectada"
    if r.returncode == 0:
        return False, "sin amenazas"
    return None, f"Defender devolvió el código {r.returncode}"


# ═════════════════════════════════════ ejecutar con permisos (una ventana UAC)
class ElevacionCancelada(Exception):
    """La persona dijo «No» en la ventana de control de cuentas."""


def ejecutar_elevado(programa: str, argumentos: list[str], timeout: float = 90.0) -> int:
    """Ejecuta un programa como administrador y espera su código de salida.

    Si el servidor ya corre como administrador, se ejecuta directo. Si no, Windows muestra UNA
    ventana de «¿Desea permitir…?» (ShellExecuteEx con el verbo runas). Así el servidor no necesita
    correr siempre con privilegios, que sería mucho más peligroso.
    """
    if es_admin() or not ES_WINDOWS:
        r = subprocess.run([programa, *argumentos], capture_output=True, text=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW if ES_WINDOWS else 0)
        return r.returncode
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                    ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                    ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                    ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                    ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]

    parametros = subprocess.list2cmdline(argumentos)
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040 | 0x00008000      # SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE
    info.lpVerb = "runas"
    info.lpFile = programa
    info.lpParameters = parametros
    info.nShow = 0                            # SW_HIDE
    shell = ctypes.windll.shell32
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    if not shell.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.windll.kernel32.GetLastError()
        if error == 1223:                     # ERROR_CANCELLED
            raise ElevacionCancelada()
        raise OSError(f"No se pudo ejecutar {Path(programa).name} (error {error})")
    k32 = ctypes.windll.kernel32
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    try:
        k32.WaitForSingleObject(info.hProcess, int(timeout * 1000))
        codigo = wintypes.DWORD()
        k32.GetExitCodeProcess(info.hProcess, ctypes.byref(codigo))
        return int(codigo.value)
    finally:
        k32.CloseHandle(info.hProcess)


def estado_servicio(nombre: str) -> str | None:
    """«RUNNING», «STOPPED»… de un servicio de Windows, con sc.exe (no PowerShell)."""
    if not ES_WINDOWS:
        return None
    try:
        r = subprocess.run(["sc.exe", "query", nombre], capture_output=True, text=True, timeout=10,
                           creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"STATE\s*:\s*\d+\s+(\w+)", r.stdout or "")
    return m.group(1) if m else None


# ═══════════════════════════════════════════════ ¿red de confianza?
_red_cache: dict = {"valor": None, "cuando": 0.0}


def red_publica(cache_s: float = 300.0) -> bool | None:
    """¿Está conectado a una red que Windows marca como PÚBLICA (café, aeropuerto, WiFi abierta)?

    La usa el cerebro de la VPN: en una red pública conviene cifrar TODO el equipo (túnel), no solo
    lo que pasa por el proxy de Tor. Se ignora la interfaz del propio túnel. None = no se sabe."""
    if not ES_WINDOWS:
        return None
    ahora = time.time()
    if ahora - _red_cache["cuando"] < cache_s:
        return _red_cache["valor"]
    valor = None
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-NetConnectionProfile | Where-Object { $_.InterfaceAlias -ne 'guardiania' } | "
             "ForEach-Object { [string]$_.NetworkCategory }"],
            capture_output=True, text=True, timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        categorias = {c.strip().lower() for c in (r.stdout or "").splitlines() if c.strip()}
        if categorias:
            valor = "public" in categorias
    except (OSError, subprocess.SubprocessError):
        valor = None
    _red_cache.update(valor=valor, cuando=ahora)
    return valor


# ═════════════════════════════════════ proxy del sistema (para que el navegador salga por Tor)
_CLAVE_PROXY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_VALORES_PROXY = ("ProxyEnable", "ProxyServer", "ProxyOverride")


def _archivo_proxy() -> Path:
    from app.local import ajustes
    return ajustes.sub("sistema") / "proxy_previo.json"


def _avisar_cambio_proxy() -> None:
    """Hace que Opera/Chrome/Edge relean el proxy sin reiniciar."""
    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(None, 39, None, 0)   # INTERNET_OPTION_SETTINGS_CHANGED
        wininet.InternetSetOptionW(None, 37, None, 0)   # INTERNET_OPTION_REFRESH
    except (AttributeError, OSError):
        pass


def proxy_sistema_poner(servidor: str) -> bool:
    """Apunta el proxy de Windows (el que usan Opera, Chrome y Edge) a `servidor`, p. ej.
    «socks=127.0.0.1:9050». Guarda lo que había para devolverlo al apagar. No pide administrador
    (es el proxy del usuario). Fuera de Windows no hace nada."""
    if not ES_WINDOWS:
        return False
    import json
    import winreg
    previo: dict = {}
    archivo = _archivo_proxy()
    try:
        previo = json.loads(archivo.read_text("utf-8"))["valores"]       # ya lo habíamos puesto: se conserva el original
    except (OSError, ValueError, KeyError):
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _CLAVE_PROXY) as k:
            for nombre in _VALORES_PROXY:
                try:
                    previo[nombre] = list(winreg.QueryValueEx(k, nombre))
                except OSError:
                    previo[nombre] = None
        archivo.write_text(json.dumps({"valores": previo, "desde": time.time()}), "utf-8")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _CLAVE_PROXY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, servidor)
        winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    _avisar_cambio_proxy()
    return True


def proxy_sistema_puesto() -> float | None:
    """Momento en que GuardianIA puso el proxy (None si no está puesto por nosotros)."""
    import json
    try:
        return float(json.loads(_archivo_proxy().read_text("utf-8")).get("desde", 0)) or None
    except (OSError, ValueError):
        return None


def proxy_sistema_quitar() -> bool:
    """Devuelve el proxy de Windows a como estaba. Solo si fue GuardianIA quien lo cambió."""
    if not ES_WINDOWS:
        return False
    import json
    import winreg
    archivo = _archivo_proxy()
    try:
        previo = json.loads(archivo.read_text("utf-8"))["valores"]
    except (OSError, ValueError, KeyError):
        return False
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _CLAVE_PROXY, 0, winreg.KEY_SET_VALUE) as k:
        for nombre in _VALORES_PROXY:
            antes = previo.get(nombre)
            if antes is None:
                try:
                    winreg.DeleteValue(k, nombre)
                except OSError:
                    pass
            else:
                winreg.SetValueEx(k, nombre, 0, antes[1], antes[0])
    try:
        archivo.unlink()
    except OSError:
        pass
    _avisar_cambio_proxy()
    return True
