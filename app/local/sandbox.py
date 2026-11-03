"""Sandbox para probar código: se ejecuta en una carpeta temporal, con límites y salida en vivo.

Dos modos, en este orden de preferencia:

* ``docker``  — contenedor sin red, con memoria, CPU y procesos limitados y sistema de archivos de solo
  lectura. Es el aislamiento real. Se usa si Docker está instalado y la imagen ya está descargada
  (no se descarga nada solo).
* ``proceso`` — un proceso aparte con carpeta temporal, entorno limpio (sin claves ni variables de la
  app), tiempo y salida limitados y, en Linux/macOS, límites de memoria y CPU del sistema. En Python se
  añade un guardián que bloquea red, subprocesos, borrados, escrituras fuera de la carpeta y la lectura
  de los datos de GuardianIA. Es protección contra ACCIDENTES (un ``rmtree`` mal puesto, un bucle
  infinito), no contra código hecho para escapar: para eso, Docker.

Nunca se ejecuta solo: lo pide la persona con un botón y solo desde este mismo equipo.
"""
from __future__ import annotations

import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

from app.local import ajustes, sistema

def _nombre_clase_java(codigo: str) -> str:
    m = re.search(r"public\s+(?:final\s+)?class\s+(\w+)", codigo) or re.search(r"\bclass\s+(\w+)", codigo)
    return m.group(1) if m else "Main"


# Cada lenguaje: archivo, etiqueta, programas que necesita, y cómo compilar/ejecutar (None = no compila).
# vm_grande: la máquina virtual reserva mucha memoria virtual (JVM, Node, Go, Rust); un límite de memoria
# virtual la rompería, así que a esos solo los frenan el tiempo y la salida.
LENGUAJES = {
    "python": {"archivo": "main.py", "imagen": "python:3.12-slim", "etiqueta": "Python", "bins": ["python"]},
    "javascript": {"archivo": "main.js", "imagen": "node:20-slim", "etiqueta": "JavaScript (Node)", "bins": ["node"],
                   "vm_grande": True},
    "typescript": {"archivo": "main.ts", "etiqueta": "TypeScript", "bins": ["tsc", "node"], "vm_grande": True},
    "bash": {"archivo": "main.sh", "etiqueta": "Bash", "bins": ["bash"]},
    "php": {"archivo": "main.php", "etiqueta": "PHP", "bins": ["php"]},
    "ruby": {"archivo": "main.rb", "etiqueta": "Ruby", "bins": ["ruby"]},
    "perl": {"archivo": "main.pl", "etiqueta": "Perl", "bins": ["perl"]},
    "lua": {"archivo": "main.lua", "etiqueta": "Lua", "bins": ["lua"]},
    "go": {"archivo": "main.go", "etiqueta": "Go", "bins": ["go"], "vm_grande": True},
    "java": {"archivo": "Main.java", "etiqueta": "Java", "bins": ["java"], "vm_grande": True},
    "c": {"archivo": "main.c", "etiqueta": "C", "bins": ["gcc"]},
    "cpp": {"archivo": "main.cpp", "etiqueta": "C++", "bins": ["g++"]},
    "rust": {"archivo": "main.rs", "etiqueta": "Rust", "bins": ["rustc"], "vm_grande": True},
    "csharp": {"archivo": "main.csx", "etiqueta": "C# (script)", "bins": ["dotnet-script"], "vm_grande": True},
}
ALIAS = {"py": "python", "python3": "python", "js": "javascript", "node": "javascript", "nodejs": "javascript",
         "mjs": "javascript", "ts": "typescript", "sh": "bash", "shell": "bash", "zsh": "bash", "rb": "ruby",
         "pl": "perl", "golang": "go", "c++": "cpp", "cc": "cpp", "rs": "rust", "cs": "csharp", "c#": "csharp"}
TIMEOUT_COMPILAR = 90.0

MAX_CODIGO = 100_000          # caracteres
MAX_SALIDA = 200_000          # caracteres entre stdout y stderr
TIMEOUT_DEFECTO = 15.0
TIMEOUT_MAXIMO = 60.0
MEMORIA_MB = 512

_docker_cache: dict = {"hasta": 0.0, "listo": False}


class ErrorSandbox(Exception):
    pass


def normalizar(lenguaje: str) -> str:
    l = ALIAS.get((lenguaje or "").strip().lower(), (lenguaje or "").strip().lower())
    if l not in LENGUAJES:
        raise ErrorSandbox(f"Lenguaje no disponible: {lenguaje!r}. Disponibles: {', '.join(LENGUAJES)}")
    return l


def _herramientas(lenguaje: str) -> dict | None:
    """Rutas de los programas que el lenguaje necesita, o None si falta alguno."""
    rutas = {}
    for b in LENGUAJES[lenguaje]["bins"]:
        ruta = sys.executable if b == "python" else shutil.which(b)
        if not ruta:
            return None
        rutas[b] = ruta
    return rutas


def _ejecutable(lenguaje: str) -> str | None:
    h = _herramientas(lenguaje)
    return next(iter(h.values())) if h else None


def _docker_listo(lenguaje: str) -> bool:
    """Docker responde y la imagen del lenguaje ya está descargada (no se baja nada sin permiso)."""
    exe = shutil.which("docker")
    imagen = LENGUAJES[lenguaje].get("imagen")
    if not exe or not imagen:
        return False
    try:
        r = subprocess.run([exe, "image", "inspect", imagen], capture_output=True, timeout=6,
                           creationflags=sistema.CREATE_NO_WINDOW if sistema.ES_WINDOWS else 0)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def modo_para(lenguaje: str, preferido: str = "auto") -> str:
    if preferido == "proceso":
        return "proceso"
    if preferido in ("auto", "docker") and _docker_listo(lenguaje):
        return "docker"
    return "proceso"


def estado() -> dict:
    return {
        "lenguajes": [{"id": k, "nombre": v["etiqueta"], "disponible": _ejecutable(k) is not None,
                       "modo": modo_para(k) if _ejecutable(k) else None,
                       "compila": k in ("typescript", "go", "c", "cpp", "rust")} for k, v in LENGUAJES.items()],
        "docker": bool(shutil.which("docker")),
        "limites": {"timeout_defecto": TIMEOUT_DEFECTO, "timeout_maximo": TIMEOUT_MAXIMO,
                    "salida_max": MAX_SALIDA, "codigo_max": MAX_CODIGO, "memoria_mb": MEMORIA_MB},
        "nota": ("Docker aísla de verdad (sin red ni acceso a sus archivos). Sin Docker, el código corre en un "
                 "proceso aparte con límites y un guardián: sirve para probar y evitar accidentes, pero no es "
                 "una caja a prueba de código malicioso."),
    }


# ───────────────────────────────────────────── guardián de Python (modo proceso)
_GUARDIAN = r'''
import sys, os
_nc = lambda p: os.path.normcase(os.path.realpath(p))
_RAIZ = _nc(os.getcwd())
_PROHIBIDOS = [_nc(p) for p in sys.argv[1:] if p]
sys.argv = [sys.argv[0]]
_BLOQ = {"socket.connect", "socket.bind", "socket.getaddrinfo", "socket.gethostbyname", "subprocess.Popen",
         "os.system", "os.exec", "os.spawn", "os.fork", "os.forkpty", "os.remove", "os.rmdir", "os.rename",
         "os.truncate", "os.chmod", "os.chown", "os.symlink", "os.link", "shutil.rmtree", "shutil.move",
         "shutil.copyfile", "ctypes.dlopen", "ctypes.dlsym", "ctypes.cdata", "winreg.OpenKey", "winreg.CreateKey",
         "winreg.SetValue", "winreg.DeleteKey", "webbrowser.open", "smtplib.SMTP.connect", "ftplib.connect",
         "urllib.Request"}
def _dentro(p):
    try:
        r = _nc(p)
        return r.startswith(_RAIZ + os.sep) or r == _RAIZ
    except Exception:
        return False
def _guardia(ev, args):
    if ev in _BLOQ:
        if ev in ("os.remove", "os.rmdir", "os.rename", "os.truncate", "shutil.rmtree", "shutil.move",
                  "shutil.copyfile") and all(_dentro(str(a)) for a in args if isinstance(a, (str, bytes, os.PathLike))):
            return
        raise PermissionError("Bloqueado por el sandbox de GuardianIA: " + ev)
    if ev == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
        ruta, modo = args[0], (args[1] or "r")
        try:
            real = _nc(ruta if isinstance(ruta, str) else os.fsdecode(ruta))
        except Exception:
            return
        if _dentro(real):
            return
        if any(real == b or real.startswith(b + os.sep) for b in _PROHIBIDOS):
            raise PermissionError("Bloqueado por el sandbox de GuardianIA: datos de la aplicación")
        if any(c in str(modo) for c in "wax+") and not _dentro(real):
            raise PermissionError("Bloqueado por el sandbox de GuardianIA: solo puede escribir en su carpeta")
sys.addaudithook(_guardia)
_entrada = os.environ.pop("GUARDIAN_ENTRADA", "main.py")
_fuente = open(_entrada, encoding="utf-8").read()
_d = os.path.dirname(os.path.abspath(_entrada))
if _d != os.getcwd():
    sys.path.insert(0, _d)       # los módulos hermanos del script se importan como en una ejecución normal
try:
    exec(compile(_fuente, _entrada, "exec"), {"__name__": "__main__", "__file__": _entrada})
except SystemExit:
    raise
except BaseException as _e:          # el traceback muestra solo el código de la persona, no el guardián
    import traceback
    traceback.print_exception(type(_e), _e, _e.__traceback__.tb_next)
    sys.exit(1)
'''


def _entorno_limpio(lenguaje: str, carpeta: Path) -> dict:
    """Sin claves ni variables de la aplicación: solo lo mínimo para arrancar."""
    base = {"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
            "PYTHONUNBUFFERED": "1", "HOME": str(carpeta), "TMPDIR": str(carpeta), "TEMP": str(carpeta),
            "TMP": str(carpeta), "NO_COLOR": "1"}
    for k in ("SYSTEMROOT", "SystemRoot", "COMSPEC", "PATHEXT", "WINDIR", "LANG", "LC_ALL"):
        if k in os.environ:
            base[k] = os.environ[k]
    return base


def _limites_posix(vm_grande: bool = False):
    def poner():
        import resource
        os.setsid()
        limites = [(resource.RLIMIT_CPU, (int(TIMEOUT_MAXIMO + TIMEOUT_COMPILAR) + 5,) * 2),
                   (resource.RLIMIT_FSIZE, (50 * 1024 * 1024,) * 2),
                   (resource.RLIMIT_NOFILE, (256, 256)),
                   (resource.RLIMIT_CORE, (0, 0))]
        if not vm_grande:
            limites.append((resource.RLIMIT_AS, (MEMORIA_MB * 1024 * 1024,) * 2))
        for recurso, valor in limites:
            try:
                resource.setrlimit(recurso, valor)
            except (ValueError, OSError):
                pass
    return poner


def _matar_arbol(proc: subprocess.Popen) -> None:
    try:
        if sistema.ES_WINDOWS:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True, timeout=10,
                           creationflags=sistema.CREATE_NO_WINDOW)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (OSError, subprocess.SubprocessError, ProcessLookupError):
        try:
            proc.kill()
        except OSError:
            pass


def _comando_docker(lenguaje: str, carpeta: Path) -> list[str]:
    arch = LENGUAJES[lenguaje]["archivo"]
    docker = shutil.which("docker") or "docker"
    cmd = [docker, "run", "--rm", "--network", "none", "--memory", f"{MEMORIA_MB}m", "--cpus", "1",
           "--pids-limit", "128", "--read-only", "--tmpfs", "/tmp:rw,size=64m", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "-v", f"{carpeta}:/work:ro", "-w", "/work",
           LENGUAJES[lenguaje]["imagen"]]
    return cmd + (["python", "-E", "-s", "-B", arch] if lenguaje == "python" else ["node", arch])


def _pasos(lenguaje: str, modo: str, carpeta: Path, herr: dict, archivo: str) -> list[tuple[str, list[str]]]:
    """Lista de (etapa, comando): «compilando» si el lenguaje lo necesita y luego «ejecutando»."""
    exe = next(iter(herr.values()))
    binario = "programa.exe" if sistema.ES_WINDOWS else "programa"
    if modo == "docker":
        return [("ejecutando", _comando_docker(lenguaje, carpeta))]
    if lenguaje == "python":
        (carpeta / "guardian_sandbox.py").write_text(_GUARDIAN, "utf-8")
        prohibidos = [str(ajustes.RAIZ_PROYECTO / "data"), str(ajustes.RAIZ_PROYECTO / ".env"),
                      str(ajustes.RAIZ_PROYECTO / "app"), str(ajustes.carpeta())]
        return [("ejecutando", [exe, "-B", "guardian_sandbox.py", *prohibidos])]
    if lenguaje == "typescript":
        js = "salida/" + re.sub(r"\.ts$", ".js", archivo)
        return [("compilando", [herr["tsc"], archivo, "--target", "es2020", "--module", "commonjs", "--lib",
                                "es2020,dom", "--outDir", "salida", "--skipLibCheck"]),
                ("ejecutando", [herr["node"], js])]
    if lenguaje == "go":
        return [("compilando", [exe, "build", "-o", binario, archivo]), ("ejecutando", [str(carpeta / binario)])]
    if lenguaje == "c":
        return [("compilando", [exe, archivo, "-O1", "-o", binario, "-lm"]), ("ejecutando", [str(carpeta / binario)])]
    if lenguaje == "cpp":
        return [("compilando", [exe, archivo, "-std=c++17", "-O1", "-o", binario]),
                ("ejecutando", [str(carpeta / binario)])]
    if lenguaje == "rust":
        return [("compilando", [exe, archivo, "-O", "-o", binario]), ("ejecutando", [str(carpeta / binario)])]
    if lenguaje == "csharp":
        return [("ejecutando", [exe, archivo])]
    return [("ejecutando", [exe, archivo])]          # js, bash, php, ruby, perl, lua, java (modo archivo único)


def _entorno_para(lenguaje: str, carpeta: Path) -> dict:
    env = _entorno_limpio(lenguaje, carpeta)
    if lenguaje == "go":            # la caché de compilación se comparte: sin ella cada prueba tardaría minutos
        cache = ajustes.sub("sandbox_cache")
        env.update({"GOCACHE": str(cache / "go-build"), "GOPATH": str(cache / "gopath"), "GOFLAGS": "-mod=mod",
                    "GOTOOLCHAIN": "local", "GOPROXY": "off", "GO111MODULE": "off", "CGO_ENABLED": "0"})
    if lenguaje == "rust":
        env.update({"CARGO_HOME": os.environ.get("CARGO_HOME", ""), "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", "")})
        env = {k: v for k, v in env.items() if v != ""}
    return env


def _correr(cmd: list[str], carpeta: Path, env: dict, limite: float, cancelado, vm_grande: bool) -> Iterator[dict]:
    """Corre un proceso y entrega ``salida`` en vivo; al final un evento interno ``_resultado``."""
    flags = (sistema.CREATE_NO_WINDOW | 0x00000200) if sistema.ES_WINDOWS else 0   # sin ventana + grupo propio
    try:
        proc = subprocess.Popen(cmd, cwd=str(carpeta), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, creationflags=flags,
                                **({} if sistema.ES_WINDOWS else {"preexec_fn": _limites_posix(vm_grande)}))
    except OSError as e:
        raise ErrorSandbox(f"No se pudo iniciar el proceso: {e}") from e
    t0 = time.perf_counter()
    cola: queue.Queue = queue.Queue()

    def leer(canal: str, flujo) -> None:
        try:
            for bloque in iter(lambda: flujo.read1(2048) if hasattr(flujo, "read1") else flujo.read(2048), b""):
                cola.put((canal, bloque.decode("utf-8", "replace")))
        finally:
            cola.put((canal, None))

    for c, f in (("stdout", proc.stdout), ("stderr", proc.stderr)):
        threading.Thread(target=leer, args=(c, f), daemon=True).start()

    abiertos, total, truncado, motivo = 2, 0, False, ""
    try:
        while abiertos:
            if cancelado and cancelado():
                motivo = "cancelado"
                _matar_arbol(proc)
            elif time.perf_counter() - t0 > limite and not motivo:
                motivo = "timeout"
                _matar_arbol(proc)
            try:
                canal, texto = cola.get(timeout=0.1)
            except queue.Empty:
                continue
            if texto is None:
                abiertos -= 1
                continue
            if total >= MAX_SALIDA:
                if not truncado:
                    truncado = True
                    _matar_arbol(proc)
                    motivo = motivo or "salida_excesiva"
                continue
            texto = texto[:MAX_SALIDA - total]
            total += len(texto)
            yield {"tipo": "salida", "canal": canal, "texto": texto}
    finally:
        if proc.poll() is None:        # el cliente se fue o hubo un error: no se deja el proceso corriendo
            _matar_arbol(proc)
    try:
        codigo = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _matar_arbol(proc)
        codigo = -9
    yield {"tipo": "_resultado", "codigo": codigo, "motivo": motivo, "truncado": truncado,
           "segundos": round(time.perf_counter() - t0, 2)}


MULTIARCHIVO = {"python", "javascript", "typescript", "bash", "php", "ruby", "perl", "lua"}


def _ruta_relativa_segura(ruta: str) -> str | None:
    r = str(ruta or "").replace("\\", "/").strip().strip("/")
    if not r or len(r) > 200 or re.search(r"(^|/)\.\.?(/|$)|[:\x00]", r) or r.startswith("~"):
        return None
    return r


def ejecutar(lenguaje: str, codigo: str, timeout: float = TIMEOUT_DEFECTO, preferido: str = "auto",
             cancelado=None, extras: dict | None = None, entrada: str | None = None) -> Iterator[dict]:
    """Ejecuta `codigo` y entrega eventos en vivo:
    inicio → [etapa compilando] → etapa ejecutando → salida (stdout/stderr, a medida que sale) → fin."""
    lenguaje = normalizar(lenguaje)
    if not codigo or not codigo.strip():
        raise ErrorSandbox("No hay código para ejecutar")
    if len(codigo) > MAX_CODIGO:
        raise ErrorSandbox(f"El código es demasiado largo (máximo {MAX_CODIGO} caracteres)")
    herr = _herramientas(lenguaje)
    if not herr:
        faltan = ", ".join(b for b in LENGUAJES[lenguaje]["bins"] if b != "python" and not shutil.which(b))
        raise ErrorSandbox(f"{LENGUAJES[lenguaje]['etiqueta']} no está instalado en este equipo (falta: {faltan})")
    timeout = max(1.0, min(float(timeout or TIMEOUT_DEFECTO), TIMEOUT_MAXIMO))
    modo = modo_para(lenguaje, preferido)
    archivo = f"{_nombre_clase_java(codigo)}.java" if lenguaje == "java" else LENGUAJES[lenguaje]["archivo"]
    if entrada and lenguaje in MULTIARCHIVO:
        archivo = _ruta_relativa_segura(entrada) or archivo
    extras = {} if lenguaje not in MULTIARCHIVO else (extras or {})
    if sum(len(v) for v in extras.values() if isinstance(v, str)) > MAX_CODIGO * 5 or len(extras) > 200:
        raise ErrorSandbox("El proyecto es demasiado grande para probarlo")

    carpeta = ajustes.sub("sandbox") / uuid.uuid4().hex[:12]
    carpeta.mkdir(parents=True)
    try:
        for ruta, contenido in extras.items():            # el resto del proyecto, con su estructura de carpetas
            rel = _ruta_relativa_segura(ruta)
            if rel and rel != archivo and isinstance(contenido, str):
                destino = carpeta / rel
                destino.parent.mkdir(parents=True, exist_ok=True)
                destino.write_text(contenido, "utf-8")
        (carpeta / archivo).parent.mkdir(parents=True, exist_ok=True)
        (carpeta / archivo).write_text(codigo, "utf-8")
        pasos = _pasos(lenguaje, modo, carpeta, herr, archivo)
        yield {"tipo": "inicio", "lenguaje": lenguaje, "modo": modo, "timeout": timeout,
               "etapas": [e for e, _ in pasos]}
        env = _entorno_para(lenguaje, carpeta)
        if lenguaje == "python":
            env["GUARDIAN_ENTRADA"] = archivo
        vm = bool(LENGUAJES[lenguaje].get("vm_grande"))
        t0 = time.perf_counter()
        resultado = {"codigo": 0, "motivo": "", "truncado": False}
        for etapa, cmd in pasos:
            yield {"tipo": "etapa", "etapa": etapa}
            limite = TIMEOUT_COMPILAR if etapa == "compilando" else timeout
            for ev in _correr(cmd, carpeta, env, limite, cancelado, vm):
                if ev["tipo"] == "_resultado":
                    resultado = ev
                else:
                    yield ev
            if resultado["codigo"] != 0 or resultado["motivo"]:
                if etapa == "compilando" and not resultado["motivo"]:
                    resultado = {**resultado, "motivo": "compilacion"}
                break
        yield {"tipo": "fin", "codigo": resultado["codigo"], "segundos": round(time.perf_counter() - t0, 2),
               "motivo": resultado["motivo"], "truncado": resultado["truncado"], "modo": modo}
    finally:
        shutil.rmtree(carpeta, ignore_errors=True)


def limpiar_viejos(max_edad_s: float = 3600) -> int:
    """Borra carpetas temporales que hayan quedado (por ejemplo, si el servidor se cerró a mitad)."""
    n = 0
    base = ajustes.sub("sandbox")
    for d in base.iterdir():
        try:
            if d.is_dir() and time.time() - d.stat().st_mtime > max_edad_s:
                shutil.rmtree(d, ignore_errors=True)
                n += 1
        except OSError:
            pass
    return n


def a_json(evento: dict) -> str:
    return json.dumps(evento, ensure_ascii=False)


__all__ = ["ErrorSandbox", "ejecutar", "estado", "normalizar", "limpiar_viejos", "LENGUAJES"]
