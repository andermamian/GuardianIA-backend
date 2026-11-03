"""Protección en tiempo real: lo que hace que un antivirus proteja sin que nadie lo abra.

Tres vigías, todos dentro del mismo servidor (sin agente, sin vincular nada):

1. **Archivos.** Descargas, escritorio, temporales y carpetas de inicio. Con watchdog, Windows avisa
   en el instante en que un archivo aparece (ReadDirectoryChangesW); sin watchdog, se revisa cada
   pocos segundos. Se espera a que el archivo termine de escribirse: analizar una descarga a medias
   da falsos negativos.
2. **Procesos.** Cada programa que arranca se analiza; si es malware con evidencia fuerte y la
   cuarentena automática está activa, se detiene y se aísla.
3. **Memorias USB.** Al conectar una, se analiza sola, como hacen los antivirus comerciales.

Límite honesto: esto actúa al instante de ver el archivo, pero NO puede impedir que se ejecute. Eso
requiere un controlador de kernel firmado por Microsoft (lo que tienen Kaspersky y Defender). Por
eso GuardianIA puede convivir con Defender: ellos bloquean en el kernel, GuardianIA suma su análisis.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from pathlib import Path

from app.local import ajustes, motor, sistema
from app.local.firmas import base as firmas_base

log = logging.getLogger("guardian.tiempo_real")

try:
    from watchdog.events import FileSystemEventHandler  # type: ignore
    from watchdog.observers import Observer  # type: ignore
except Exception:  # noqa: BLE001
    Observer = None
    FileSystemEventHandler = object

TEMPORALES_NAVEGADOR = (".crdownload", ".part", ".partial", ".download", ".opdownload", ".tmp")
ESPERA_ESTABLE = 1.5            # segundos sin cambios antes de analizar
MAX_POR_MINUTO = 120            # freno ante tormentas de archivos (una descompresión enorme, p. ej.)


class _Manejador(FileSystemEventHandler):
    def __init__(self, vigilante: "Vigilante") -> None:
        self.v = vigilante

    def on_created(self, event):  # noqa: D401
        if not event.is_directory:
            self.v.aviso(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.v.aviso(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.v.aviso(event.dest_path)


class Vigilante:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pendientes: dict[str, float] = {}
        self._parar = threading.Event()
        self._hilos: list[threading.Thread] = []
        self._observador = None
        self.eventos: deque[dict] = deque(maxlen=200)
        self.activo = False
        self.user_id: str | None = None
        self.carpetas: list[str] = []
        self.analizados = 0
        self.amenazas = 0
        self.desde: float | None = None
        self._ventana: deque[float] = deque(maxlen=MAX_POR_MINUTO)

    # ── ciclo de vida
    def iniciar(self, user_id: str) -> None:
        with self._lock:
            self.user_id = user_id
            if self.activo:
                return
            self._parar.clear()
            self.activo = True
            self.desde = time.time()
        carpetas = sistema.carpetas_calientes()
        self.carpetas = [str(c) for c in carpetas]
        if Observer is not None:
            try:
                obs = Observer()
                for c in carpetas:
                    recursivo = "temp" not in c.name.lower()   # Temp es ruidosa: solo su primer nivel
                    obs.schedule(_Manejador(self), str(c), recursive=recursivo)
                obs.daemon = True
                obs.start()
                self._observador = obs
            except Exception:  # noqa: BLE001
                log.exception("watchdog no pudo arrancar; se usa sondeo")
                self._observador = None
        objetivos = [self._analizador, self._procesos, self._usb, self._red]
        if self._observador is None:
            objetivos.append(self._sondeo)
        self._hilos = [threading.Thread(target=f, name=f"tr-{f.__name__}", daemon=True) for f in objetivos]
        for h in self._hilos:
            h.start()
        self._evento("sistema", "Protección en tiempo real activada", nivel="info")

    def detener(self) -> None:
        with self._lock:
            if not self.activo:
                return
            self.activo = False
        self._parar.set()
        if self._observador is not None:
            try:
                self._observador.stop()
                self._observador.join(timeout=3)
            except Exception:  # noqa: BLE001
                pass
            self._observador = None
        self._evento("sistema", "Protección en tiempo real desactivada", nivel="info")

    def estado(self) -> dict:
        return {"activo": self.activo, "carpetas": self.carpetas, "desde": self.desde,
                "motor_eventos": "watchdog (instantáneo)" if self._observador else "sondeo cada 4 s",
                "analizados": self.analizados, "amenazas": self.amenazas}

    # ── eventos
    def _evento(self, tipo: str, texto: str, *, nivel: str = "limpio", ruta: str | None = None,
                accion: str | None = None, extra: dict | None = None) -> None:
        self.eventos.appendleft({"hora": time.time(), "tipo": tipo, "texto": texto, "nivel": nivel,
                                 "ruta": ruta, "accion": accion, **(extra or {})})

    def aviso(self, ruta: str) -> None:
        baja = ruta.lower()
        if baja.endswith(TEMPORALES_NAVEGADOR) or str(ajustes.carpeta()).lower() in baja:
            return
        if Path(ruta).suffix.lower() not in motor.EXT_RIESGO and Path(ruta).suffix:
            return
        with self._lock:
            self._pendientes[ruta] = time.time()

    # ── hilo: analiza lo que ya terminó de escribirse
    def _analizador(self) -> None:
        sistema.hilo_en_segundo_plano()
        tamanos: dict[str, int] = {}
        while not self._parar.wait(0.5):
            ahora = time.time()
            with self._lock:
                listos = [r for r, t in self._pendientes.items() if ahora - t >= ESPERA_ESTABLE]
            for ruta in listos:
                p = Path(ruta)
                try:
                    tam = p.stat().st_size
                except OSError:
                    with self._lock:
                        self._pendientes.pop(ruta, None)
                    continue
                if tamanos.get(ruta) != tam:          # aún está creciendo: esperar otra vuelta
                    tamanos[ruta] = tam
                    with self._lock:
                        self._pendientes[ruta] = ahora
                    continue
                with self._lock:
                    self._pendientes.pop(ruta, None)
                tamanos.pop(ruta, None)
                if len(self._ventana) == MAX_POR_MINUTO and ahora - self._ventana[0] < 60:
                    continue                          # tormenta: el análisis programado lo cubrirá
                self._ventana.append(ahora)
                self.revisar(p, "archivo")

    def revisar(self, ruta: Path, origen: str, pid: int | None = None) -> dict | None:
        from app.local.escaner import escaner
        conf = ajustes.leer()
        v = motor.analizar_archivo(ruta, firmas=firmas_base(), exclusiones=set(conf["exclusiones_sha256"]),
                                   defender=bool(conf["segunda_opinion_defender"]))
        if v is None:
            return None
        self.analizados += 1
        if v.nivel == "limpio":
            if origen == "archivo":
                self._evento(origen, f"Revisado: {ruta.name}", ruta=str(ruta))
            return v.a_dict()
        self.amenazas += 1
        hallazgo = {**v.a_dict(), "origen": origen, "estado": "detectado", "hora": time.time()}
        if v.accion == "aislar" and conf["cuarentena_automatica"] and self.user_id:
            hallazgo.update(escaner.aislar(self.user_id, hallazgo, pid))
        accion = {"aislado": "Aislado en cuarentena", "no_aislado": "No se pudo aislar"}.get(
            hallazgo["estado"], "Requiere su decisión")
        self._evento(origen, f"{v.nivel.capitalize()}: {ruta.name}", nivel=v.nivel, ruta=str(ruta), accion=accion,
                     extra={"motivos": v.motivos[:3], "familia": v.familia, "sha256": v.sha256,
                            "estado": hallazgo["estado"]})
        self._alertar(hallazgo)
        return hallazgo

    def _alertar(self, h: dict) -> None:
        if not self.user_id:
            return
        from app.db.session import SessionLocal
        from app.services.alerts import raise_alert
        db = SessionLocal()
        try:
            raise_alert(db, user_id=self.user_id, category="app",
                        severity="high" if h["nivel"] == "malicioso" else "medium",
                        title=f"Tiempo real: {h['nombre']} es {h['nivel']}",
                        description=("Aislado en cuarentena. " if h["estado"] == "aislado" else "")
                        + "; ".join(h["motivos"][:3]),
                        data={"sha256": h["sha256"], "ruta": h["ruta"][:300]}, engine=motor.MOTOR_LOCAL,
                        notify=h["nivel"] == "malicioso")
            db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
        finally:
            db.close()

    # ── hilo: programas que arrancan
    def _procesos(self) -> None:
        sistema.hilo_en_segundo_plano()
        conocidos = {pid for pid, _, _ in sistema.procesos()}
        revisados: dict[str, float] = {}
        while not self._parar.wait(3):
            actuales = sistema.procesos()
            for pid, nombre, exe in actuales:
                if pid in conocidos:
                    continue
                clave = str(exe).lower()
                if clave in revisados and time.time() - revisados[clave] < 3600:
                    continue                          # el mismo programa, abierto otra vez
                revisados[clave] = time.time()
                if sistema.intocable(exe):
                    continue
                h = self.revisar(exe, "proceso", pid)
                if h and h["nivel"] != "limpio":
                    log.warning("Proceso %s (%s): %s", nombre, pid, h["nivel"])
            conocidos = {pid for pid, _, _ in actuales}
            if len(revisados) > 5000:
                revisados.clear()

    # ── hilo: memorias USB
    def _usb(self) -> None:
        from app.local.escaner import escaner
        previas = sistema.unidades_extraibles()
        while not self._parar.wait(5):
            actuales = sistema.unidades_extraibles()
            for unidad in sorted(actuales - previas):
                self._evento("usb", f"Memoria conectada: {unidad}", nivel="info", ruta=unidad)
                if self.user_id and not escaner.ocupado():
                    try:
                        escaner.iniciar(self.user_id, "usb", unidad, origen="usb")
                        self._evento("usb", f"Analizando {unidad} automáticamente", nivel="info", ruta=unidad)
                    except (RuntimeError, ValueError) as e:
                        self._evento("usb", f"No se pudo analizar {unidad}: {e}", nivel="info", ruta=unidad)
            previas = actuales

    # ── hilo: vigilancia de la red (conexiones peligrosas nuevas)
    def _red(self) -> None:
        """Cada minuto revisa si aparecieron conexiones a puertos de malware o cambios de DNS.

        Es liviano: no analiza cada paquete (eso requeriría un driver de red), sino que observa las
        conexiones establecidas, que es donde una puerta trasera se hace visible.
        """
        from app.local import red as _red
        avisados: set = set()
        while not self._parar.wait(60):
            try:
                estado = _red.revisar_todo()
            except Exception:  # noqa: BLE001
                continue
            for h in estado.get("hallazgos", []):
                if h["nivel"] not in ("peligroso", "sospechoso"):
                    continue
                clave = (h["categoria"], str(h["datos"]))
                if clave in avisados:
                    continue
                avisados.add(clave)
                self._evento("red", h["titulo"], nivel="malicioso" if h["nivel"] == "peligroso" else "sospechoso",
                             extra={"detalle": h["detalle"], "categoria": h["categoria"]})
                if h["nivel"] == "peligroso" and self.user_id:
                    self._alertar_texto(f"Red: {h['titulo']}", h["detalle"])
            if len(avisados) > 500:
                avisados.clear()

    def _alertar_texto(self, titulo: str, detalle: str) -> None:
        from app.db.session import SessionLocal
        from app.services.alerts import raise_alert
        db = SessionLocal()
        try:
            raise_alert(db, user_id=self.user_id, category="app", severity="high", title=titulo,
                        description=detalle[:300], engine="red-1.0.0", notify=True)
            db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
        finally:
            db.close()

    # ── respaldo sin watchdog
    def _sondeo(self) -> None:
        vistos: dict[str, float] = {}
        primera = True
        while not self._parar.wait(4):
            for c in self.carpetas:
                try:
                    for e in Path(c).iterdir():
                        if not e.is_file():
                            continue
                        m = e.stat().st_mtime
                        if vistos.get(str(e)) != m:
                            vistos[str(e)] = m
                            if not primera:
                                self.aviso(str(e))
                except OSError:
                    continue
            primera = False


vigilante = Vigilante()
