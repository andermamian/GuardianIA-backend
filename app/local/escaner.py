"""El escáner del equipo: recorre el disco, analiza en paralelo y publica su progreso.

Cómo está armado (y por qué):

  ┌───────────────┐   cola acotada   ┌──────────────────────┐
  │ recorredor    │ ───────────────▶ │ N hilos de análisis  │──▶ veredictos, cuarentena
  │ (os.scandir)  │                  │ (prioridad «fondo»)  │
  └───────────────┘                  └──────────────────────┘
          ▲                                    ▲
          └──────── controlador (1 s): mide la CPU que usan LOS DEMÁS programas y
                    ajusta cuántos hilos trabajan; calcula velocidad y tiempo restante.

* **Productor–consumidor.** En el análisis completo no se espera a listar todo el disco para
  empezar: se analiza mientras se recorre. En el rápido y el personalizado sí se lista primero, para
  revisar lo más riesgoso antes (ejecutables recientes en Descargas, por ejemplo).
* **La CPU se mide descontando la propia.** Si el escáner midiera la CPU total, se vería a sí mismo
  ocupado y se frenaría solo. Lo que importa es si USTED está usando el equipo.
* **Caché de lo ya revisado.** Un archivo que no cambió (misma fecha y tamaño) y que salió limpio con
  la misma versión de motor y de firmas no se vuelve a leer. El segundo análisis completo tarda una
  fracción del primero. Si las firmas se actualizan, la caché se invalida sola.
* **Todo es interrumpible.** Pausar, reanudar y detener responden en menos de medio segundo.
"""
from __future__ import annotations

import logging
import os
import queue
import sqlite3
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from app.local import ajustes, cuarentena, motor, sistema
from app.local.firmas import base as firmas_base

log = logging.getLogger("guardian.escaner")

MODOS = ("rapido", "completo", "personalizado", "usb")
LIMITE_RAPIDO = 30_000
_FIN = object()


# ═══════════════════════════════════════════════════ caché de lo ya revisado
class Cache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._con = sqlite3.connect(str(ajustes.sub("cache") / "revisados.sqlite"), check_same_thread=False)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute("CREATE TABLE IF NOT EXISTS revisados (ruta TEXT PRIMARY KEY, huella TEXT NOT NULL)")
        self._pendientes: list[tuple[str, str]] = []

    def limpio(self, ruta: str, huella: str) -> bool:
        with self._lock:
            fila = self._con.execute("SELECT huella FROM revisados WHERE ruta = ?", (ruta,)).fetchone()
        return bool(fila and fila[0] == huella)

    def marcar(self, ruta: str, huella: str) -> None:
        with self._lock:
            self._pendientes.append((ruta, huella))
            if len(self._pendientes) >= 500:
                self._volcar()

    def _volcar(self) -> None:
        if self._pendientes:
            self._con.executemany("INSERT OR REPLACE INTO revisados VALUES (?, ?)", self._pendientes)
            self._con.commit()
            self._pendientes.clear()

    def volcar(self) -> None:
        with self._lock:
            self._volcar()

    def borrar(self) -> None:
        with self._lock:
            self._pendientes.clear()
            self._con.execute("DELETE FROM revisados")
            self._con.commit()


def _huella(tamano: int, mtime_ns: int) -> str:
    return f"{mtime_ns}:{tamano}:{motor.MOTOR_LOCAL}:{firmas_base().version}"


# ═══════════════════════════════════════════════════════ un análisis
class Analisis:
    def __init__(self, user_id: str, modo: str, rutas: list[Path], rendimiento: str, origen: str) -> None:
        self.id = str(uuid.uuid4())
        self.user_id = user_id
        self.modo = modo
        self.rutas = rutas
        self.rendimiento = rendimiento
        self.origen = origen
        self.lock = threading.Lock()
        self.cancelado = threading.Event()
        self.corriendo = threading.Event()
        self.corriendo.set()
        self.estado = "preparando"
        self.iniciado = time.time()
        self.terminado: float | None = None
        self.enumeracion_completa = False
        self.descubiertos = 0
        self.bytes_descubiertos = 0
        self.analizados = 0
        self.bytes_analizados = 0
        self.en_cache = 0
        self.omitidos = 0
        self.limpios = 0
        self.sospechosos = 0
        self.maliciosos = 0
        self.aislados = 0
        self.actual = ""
        self.fase = "Preparando el análisis"
        self.amenazas: list[dict] = []
        self.max_hilos = self._hilos_maximos()
        self.hilos = self.max_hilos
        self.cpu_otros = 0.0
        self.cpu_total = 0.0
        self.muestras: deque[tuple[float, int, int]] = deque(maxlen=12)
        self.error: str | None = None
        self.pausado_total = 0.0
        self._pausa_desde: float | None = None

    def _hilos_maximos(self) -> int:
        n = sistema.nucleos()
        if self.rendimiento == "turbo":
            return max(2, min(10, n - 2))
        if self.rendimiento == "silencioso":
            return 2
        # Ryzen 7 (8 núcleos / 16 hilos) → 6. Más no ayuda: parte del análisis retiene el GIL de Python.
        return max(2, min(8, n // 2 - 2))

    # ── velocidades
    def _tasas(self) -> tuple[float, float]:
        if len(self.muestras) < 2:
            return 0.0, 0.0
        (t0, a0, b0), (t1, a1, b1) = self.muestras[0], self.muestras[-1]
        dt = max(t1 - t0, 1e-6)
        return (a1 - a0) / dt, (b1 - b0) / dt

    def instantanea(self, con_amenazas: bool = True) -> dict:
        with self.lock:
            archivos_s, bytes_s = self._tasas()
            total = self.descubiertos if self.enumeracion_completa else None
            if total:
                porcentaje = min(100.0, 100.0 * self.analizados / total)
            elif self.descubiertos:
                porcentaje = min(99.0, 100.0 * self.analizados / self.descubiertos)
            else:
                porcentaje = 0.0
            if self.estado in ("terminado", "cancelado"):
                porcentaje = 100.0 if self.estado == "terminado" else porcentaje
            eta = None
            if self.enumeracion_completa and self.estado == "analizando":
                restantes_b = max(0, self.bytes_descubiertos - self.bytes_analizados)
                restantes_a = max(0, self.descubiertos - self.analizados)
                if bytes_s > 1024:
                    eta = restantes_b / bytes_s
                elif archivos_s > 0.1:
                    eta = restantes_a / archivos_s
            fin = self.terminado or time.time()
            pausado = self.pausado_total + (time.time() - self._pausa_desde if self._pausa_desde else 0)
            return {
                "id": self.id, "modo": self.modo, "origen": self.origen, "estado": self.estado, "fase": self.fase,
                "rutas": [str(r) for r in self.rutas][:10], "iniciado": self.iniciado, "terminado": self.terminado,
                "transcurrido_s": round(max(0.0, fin - self.iniciado - pausado), 1),
                "porcentaje": round(porcentaje, 1), "porcentaje_estimado": not self.enumeracion_completa,
                "descubiertos": self.descubiertos, "total": total, "analizados": self.analizados,
                "en_cache": self.en_cache, "omitidos": self.omitidos,
                "bytes_total": self.bytes_descubiertos if self.enumeracion_completa else None,
                "bytes_analizados": self.bytes_analizados,
                "limpios": self.limpios, "sospechosos": self.sospechosos, "maliciosos": self.maliciosos,
                "aislados": self.aislados, "archivo_actual": self.actual,
                "velocidad_archivos_s": round(archivos_s, 1), "velocidad_mb_s": round(bytes_s / 1048576, 2),
                "eta_s": None if eta is None else round(eta), "hilos": self.hilos, "hilos_max": self.max_hilos,
                "cpu_equipo": self.cpu_total, "cpu_otros": self.cpu_otros, "rendimiento": self.rendimiento,
                "amenazas": list(self.amenazas[-200:]) if con_amenazas else len(self.amenazas),
                "error": self.error,
            }


# ═══════════════════════════════════════════════════════ el escáner
class Escaner:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._db_lock = threading.Lock()
        self.actual: Analisis | None = None
        self.ultimo: dict | None = None
        self._cache: Cache | None = None
        self._programador: threading.Thread | None = None
        self._parar = threading.Event()

    @property
    def cache(self) -> Cache:
        # Con candado: sin él, seis hilos que arrancan a la vez podían crear seis cachés distintas y
        # las marcas de las descartadas se perdían (el siguiente análisis releía esos archivos).
        if self._cache is None:
            with self._lock:
                if self._cache is None:
                    self._cache = Cache()
        return self._cache

    # ── control
    def ocupado(self) -> bool:
        return self.actual is not None and self.actual.estado not in ("terminado", "cancelado", "error")

    def iniciar(self, user_id: str, modo: str, ruta: str | None = None, rendimiento: str | None = None,
                origen: str = "manual") -> dict:
        if modo not in MODOS:
            raise ValueError("Modo de análisis desconocido")
        with self._lock:
            if self.ocupado():
                raise RuntimeError("Ya hay un análisis en curso: deténgalo o espere a que termine")
            rutas = self._rutas(modo, ruta)
            if not rutas:
                raise ValueError("No hay carpetas que analizar")
            a = Analisis(user_id, modo, rutas, rendimiento or ajustes.leer()["rendimiento"], origen)
            self.actual = a
        threading.Thread(target=self._ejecutar, args=(a,), name=f"escaneo-{modo}", daemon=True).start()
        return a.instantanea()

    def _rutas(self, modo: str, ruta: str | None) -> list[Path]:
        if modo in ("personalizado", "usb"):
            if not ruta:
                raise ValueError("Indique la carpeta o unidad a analizar")
            p = Path(os.path.expandvars(ruta.strip().strip('"'))).expanduser()
            if not p.is_absolute() or not p.exists():
                raise ValueError(f"No existe la ruta «{ruta}»")
            return [p]
        if modo == "completo":
            return sistema.unidades()
        return sistema.carpetas_calientes()

    def pausar(self) -> dict:
        a = self._requerir()
        with a.lock:
            if a.estado in ("analizando", "enumerando"):
                a.corriendo.clear()
                a._estado_previo = a.estado
                a.estado, a.fase = "pausado", "En pausa"
                a._pausa_desde = time.time()
        return a.instantanea()

    def reanudar(self) -> dict:
        a = self._requerir()
        with a.lock:
            if a.estado == "pausado":
                a.estado = getattr(a, "_estado_previo", "analizando")
                a.fase = "Analizando" if a.estado == "analizando" else "Buscando archivos"
                if a._pausa_desde:
                    a.pausado_total += time.time() - a._pausa_desde
                    a._pausa_desde = None
                a.corriendo.set()
        return a.instantanea()

    def cancelar(self) -> dict:
        a = self._requerir()
        with a.lock:
            if a.estado not in ("terminado", "cancelado", "error"):
                a.estado, a.fase = "cancelando", "Deteniendo…"
                if a._pausa_desde:
                    a.pausado_total += time.time() - a._pausa_desde
                    a._pausa_desde = None
        a.cancelado.set()
        a.corriendo.set()
        return a.instantanea()

    def _requerir(self) -> Analisis:
        if self.actual is None:
            raise LookupError("No hay ningún análisis")
        return self.actual

    def instantanea(self) -> dict | None:
        if self.actual is not None:
            return self.actual.instantanea()
        return self.ultimo

    # ── ejecución
    def _ejecutar(self, a: Analisis) -> None:
        cola: queue.Queue = queue.Queue(maxsize=20_000)
        hilos = [threading.Thread(target=self._trabajador, args=(a, cola, i), name=f"analisis-{i}", daemon=True)
                 for i in range(a.max_hilos)]
        control = threading.Thread(target=self._controlador, args=(a,), name="control-escaneo", daemon=True)
        try:
            control.start()
            for h in hilos:
                h.start()
            self._enumerar(a, cola)
        except Exception as e:  # noqa: BLE001 - el análisis nunca tumba al servidor
            log.exception("Fallo en el análisis")
            a.error = f"{type(e).__name__}: {e}"
            a.cancelado.set()
            a.corriendo.set()
        finally:
            for _ in hilos:
                cola.put(_FIN)
            for h in hilos:
                h.join()
            self.cache.volcar()
            self._finalizar(a)

    def _enumerar(self, a: Analisis, cola: queue.Queue) -> None:
        ahora = time.time()
        vistos: set[str] = set()
        with a.lock:
            a.estado, a.fase = "enumerando", "Buscando archivos"

        def agregar(ruta: Path, tamano: int, mtime_ns: int, etiqueta: str, pid: int | None = None) -> bool:
            clave = str(ruta).lower() if sistema.ES_WINDOWS else str(ruta)
            if clave in vistos or tamano <= 0 or tamano > motor.MAX_ARCHIVO:
                return False
            vistos.add(clave)
            with a.lock:
                a.descubiertos += 1
                a.bytes_descubiertos += tamano
            return True

        items: list[tuple[int, tuple]] = []
        encolar_directo = a.modo == "completo"

        def emitir(item: tuple, prioridad: int = 0) -> None:
            if encolar_directo:
                while not a.cancelado.is_set():
                    try:
                        cola.put(item, timeout=0.3)
                        return
                    except queue.Full:
                        continue
            else:
                items.append((prioridad, item))

        # 1) Memoria y objetos de inicio: lo primero que revisa un antivirus de verdad.
        if a.modo in ("rapido", "completo"):
            with a.lock:
                a.fase = "Revisando programas en ejecución"
            for pid, nombre, exe in sistema.procesos():
                try:
                    st = exe.stat()
                except OSError:
                    continue
                if agregar(exe, st.st_size, st.st_mtime_ns, "memoria"):
                    emitir((exe, st.st_size, st.st_mtime_ns, f"En ejecución: {nombre}", pid), 100)
            with a.lock:
                a.fase = "Revisando programas de inicio automático"
            for origen, exe in sistema.objetos_inicio():
                try:
                    st = exe.stat()
                except OSError:
                    continue
                if agregar(exe, st.st_size, st.st_mtime_ns, "inicio"):
                    emitir((exe, st.st_size, st.st_mtime_ns, origen, None), 90)

        # 2) Recorrido de carpetas.
        profundidad = {"rapido": 4, "usb": 6}.get(a.modo, 64)
        solo_riesgo = a.modo == "rapido"
        with a.lock:
            a.fase = "Buscando archivos"
        for raiz in a.rutas:
            pila = [(raiz, 0)]
            while pila and not a.cancelado.is_set():
                a.corriendo.wait()
                carpeta, nivel = pila.pop()
                if sistema.omitir_recorrido(carpeta) or carpeta == ajustes.carpeta():
                    continue
                try:
                    entradas = list(os.scandir(carpeta))
                except (OSError, PermissionError):
                    continue
                for e in entradas:
                    try:
                        if e.is_symlink() or (hasattr(e, "is_junction") and e.is_junction()):
                            continue      # evita bucles y analizar lo mismo dos veces
                        if e.is_dir(follow_symlinks=False):
                            if nivel < profundidad and e.name not in sistema.OMITIR_NOMBRES:
                                pila.append((Path(e.path), nivel + 1))
                            continue
                        if not e.is_file(follow_symlinks=False):
                            continue
                        ruta = Path(e.path)
                        if solo_riesgo and ruta.suffix.lower() not in motor.EXT_RIESGO:
                            continue
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if agregar(ruta, st.st_size, st.st_mtime_ns, "disco"):
                        emitir((ruta, st.st_size, st.st_mtime_ns, None, None),
                               motor.prioridad(ruta, st.st_size, st.st_mtime, ahora))
                    if solo_riesgo and len(items) >= LIMITE_RAPIDO:
                        break

        if not encolar_directo:
            items.sort(key=lambda x: -x[0])
            with a.lock:
                a.enumeracion_completa = True
                if a.estado != "pausado":
                    a.estado, a.fase = "analizando", "Analizando"
            for _, item in items:
                if a.cancelado.is_set():
                    break
                cola.put(item)
        else:
            with a.lock:
                a.enumeracion_completa = True
                if a.estado != "pausado":
                    a.estado, a.fase = "analizando", "Analizando"

    def _trabajador(self, a: Analisis, cola: queue.Queue, indice: int) -> None:
        sistema.hilo_en_segundo_plano()
        firmas = firmas_base()
        conf = ajustes.leer()
        exclusiones = set(conf["exclusiones_sha256"])
        defender = bool(conf["segunda_opinion_defender"])
        while True:
            item = cola.get()
            if item is _FIN:
                return
            if a.cancelado.is_set():
                continue
            a.corriendo.wait()
            # Si el controlador redujo los hilos, los que sobran esperan su turno.
            while indice >= a.hilos and not a.cancelado.is_set():
                time.sleep(0.15)
            if a.estado == "enumerando" and a.modo == "completo":
                with a.lock:
                    if a.estado == "enumerando":
                        a.estado, a.fase = "analizando", "Analizando mientras se recorre el disco"
            try:
                self._procesar(a, item, firmas, exclusiones, defender, conf)
            except Exception:  # noqa: BLE001 - un archivo raro no puede tumbar un hilo del análisis
                log.exception("Error analizando %s", item[0])
                with a.lock:
                    a.analizados += 1
                    a.omitidos += 1

    def _procesar(self, a: Analisis, item: tuple, firmas, exclusiones: set[str], defender: bool,
                  conf: dict) -> None:
        ruta, tamano, mtime_ns, etiqueta, pid = item
        with a.lock:
            a.actual = str(ruta)
        huella = _huella(tamano, mtime_ns)
        if self.cache.limpio(str(ruta), huella):
            with a.lock:
                a.analizados += 1
                a.en_cache += 1
                a.limpios += 1
                a.bytes_analizados += tamano
            return
        v = motor.analizar_archivo(ruta, firmas=firmas, exclusiones=exclusiones, defender=defender)
        if a.rendimiento == "silencioso":
            time.sleep(0.004)
        with a.lock:
            a.analizados += 1
            a.bytes_analizados += tamano
            if v is None:
                a.omitidos += 1
                return
            if v.nivel == "limpio":
                a.limpios += 1
            elif v.nivel == "sospechoso":
                a.sospechosos += 1
            else:
                a.maliciosos += 1
        if v.nivel == "limpio":
            self.cache.marcar(str(ruta), huella)
            return
        hallazgo = {**v.a_dict(), "origen": etiqueta or "disco", "estado": "detectado", "hora": time.time()}
        if v.accion == "aislar" and conf["cuarentena_automatica"]:
            hallazgo.update(self.aislar(a.user_id, hallazgo, pid))
            if hallazgo["estado"] == "aislado":
                with a.lock:
                    a.aislados += 1
        with a.lock:
            a.amenazas.append(hallazgo)

    def aislar(self, user_id: str, hallazgo: dict, pid: int | None = None) -> dict:
        """Aísla y devuelve {estado, cuarentena_id | detalle}. Detiene el proceso si está corriendo."""
        from app.db.session import SessionLocal
        if pid:
            sistema.terminar_proceso(pid)
            time.sleep(0.3)
        with self._db_lock:
            db = SessionLocal()
            try:
                item = cuarentena.aislar(db, user_id, hallazgo)
                db.commit()
                return {"estado": "aislado", "cuarentena_id": item.id}
            except (OSError, PermissionError, FileNotFoundError) as e:
                db.rollback()
                return {"estado": "no_aislado", "detalle": str(e)[:200]}
            finally:
                db.close()

    def _controlador(self, a: Analisis) -> None:
        previo = (time.monotonic(), sum(os.times()[:2]))
        while True:
            fin = a.estado in ("terminado", "cancelado", "error")
            ahora = time.monotonic()
            propio = sum(os.times()[:2])
            total = sistema.cpu_percent()
            dt = max(ahora - previo[0], 1e-6)
            mio = 100.0 * (propio - previo[1]) / dt / sistema.nucleos()
            previo = (ahora, propio)
            otros = max(0.0, total - mio)
            with a.lock:
                a.cpu_total, a.cpu_otros = round(total, 1), round(otros, 1)
                a.muestras.append((time.time(), a.analizados, a.bytes_analizados))
                if a.rendimiento == "auto":
                    if otros > 60:
                        a.hilos = 2              # usted está trabajando: el escáner se aparta
                    elif otros > 35:
                        a.hilos = max(2, a.max_hilos // 2)
                    else:
                        a.hilos = a.max_hilos
            if fin:
                return
            time.sleep(1.0)

    def _finalizar(self, a: Analisis) -> None:
        with a.lock:
            a.terminado = time.time()
            if a.error:
                a.estado, a.fase = "error", "El análisis se detuvo por un error"
            elif a.cancelado.is_set():
                a.estado, a.fase = "cancelado", "Detenido por usted"
            else:
                a.estado, a.fase = "terminado", "Análisis terminado"
            a.actual = ""
            a.hilos = 0
        final = a.instantanea()
        self.ultimo = final
        cambios = {}
        if a.modo == "rapido" and a.estado == "terminado":
            cambios["ultimo_rapido"] = a.terminado
        if a.modo == "completo" and a.estado == "terminado":
            cambios["ultimo_completo"] = a.terminado
        if cambios:
            ajustes.guardar(cambios)
        try:
            self._registrar(a, final)
        except Exception:  # noqa: BLE001
            log.exception("No se pudo guardar el resultado del análisis")

    def _registrar(self, a: Analisis, final: dict) -> None:
        from app.core import audit
        from app.db.models import ScanRun
        from app.db.session import SessionLocal
        from app.services.alerts import raise_alert
        from app.services.realtime import hub, user_channel
        hallazgos = [{"nombre": h["nombre"][-60:], "nivel": h["nivel"], "probabilidad": h["probabilidad"],
                      "familia": h["familia"], "sha256": h["sha256"], "motivos": h["motivos"][:4],
                      "estado": h["estado"]} for h in a.amenazas]
        hallazgos.sort(key=lambda h: (h["nivel"] != "malicioso", -h["probabilidad"]))
        db = SessionLocal()
        try:
            corrida = ScanRun(user_id=a.user_id, origen="equipo", device_id=cuarentena.EQUIPO, tipo=a.modo,
                              total=a.analizados, limpios=a.limpios, sospechosos=a.sospechosos,
                              maliciosos=a.maliciosos, omitidos=a.omitidos,
                              duracion_ms=int(final["transcurrido_s"] * 1000), hallazgos=hallazgos[:20],
                              en_cuarentena=a.aislados)
            db.add(corrida)
            db.flush()
            if a.maliciosos:
                raise_alert(db, user_id=a.user_id, category="app", severity="high",
                            title=f"{a.maliciosos} amenaza(s) en su equipo",
                            description=f"Análisis {a.modo}: {a.aislados} en cuarentena. "
                                        + ", ".join(h["nombre"] for h in hallazgos[:3]),
                            data={"scan_run": corrida.id}, engine=motor.MOTOR_LOCAL)
            audit.record(db, "proteccion.escaneo_local", actor_id=a.user_id, target_type="scan_run",
                         target_id=corrida.id, detail={"modo": a.modo, "total": a.analizados,
                                                       "maliciosos": a.maliciosos, "estado": a.estado},
                         level="warning" if a.maliciosos else "info", commit=False)
            db.commit()
            hub.publish(user_channel(a.user_id), {"tipo": "escaneo", "estado": a.estado, "id": a.id,
                                                  "maliciosos": a.maliciosos})
        finally:
            db.close()

    # ── análisis automáticos
    def iniciar_programador(self) -> None:
        if self._programador and self._programador.is_alive():
            return
        self._parar.clear()
        self._programador = threading.Thread(target=self._programar, name="programador-av", daemon=True)
        self._programador.start()

    def detener(self) -> None:
        self._parar.set()
        if self.ocupado() and self.actual:
            self.actual.cancelado.set()
            self.actual.corriendo.set()

    def _programar(self) -> None:
        # Espera inicial: no arrancar un análisis en el mismo instante en que el equipo enciende.
        if self._parar.wait(180):
            return
        while not self._parar.is_set():
            try:
                self._tal_vez_analizar()
            except Exception:  # noqa: BLE001
                log.exception("Programador de análisis")
            if self._parar.wait(120):
                return

    def _tal_vez_analizar(self) -> None:
        conf = ajustes.leer()
        dueño = conf.get("propietario")
        if not dueño or self.ocupado():
            return
        ahora = time.time()
        if not conf["ultimo_completo"]:
            # Recién instalado: el completo se agenda para dentro de un ciclo, no hoy.
            ajustes.guardar({"ultimo_completo": ahora})
            conf["ultimo_completo"] = ahora
        cpu = sistema.cpu_percent()
        horas, dias = int(conf["auto_rapido_horas"] or 0), int(conf["auto_completo_dias"] or 0)
        if horas and ahora - conf["ultimo_rapido"] > horas * 3600 and cpu < 50:
            self.iniciar(dueño, "rapido", origen="automatico")
        elif dias and ahora - conf["ultimo_completo"] > dias * 86400 and cpu < 30:
            self.iniciar(dueño, "completo", origen="automatico")


escaner = Escaner()
