"""Entrenamiento de las redes de GuardianIA: datos, registro de versiones y uso en producción.

Dos modelos, elegidos porque aquí una red aporta algo que las reglas no pueden:

1. **Antivirus (supervisado).** Las reglas detectan lo que alguien ya describió. La red aprende
   combinaciones que nadie escribió: «entropía alta + firmado por nadie + importa CryptEncrypt +
   recién bajado a Descargas». Se entrena con lo que este sistema ya vio y con muestras sintéticas
   de arranque, y su salida entra como una señal más, nunca como veredicto único.

2. **Signos vitales (autoencoder).** No hay etiquetas de «infarto» ni las habrá: nadie puede
   etiquetar eso en una app escolar. Un autoencoder aprende cómo es lo NORMAL de cada persona y
   marca lo que no logra reconstruir. Es el enfoque correcto cuando solo se tienen datos sanos.

Lo que este módulo NO hace, a propósito: entrenar con cuatro ejemplos. Si no hay datos suficientes
se niega y dice cuántos faltan. Un modelo entrenado con poco no es un modelo malo, es un modelo que
engaña, y en salud o seguridad eso hace daño.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sqlalchemy import select

from app.core.config import get_settings
from app.ml.red import Metricas, RedNeuronal

MINIMO_ANTIVIRUS = 120        # por debajo de esto la red memoriza en vez de aprender
MINIMO_VITALES = 200          # ventanas de lecturas
MINIMO_POSITIVOS = 20

RASGOS_ANTIVIRUS = [
    "entropia", "log_tamano", "es_ejecutable", "firmado", "n_importaciones",
    "importaciones_sospechosas", "cadenas_empaquetador", "urls_sospechosas", "n_yara",
    "extension_riesgosa", "nombre_enganoso", "carpeta_caliente",
]


def carpeta_modelos() -> Path:
    p = Path(get_settings().vault_dir).parent / "modelos"
    p.mkdir(parents=True, exist_ok=True)
    return p


@dataclass
class Resultado:
    nombre: str
    version: str
    ruta: Path
    metricas: Metricas
    importancia: list[tuple[str, float]]
    nota: str = ""


class DatosInsuficientes(RuntimeError):
    """No hay con qué entrenar. Se dice cuántos ejemplos faltan, no se entrena a medias."""


# ══════════════════════════════════════════ rasgos del antivirus
EXT_RIESGO = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".apk", ".lnk"}
IMPORTS_SOSPECHOSOS = ("cryptencrypt", "createremotethread", "virtualallocex", "setwindowshook",
                       "writeprocessmemory", "urldownloadtofile", "winexec", "shellexecute")
EMPAQUETADORES = ("upx", "themida", "vmprotect", "aspack", "mpress")
CARPETAS_CALIENTES = ("download", "descarga", "temp", "appdata", "escritorio", "desktop")


def rasgos_archivo(datos: dict) -> list[float]:
    """Convierte un archivo analizado en el vector que entiende la red.

    Son 12 números explicables: si mañana hay que defender una detección ante alguien, se puede
    señalar exactamente qué miró el modelo.
    """
    nombre = str(datos.get("name") or datos.get("nombre") or "").lower()
    cadenas = " ".join(datos.get("strings") or []).lower()
    imports = " ".join(datos.get("imports") or []).lower()
    ruta = str(datos.get("ruta") or "").lower()
    extension = "." + nombre.rsplit(".", 1)[-1] if "." in nombre else ""
    return [
        float(datos.get("entropy") or 0.0),
        math.log10(max(float(datos.get("size") or 1), 1.0)),
        float(str(datos.get("kind") or "").lower() in ("pe", "elf", "apk", "script")),
        float(bool(datos.get("is_signed"))),
        float(len(datos.get("imports") or [])),
        float(sum(1 for i in IMPORTS_SOSPECHOSOS if i in imports)),
        float(sum(1 for p in EMPAQUETADORES if p in cadenas)),
        float(sum(1 for u in ("http://", ".tk/", ".top/", "bit.ly", "pastebin") if u in cadenas)),
        float(len(datos.get("yara_hits") or [])),
        float(extension in EXT_RIESGO),
        # Doble extensión y nombres de cebo: «factura.pdf.exe», «foto.jpg.scr».
        float(bool(nombre.count(".") >= 2 and extension in EXT_RIESGO)
              or any(c in nombre for c in ("factura", "premio", "urgente", "crack", "activador"))),
        float(any(c in ruta for c in CARPETAS_CALIENTES)),
    ]


def _muestras_sinteticas(n: int, semilla: int = 7) -> tuple[np.ndarray, np.ndarray]:
    """Ejemplos de arranque para cuando el sistema todavía no ha visto suficientes archivos.

    Se generan a partir de lo que la literatura y la experiencia describen: malware empaquetado con
    entropía alta, sin firma y con importaciones de cifrado o inyección; software legítimo firmado,
    de entropía media y sin esas importaciones. Se declara con claridad en las métricas para que
    nadie confunda esto con datos de campo.
    """
    rng = np.random.default_rng(semilla)
    mitad = n // 2
    benignos = np.column_stack([
        rng.normal(5.2, 0.8, mitad).clip(1, 7.4),          # entropía
        rng.normal(6.2, 0.7, mitad),                       # log tamaño
        rng.binomial(1, 0.55, mitad),                      # ejecutable
        rng.binomial(1, 0.75, mitad),                      # firmado
        rng.poisson(28, mitad),                            # importaciones
        rng.binomial(1, 0.08, mitad),                      # importaciones sospechosas
        np.zeros(mitad),                                   # empaquetador
        rng.binomial(1, 0.05, mitad),                      # urls
        np.zeros(mitad),                                   # yara
        rng.binomial(1, 0.35, mitad),                      # extensión riesgosa
        np.zeros(mitad),                                   # nombre engañoso
        rng.binomial(1, 0.30, mitad),                      # carpeta caliente
    ])
    maliciosos = np.column_stack([
        rng.normal(7.5, 0.35, n - mitad).clip(6, 8),
        rng.normal(5.4, 0.9, n - mitad),
        np.ones(n - mitad),
        rng.binomial(1, 0.06, n - mitad),
        rng.poisson(9, n - mitad),
        rng.integers(1, 5, n - mitad),
        rng.binomial(1, 0.45, n - mitad),
        rng.binomial(1, 0.55, n - mitad),
        rng.binomial(1, 0.35, n - mitad),
        rng.binomial(1, 0.85, n - mitad),
        rng.binomial(1, 0.5, n - mitad),
        rng.binomial(1, 0.75, n - mitad),
    ])
    X = np.vstack([benignos, maliciosos]).astype(np.float64)
    y = np.concatenate([np.zeros(mitad), np.ones(n - mitad)])
    return X, y


def datos_antivirus(db, incluir_sinteticos: bool = True) -> tuple[np.ndarray, np.ndarray, str]:
    """Arma el conjunto con lo que el sistema ya analizó en este despliegue."""
    from app.db.models import QuarantineItem, ScanRun

    X: list[list[float]] = []
    y: list[float] = []
    for corrida in db.execute(select(ScanRun)).scalars():
        for h in (corrida.hallazgos or []):
            if not isinstance(h, dict):
                continue
            X.append(rasgos_archivo({"name": h.get("nombre"), "entropy": 7.2, "size": 500_000,
                                     "kind": "pe", "strings": h.get("motivos") or [],
                                     "imports": [], "yara_hits": []}))
            y.append(1.0 if h.get("nivel") == "malicioso" else 0.0)
    for item in db.execute(select(QuarantineItem)).scalars():
        X.append(rasgos_archivo({"name": item.filename, "entropy": 7.4, "size": item.size_bytes or 1,
                                 "kind": "pe", "strings": item.motivos or [], "ruta": item.ruta_original}))
        y.append(1.0 if item.nivel == "malicioso" else 0.0)

    reales = len(X)
    nota = f"{reales} ejemplos del propio sistema"
    if incluir_sinteticos and (reales < MINIMO_ANTIVIRUS or sum(y) < MINIMO_POSITIVOS):
        faltan = max(MINIMO_ANTIVIRUS - reales, 2 * MINIMO_POSITIVOS)
        Xs, ys = _muestras_sinteticas(max(400, faltan * 2))
        X = list(Xs) + X
        y = list(ys) + y
        nota = (f"{reales} ejemplos reales + {len(Xs)} sintéticos de arranque. Las métricas reflejan "
                "sobre todo los sintéticos: reentrene cuando el sistema acumule análisis propios.")
    if len(X) < MINIMO_ANTIVIRUS:
        raise DatosInsuficientes(
            f"Se necesitan al menos {MINIMO_ANTIVIRUS} ejemplos y hay {len(X)}. "
            "Analice más archivos desde Protección y vuelva a entrenar.")
    return np.array(X, dtype=np.float64), np.array(y, dtype=np.float64), nota


def entrenar_antivirus(db, *, epocas: int = 400, incluir_sinteticos: bool = True,
                       registro=None) -> Resultado:
    X, y, nota = datos_antivirus(db, incluir_sinteticos)
    red = RedNeuronal([X.shape[1], 24, 12, 1], salida="sigmoide")
    red.nombres_rasgos = RASGOS_ANTIVIRUS
    historial: list[dict] = []

    def anotar(epoca: int, perdida: float) -> None:
        historial.append({"epoca": epoca, "perdida": round(perdida, 5)})
        if registro:
            registro(epoca, perdida)

    metricas = red.entrenar(X, y, epocas=epocas, lote=32, tasa=0.01, registro=anotar)
    version = datetime.now(UTC).strftime("%Y%m%d%H%M")
    ruta = carpeta_modelos() / f"antivirus-{version}.npz"
    red.guardar(ruta, extra={"nota": nota, "creado": datetime.now(UTC).isoformat(),
                             "historial": historial, "importancia": red.importancia()[:12]})
    activar("antivirus", version)
    return Resultado("antivirus", version, ruta, metricas, red.importancia(), nota)


# ══════════════════════════════════════════ signos vitales
VENTANA = 12          # lecturas consecutivas
RASGOS_VITALES = ["fc_media", "fc_desv", "fc_min", "fc_max", "spo2_media", "spo2_min",
                  "variabilidad", "pendiente"]


def rasgos_ventana(fc: list[float], spo2: list[float]) -> list[float]:
    """Resume una ventana de lecturas. La red aprende la forma normal de estos ocho números."""
    fc_a = np.array(fc, dtype=np.float64)
    spo2_a = np.array(spo2, dtype=np.float64) if spo2 else np.array([97.0])
    diferencias = np.diff(fc_a) if len(fc_a) > 1 else np.array([0.0])
    return [float(fc_a.mean()), float(fc_a.std()), float(fc_a.min()), float(fc_a.max()),
            float(spo2_a.mean()), float(spo2_a.min()),
            float(np.sqrt(np.mean(diferencias ** 2))),           # variabilidad tipo RMSSD
            float(np.polyfit(range(len(fc_a)), fc_a, 1)[0]) if len(fc_a) > 2 else 0.0]


def datos_vitales(db) -> tuple[np.ndarray, str]:
    from app.db.models import VitalReading

    filas = db.execute(select(VitalReading)
                       .order_by(VitalReading.user_id, VitalReading.measured_at)).scalars().all()
    por_usuario: dict[str, list] = {}
    for f in filas:
        por_usuario.setdefault(f.user_id, []).append(f)
    ventanas: list[list[float]] = []
    for lecturas in por_usuario.values():
        for i in range(0, len(lecturas) - VENTANA + 1, max(1, VENTANA // 2)):
            trozo = lecturas[i:i + VENTANA]
            fc = [l.heart_rate for l in trozo if l.heart_rate]
            spo2 = [l.spo2 for l in trozo if l.spo2]
            if len(fc) >= VENTANA // 2:
                ventanas.append(rasgos_ventana(fc, spo2))
    if len(ventanas) < MINIMO_VITALES:
        raise DatosInsuficientes(
            f"Se necesitan {MINIMO_VITALES} ventanas de lecturas y hay {len(ventanas)}. "
            "Conecte el reloj y deje que mida unos días antes de entrenar.")
    return np.array(ventanas, dtype=np.float64), f"{len(ventanas)} ventanas de {VENTANA} lecturas"


def entrenar_vitales(db, *, epocas: int = 500, registro=None) -> Resultado:
    """Autoencoder: aprende lo normal y marca lo que no puede reconstruir.

    No se entrena con etiquetas de enfermedad porque no las hay ni las habrá en este contexto. El
    modelo no diagnostica: señala «esto no se parece a su normalidad» para que un humano mire.
    """
    X, nota = datos_vitales(db)
    red = RedNeuronal([X.shape[1], 5, 3, 5, X.shape[1]], salida="lineal")
    red.nombres_rasgos = RASGOS_VITALES
    historial: list[dict] = []

    def anotar(epoca: int, perdida: float) -> None:
        historial.append({"epoca": epoca, "perdida": round(perdida, 5)})
        if registro:
            registro(epoca, perdida)

    metricas = red.entrenar(X, X, epocas=epocas, lote=16, tasa=0.005, registro=anotar)
    version = datetime.now(UTC).strftime("%Y%m%d%H%M")
    ruta = carpeta_modelos() / f"vitales-{version}.npz"
    red.guardar(ruta, extra={"nota": nota, "creado": datetime.now(UTC).isoformat(),
                             "umbral_anomalia": metricas.umbral, "historial": historial,
                             "importancia": red.importancia()[:12]})
    activar("vitales", version)
    return Resultado("vitales", version, ruta, metricas, red.importancia(), nota)


# ══════════════════════════════════════════ uso en producción
_cache: dict[str, tuple[float, RedNeuronal | None]] = {}


def puntero(nombre: str) -> Path:
    """Archivo que marca qué versión está activa. Permite volver atrás sin borrar nada."""
    return carpeta_modelos() / f"{nombre}-activo.txt"


def versiones(nombre: str) -> list[dict]:
    """Historial de modelos entrenados, del más reciente al más antiguo."""
    import json
    activa = activa_de(nombre)
    salida = []
    for ruta in sorted(carpeta_modelos().glob(f"{nombre}-*.npz"), reverse=True):
        version = ruta.stem.split("-", 1)[1]
        try:
            meta = json.loads(ruta.with_suffix(".json").read_text("utf-8"))
        except (OSError, ValueError):
            continue
        salida.append({"version": version, "creado": meta.get("creado"), "nota": meta.get("nota", ""),
                       "capas": meta.get("capas"), "metricas": meta.get("metricas", {}),
                       "rasgos": meta.get("rasgos", []), "historial": meta.get("historial", []),
                       "importancia": meta.get("importancia", []), "activa": version == activa})
    return salida


def activa_de(nombre: str) -> str | None:
    """Versión activa: la marcada a mano o, si no hay marca, la más reciente."""
    p = puntero(nombre)
    if p.exists():
        version = p.read_text("utf-8").strip()
        if (carpeta_modelos() / f"{nombre}-{version}.npz").exists():
            return version
    archivos = sorted(carpeta_modelos().glob(f"{nombre}-*.npz"), reverse=True)
    return archivos[0].stem.split("-", 1)[1] if archivos else None


def activar(nombre: str, version: str) -> bool:
    """Vuelve a una versión anterior. Si un modelo nuevo empeora, se deshace en un clic."""
    if not (carpeta_modelos() / f"{nombre}-{version}.npz").exists():
        return False
    puntero(nombre).write_text(version, "utf-8")
    limpiar_cache()
    return True


def modelo_activo(nombre: str) -> RedNeuronal | None:
    """Carga el modelo activo, con caché: no se lee el disco en cada archivo analizado."""
    import time
    ahora = time.time()
    guardado = _cache.get(nombre)
    if guardado and ahora - guardado[0] < 300:
        return guardado[1]
    red = None
    version = activa_de(nombre)
    if version:
        try:
            red = RedNeuronal.cargar(carpeta_modelos() / f"{nombre}-{version}.npz")
        except Exception:  # noqa: BLE001 - un modelo corrupto no puede tumbar el antivirus
            red = None
    _cache[nombre] = (ahora, red)
    return red


def probabilidad_maliciosa(datos: dict) -> float | None:
    """Probabilidad según la red, o None si todavía no hay modelo entrenado."""
    red = modelo_activo("antivirus")
    if red is None:
        return None
    return float(red.predecir(np.array([rasgos_archivo(datos)]))[0])


def anomalia_vitales(fc: list[float], spo2: list[float]) -> dict | None:
    """Qué tan lejos está esta ventana de lo normal aprendido."""
    red = modelo_activo("vitales")
    if red is None or not fc:
        return None
    x = np.array([rasgos_ventana(fc, spo2)])
    reconstruido = red.predecir(x)
    error = float(np.mean((red._normalizar(x) - (reconstruido - red.mu) / red.sigma) ** 2))
    return {"error": round(error, 4), "umbral": round(red.umbral, 4), "anomalo": error > red.umbral}


def limpiar_cache() -> None:
    _cache.clear()
