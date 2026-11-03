"""Red neuronal multicapa escrita desde cero con NumPy.

Por qué propia y no PyTorch o TensorFlow: en el equipo donde corre GuardianIA (un portátil, sin GPU)
esas librerías pesan entre 800 MB y 2 GB y no aportan nada para redes de este tamaño. Aquí caben en
un archivo, el entrenamiento tarda segundos, y cada línea es explicable ante un jurado. Para el
problema que tenemos —unas decenas de rasgos y miles de ejemplos— una MLP bien entrenada rinde igual
que un framework pesado.

Qué incluye, y por qué cada pieza:

* **Inicialización He** en capas ReLU: con pesos mal escalados la señal se desvanece o explota.
* **Adam**: adapta el paso por parámetro; con datos de escalas distintas converge mucho antes que un
  descenso de gradiente simple.
* **Normalización aprendida de los datos** (media y desviación del conjunto de entrenamiento,
  guardadas con el modelo): sin esto, la entropía (0 a 8) y el tamaño en bytes (millones) compiten
  de forma absurda.
* **Pesos por clase**: en seguridad los positivos son raros. Sin compensar, la red aprende a decir
  «limpio» siempre y acierta el 98 % siendo inútil.
* **Parada temprana** sobre un conjunto de validación: el punto donde deja de aprender y empieza a
  memorizar.
* **Umbral elegido por F1**, no 0,5 por costumbre: en detección, mover el umbral cambia por completo
  cuántas amenazas se escapan y cuántos falsos positivos molestan.

Limitación dicha de frente: una red entrenada con pocos datos generaliza mal. Por eso el módulo de
entrenamiento se niega a entrenar con menos ejemplos de los razonables en vez de producir un modelo
que aparenta funcionar.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

VERSION_FORMATO = 1


@dataclass
class Metricas:
    """Lo que de verdad importa medir en un detector, no solo la exactitud."""
    exactitud: float = 0.0
    precision: float = 0.0
    sensibilidad: float = 0.0       # recall: de las amenazas reales, cuántas detecta
    f1: float = 0.0
    auc: float = 0.0
    umbral: float = 0.5
    matriz: list[list[int]] = field(default_factory=list)   # [[VN, FP], [FN, VP]]
    ejemplos_entrenamiento: int = 0
    ejemplos_validacion: int = 0
    epocas: int = 0
    perdida_final: float = 0.0

    def to_dict(self) -> dict:
        return {"exactitud": round(self.exactitud, 4), "precision": round(self.precision, 4),
                "sensibilidad": round(self.sensibilidad, 4), "f1": round(self.f1, 4),
                "auc": round(self.auc, 4), "umbral": round(self.umbral, 3), "matriz": self.matriz,
                "ejemplos_entrenamiento": self.ejemplos_entrenamiento,
                "ejemplos_validacion": self.ejemplos_validacion, "epocas": self.epocas,
                "perdida_final": round(self.perdida_final, 5)}


def _softmax(z: np.ndarray) -> np.ndarray:
    """Softmax estable: se resta el máximo antes de exponenciar para no desbordar."""
    z = z - z.max(axis=1, keepdims=True)
    exp = np.exp(z)
    return exp / exp.sum(axis=1, keepdims=True)


def _sigmoide(z: np.ndarray) -> np.ndarray:
    # Formulación estable: exp de números grandes desborda y produce NaN silenciosos.
    positivo = z >= 0
    salida = np.empty_like(z, dtype=np.float64)
    salida[positivo] = 1.0 / (1.0 + np.exp(-z[positivo]))
    exp_z = np.exp(z[~positivo])
    salida[~positivo] = exp_z / (1.0 + exp_z)
    return salida


class RedNeuronal:
    """MLP con salida sigmoide (clasificación binaria) o lineal (reconstrucción).

    capas=[10, 16, 8, 1] significa 10 rasgos de entrada, dos capas ocultas y una salida.
    """

    def __init__(self, capas: list[int], *, salida: str = "sigmoide", semilla: int = 42,
                 l2: float = 1e-4):
        # salida: "sigmoide" (binaria) | "lineal" (reconstrucción) | "softmax" (varias clases)
        if len(capas) < 2:
            raise ValueError("Se necesitan al menos capa de entrada y de salida")
        self.capas = list(capas)
        self.salida = salida
        self.l2 = l2
        rng = np.random.default_rng(semilla)
        self.W: list[np.ndarray] = []
        self.b: list[np.ndarray] = []
        for entrada, sal in zip(capas[:-1], capas[1:]):
            # He: varianza 2/n_entradas, la adecuada cuando la activación es ReLU.
            self.W.append(rng.normal(0, np.sqrt(2.0 / entrada), size=(entrada, sal)))
            self.b.append(np.zeros(sal))
        self.mu = np.zeros(capas[0])
        self.sigma = np.ones(capas[0])
        self.umbral = 0.5
        self.metricas = Metricas()
        self.nombres_rasgos: list[str] = []

    # ───────────────────────────────────────────── propagación
    def _normalizar(self, X: np.ndarray) -> np.ndarray:
        return (X - self.mu) / self.sigma

    def _adelante(self, X: np.ndarray) -> tuple[np.ndarray, list[np.ndarray], list[np.ndarray]]:
        activaciones = [X]
        preactivaciones: list[np.ndarray] = []
        a = X
        for i, (W, b) in enumerate(zip(self.W, self.b)):
            z = a @ W + b
            preactivaciones.append(z)
            ultima = i == len(self.W) - 1
            if ultima:
                if self.salida == "sigmoide":
                    a = _sigmoide(z)
                elif self.salida == "softmax":
                    a = _softmax(z)
                else:
                    a = z
            else:
                a = np.maximum(0.0, z)      # ReLU
            activaciones.append(a)
        return a, activaciones, preactivaciones

    def predecir(self, X: np.ndarray) -> np.ndarray:
        """Probabilidad (sigmoide) o reconstrucción (lineal). Acepta una muestra o muchas."""
        X = np.atleast_2d(np.asarray(X, dtype=np.float64))
        salida, _, _ = self._adelante(self._normalizar(X))
        return salida.ravel() if self.salida == "sigmoide" else salida

    def clasificar(self, X: np.ndarray) -> np.ndarray:
        return (self.predecir(X) >= self.umbral).astype(int)

    # ───────────────────────────────────────────── entrenamiento
    def entrenar(self, X: np.ndarray, y: np.ndarray, *, epocas: int = 300, lote: int = 32,
                 tasa: float = 0.01, validacion: float = 0.25, paciencia: int = 30,
                 pesos_clase: bool = True, semilla: int = 42, registro=None,
                 datos_validacion: tuple[np.ndarray, np.ndarray] | None = None) -> Metricas:
        """datos_validacion permite pasar un conjunto separado desde fuera.

        Hace falta cuando los datos se aumentan: si las variantes de una misma frase caen en
        entrenamiento y en validación, la red ya vio casi el mismo ejemplo y las métricas salen
        infladas. Separar antes de aumentar es la única forma de medir de verdad.
        """
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y, dtype=np.float64)
        if self.salida == "softmax":
            # Etiquetas de clase (0,1,2…) a one-hot: es lo que compara la entropía cruzada.
            if y.ndim == 1:
                clases = self.capas[-1]
                unos = np.zeros((len(y), clases))
                unos[np.arange(len(y)), y.astype(int)] = 1.0
                y = unos
        else:
            y = y.ravel()
        rng = np.random.default_rng(semilla)
        orden = rng.permutation(len(X))
        X, y = X[orden], y[orden]

        if datos_validacion is not None:
            Xtr, ytr = X, y
            Xva = np.asarray(datos_validacion[0], dtype=np.float64)
            yva = np.asarray(datos_validacion[1], dtype=np.float64)
            if self.salida == "softmax" and yva.ndim == 1:
                unos = np.zeros((len(yva), self.capas[-1]))
                unos[np.arange(len(yva)), yva.astype(int)] = 1.0
                yva = unos
        else:
            corte = max(1, int(len(X) * (1 - validacion)))
            Xtr, ytr, Xva, yva = X[:corte], y[:corte], X[corte:], y[corte:]

        # La normalización se aprende SOLO del entrenamiento: usar todo el conjunto filtra
        # información de validación y las métricas salen infladas.
        self.mu = Xtr.mean(axis=0)
        self.sigma = np.where(Xtr.std(axis=0) < 1e-8, 1.0, Xtr.std(axis=0))
        Xtr_n, Xva_n = self._normalizar(Xtr), self._normalizar(Xva)

        peso_pos = 1.0
        if pesos_clase and self.salida == "sigmoide":
            positivos = max(1.0, ytr.sum())
            peso_pos = float((len(ytr) - positivos) / positivos)
            peso_pos = float(np.clip(peso_pos, 0.2, 20.0))   # sin esto, un dataset muy sesgado desborda

        mW = [np.zeros_like(W) for W in self.W]
        vW = [np.zeros_like(W) for W in self.W]
        mb = [np.zeros_like(b) for b in self.b]
        vb = [np.zeros_like(b) for b in self.b]
        beta1, beta2, eps = 0.9, 0.999, 1e-8
        paso = 0
        mejor_perdida, mejores_pesos, sin_mejorar, epocas_hechas = np.inf, None, 0, 0

        for epoca in range(1, epocas + 1):
            epocas_hechas = epoca
            indices = rng.permutation(len(Xtr_n))
            for inicio in range(0, len(indices), lote):
                trozo = indices[inicio:inicio + lote]
                xb, yb = Xtr_n[trozo], ytr[trozo]
                salida, activaciones, preactivaciones = self._adelante(xb)
                salida = salida.ravel() if self.salida == "sigmoide" else salida

                if self.salida == "sigmoide":
                    pesos = np.where(yb > 0.5, peso_pos, 1.0)
                    # Derivada de la entropía cruzada con sigmoide: se simplifica a (ŷ - y).
                    delta = ((salida - yb) * pesos / len(xb)).reshape(-1, 1)
                elif self.salida == "softmax":
                    # Con softmax + entropía cruzada la derivada también es (ŷ - y).
                    delta = (salida - yb) / len(xb)
                else:
                    delta = 2.0 * (salida - yb.reshape(salida.shape)) / len(xb)

                paso += 1
                for capa in range(len(self.W) - 1, -1, -1):
                    gW = activaciones[capa].T @ delta + self.l2 * self.W[capa]
                    gb = delta.sum(axis=0)
                    if capa > 0:
                        delta = (delta @ self.W[capa].T) * (preactivaciones[capa - 1] > 0)
                    # Adam
                    mW[capa] = beta1 * mW[capa] + (1 - beta1) * gW
                    vW[capa] = beta2 * vW[capa] + (1 - beta2) * (gW ** 2)
                    mb[capa] = beta1 * mb[capa] + (1 - beta1) * gb
                    vb[capa] = beta2 * vb[capa] + (1 - beta2) * (gb ** 2)
                    mW_c = mW[capa] / (1 - beta1 ** paso)
                    vW_c = vW[capa] / (1 - beta2 ** paso)
                    mb_c = mb[capa] / (1 - beta1 ** paso)
                    vb_c = vb[capa] / (1 - beta2 ** paso)
                    self.W[capa] -= tasa * mW_c / (np.sqrt(vW_c) + eps)
                    self.b[capa] -= tasa * mb_c / (np.sqrt(vb_c) + eps)

            perdida = self._perdida(Xva_n, yva) if len(Xva_n) else self._perdida(Xtr_n, ytr)
            if registro and epoca % 25 == 0:
                registro(epoca, perdida)
            if perdida < mejor_perdida - 1e-5:
                mejor_perdida = perdida
                mejores_pesos = ([W.copy() for W in self.W], [b.copy() for b in self.b])
                sin_mejorar = 0
            else:
                sin_mejorar += 1
                if sin_mejorar >= paciencia:
                    break                     # deja de aprender y empieza a memorizar

        if mejores_pesos:
            self.W, self.b = mejores_pesos

        self.metricas = self._evaluar(Xva if len(Xva) else Xtr, yva if len(yva) else ytr)
        self.metricas.ejemplos_entrenamiento = int(len(Xtr))
        self.metricas.ejemplos_validacion = int(len(Xva))
        self.metricas.epocas = epocas_hechas
        self.metricas.perdida_final = float(mejor_perdida)
        return self.metricas

    def _perdida(self, Xn: np.ndarray, y: np.ndarray) -> float:
        salida, _, _ = self._adelante(Xn)
        if self.salida == "softmax":
            p = np.clip(salida, 1e-9, 1.0)
            return float(-np.mean(np.sum(y * np.log(p), axis=1)))
        if self.salida == "sigmoide":
            p = np.clip(salida.ravel(), 1e-9, 1 - 1e-9)
            return float(-np.mean(y * np.log(p) + (1 - y) * np.log(1 - p)))
        return float(np.mean((salida - y.reshape(salida.shape)) ** 2))

    # ───────────────────────────────────────────── evaluación
    def _evaluar(self, X: np.ndarray, y: np.ndarray) -> Metricas:
        if self.salida == "softmax":
            reales = y.argmax(axis=1) if y.ndim > 1 else y.astype(int)
            predichas = self.predecir(X).argmax(axis=1)
            clases = self.capas[-1]
            matriz = [[int(((reales == i) & (predichas == j)).sum()) for j in range(clases)]
                      for i in range(clases)]
            # F1 macro: promedia por clase, así una clase rara no queda escondida tras la mayoritaria.
            f1s = []
            for c in range(clases):
                vp = matriz[c][c]
                fp = sum(matriz[r][c] for r in range(clases)) - vp
                fn = sum(matriz[c]) - vp
                prec = vp / (vp + fp) if vp + fp else 0.0
                sens = vp / (vp + fn) if vp + fn else 0.0
                f1s.append(2 * prec * sens / (prec + sens) if prec + sens else 0.0)
            return Metricas(exactitud=float((reales == predichas).mean()),
                            precision=float(np.mean(f1s)), sensibilidad=float(np.mean(f1s)),
                            f1=float(np.mean(f1s)), matriz=matriz)
        if self.salida != "sigmoide":
            errores = np.mean((self.predecir(X) - X) ** 2, axis=1)
            m = Metricas(umbral=float(np.percentile(errores, 95)))
            return m
        p = self.predecir(X)
        self.umbral = self._mejor_umbral(y, p)
        pred = (p >= self.umbral).astype(int)
        vp = int(((pred == 1) & (y == 1)).sum())
        vn = int(((pred == 0) & (y == 0)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        precision = vp / (vp + fp) if vp + fp else 0.0
        sensibilidad = vp / (vp + fn) if vp + fn else 0.0
        f1 = 2 * precision * sensibilidad / (precision + sensibilidad) if precision + sensibilidad else 0.0
        return Metricas(exactitud=(vp + vn) / max(1, len(y)), precision=precision,
                        sensibilidad=sensibilidad, f1=f1, auc=self._auc(y, p),
                        umbral=float(self.umbral), matriz=[[vn, fp], [fn, vp]])

    @staticmethod
    def _mejor_umbral(y: np.ndarray, p: np.ndarray) -> float:
        """El 0,5 es una convención, no una decisión. Aquí se elige el umbral con mejor F1."""
        mejor, mejor_f1 = 0.5, -1.0
        for umbral in np.unique(np.round(np.concatenate([p, [0.5]]), 3)):
            pred = (p >= umbral).astype(int)
            vp = ((pred == 1) & (y == 1)).sum()
            fp = ((pred == 1) & (y == 0)).sum()
            fn = ((pred == 0) & (y == 1)).sum()
            precision = vp / (vp + fp) if vp + fp else 0.0
            sens = vp / (vp + fn) if vp + fn else 0.0
            f1 = 2 * precision * sens / (precision + sens) if precision + sens else 0.0
            if f1 > mejor_f1:
                mejor, mejor_f1 = float(umbral), float(f1)
        return mejor

    @staticmethod
    def _auc(y: np.ndarray, p: np.ndarray) -> float:
        """AUC por el método de rangos (Mann-Whitney): no depende del umbral elegido."""
        positivos, negativos = p[y == 1], p[y == 0]
        if not len(positivos) or not len(negativos):
            return 0.0
        orden = np.argsort(np.concatenate([positivos, negativos]))
        rangos = np.empty(len(orden), dtype=np.float64)
        rangos[orden] = np.arange(1, len(orden) + 1)
        suma_pos = rangos[:len(positivos)].sum()
        return float((suma_pos - len(positivos) * (len(positivos) + 1) / 2) / (len(positivos) * len(negativos)))

    # ───────────────────────────────────────────── persistencia
    def guardar(self, ruta: Path, extra: dict | None = None) -> Path:
        ruta.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(ruta, **{f"W{i}": W for i, W in enumerate(self.W)},
                            **{f"b{i}": b for i, b in enumerate(self.b)}, mu=self.mu, sigma=self.sigma)
        meta = {"formato": VERSION_FORMATO, "capas": self.capas, "salida": self.salida,
                "umbral": float(self.umbral), "l2": self.l2, "rasgos": self.nombres_rasgos,
                "metricas": self.metricas.to_dict(), **(extra or {})}
        ruta.with_suffix(".json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), "utf-8")
        return ruta

    @classmethod
    def cargar(cls, ruta: Path) -> RedNeuronal:
        meta = json.loads(ruta.with_suffix(".json").read_text("utf-8"))
        red = cls(meta["capas"], salida=meta.get("salida", "sigmoide"), l2=meta.get("l2", 1e-4))
        datos = np.load(ruta)
        red.W = [datos[f"W{i}"] for i in range(len(red.capas) - 1)]
        red.b = [datos[f"b{i}"] for i in range(len(red.capas) - 1)]
        red.mu, red.sigma = datos["mu"], datos["sigma"]
        red.umbral = meta.get("umbral", 0.5)
        red.nombres_rasgos = meta.get("rasgos", [])
        m = meta.get("metricas", {})
        red.metricas = Metricas(**{k: v for k, v in m.items() if k in Metricas.__annotations__})
        return red

    def importancia(self) -> list[tuple[str, float]]:
        """Qué rasgos pesan más, por la magnitud de los pesos de la primera capa.

        No es SHAP, y no pretende serlo: es una aproximación honesta y barata que sirve para
        explicarle a alguien por qué el modelo mira lo que mira.
        """
        pesos = np.abs(self.W[0]).sum(axis=1)
        total = pesos.sum() or 1.0
        nombres = self.nombres_rasgos or [f"rasgo_{i}" for i in range(len(pesos))]
        pares = sorted(zip(nombres, (pesos / total).tolist()), key=lambda x: -x[1])
        return [(n, round(v, 4)) for n, v in pares]
