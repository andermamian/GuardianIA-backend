"""Red neuronal de intención para el Asistente AI.

Qué resuelve. Hoy la intención se decide con expresiones regulares, y eso falla con la forma en que
la gente escribe de verdad: «crea un word ocn un plan clase», «asme una tabla de notaz», «q hago si
me robaron el celu». Una regla exige la palabra exacta; una red entrenada con n-gramas de caracteres
tolera el error de tipeo, la tilde faltante y la abreviatura.

Cómo está hecha, y por qué así:

* **N-gramas de caracteres (3 y 4) con hashing a 512 dimensiones.** No se usa un vocabulario fijo de
  palabras porque una palabra nueva o mal escrita quedaría fuera; los trozos de tres letras de
  «planilla» y «planila» se parecen casi todos. El hashing evita guardar un diccionario y mantiene
  el vector de tamaño constante.
* **MLP con softmax** sobre 8 intenciones. Es un problema pequeño y separable: no hace falta un
  transformer para esto, y uno no cabría en el equipo del usuario.
* **Corpus semilla en español de Colombia**, con la forma en que escriben docentes y usuarios
  reales, incluidos los errores frecuentes.

Límite dicho de frente: esta red decide *qué quiere* la persona, no *qué contestar*. La respuesta la
sigue escribiendo el modelo de lenguaje. Y para la intención de crisis, la red NUNCA reemplaza a las
reglas de seguridad: solo puede añadir sospecha, nunca quitarla, porque un falso negativo ahí se
mide en vidas.
"""
from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from app.ml.red import RedNeuronal

DIMENSIONES = 256   # menos dimensiones = menos dispersión, clave con un corpus pequeño
NGRAMAS = (3, 4)

INTENCIONES = ["crear_archivo", "codigo", "seguridad", "salud", "dispositivo", "emergencia",
               "charla", "conocimiento"]

# Corpus semilla: frases reales, con los errores de tipeo que la gente comete.
CORPUS: dict[str, list[str]] = {
    "crear_archivo": [
        "hazme un excel con las notas de mi curso", "crea un word con el plan de clase",
        "crea un word ocn un plan clase del cuento la bella y la bestia",
        "necesito una presentacion de 6 diapositivas para la sustentacion",
        "genera un pdf con la circular para los padres", "asme una tabla de notaz en excel",
        "quiero una planilla de asistencia", "diseñame un afiche para el dia del agua",
        "elabora un informe en word sobre el prae", "hazme un grafico de barras con esas cifras",
        "genera un codigo qr con el enlace del aula virtual", "crea una cancion para la clase",
        "necesito un acta de reunion de padres", "hazme un cronograma en excel del cuarto periodo",
        "arma una presentacion sobre el sistema solar", "quiero un word de 30 hojas del plan anual",
        "crea un documento con el proyecto pedagogico", "hazme una ficha de trabajo para segundo",
    ],
    "codigo": [
        "escribeme un programa en python que ordene una lista", "como hago un bucle for en java",
        "necesito una consulta sql para sacar promedios", "hazme una funcion que valide un correo",
        "corrigeme este codigo que me da error", "como conecto python con mysql",
        "escribe una app en flutter para tomar asistencia", "que significa este error de javascript",
        "hazme una pagina html con un formulario", "programa un juego sencillo en python",
        "como uso git para subir mi proyecto", "necesito un script de powershell que renombre archivos",
        "explicame que hace esta clase de kotlin", "hazme una api con fastapi",
    ],
    "seguridad": [
        "este enlace es seguro", "me llego un correo raro del banco", "que es el phishing",
        "como pongo una contraseña segura", "revisa este archivo que me mandaron",
        "creo que me hackearon el facebook", "como activo la verificacion en dos pasos",
        "es seguro conectarme al wifi del centro comercial", "me pidieron un codigo por whatsapp",
        "que hago si di mi clave por telefono", "este apk es confiable",
        "como se si tengo virus en el computador", "analiza mis aplicaciones",
    ],
    "salud": [
        "que significa tener 120 pulsaciones", "mi reloj marca la oxigenacion en 92",
        "como interpreto mi frecuencia cardiaca", "me siento mareado desde ayer",
        "cuantas horas debe dormir un niño de 7 años", "que es la variabilidad cardiaca",
        "mi ritmo cardiaco sube cuando camino", "es normal tener el pulso en 55 en reposo",
        "que hago para bajar la tension", "me duele la cabeza hace tres dias",
    ],
    "dispositivo": [
        "me robaron el celular que hago", "como bloqueo mi computador a distancia",
        "perdi el telefono ayer en el bus", "quiero ubicar mi equipo",
        "como vinculo un dispositivo nuevo", "suena la alarma en mi celular perdido",
        "como borro los datos de mi telefono robado", "no aparece mi equipo en la lista",
    ],
    "emergencia": [
        "necesito ayuda urgente", "llama a mis contactos de emergencia",
        "me siento muy mal y estoy solo", "activa el boton de sos",
        "hubo un accidente en la escuela", "avisa a mi familia que estoy en el hospital",
    ],
    "charla": [
        "hola como estas", "buenos dias", "gracias por la ayuda", "que tal funcionas",
        "quien te creo", "eres una persona", "listo hasta luego", "muy bien gracias",
    ],
    "conocimiento": [
        "cuantos habitantes tiene colombia", "quien escribio cien años de soledad",
        "explicame la fotosintesis para segundo grado", "cual es la capital de mongolia",
        "como se calcula el area de un triangulo", "que paso en la batalla de boyaca",
        "cuales son los derechos basicos de aprendizaje", "explicame la division para niños",
        "que dice la ley 1620 sobre convivencia escolar", "como se hace un contrato de arrendamiento",
        "cuanto es el uvt para este año", "que vitaminas tiene la guayaba",
        "explicame como funciona un motor de combustion", "que es la norma ntc 1486",
    ],
}


def normalizar(texto: str) -> str:
    """Minúsculas, sin tildes y sin ruido: «Diséñame!!» y «disename» deben verse igual."""
    plano = unicodedata.normalize("NFKD", (texto or "").lower())
    plano = "".join(c for c in plano if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9ñ ]", " ", plano)).strip()


def vectorizar(texto: str, dimensiones: int = DIMENSIONES) -> np.ndarray:
    """Texto a vector por hashing de n-gramas de caracteres.

    Se usan trozos de 3 y 4 letras con un espacio al inicio y al final, de modo que «planilla» y
    «planila» comparten casi todos sus trozos. El signo del hash reparte las colisiones en ambos
    sentidos, que es el truco estándar para que no se acumulen.
    """
    v = np.zeros(dimensiones, dtype=np.float64)
    limpio = f" {normalizar(texto)} "
    if len(limpio) <= 2:
        return v
    for n in NGRAMAS:
        for i in range(len(limpio) - n + 1):
            trozo = limpio[i:i + n]
            h = _hash(trozo)
            v[h % dimensiones] += 1.0 if (h >> 16) % 2 else -1.0
    norma = np.linalg.norm(v)
    return v / norma if norma else v


def _hash(texto: str) -> int:
    """FNV-1a: determinista entre ejecuciones (el hash() de Python no lo es)."""
    h = 0x811C9DC5
    for b in texto.encode("utf-8"):
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


VARIANTES = 6   # cada frase genera varias versiones: es la forma de entrenar con poco corpus


def corpus_a_datos(extra: dict[str, list[str]] | None = None) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Convierte el corpus en datos, multiplicando cada frase con variantes realistas.

    Con 8 intenciones y ~100 frases, entrenar solo con el texto original da una red mediocre. El
    aumento de datos —erratas, palabras omitidas, abreviaturas— es lo que hace que aprenda la forma
    del mensaje y no las frases de memoria. Es la misma técnica que se usa en visión al rotar y
    recortar imágenes.
    """
    corpus = {k: list(v) for k, v in CORPUS.items()}
    for intencion, frases in (extra or {}).items():
        if intencion in corpus:
            corpus[intencion].extend(frases)
    X, y = [], []
    for indice, intencion in enumerate(INTENCIONES):
        for frase in corpus.get(intencion, []):
            X.append(vectorizar(frase))
            y.append(indice)
            for k in range(VARIANTES):
                X.append(vectorizar(_variar(frase, k)))
                y.append(indice)
    return np.array(X), np.array(y), INTENCIONES


def _variar(frase: str, semilla: int) -> str:
    """Genera una versión con el tipo de ruido que produce una persona escribiendo rápido."""
    rng = np.random.default_rng((abs(_hash(frase)) + semilla) % (2**32))
    texto = frase
    modo = semilla % 4
    if modo == 0 and len(texto) > 8:                      # letras cambiadas de orden
        i = int(rng.integers(1, len(texto) - 2))
        texto = texto[:i] + texto[i + 1] + texto[i] + texto[i + 2:]
    elif modo == 1 and len(texto) > 8:                    # letra omitida
        i = int(rng.integers(1, len(texto) - 1))
        texto = texto[:i] + texto[i + 1:]
    elif modo == 2:                                       # palabra omitida (mensajes telegráficos)
        palabras = texto.split()
        if len(palabras) > 3:
            del palabras[int(rng.integers(0, len(palabras)))]
        texto = " ".join(palabras)
    else:                                                 # abreviaturas frecuentes
        for largo, corto in (("que ", "q "), ("por favor", "xfa"), ("porque", "xq"),
                             ("celular", "celu"), ("computador", "compu"), ("para ", "pa ")):
            texto = texto.replace(largo, corto)
    return texto


def separar_por_frase(extra: dict[str, list[str]] | None = None, validacion: float = 0.2,
                      semilla: int = 11) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Reparte las FRASES (no las variantes) y solo después aumenta el entrenamiento.

    Si una frase y sus erratas quedan repartidas entre ambos conjuntos, la red ya vio casi el mismo
    ejemplo y la exactitud sale cercana al 100 % sin significar nada. Aquí la validación contiene
    frases que la red no vio nunca.
    """
    corpus = {k: list(v) for k, v in CORPUS.items()}
    for intencion, frases in (extra or {}).items():
        if intencion in corpus:
            corpus[intencion].extend(frases)
    rng = np.random.default_rng(semilla)
    Xtr, ytr, Xva, yva = [], [], [], []
    for indice, intencion in enumerate(INTENCIONES):
        frases = list(corpus.get(intencion, []))
        rng.shuffle(frases)
        corte = max(1, int(len(frases) * (1 - validacion)))
        for frase in frases[:corte]:
            Xtr.append(vectorizar(frase))
            ytr.append(indice)
            for k in range(VARIANTES):
                Xtr.append(vectorizar(_variar(frase, k)))
                ytr.append(indice)
        for frase in frases[corte:]:          # validación sin aumentar: texto tal cual
            Xva.append(vectorizar(frase))
            yva.append(indice)
    return np.array(Xtr), np.array(ytr), np.array(Xva), np.array(yva)


def entrenar(carpeta: Path, *, epocas: int = 350, extra: dict[str, list[str]] | None = None):
    """Entrena la red de intención y la guarda. Devuelve (red, métricas, ruta)."""
    Xtr, ytr, Xva, yva = separar_por_frase(extra)
    X, y, etiquetas = Xtr, ytr, INTENCIONES
    red = RedNeuronal([X.shape[1], 96, 48, len(etiquetas)], salida="softmax", l2=3e-4)
    red.nombres_rasgos = [f"ngrama_{i}" for i in range(X.shape[1])]
    historial: list[dict] = []
    metricas = red.entrenar(X, y, epocas=epocas, lote=32, tasa=0.008, paciencia=60,
                            datos_validacion=(Xva, yva),
                            registro=lambda e, p: historial.append({"epoca": e, "perdida": round(p, 5)}))
    version = datetime.now(UTC).strftime("%Y%m%d%H%M")
    ruta = carpeta / f"intencion-{version}.npz"
    red.guardar(ruta, extra={"intenciones": etiquetas, "ejemplos": int(len(X)), "historial": historial,
                             "nota": f"{len(etiquetas)} intenciones · corpus semilla con aumento de datos",
                             "creado": datetime.now(UTC).isoformat()})
    from app.ml.entrenamiento import activar
    activar("intencion", version)
    return red, metricas, ruta


def clasificar(texto: str, red: RedNeuronal | None) -> tuple[str, float]:
    """Devuelve (intención, confianza). Sin modelo entrenado, «desconocida» con confianza 0."""
    if red is None:
        return "desconocida", 0.0
    probabilidades = red.predecir(np.array([vectorizar(texto)]))[0]
    indice = int(np.argmax(probabilidades))
    return INTENCIONES[indice], float(probabilidades[indice])
