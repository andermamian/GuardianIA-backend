"""Lectura de archivos para el asistente: extraer, dividir y recuperar lo pertinente.

Por qué no se le manda el documento entero al modelo: un modelo local maneja unos pocos miles de
palabras de contexto. Un PDF de 50 páginas no cabe, y aunque cupiera, el modelo se pierde entre
tanto texto y responde peor. El camino correcto es el mismo que usan los asistentes grandes:

    archivo → texto → fragmentos → se recuperan los 4 o 5 más relevantes → esos van al modelo

La recuperación usa BM25, el algoritmo clásico de los buscadores, implementado aquí en unas 30
líneas: no necesita modelo de embeddings ni GPU, funciona offline y en español se comporta bien
porque pondera las palabras raras (las que de verdad distinguen un fragmento).

Formatos: PDF, Word, Excel, PowerPoint, CSV, TXT, Markdown, JSON, código e imágenes (OCR).
Las imágenes también pueden ir al modelo si es de visión; eso lo decide app/ai/assistant.py.
"""
from __future__ import annotations

import csv
import io
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field

MAX_TEXTO = 400_000       # ~200 páginas; más que eso se trunca y se avisa
MAX_FRAGMENTO = 1_200     # caracteres por fragmento
SOLAPE = 150              # continuidad entre fragmentos para no cortar una idea a la mitad

EXTRACTORES: dict[str, str] = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "text/csv": "csv", "text/plain": "texto", "text/markdown": "texto", "application/json": "texto",
    "image/jpeg": "imagen", "image/png": "imagen", "image/webp": "imagen", "image/gif": "imagen",
}
EXT_TEXTO = {".txt", ".md", ".csv", ".json", ".py", ".js", ".ts", ".java", ".kt", ".php", ".sql",
             ".html", ".css", ".xml", ".yml", ".yaml", ".sh", ".c", ".cpp", ".cs", ".go", ".rs"}


class NoSePuedeLeer(ValueError):
    """El archivo llegó bien pero no hay forma de sacarle texto. Se dice, no se finge."""


# Qué paquete hace falta para cada formato, con el nombre que se instala (no el de importación).
PAQUETES = {"pypdf": ("pypdf", "PDF"), "docx": ("python-docx", "Word"), "openpyxl": ("openpyxl", "Excel"),
            "pptx": ("python-pptx", "PowerPoint"), "PIL": ("Pillow", "imágenes"),
            "pytesseract": ("pytesseract", "OCR de imágenes")}


def _falta(modulo: str) -> NoSePuedeLeer:
    """Traduce un ModuleNotFoundError en una instrucción que la persona puede seguir.

    Mostrarle «No module named pypdf» a quien usa la app no le sirve de nada; decirle qué ejecutar, sí.
    """
    paquete, para = PAQUETES.get(modulo, (modulo, "este formato"))
    return NoSePuedeLeer(
        f"Falta instalar el lector de {para} en el servidor. En la carpeta del proyecto ejecute:  "
        f"python -m app.cli instalar-lectura   (o bien: pip install {paquete})")


@dataclass
class Documento:
    nombre: str
    mime: str
    texto: str
    paginas: int = 0
    truncado: bool = False
    metodo: str = ""          # cómo se extrajo: útil para explicárselo a la persona
    fragmentos: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────────────── extracción
def _pdf(datos: bytes) -> tuple[str, int, str]:
    try:
        from pypdf import PdfReader
    except ImportError as e:
        raise _falta("pypdf") from e
    lector = PdfReader(io.BytesIO(datos))
    if lector.is_encrypted:
        try:
            lector.decrypt("")  # PDF con contraseña vacía: común en documentos «protegidos»
        except Exception as e:  # noqa: BLE001
            raise NoSePuedeLeer("El PDF está protegido con contraseña") from e
    partes = []
    for i, pagina in enumerate(lector.pages, start=1):
        try:
            texto = pagina.extract_text() or ""
        except Exception:  # noqa: BLE001 - una página rota no puede tumbar el documento entero
            texto = ""
        if texto.strip():
            partes.append(f"[Página {i}]\n{texto.strip()}")
    if not partes:
        raise NoSePuedeLeer(
            "Este PDF no tiene texto seleccionable: probablemente es un escaneo. Conviértalo con un "
            "OCR o envíeme una foto de las páginas, que esas sí las paso por reconocimiento de texto.")
    return "\n\n".join(partes), len(lector.pages), "texto del PDF"


def _docx(datos: bytes) -> tuple[str, int, str]:
    try:
        from docx import Document as Doc
    except ImportError as e:
        raise _falta("docx") from e
    doc = Doc(io.BytesIO(datos))
    partes = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
    for t, tabla in enumerate(doc.tables, start=1):
        filas = [" | ".join(c.text.strip() for c in fila.cells) for fila in tabla.rows]
        if filas:
            partes.append(f"[Tabla {t}]\n" + "\n".join(filas))
    if not partes:
        raise NoSePuedeLeer("El documento de Word está vacío")
    return "\n\n".join(partes), 0, "texto y tablas de Word"


def _xlsx(datos: bytes) -> tuple[str, int, str]:
    try:
        from openpyxl import load_workbook
    except ImportError as e:
        raise _falta("openpyxl") from e
    wb = load_workbook(io.BytesIO(datos), data_only=True, read_only=True)  # data_only: valores, no fórmulas
    partes = []
    for ws in wb.worksheets:
        filas = []
        for fila in ws.iter_rows(values_only=True):
            valores = [str(v) for v in fila if v is not None]
            if valores:
                filas.append(" | ".join(valores))
            if len(filas) >= 400:  # una hoja enorme no aporta más contexto útil
                filas.append("… (hoja truncada)")
                break
        if filas:
            partes.append(f"[Hoja «{ws.title}»]\n" + "\n".join(filas))
    wb.close()
    if not partes:
        raise NoSePuedeLeer("La hoja de cálculo no tiene datos")
    return "\n\n".join(partes), len(partes), "celdas de Excel (valores calculados)"


def _pptx(datos: bytes) -> tuple[str, int, str]:
    try:
        from pptx import Presentation
    except ImportError as e:
        raise _falta("pptx") from e
    prs = Presentation(io.BytesIO(datos))
    partes = []
    for i, s in enumerate(prs.slides, start=1):
        textos = [f.text.strip() for f in s.shapes if getattr(f, "has_text_frame", False) and f.text.strip()]
        if s.has_notes_slide and s.notes_slide.notes_text_frame.text.strip():
            textos.append(f"(Notas: {s.notes_slide.notes_text_frame.text.strip()})")
        if textos:
            partes.append(f"[Diapositiva {i}]\n" + "\n".join(textos))
    if not partes:
        raise NoSePuedeLeer("La presentación no tiene texto")
    return "\n\n".join(partes), len(prs.slides), "texto y notas de PowerPoint"


def _csv(datos: bytes) -> tuple[str, int, str]:
    texto = _decodificar(datos)
    try:
        dialecto = csv.Sniffer().sniff(texto[:2000])
        delimitador = dialecto.delimiter
    except csv.Error:
        delimitador = ","  # separador poco común: se asume coma antes que fallar
    filas = list(csv.reader(io.StringIO(texto), delimiter=delimitador))
    lineas = [" | ".join(c.strip() for c in fila) for fila in filas[:1000] if any(c.strip() for c in fila)]
    if not lineas:
        raise NoSePuedeLeer("El CSV está vacío")
    return "\n".join(lineas), len(filas), f"CSV con {len(filas)} filas"


def _texto_plano(datos: bytes) -> tuple[str, int, str]:
    texto = _decodificar(datos)
    if not texto.strip():
        raise NoSePuedeLeer("El archivo está vacío")
    return texto, 0, "texto plano"


def _imagen(datos: bytes) -> tuple[str, int, str]:
    """OCR de la imagen. Si no hay motor instalado, se dice con claridad."""
    try:
        import pytesseract
        from PIL import Image
    except ImportError as e:
        raise _falta("pytesseract") from e
    try:
        img = Image.open(io.BytesIO(datos))
        img.load()
    except Exception as e:  # noqa: BLE001
        raise NoSePuedeLeer("No se pudo abrir la imagen") from e
    idiomas = "spa+eng" if "spa" in _idiomas_ocr() else "eng"
    try:
        texto = pytesseract.image_to_string(img, lang=idiomas).strip()
    except Exception as e:  # noqa: BLE001
        if "tesseract" in str(e).lower():
            raise NoSePuedeLeer(
                "El programa Tesseract no está instalado en este equipo (el paquete de Python solo lo usa). "
                "En Windows descárguelo de https://github.com/UB-Mannheim/tesseract/wiki y marque el idioma "
                "español durante la instalación.") from e
        raise NoSePuedeLeer(f"El OCR falló: {type(e).__name__}") from e
    if len(texto) < 10:
        raise NoSePuedeLeer(
            "No encontré texto legible en la imagen. Si es una foto de un objeto o una escena, "
            "necesita un modelo de visión (por ejemplo, ollama pull llava) para describirla.")
    aviso = "" if idiomas.startswith("spa") else (
        "\n\n[Nota: el OCR no tiene el paquete de español instalado; las tildes pueden salir mal. "
        "En Windows, instale Tesseract con el idioma español.]")
    return texto + aviso, 0, f"OCR ({idiomas})"


def _idiomas_ocr() -> set[str]:
    try:
        import pytesseract
        return set(pytesseract.get_languages(config=""))
    except Exception:  # noqa: BLE001
        return set()


def _decodificar(datos: bytes) -> str:
    for codificacion in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):  # cp1252: lo que produce Windows
        try:
            return datos.decode(codificacion)
        except UnicodeDecodeError:
            continue
    return datos.decode("utf-8", errors="replace")


def tipo_de(mime: str, nombre: str) -> str:
    if mime in EXTRACTORES:
        return EXTRACTORES[mime]
    if any(nombre.lower().endswith(ext) for ext in EXT_TEXTO):
        return "texto"
    return ""


def extraer(nombre: str, mime: str, datos: bytes) -> Documento:
    """Saca el texto del archivo. Lanza NoSePuedeLeer con un motivo entendible si no se puede."""
    clase = tipo_de(mime, nombre)
    if not clase:
        raise NoSePuedeLeer(f"No sé leer archivos de tipo «{mime or 'desconocido'}»")
    extractor = {"pdf": _pdf, "docx": _docx, "xlsx": _xlsx, "pptx": _pptx, "csv": _csv,
                 "texto": _texto_plano, "imagen": _imagen}[clase]
    texto, paginas, metodo = extractor(datos)
    truncado = len(texto) > MAX_TEXTO
    texto = texto[:MAX_TEXTO]
    doc = Documento(nombre=nombre, mime=mime, texto=texto, paginas=paginas, truncado=truncado, metodo=metodo)
    doc.fragmentos = fragmentar(texto)
    return doc


# ─────────────────────────────────────────── fragmentación y búsqueda
def fragmentar(texto: str, tamano: int = MAX_FRAGMENTO, solape: int = SOLAPE) -> list[str]:
    """Corta por párrafos, no a ciegas: así un fragmento no empieza a mitad de una frase."""
    parrafos = [p.strip() for p in re.split(r"\n\s*\n", texto) if p.strip()]
    fragmentos: list[str] = []
    actual = ""
    for parrafo in parrafos:
        if len(actual) + len(parrafo) + 2 <= tamano:
            actual = f"{actual}\n\n{parrafo}" if actual else parrafo
            continue
        if actual:
            fragmentos.append(actual)
            actual = actual[-solape:] + "\n\n" + parrafo if len(parrafo) < tamano else parrafo
        else:
            for i in range(0, len(parrafo), tamano - solape):  # párrafo gigante: se corta por tamaño
                fragmentos.append(parrafo[i:i + tamano])
            actual = ""
    if actual:
        fragmentos.append(actual)
    return fragmentos[:400]


VACIAS = {"que", "como", "para", "por", "con", "del", "las", "los", "una", "uno", "este", "esta",
          "dice", "sobre", "cual", "cuales", "donde", "cuando", "quien", "hay", "son", "ser", "mas",
          "documento", "archivo", "texto", "favor", "puedes", "podrias", "dime", "explica"}


def _tokens(texto: str) -> list[str]:
    plano = unicodedata.normalize("NFKD", texto.lower())
    plano = "".join(c for c in plano if not unicodedata.combining(c))
    return [p for p in re.findall(r"[a-z0-9ñ]{3,}", plano) if p not in VACIAS]


def buscar(pregunta: str, fragmentos: list[str], k: int = 4, presupuesto: int = 6000) -> list[tuple[int, str, float]]:
    """BM25: puntúa cada fragmento por las palabras de la pregunta, dando más peso a las raras.

    Devuelve (índice, texto, puntaje) de los mejores, respetando un presupuesto de caracteres para
    no desbordar el contexto del modelo.
    """
    if not fragmentos:
        return []
    consulta = _tokens(pregunta)
    if not consulta:
        return [(i, f, 0.0) for i, f in enumerate(fragmentos[:k])]  # sin palabras útiles: los primeros
    docs = [_tokens(f) for f in fragmentos]
    largo_medio = sum(len(d) for d in docs) / len(docs) or 1
    frecuencia_doc = Counter(t for d in docs for t in set(d))
    n = len(docs)
    k1, b = 1.5, 0.75
    puntajes = []
    for i, doc in enumerate(docs):
        tf = Counter(doc)
        puntaje = 0.0
        for termino in consulta:
            if termino not in tf:
                continue
            idf = math.log(1 + (n - frecuencia_doc[termino] + 0.5) / (frecuencia_doc[termino] + 0.5))
            numerador = tf[termino] * (k1 + 1)
            denominador = tf[termino] + k1 * (1 - b + b * len(doc) / largo_medio)
            puntaje += idf * numerador / denominador
        puntajes.append((puntaje, i))
    puntajes.sort(reverse=True)
    elegidos: list[tuple[int, str, float]] = []
    usado = 0
    for puntaje, i in puntajes[:k * 2]:
        if puntaje <= 0 and elegidos:
            break
        if usado + len(fragmentos[i]) > presupuesto:
            continue
        elegidos.append((i, fragmentos[i], round(puntaje, 2)))
        usado += len(fragmentos[i])
        if len(elegidos) >= k:
            break
    return elegidos or [(0, fragmentos[0], 0.0)]


def contexto_para(pregunta: str, documentos: list[Documento], presupuesto: int = 6000) -> tuple[str, list[dict]]:
    """Arma el texto que acompaña la pregunta y la lista de lo que se usó, para poder citarlo."""
    if not documentos:
        return "", []
    porcion = max(1500, presupuesto // len(documentos))
    bloques, usados = [], []
    for doc in documentos:
        trozos = buscar(pregunta, doc.fragmentos, k=3, presupuesto=porcion)
        if doc.fragmentos and doc.fragmentos[0].startswith("[RESUMEN]") and not any(i == 0 for i, _, _ in trozos):
            trozos = [(0, doc.fragmentos[0][:900], 0.0)] + trozos     # el resumen del archivo siempre acompaña
        for indice, texto, puntaje in trozos:
            bloques.append(f"[Documento: {doc.nombre} · fragmento {indice + 1} de {len(doc.fragmentos)}]\n{texto}")
            usados.append({"documento": doc.nombre, "fragmento": indice + 1, "relevancia": puntaje})
    return "\n\n".join(bloques), usados
