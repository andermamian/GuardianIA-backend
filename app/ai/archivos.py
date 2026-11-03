"""Lector universal de archivos para el asistente: fotos, videos grandes, ZIP/TAR, audio y lo que venga.

Trabaja SIEMPRE sobre una ruta en disco (el servidor recibe el archivo por partes y no lo carga entero en memoria),
así un video de varios GB o un ZIP enorme no tumban nada. De cada archivo sale:

* un ``Documento`` (texto buscable) cuyo primer párrafo es un «[RESUMEN]» con lo esencial, y
* hasta ``MAX_IMAGENES`` imágenes reducidas (fotos, fotogramas de un video) por si el modelo es de visión.

Nada se ejecuta ni se descomprime en disco: los ZIP/TAR se leen en memoria, con límites contra «bombas de
descompresión», y los archivos con posibles credenciales (.env, claves privadas) se omiten."""
from __future__ import annotations

import base64
import gzip
import io
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from app.ai import lectura
from app.ai.lectura import Documento, NoSePuedeLeer

MAX_IMAGENES = 8
MAX_MIEMBROS_LISTADOS = 400
MAX_MIEMBROS_LEIDOS = 200
MAX_LECTURA_TEXTO = 200_000          # bytes por archivo de texto dentro de un comprimido
MAX_LECTURA_OFFICE = 30 * 1024 * 1024
MAX_TOTAL_DESCOMPRIMIDO = 400 * 1024 * 1024
MAX_RATIO = 250                       # más comprimido que esto = posible bomba
MAX_PROFUNDIDAD = 2                   # ZIP dentro de ZIP
FOTOGRAMAS = 8

EXT_IMAGEN = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".heif"}
EXT_VIDEO = {".mp4", ".mov", ".mkv", ".avi", ".webm", ".m4v", ".3gp", ".flv", ".wmv", ".mpg", ".mpeg", ".ts"}
EXT_AUDIO = {".mp3", ".wav", ".ogg", ".m4a", ".aac", ".flac", ".opus", ".wma"}
EXT_TEXTO = lectura.EXT_TEXTO | {".toml", ".ini", ".cfg", ".conf", ".log", ".rst", ".tex", ".bat", ".ps1", ".r", ".m",
                                 ".swift", ".dart", ".rb", ".pl", ".lua", ".gradle", ".properties", ".vue", ".jsx",
                                 ".tsx", ".scss", ".less", ".sql", ".csv", ".tsv", ".srt", ".vtt", ".ipynb", ".svg",
                                 ".gitignore", ".dockerfile", ".makefile", ".h", ".hpp", ".kts", ".xaml", ".manifest"}
EXT_OFFICE = {".pdf": "pdf", ".docx": "docx", ".xlsx": "xlsx", ".pptx": "pptx"}
EXT_ODF = {".odt", ".ods", ".odp"}
IGNORAR = re.compile(r"(^|/)(node_modules|\.git|\.svn|__pycache__|venv|\.venv|dist|build|target|\.idea|\.gradle)(/|$)|"
                     r"(^|/)(package-lock\.json|yarn\.lock|poetry\.lock|\.DS_Store|Thumbs\.db)$", re.IGNORECASE)
SECRETOS = re.compile(r"(^|/)(\.env(\..*)?|id_rsa|id_ed25519|.*\.pem|.*\.key|.*\.pfx|.*\.p12|.*\.keystore|"
                      r"credentials(\.json)?|secrets?\.(json|ya?ml)|\.npmrc|\.pypirc)$", re.IGNORECASE)
PRIORIDAD = re.compile(r"(^|/)(readme|leeme|main|app|index|setup|requirements|package\.json|pyproject|makefile|"
                       r"dockerfile|docker-compose|config)", re.IGNORECASE)


@dataclass
class Resultado:
    documento: Documento
    imagenes: list[str] = field(default_factory=list)       # JPEG reducidos en base64
    clase: str = ""


def _ext(nombre: str) -> str:
    return Path(nombre.lower()).suffix


def _mb(n: int) -> str:
    return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{max(1, n // 1024)} KB" if n >= 1024 else f"{n} B"


def _hms(segundos: float) -> str:
    s = int(segundos)
    return f"{s // 3600}:{s % 3600 // 60:02d}:{s % 60:02d}" if s >= 3600 else f"{s // 60}:{s % 60:02d}"


def _huele_a_texto(muestra: bytes) -> bool:
    """¿Parece texto? Sin bytes nulos y casi todo imprimible: sirve para cualquier extensión (.log, .ini, sin extensión…)."""
    if not muestra or b"\x00" in muestra:
        return False
    raros = sum(1 for b in muestra if b < 9 or 13 < b < 32)
    return raros / len(muestra) < 0.02


def clase_de(ruta: Path, nombre: str, mime: str = "") -> str:
    with open(ruta, "rb") as f:
        cab = f.read(560)
    e = _ext(nombre)
    if cab.startswith(b"%PDF-"):
        return "pdf"
    if cab.startswith(b"PK\x03\x04") or cab.startswith(b"PK\x05\x06"):
        if e in EXT_OFFICE:
            return EXT_OFFICE[e]
        if e in EXT_ODF:
            return "odf"
        if e == ".epub":
            return "epub"
        return "zip"
    if cab[:2] == b"\x1f\x8b":
        return "tar" if re.search(r"\.(tar\.gz|tgz)$", nombre.lower()) else "gzip"
    if cab[257:262] == b"ustar" or re.search(r"\.(tar|tar\.bz2|tbz2?|tar\.xz|txz)$", nombre.lower()):
        return "tar"
    if cab.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if cab.startswith(b"Rar!"):
        return "rar"
    if e in EXT_IMAGEN or cab[:3] == b"\xff\xd8\xff" or cab[:8] == b"\x89PNG\r\n\x1a\n" or cab[:4] == b"RIFF" and cab[8:12] == b"WEBP":
        return "imagen"
    if e in EXT_VIDEO or mime.startswith("video/"):
        return "video"
    if e in EXT_AUDIO or mime.startswith("audio/"):
        return "audio"
    if e in (".csv", ".tsv"):
        return "csv"
    if e in EXT_TEXTO or mime.startswith("text/") or mime == "application/json" or _huele_a_texto(cab):
        return "texto"
    return "binario"


# ─────────────────────────────────────────────────────────── imágenes
def miniatura(datos: bytes, lado: int = 1280) -> str:
    """JPEG reducido en base64 (o «» si no se puede abrir)."""
    try:
        from PIL import Image, ImageOps
        img = Image.open(io.BytesIO(datos))
        img = ImageOps.exif_transpose(img)
        img.thumbnail((lado, lado))
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=82)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception:  # noqa: BLE001
        return ""


def _ocr_suave(datos: bytes) -> str:
    """OCR si hay motor; si no, o si no hay texto, cadena vacía (una foto sin texto NO es un error)."""
    try:
        texto, _, _ = lectura._imagen(datos)
        return texto.strip()
    except Exception:  # noqa: BLE001
        return ""


def _leer_imagen(ruta: Path, nombre: str) -> Resultado:
    datos = ruta.read_bytes()
    partes = []
    try:
        from PIL import Image, ExifTags
        img = Image.open(io.BytesIO(datos))
        partes.append(f"{img.width}x{img.height} px, formato {img.format or _ext(nombre).lstrip('.').upper()}")
        exif = img.getexif() if hasattr(img, "getexif") else {}
        nombres = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()} if exif else {}
        cam = " ".join(str(nombres[k]) for k in ("Make", "Model") if nombres.get(k))
        if cam:
            partes.append(f"cámara {cam}")
        if nombres.get("DateTime"):
            partes.append(f"tomada el {nombres['DateTime']}")
        try:
            if exif.get_ifd(0x8825):
                partes.append("tiene ubicación GPS incrustada")
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001
        partes.append("imagen (no se pudieron leer sus metadatos)")
    miniatura_b64 = miniatura(datos)
    ocr = _ocr_suave(datos)
    resumen = f"[RESUMEN] Imagen «{nombre}»: {', '.join(partes)}, {_mb(len(datos))}."
    if not miniatura_b64:
        resumen += " No pude abrirla para mostrársela al modelo."
    texto = resumen + (f"\n\n[Texto detectado en la imagen]\n{ocr}" if ocr else "\n\n(Sin texto legible: se describe a partir de la imagen si el modelo es de visión.)")
    return Resultado(Documento(nombre, "image/*", texto, 0, False, "imagen" + (" + OCR" if ocr else "")),
                     [miniatura_b64] if miniatura_b64 else [], "imagen")


# ─────────────────────────────────────────────────────────── video y audio
def _ffprobe(ruta: Path) -> dict:
    exe = shutil.which("ffprobe")
    if not exe:
        return {}
    try:
        r = subprocess.run([exe, "-v", "error", "-print_format", "json", "-show_format", "-show_streams", str(ruta)],
                           capture_output=True, timeout=60)
        return json.loads(r.stdout or b"{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}


def _leer_video(ruta: Path, nombre: str) -> Resultado:
    tam = ruta.stat().st_size
    info = _ffprobe(ruta)
    fmt = info.get("format", {})
    flujos = info.get("streams", [])
    if not info:
        texto = (f"[RESUMEN] Video «{nombre}», {_mb(tam)}. No pude analizarlo porque falta ffmpeg/ffprobe en este equipo "
                 "(instálelo desde https://ffmpeg.org/download.html para que lea fotogramas y subtítulos).")
        return Resultado(Documento(nombre, "video/*", texto, 0, False, "solo metadatos"), [], "video")
    dur = float(fmt.get("duration") or 0)
    v = next((s for s in flujos if s.get("codec_type") == "video"), {})
    a = next((s for s in flujos if s.get("codec_type") == "audio"), {})
    subs = [s for s in flujos if s.get("codec_type") == "subtitle"]
    fps = ""
    try:
        n, d = (v.get("avg_frame_rate") or "0/1").split("/")
        fps = f"{float(n) / float(d):.0f} fps" if float(d) else ""
    except (ValueError, ZeroDivisionError):
        pass
    desc = [f"duración {_hms(dur)}" if dur else "duración desconocida",
            f"{v.get('width', '?')}x{v.get('height', '?')}" + (f" a {fps}" if fps else ""),
            f"video {v.get('codec_name', '?')}",
            f"audio {a.get('codec_name', '?')} ({a.get('channels', '?')} canales)" if a else "sin audio",
            _mb(tam)]
    titulo = (fmt.get("tags") or {}).get("title")
    if titulo:
        desc.append(f"título «{titulo}»")

    imagenes, marcas = [], []
    exe = shutil.which("ffmpeg")
    if exe and dur > 0:
        n = max(3, min(FOTOGRAMAS, int(dur // 5) + 1))
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(n):
                t = dur * (i + 0.5) / n
                salida = Path(tmp) / f"f{i}.jpg"
                try:
                    subprocess.run([exe, "-v", "error", "-y", "-ss", f"{t:.2f}", "-i", str(ruta), "-frames:v", "1",
                                    "-vf", "scale='min(1024,iw)':-2", "-q:v", "4", str(salida)],
                                   capture_output=True, timeout=90)
                except (OSError, subprocess.SubprocessError):
                    continue
                if salida.exists() and salida.stat().st_size > 0:
                    imagenes.append(base64.b64encode(salida.read_bytes()).decode())
                    marcas.append(_hms(t))
    subtitulos = ""
    if subs and exe:
        with tempfile.TemporaryDirectory() as tmp:
            srt = Path(tmp) / "s.srt"
            try:
                subprocess.run([exe, "-v", "error", "-y", "-i", str(ruta), "-map", "0:s:0", str(srt)],
                               capture_output=True, timeout=120)
                if srt.exists():
                    crudo = srt.read_text("utf-8", "replace")
                    subtitulos = re.sub(r"\n\d+\n\d\d:\d\d:\d\d[,.]\d+ --> .*?\n", "\n", "\n" + crudo)
                    subtitulos = re.sub(r"<[^>]+>", "", subtitulos).strip()
            except (OSError, subprocess.SubprocessError):
                pass
    texto = f"[RESUMEN] Video «{nombre}»: {', '.join(desc)}."
    if imagenes:
        texto += f" Revisé {len(imagenes)} fotogramas repartidos a lo largo del video (segundos {', '.join(marcas)})."
    texto += (" Incluye subtítulos, que leí abajo." if subtitulos else
              " El audio no se transcribe (no hay motor de voz instalado): solo cuento con los fotogramas y los metadatos.")
    if subtitulos:
        texto += f"\n\n[Subtítulos]\n{subtitulos[:lectura.MAX_TEXTO]}"
    return Resultado(Documento(nombre, "video/*", texto, 0, len(subtitulos) > lectura.MAX_TEXTO,
                               "metadatos + fotogramas" + (" + subtítulos" if subtitulos else "")), imagenes, "video")


def _leer_audio(ruta: Path, nombre: str) -> Resultado:
    tam = ruta.stat().st_size
    info = _ffprobe(ruta)
    fmt = info.get("format", {})
    tags = {k.lower(): v for k, v in (fmt.get("tags") or {}).items()}
    dur = float(fmt.get("duration") or 0)
    partes = [f"duración {_hms(dur)}" if dur else "duración desconocida", _mb(tam)]
    for k, etiqueta in (("title", "título"), ("artist", "artista"), ("album", "álbum"), ("date", "fecha")):
        if tags.get(k):
            partes.append(f"{etiqueta}: {tags[k]}")
    texto = (f"[RESUMEN] Audio «{nombre}»: {', '.join(partes)}. No transcribo audio (sin motor de voz): solo cuento con "
             "estos metadatos. Si tiene la letra o la transcripción, péguela o adjúntela como texto.")
    return Resultado(Documento(nombre, "audio/*", texto, 0, False, "metadatos"), [], "audio")


# ─────────────────────────────────────────────────────────── comprimidos
class _Presupuesto:
    def __init__(self) -> None:
        self.descomprimido = 0
        self.leidos = 0
        self.imagenes: list[str] = []


def _cuerpo_de_archivo(ruta_interna: str, datos: bytes) -> tuple[str, str] | None:
    """(texto, etiqueta) de un archivo de dentro del comprimido, o None si no se puede o no conviene leerlo."""
    e = _ext(ruta_interna)
    try:
        if e in EXT_OFFICE:
            texto, _, _ = {"pdf": lectura._pdf, "docx": lectura._docx, "xlsx": lectura._xlsx,
                           "pptx": lectura._pptx}[EXT_OFFICE[e]](datos)
            return texto, EXT_OFFICE[e]
        if e in EXT_ODF or e == ".epub":
            return _odf_o_epub(datos), e.lstrip(".")
        if e == ".ipynb":
            nb = json.loads(datos.decode("utf-8", "replace"))
            celdas = [f"[{c.get('cell_type')}]\n" + "".join(c.get("source", [])) for c in nb.get("cells", [])]
            return "\n\n".join(celdas), "notebook"
        if e in (".html", ".htm"):
            html = lectura._decodificar(datos)
            html = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
            return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip(), "html"
        if e in EXT_TEXTO or _huele_a_texto(datos[:4096]):
            return lectura._decodificar(datos[:MAX_LECTURA_TEXTO]), "texto"
    except Exception:  # noqa: BLE001 - un archivo roto no debe frenar la lectura del resto
        return None
    return None


def _odf_o_epub(datos: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(datos)) as z:
        partes = []
        for n in z.namelist():
            if n.endswith(("content.xml",)) or n.endswith((".xhtml", ".html")):
                xml = z.read(n)[:3_000_000].decode("utf-8", "replace")
                xml = re.sub(r"(?is)<(script|style).*?</\1>", " ", xml)
                partes.append(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", xml)).strip())
        return "\n\n".join(partes)


def _en_trozos(ruta: str, texto: str, tam: int = 900) -> list[str]:
    """Cada trozo lleva la ruta del archivo: así cualquier fragmento recuperado dice de dónde sale."""
    trozos, actual = [], ""
    for linea in texto.replace("\r", "").split("\n"):
        if len(actual) + len(linea) + 1 > tam and actual:
            trozos.append(actual)
            actual = ""
        while len(linea) > tam:
            trozos.append(linea[:tam])
            linea = linea[tam:]
        actual += linea + "\n"
    if actual.strip():
        trozos.append(actual)
    return [f"[{ruta}]\n{t.strip()}" for t in trozos if t.strip()]


def _armar_comprimido(nombre: str, miembros: list[tuple[str, int, int]], leer, presup: _Presupuesto,
                      profundidad: int, etiqueta: str) -> tuple[list[str], dict]:
    """Recorre los miembros (ruta, tamaño, tamaño comprimido) y arma los párrafos de texto. ``leer(ruta, tope)`` da bytes."""
    por_tipo: dict[str, int] = {}
    omitidos: dict[str, int] = {"imágenes y medios": 0, "binarios": 0, "posibles credenciales": 0, "ignorados (dependencias/.git)": 0,
                                 "sospechosos (bomba de descompresión)": 0}
    arbol = []
    candidatos = []
    carpetas = set()
    for ruta, tam, comp in miembros:
        if ruta.endswith("/"):
            carpetas.add(ruta)
            continue
        e = _ext(ruta) or "(sin extensión)"
        por_tipo[e] = por_tipo.get(e, 0) + 1
        if len(arbol) < MAX_MIEMBROS_LISTADOS:
            arbol.append(f"{ruta} ({_mb(tam)})")
        if IGNORAR.search(ruta):
            omitidos["ignorados (dependencias/.git)"] += 1
        elif SECRETOS.search(ruta):
            omitidos["posibles credenciales"] += 1
        elif comp and tam / max(comp, 1) > MAX_RATIO and tam > 50 * 1024 * 1024:
            omitidos["sospechosos (bomba de descompresión)"] += 1
        elif e in EXT_IMAGEN:
            candidatos.append((ruta, tam, "imagen"))
            omitidos["imágenes y medios"] += 1
        elif e in EXT_VIDEO or e in EXT_AUDIO:
            omitidos["imágenes y medios"] += 1
        else:
            candidatos.append((ruta, tam, "texto"))
    # lo importante primero (README, main, config…), luego lo demás por orden
    candidatos.sort(key=lambda c: (0 if PRIORIDAD.search(c[0]) else 1, c[0]))
    parrafos: list[str] = []
    leidos, no_leidos = 0, []
    for ruta, tam, clase in candidatos:
        if clase == "imagen":
            if len(presup.imagenes) < 4 and tam < 8 * 1024 * 1024 and presup.descomprimido + tam < MAX_TOTAL_DESCOMPRIMIDO:
                try:
                    datos = leer(ruta, tam)
                    presup.descomprimido += len(datos)
                    mini = miniatura(datos, 1024)
                    if mini:
                        presup.imagenes.append(mini)
                        parrafos.append(f"[{ruta}]\n(Imagen incluida entre las que ve el modelo, si es de visión.)")
                except Exception:  # noqa: BLE001
                    pass
            continue
        if leidos >= MAX_MIEMBROS_LEIDOS or presup.descomprimido >= MAX_TOTAL_DESCOMPRIMIDO:
            no_leidos.append(ruta)
            continue
        tope = MAX_LECTURA_OFFICE if _ext(ruta) in EXT_OFFICE or _ext(ruta) in EXT_ODF else MAX_LECTURA_TEXTO
        if tam > tope * 5 and _ext(ruta) not in EXT_OFFICE:
            tope = MAX_LECTURA_TEXTO
        try:
            datos = leer(ruta, tope)
        except Exception:  # noqa: BLE001 - cifrado, corrupto…
            no_leidos.append(ruta + " (cifrado o dañado)")
            continue
        presup.descomprimido += len(datos)
        if datos[:4] == b"PK\x03\x04" and profundidad < MAX_PROFUNDIDAD and _ext(ruta) not in set(EXT_OFFICE) | EXT_ODF | {".epub"}:
            try:
                interno = zipfile.ZipFile(io.BytesIO(datos))
                sub, _ = _armar_comprimido(ruta, [(i.filename, i.file_size, i.compress_size) for i in interno.infolist()],
                                           lambda r, t, z=interno: z.read(r)[:t], presup, profundidad + 1, "zip")
                parrafos += [f"[{ruta}/{p[1:]}" if p.startswith("[") else p for p in sub]
                leidos += 1
                continue
            except Exception:  # noqa: BLE001
                pass
        cuerpo = _cuerpo_de_archivo(ruta, datos)
        if cuerpo is None:
            omitidos["binarios"] += 1
            continue
        texto, _ = cuerpo
        if not texto.strip():
            continue
        parrafos += _en_trozos(ruta, texto)
        leidos += 1
        presup.leidos += 1
    n_arch = len([m for m in miembros if not m[0].endswith("/")])
    tipos = ", ".join(f"{k} ×{v}" for k, v in sorted(por_tipo.items(), key=lambda kv: -kv[1])[:10])
    omit = "; ".join(f"{v} {k}" for k, v in omitidos.items() if v)
    resumen = (f"[RESUMEN] {etiqueta} «{nombre}»: {n_arch} archivos en {len(carpetas) or 1} carpeta(s)"
               f"{', tamaño descomprimido ' + _mb(sum(m[1] for m in miembros)) if miembros else ''}. Tipos: {tipos or '—'}. "
               f"Leí el contenido de {leidos} archivo(s)." + (f" No leí: {omit}." if omit else "")
               + (f" Quedaron sin leer por el límite: {len(no_leidos)}." if no_leidos else ""))
    estructura = "[ESTRUCTURA]\n" + "\n".join(arbol) + (f"\n… y {n_arch - len(arbol)} más" if n_arch > len(arbol) else "")
    return [resumen] + _trocear_estructura(estructura) + parrafos, {"leidos": leidos, "archivos": n_arch}


def _trocear_estructura(texto: str, tam: int = 1000) -> list[str]:
    lineas, salida, actual = texto.split("\n"), [], ""
    for l in lineas:
        if len(actual) + len(l) + 1 > tam and actual:
            salida.append(actual.strip())
            actual = "[ESTRUCTURA continuación]\n"
        actual += l + "\n"
    if actual.strip():
        salida.append(actual.strip())
    return salida


def _leer_zip(ruta: Path, nombre: str) -> Resultado:
    try:
        z = zipfile.ZipFile(ruta)
    except zipfile.BadZipFile as e:
        raise NoSePuedeLeer("El ZIP está dañado o no es un ZIP válido") from e
    infos = z.infolist()
    if len(infos) > 50_000:
        raise NoSePuedeLeer("El ZIP tiene demasiados archivos (más de 50 000); divídalo en partes")
    presup = _Presupuesto()

    def leer(r: str, tope: int, z=z) -> bytes:
        with z.open(r) as f:
            return f.read(tope)
    parrafos, meta = _armar_comprimido(nombre, [(i.filename, i.file_size, i.compress_size) for i in infos], leer, presup, 0,
                                       "Archivo ZIP")
    return _resultado_comprimido(nombre, "application/zip", parrafos, presup, "zip")


def _leer_tar(ruta: Path, nombre: str) -> Resultado:
    try:
        t = tarfile.open(ruta, "r:*")
    except (tarfile.TarError, OSError) as e:
        raise NoSePuedeLeer("No pude abrir el archivo TAR/TGZ (¿está dañado?)") from e
    miembros = [m for m in t.getmembers() if m.isfile()]
    if len(miembros) > 50_000:
        raise NoSePuedeLeer("El archivo tiene demasiados elementos (más de 50 000); divídalo en partes")
    por_nombre = {m.name: m for m in miembros}
    presup = _Presupuesto()

    def leer(r: str, tope: int) -> bytes:
        f = t.extractfile(por_nombre[r])
        return f.read(tope) if f else b""
    parrafos, _ = _armar_comprimido(nombre, [(m.name, m.size, 0) for m in miembros], leer, presup, 0, "Archivo TAR")
    t.close()
    return _resultado_comprimido(nombre, "application/x-tar", parrafos, presup, "tar")


def _leer_gzip(ruta: Path, nombre: str) -> Resultado:
    with gzip.open(ruta, "rb") as f:
        datos = f.read(MAX_LECTURA_TEXTO * 5)
    interno = re.sub(r"\.gz$", "", nombre, flags=re.IGNORECASE)
    cuerpo = _cuerpo_de_archivo(interno, datos)
    if not cuerpo:
        raise NoSePuedeLeer(f"El .gz contiene datos binarios que no sé leer ({_mb(len(datos))} descomprimidos)")
    parrafos = [f"[RESUMEN] Archivo comprimido «{nombre}» con un solo archivo ({interno})."] + _en_trozos(interno, cuerpo[0])
    return _resultado_comprimido(nombre, "application/gzip", parrafos, _Presupuesto(), "gzip")


def _resultado_comprimido(nombre: str, mime: str, parrafos: list[str], presup: _Presupuesto, clase: str) -> Resultado:
    texto = "\n\n".join(parrafos)
    truncado = len(texto) > lectura.MAX_TEXTO
    return Resultado(Documento(nombre, mime, texto[:lectura.MAX_TEXTO], 0, truncado, f"{clase} ({presup.leidos} archivos leídos)"),
                     presup.imagenes, clase)


# ─────────────────────────────────────────────────────────── entrada
TOPE_DOC_MB = 100            # un PDF/Word/Excel mayor de esto no se lee entero en memoria


def leer(ruta: Path, nombre: str, mime: str = "") -> Resultado:
    """Lee cualquier archivo desde disco. Lanza NoSePuedeLeer solo cuando de verdad no hay nada que ofrecer."""
    clase = clase_de(ruta, nombre, mime)
    tam = ruta.stat().st_size
    if tam == 0:
        raise NoSePuedeLeer("El archivo está vacío")
    if clase == "imagen":
        return _leer_imagen(ruta, nombre)
    if clase == "video":
        return _leer_video(ruta, nombre)
    if clase == "audio":
        return _leer_audio(ruta, nombre)
    if clase == "zip":
        return _leer_zip(ruta, nombre)
    if clase == "tar":
        return _leer_tar(ruta, nombre)
    if clase == "gzip":
        return _leer_gzip(ruta, nombre)
    if clase in ("7z", "rar"):
        raise NoSePuedeLeer(f"Los archivos .{clase} no se pueden abrir aquí. Conviértalo a ZIP (o TAR.GZ) y vuelva a adjuntarlo.")
    if clase in ("pdf", "docx", "xlsx", "pptx", "odf", "epub"):
        if tam > TOPE_DOC_MB * 1048576:
            raise NoSePuedeLeer(f"Este documento pesa {_mb(tam)}; para leerlo entero el límite es {TOPE_DOC_MB} MB. Adjunte una parte.")
        datos = ruta.read_bytes()
        if clase in ("odf", "epub"):
            texto = _odf_o_epub(datos)
            if not texto.strip():
                raise NoSePuedeLeer("No encontré texto en el documento")
            doc = Documento(nombre, mime, texto[:lectura.MAX_TEXTO], 0, len(texto) > lectura.MAX_TEXTO, clase.upper())
            doc.fragmentos = lectura.fragmentar(doc.texto)
            return Resultado(doc, [], clase)
        doc = lectura.extraer(nombre, mime or {"pdf": "application/pdf", "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                                "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                                "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation"}[clase], datos)
        return Resultado(doc, [], clase)
    if clase in ("texto", "csv"):
        with open(ruta, "rb") as f:
            datos = f.read(lectura.MAX_TEXTO * 4)
        cuerpo = _cuerpo_de_archivo(nombre, datos) if clase == "texto" else None
        if clase == "csv":
            texto, pag, met = lectura._csv(datos)
        else:
            texto, met = (cuerpo or (lectura._decodificar(datos), "texto"))[0], "texto"
        if not texto.strip():
            raise NoSePuedeLeer("El archivo no tiene texto")
        truncado = tam > lectura.MAX_TEXTO * 4 or len(texto) > lectura.MAX_TEXTO
        doc = Documento(nombre, mime or "text/plain", texto[:lectura.MAX_TEXTO], 0, truncado, met)
        doc.fragmentos = lectura.fragmentar(doc.texto)
        return Resultado(doc, [], clase)
    # Binario desconocido: no se finge que se leyó, pero la conversación puede seguir con lo que sí se sabe.
    with open(ruta, "rb") as f:
        cab = f.read(16)
    texto = (f"[RESUMEN] Archivo «{nombre}», {_mb(tam)}, formato binario que no sé leer (primeros bytes: {cab.hex(' ')}). "
             "Solo cuento con su nombre y tamaño; si me dice qué es o lo convierte a un formato común (PDF, texto, ZIP), lo leo.")
    doc = Documento(nombre, mime or "application/octet-stream", texto, 0, False, "solo metadatos")
    doc.fragmentos = [texto]
    return Resultado(doc, [], "binario")
