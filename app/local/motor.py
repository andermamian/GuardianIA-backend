"""Análisis de un archivo del disco: de los bytes al veredicto.

Aquí se extraen los rasgos (hash, tipo real, cadenas, entropía, importaciones, firma digital) y se
pasan al motor multicapa que ya existía (app.ai.antivirus). Encima se añaden las señales que solo
se pueden ver teniendo el archivo en la mano: doble extensión, firma alterada, accesos directos que
lanzan comandos, ZIP con ejecutables dentro, macros en documentos de Office…

Decisión clave de diseño — **quién decide aislar**:
un archivo solo se aísla solo si hay evidencia fuerte (su huella está en la base de malware, coincide
con una firma de familia conocida o Defender también lo detecta). Lo que es malicioso solo por
heurística se reporta y la persona decide. Un falso positivo que borra el instalador de un programa
legítimo hace que la gente desactive el antivirus, y un antivirus desactivado no protege nada.
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from app.ai import antivirus as av
from app.local import pe, sistema
from app.local.firmas import BaseFirmas

MOTOR_LOCAL = "local-1.0.0"
LEER_COMPLETO = 32 * 1024 * 1024        # hasta aquí se lee todo en memoria (un solo paso por el disco)
MAX_ARCHIVO = 1024 * 1024 * 1024        # más de 1 GB: solo se calcula la huella
MUESTRA_CABEZA = 2 * 1024 * 1024
MUESTRA_COLA = 512 * 1024

EXT_EJECUTABLE = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".ocx", ".sys", ".msi"}
EXT_SCRIPT = {".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".sh"}
EXT_OFFICE_ZIP = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".dotm", ".xltm"}
EXT_RIESGO = EXT_EJECUTABLE | EXT_SCRIPT | {".lnk", ".jar", ".apk", ".iso", ".img", ".vhd", ".zip", ".rar",
                                            ".7z", ".docm", ".xlsm", ".pptm", ".doc", ".xls", ".pdf", ".url"}

_DOBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|avi|zip|rar)\s*\.(exe|scr|com|pif|"
                        r"bat|cmd|js|jse|vbs|vbe|hta|wsf|lnk)$", re.I)
_ASCII = re.compile(rb"[\x20-\x7e]{6,400}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,200}")
_LNK_MALO = re.compile(r"(powershell|pwsh|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|bitsadmin|certutil)",
                       re.I)
_LNK_CARGA = re.compile(r"(-enc|-e\s|frombase64|http[s]?://|iex|invoke-|downloadstring|/c\s)", re.I)


@dataclass
class Veredicto:
    ruta: str
    nombre: str
    sha256: str
    tamano: int
    tipo: str
    nivel: str                      # limpio | sospechoso | malicioso
    probabilidad: float
    puntaje: int
    familia: str | None
    motivos: list[str]
    tecnicas: list[str]
    accion: str                     # ninguna | revisar | aislar
    firma: str | None = None
    defender: str | None = None
    detalles: list[dict] = field(default_factory=list)

    def a_dict(self) -> dict:
        return {"ruta": self.ruta, "nombre": self.nombre, "sha256": self.sha256, "tamano": self.tamano,
                "tipo": self.tipo, "nivel": self.nivel, "probabilidad": round(self.probabilidad, 3),
                "puntaje": self.puntaje, "familia": self.familia, "motivos": self.motivos[:6],
                "tecnicas": self.tecnicas, "accion": self.accion, "firma": self.firma, "defender": self.defender}


# ═══════════════════════════════════════════════════════ lectura
def _leer(ruta: Path, tamano: int) -> tuple[str, bytes, bool]:
    """(sha256, bytes para analizar, ¿están completos?). Un solo recorrido del archivo."""
    with open(ruta, "rb") as fh:
        if tamano <= LEER_COMPLETO:
            datos = fh.read()
            return hashlib.sha256(datos).hexdigest(), datos, True
        sha = hashlib.sha256()
        cabeza = fh.read(MUESTRA_CABEZA)
        sha.update(cabeza)
        cola = b""
        while bloque := fh.read(4 * 1024 * 1024):
            sha.update(bloque)
            cola = (cola + bloque)[-MUESTRA_COLA:]
        return sha.hexdigest(), cabeza + cola, False


def tipo_real(datos: bytes, nombre: str) -> str:
    """El tipo por los primeros bytes, no por la extensión: la extensión la elige el atacante."""
    ext = Path(nombre).suffix.lower()
    if datos[:2] == b"MZ":
        return "pe"
    if datos[:4] == b"\x7fELF":
        return "elf"
    if datos[:4] == b"%PDF":
        return "pdf"
    if datos[:4] == b"PK\x03\x04":
        if ext in (".apk", ".jar", ".aab"):
            return "apk"
        if ext in EXT_OFFICE_ZIP:
            return "office"
        return "zip"
    if datos[:4] == b"\xd0\xcf\x11\xe0":
        return "office"
    if datos[:8] == b"L\x00\x00\x00\x01\x14\x02\x00":
        return "lnk"
    if ext in EXT_SCRIPT:
        return "script"
    return "unknown"


def cadenas(datos: bytes, maximo: int = 800) -> list[str]:
    salida = [m.decode("ascii", "ignore") for m in _ASCII.findall(datos[:MUESTRA_CABEZA + MUESTRA_COLA])[:maximo]]
    if len(salida) < maximo:
        salida += [m.decode("utf-16-le", "ignore") for m in _UTF16.findall(datos[:MUESTRA_CABEZA])[:maximo - len(salida)]]
    return salida


# ═══════════════════════════════════════════════════ señales locales
def _extra(nombre: str, ruta: str, tipo: str, datos: bytes, textos: list[str], info_pe: pe.InfoPE | None,
           completo: bool) -> list[av.Detection]:
    d: list[av.Detection] = []
    if "\u202e" in nombre:
        d.append(av.Detection(45, "El nombre usa un carácter invisible que invierte el texto para esconder la "
                                  "extensión real", "heuristica"))
    if _DOBLE_EXT.search(nombre):
        d.append(av.Detection(30, "Doble extensión: se hace pasar por documento o imagen pero es ejecutable",
                              "heuristica"))
    ext = Path(nombre).suffix.lower()
    if tipo == "pe" and ext and ext not in EXT_EJECUTABLE and ext not in (".tmp", ".bin", ".dat", ".mui", ".node",
                                                                           ".pyd", ".efi", ".drv", ".ax", ".tlb"):
        d.append(av.Detection(20, f"Es un ejecutable disfrazado con extensión «{ext}»", "heuristica"))
    if info_pe is not None:
        for anomalia in info_pe.anomalias[:3]:
            d.append(av.Detection(8, anomalia.capitalize(), "heuristica"))
    if tipo == "lnk":
        texto = " ".join(textos)
        if _LNK_MALO.search(texto) and _LNK_CARGA.search(texto):
            d.append(av.Detection(45, "Acceso directo que ejecuta comandos ocultos (técnica común de phishing)",
                                  "heuristica"))
    ruta_baja = ruta.lower()
    en_temporal = any(x in ruta_baja for x in ("\\temp\\", "/tmp/", "\\start menu\\programs\\startup"))
    if tipo == "pe" and en_temporal:
        d.append(av.Detection(6, "Ejecutable en una carpeta temporal o de inicio automático", "heuristica"))
    if tipo in ("zip", "office", "apk") and completo:
        d += _revisar_zip(datos, tipo)
    return d


def _revisar_zip(datos: bytes, tipo: str) -> list[av.Detection]:
    d: list[av.Detection] = []
    try:
        with zipfile.ZipFile(io.BytesIO(datos)) as z:
            entradas = z.infolist()[:500]
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
        return d
    peligrosos = [e for e in entradas if Path(e.filename).suffix.lower() in (EXT_EJECUTABLE | EXT_SCRIPT | {".lnk", ".iso"})]
    cifrado = any(e.flag_bits & 0x1 for e in entradas)
    if tipo == "office" and any(e.filename.lower().endswith("vbaproject.bin") for e in entradas):
        d.append(av.Detection(12, "Documento de Office con macros", "heuristica"))
    if tipo == "zip":
        if peligrosos and cifrado:
            d.append(av.Detection(25, "ZIP con contraseña que contiene ejecutables (táctica para evadir antivirus)",
                                  "heuristica"))
        elif peligrosos and len(entradas) <= 3:
            d.append(av.Detection(10, f"ZIP que solo trae un ejecutable: {Path(peligrosos[0].filename).name}",
                                  "heuristica"))
        if any(_DOBLE_EXT.search(Path(e.filename).name) for e in entradas):
            d.append(av.Detection(30, "Dentro del ZIP hay un archivo con doble extensión", "heuristica"))
        comprimido = sum(e.compress_size for e in entradas) or 1
        if sum(e.file_size for e in entradas) / comprimido > 200:
            d.append(av.Detection(15, "Compresión anómala (posible bomba ZIP)", "heuristica"))
    return d


def contenido_zip(datos: bytes, limite: int = 60) -> list[tuple[str, bytes]]:
    """Archivos de riesgo dentro de un ZIP, para analizarlos uno por uno. Acotado contra bombas."""
    salida: list[tuple[str, bytes]] = []
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(datos)) as z:
            for e in z.infolist()[:500]:
                if len(salida) >= limite or e.is_dir() or e.flag_bits & 0x1:
                    continue
                if Path(e.filename).suffix.lower() not in EXT_RIESGO or e.file_size > 48 * 1024 * 1024:
                    continue
                if e.compress_size and e.file_size / e.compress_size > 200:
                    continue
                total += e.file_size
                if total > 160 * 1024 * 1024:
                    break
                with z.open(e) as fh:
                    salida.append((e.filename, fh.read(48 * 1024 * 1024)))
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError):
        pass
    return salida


# ═══════════════════════════════════════════════════════ veredicto
def _nivel(puntaje: int, prob: float) -> str:
    """Más exigente que el motor del servidor con la probabilidad sola.

    La red neuronal se entrenó con pocos datos: puede opinar, pero no condenar un archivo sin que
    haya señales concretas detrás. Por eso «malicioso» por probabilidad exige además puntaje.
    """
    if puntaje >= 60 or (prob >= 0.85 and puntaje >= 30):
        return "malicioso"
    if puntaje >= 30 or prob >= 0.65:
        return "sospechoso"
    return "limpio"


# Reglas de firma con muy pocos falsos positivos: son las únicas que, solas, justifican aislar.
_REGLAS_FUERTES = {why for name, _, _, _, why in av.SIGNATURE_RULES
                   if name in ("eicar_test", "ransom_note", "credential_dump", "crypto_miner")}
_REGLA_SHELL = next(why for name, _, _, _, why in av.SIGNATURE_RULES if name == "reverse_shell")
_MOTIVOS_IMPORT = {why: key for key, (_, why) in av.SUSPICIOUS_IMPORTS.items()}
_INYECCION = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
_ESPIA = {"SetWindowsHookEx", "GetAsyncKeyState"}


def _depurar(detecciones: list[av.Detection], tipo: str) -> list[av.Detection]:
    """Corrige dos fuentes de falsos positivos del motor genérico al analizar un disco real.

    1. Muchas aplicaciones legítimas importan funciones «sensibles» (los juegos leen el teclado con
       GetAsyncKeyState, los navegadores reservan memoria en otros procesos). Sumar cada una por
       separado condenaría a Chrome. Lo que delata al malware es la COMBINACIÓN: las tres funciones
       de inyección juntas, o el gancho de teclado junto con la lectura de teclas.
    2. La regla de «shell remota» busca «cmd.exe» y «socket»; en un ejecutable eso aparece en miles
       de programas normales. En scripts sí es una señal fuerte; en un .exe vale mucho menos.
    """
    usadas = {_MOTIVOS_IMPORT[x.reason] for x in detecciones if x.reason in _MOTIVOS_IMPORT}
    salida = [x for x in detecciones if x.reason not in _MOTIVOS_IMPORT]
    if usadas:
        if _INYECCION <= usadas:
            salida.append(av.Detection(30, "Combina las tres funciones de inyección de código en otros procesos",
                                       "heuristica"))
        elif _ESPIA <= usadas:
            salida.append(av.Detection(22, "Engancha y lee el teclado (patrón de keylogger)", "heuristica"))
        else:
            salida.append(av.Detection(min(10, 3 * len(usadas)),
                                       "Usa funciones sensibles del sistema: " + ", ".join(sorted(usadas)[:4]),
                                       "heuristica"))
    if tipo == "pe":
        salida = [av.Detection(12, x.reason + " (en un ejecutable es una señal débil)", "heuristica")
                  if x.reason == _REGLA_SHELL else x for x in salida]
    return salida


def _evaluar(nombre: str, ruta: str, sha: str, tamano: int, tipo: str, datos: bytes, completo: bool,
             firma: tuple[bool | None, str] | None) -> tuple[av.ScanResult, list[av.Detection], pe.InfoPE | None, list[str]]:
    textos = cadenas(datos)
    info_pe = pe.analizar(datos) if tipo == "pe" else None
    importaciones = (info_pe.importaciones + info_pe.dlls) if info_pe else []
    # Antes de verificar la firma: si trae certificado, se trata como neutral (ni suma ni resta).
    firmado = bool(firma[0]) if firma else bool(info_pe and info_pe.tiene_certificado)
    muestra = av.FileSample(
        name=nombre[:260], size=tamano, sha256=sha, kind=tipo if tipo in ("pe", "apk", "elf", "pdf", "office", "script")
        else "unknown", header_hex=datos[:64].hex(), strings=textos, entropy=pe.entropia(datos[:262144]),
        imports=importaciones[:600], is_signed=firmado, signer="firma Authenticode válida" if firmado else None)
    resultado = av.scan_file(muestra)
    extras = _extra(nombre, ruta, tipo, datos, textos, info_pe, completo)
    if firma and firma[1] == "firma alterada":
        extras.append(av.Detection(35, "La firma digital no coincide con el contenido: el archivo se modificó "
                                       "después de firmarse", "heuristica"))
    return resultado, extras, info_pe, textos


def _prob_red(resultado: av.ScanResult) -> float | None:
    for x in resultado.detections:
        if x.technique == "modelo" and x.reason.startswith("Red neuronal"):
            m = re.search(r"(\d+)\s*%", x.reason)
            return int(m.group(1)) / 100 if m else None
    return None


def analizar_bytes(nombre: str, ruta: str, datos: bytes, *, tamano: int | None = None, sha: str | None = None,
                   completo: bool = True, firmas: BaseFirmas, exclusiones: set[str] | None = None,
                   verificar_firma: bool = True, defender: bool = False, profundidad: int = 0) -> Veredicto:
    tamano = tamano if tamano is not None else len(datos)
    sha = sha or hashlib.sha256(datos).hexdigest()
    tipo = tipo_real(datos, nombre)

    if exclusiones and sha in exclusiones:
        return Veredicto(ruta, nombre, sha, tamano, tipo, "limpio", 0.0, 0, None,
                         ["Excluido por usted (lo restauró como falso positivo)"], ["exclusion"], "ninguna")
    if firmas.es_malo(sha):
        eicar = sha == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        return Veredicto(ruta, nombre, sha, tamano, tipo, "malicioso", 0.99, 100,
                         "EICAR (archivo de prueba)" if eicar else "Malware conocido",
                         ["Su huella coincide con una muestra de malware conocida (base de firmas)"]
                         if not eicar else ["Archivo de prueba EICAR: el antivirus funciona correctamente"],
                         ["reputacion"], "aislar")

    resultado, extras, info_pe, _ = _evaluar(nombre, ruta, sha, tamano, tipo, datos, completo, None)
    detecciones = _depurar(list(resultado.detections), tipo) + extras
    puntaje = max(0, min(100, sum(x.points for x in detecciones)))
    firma_txt = None

    # La firma se verifica solo si hay algo que aclarar: en archivos limpios sería tiempo perdido.
    if (verificar_firma and tipo == "pe" and profundidad == 0 and Path(ruta).suffix.lower() in EXT_EJECUTABLE
            and (puntaje >= 15 or (info_pe and info_pe.anomalias))):
        firma = sistema.verificar_firma(Path(ruta))
        if firma[0] is not None:
            firma_txt = firma[1]
            resultado, extras, info_pe, _ = _evaluar(nombre, ruta, sha, tamano, tipo, datos, completo, firma)
            detecciones = _depurar(list(resultado.detections), tipo) + extras
            if firma[0]:
                detecciones.append(av.Detection(-20, "Firmado digitalmente por un editor verificado", "heuristica"))
            puntaje = max(0, min(100, sum(x.points for x in detecciones)))

    tecnicas = {x.technique for x in detecciones if x.points > 0}
    # La probabilidad del motor se recalcula con el puntaje depurado; la de la red neuronal se
    # conserva como una opinión más, promediada, igual que hace el motor del servidor.
    prob_red = _prob_red(resultado)
    prob = av._model_probability(puntaje, len(tecnicas))
    if prob_red is not None:
        prob = 0.5 * prob + 0.5 * prob_red
    if firma_txt == "válida":
        prob *= 0.6
    nivel = _nivel(puntaje, prob)
    familia = resultado.family_guess

    # ── contenido de un ZIP: si algo adentro es malicioso, el ZIP también
    if tipo == "zip" and completo and profundidad == 0:
        for interno, contenido in contenido_zip(datos):
            v = analizar_bytes(Path(interno).name, f"{ruta}>{interno}", contenido, firmas=firmas,
                               exclusiones=exclusiones, verificar_firma=False, profundidad=1)
            if v.nivel != "limpio":
                pts = 70 if v.nivel == "malicioso" else 30
                detecciones.append(av.Detection(pts, f"Contiene «{Path(interno).name}»: {v.motivos[0]}",
                                                "reputacion" if "reputacion" in v.tecnicas else "firma"))
                familia = familia or v.familia
        puntaje = max(0, min(100, sum(x.points for x in detecciones)))
        tecnicas = {x.technique for x in detecciones if x.points > 0}
        nivel = _nivel(puntaje, prob)

    # ── segunda opinión: Windows Defender, solo cuando hay dudas
    defender_txt = None
    if defender and nivel != "limpio" and profundidad == 0 and sistema.defender_disponible():
        detecta, detalle = sistema.defender_escanear(Path(ruta))
        defender_txt = detalle
        if detecta:
            detecciones.append(av.Detection(60, f"Windows Defender también lo detecta: {detalle}", "segunda_opinion"))
            nivel, prob = "malicioso", max(prob, 0.97)
            familia = familia or detalle
            tecnicas.add("segunda_opinion")
        elif detecta is False and nivel == "malicioso" and not tecnicas & {"reputacion", "firma"}:
            # Solo heurística contra un motor independiente que dice limpio: se baja a sospechoso.
            nivel = "sospechoso"
            detecciones.append(av.Detection(0, "Windows Defender no lo considera malicioso", "segunda_opinion"))

    # La probabilidad mostrada debe ser coherente con el nivel (la evidencia concreta manda).
    if "reputacion" in tecnicas or "segunda_opinion" in tecnicas:
        prob = max(prob, 0.97)
    if nivel == "malicioso":
        prob = max(prob, 0.85)
    elif nivel == "sospechoso":
        prob = max(prob, 0.5)

    fuerte = any((x.technique in ("reputacion", "segunda_opinion") and x.points >= 40)
                 or x.reason in _REGLAS_FUERTES for x in detecciones)
    if nivel == "malicioso" and fuerte and not sistema.intocable(ruta):
        accion = "aislar"
    elif nivel != "limpio":
        accion = "revisar"
    else:
        accion = "ninguna"

    detecciones.sort(key=lambda x: -x.points)
    motivos = [x.reason for x in detecciones if x.points > 0] or ["Sin señales de amenaza"]
    return Veredicto(ruta, nombre, sha, tamano, tipo, nivel, round(min(prob, 0.999), 3), puntaje, familia,
                     motivos, sorted(tecnicas), accion, firma_txt, defender_txt)


def analizar_archivo(ruta: Path, *, firmas: BaseFirmas, exclusiones: set[str] | None = None,
                     defender: bool = False) -> Veredicto | None:
    """None si no se pudo leer (en uso, sin permiso) o si no vale la pena (vacío, gigante)."""
    try:
        st = ruta.stat()
        if st.st_size == 0 or st.st_size > MAX_ARCHIVO:
            return None
        sha, datos, completo = _leer(ruta, st.st_size)
    except (OSError, PermissionError, MemoryError):
        return None
    return analizar_bytes(ruta.name, str(ruta), datos, tamano=st.st_size, sha=sha, completo=completo,
                          firmas=firmas, exclusiones=exclusiones, defender=defender)


def prioridad(ruta: Path, tamano: int, mtime: float, ahora: float) -> int:
    """Riesgo a priori: lo ejecutable, reciente y en carpetas calientes se revisa primero."""
    ext = ruta.suffix.lower()
    puntos = 10 if ext in EXT_EJECUTABLE else 8 if ext in EXT_SCRIPT else 5 if ext in EXT_RIESGO else 1
    padre = str(ruta.parent).lower()
    if any(c in padre for c in ("download", "descarga", "desktop", "escritorio", "temp", "startup")):
        puntos += 4
    edad = (ahora - mtime) / 86400
    puntos += 3 if edad < 7 else 1 if edad < 30 else 0
    return puntos
