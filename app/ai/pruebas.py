"""Código dentro del chat: encontrar bloques, decidir si hay que probarlos y presentar el resultado.

El chat usa esto para dos cosas:
- **Probar** el código con el sandbox cuando la persona lo pide («prueba este código», «ejecútalo»).
- **Organizar** bloques de código en un proyecto ZIP.
Aquí no se ejecuta nada: solo se analiza texto. La ejecución real vive en app/local/sandbox.py."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from app.local import sandbox as _sandbox

BLOQUE = re.compile(r"```[ \t]*([\w+#.-]*)[^\n]*\n(.*?)```", re.DOTALL)
ALIAS = _sandbox.ALIAS
EJECUTABLES = tuple(_sandbox.LENGUAJES)          # todo lo que el sandbox sabe correr (si está instalado en el equipo)
EXT = {"python": "py", "javascript": "js", "typescript": "ts", "lua": "lua", "perl": "pl", "html": "html", "css": "css", "json": "json",
       "bash": "sh", "sh": "sh", "sql": "sql", "java": "java", "c": "c", "cpp": "cpp", "csharp": "cs", "go": "go",
       "rust": "rs", "php": "php", "ruby": "rb", "yaml": "yml", "xml": "xml", "markdown": "md", "dart": "dart",
       "kotlin": "kt", "swift": "swift", "text": "txt", "": "txt"}
_PIDE_PROBAR = re.compile(
    r"\b(prueba(lo|la|me)?|probar|probarlo|ejecuta(lo|la|me)?|ejecutar|ejecutalo|corre(lo|la)?|correr|"
    r"corrida|run|testea(lo|la)?|testear|verifica(lo|la)? (que )?(funcion\w+|corr\w+)|"
    r"mira si (funciona|corre|sirve)|comprueba(lo|la)?|a ver si (funciona|corre))\b")


@dataclass
class Bloque:
    lenguaje: str
    codigo: str


def _plano(texto: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", texto.lower()) if not unicodedata.combining(c))


def bloques(texto: str) -> list[Bloque]:
    """Bloques ``` del texto, con el lenguaje normalizado (py → python)."""
    salida = []
    for m in BLOQUE.finditer(texto or ""):
        lenguaje = (m.group(1) or "").lower().strip()
        lenguaje = ALIAS.get(lenguaje, lenguaje)
        codigo = m.group(2).strip("\n")
        if codigo.strip():
            salida.append(Bloque(lenguaje, codigo))
    return salida


def pide_probar(mensaje: str) -> bool:
    return bool(_PIDE_PROBAR.search(_plano(mensaje)))


def codigo_a_probar(mensaje: str, historial: list) -> Bloque | None:
    """El bloque que se debe ejecutar: el del propio mensaje o, si no trae, el último del chat.

    Solo si la persona lo pidió expresamente y el bloque es de un lenguaje que el sandbox sabe correr.
    Con varios bloques en el mensaje se toma el último (suele ser el programa completo)."""
    if not pide_probar(mensaje):
        return None
    propios = [b for b in bloques(mensaje) if b.lenguaje in EJECUTABLES]
    if propios:
        return propios[-1]
    for turno in reversed(historial or []):
        contenido = getattr(turno, "content", "") or ""
        candidatos = [b for b in bloques(contenido) if b.lenguaje in EJECUTABLES]
        if candidatos:
            return candidatos[-1]
    return None


def resumen_resultado(lenguaje: str, salida: str, codigo_salida: int | None, segundos: float, motivo: str = "") -> str:
    """Texto en Markdown con lo que pasó al ejecutar, para mostrarlo en el chat y guardarlo."""
    motivos = {"timeout": "Se detuvo por pasar el tiempo límite", "cancelado": "Cancelado",
               "salida_excesiva": "Se detuvo por producir demasiada salida"}
    estado = ("✅ Terminó bien" if codigo_salida == 0 else
              f"⏱ {motivos.get(motivo, motivo)}" if motivo else f"❌ Falló (código {codigo_salida})")
    cuerpo = salida.strip("\n")
    if len(cuerpo) > 6000:
        cuerpo = cuerpo[:3000] + "\n… (salida recortada) …\n" + cuerpo[-2500:]
    bloque = f"```text\n{cuerpo}\n```" if cuerpo else "_Sin salida._"
    return f"🧪 **Prueba en el sandbox ({lenguaje}):** {estado} en {segundos:.1f} s.\n\n{bloque}\n\n"


def contexto_para_modelo(lenguaje: str, codigo: str, resultado: str) -> str:
    """Se añade al mensaje para que el modelo explique el resultado o corrija el error."""
    return (f"El sistema YA EJECUTÓ en el sandbox el siguiente código ({lenguaje}):\n```{lenguaje}\n{codigo[:12000]}\n```\n"
            f"Resultado de la ejecución:\n{resultado}\n"
            "Explica en pocas líneas qué pasó. Si hubo un error, di la causa y entrega el código corregido completo "
            "en un solo bloque; si salió bien, confirma qué hace y propón una mejora solo si es realmente útil.")


def codigo_de_la_conversacion(mensaje: str, historial: list, maximo_chars: int = 200_000) -> list[Bloque]:
    """Todos los bloques de código de la conversación (más recientes al final), para armar un ZIP."""
    vistos, salida, total = set(), [], 0
    textos = [getattr(t, "content", "") or "" for t in (historial or [])] + [mensaje]
    for texto in textos:
        for b in bloques(texto):
            clave = (b.lenguaje, b.codigo)
            if clave in vistos:
                continue
            vistos.add(clave)
            total += len(b.codigo)
            if total > maximo_chars:
                return salida
            salida.append(b)
    return salida


_NOMBRE_EN_PRIMERA_LINEA = re.compile(
    r"^\s*(?:#|//|--|/\*|<!--)\s*(?:archivo|file|nombre|filename)\s*[:=]\s*([\w./ -]{1,100}?)\s*(?:\*/|-->)?\s*$",
    re.IGNORECASE)


def nombre_sugerido(b: Bloque, indice: int, usados: set[str]) -> str:
    """Nombre para un bloque: el que declara en su primera línea («# archivo: utils.py») o uno por lenguaje."""
    primera = b.codigo.splitlines()[0] if b.codigo.splitlines() else ""
    m = _NOMBRE_EN_PRIMERA_LINEA.match(primera)
    ext = EXT.get(b.lenguaje, "txt")
    nombre = m.group(1).strip() if m else ("main" if indice == 0 else f"modulo{indice + 1}") + f".{ext}"
    base, punto, e = nombre.rpartition(".")
    candidato, n = nombre, 2
    while candidato.lower() in usados:
        candidato = f"{base or nombre}_{n}{punto}{e}" if punto else f"{nombre}_{n}"
        n += 1
    usados.add(candidato.lower())
    return candidato


# ───────────────────────────── código generado por el asistente: ¿varios archivos? ¿se puede probar solo?
_LENGUAJES_CODIGO = set(EXT) - {"", "text", "markdown", "json", "yaml", "xml"}
_INTERACTIVO = re.compile(
    r"\binput\s*\(|\bsys\.stdin|\btkinter\b|\bpygame\b|\bturtle\b|\bPyQt\d?\b|\bkivy\b|\bflask\b|\bfastapi\b|"
    r"\buvicorn\b|\bhttp\.server\b|\bsocketserver\b|process\.stdin|readline\b|createServer|\.listen\s*\(|"
    r"\bScanner\s*\(|\bscanf\s*\(|\bcin\s*>>|\bgets\s*\(|\bread\s+-|\bfmt\.Scan|\bread_line\b|\$stdin|STDIN|"
    r"\bwindow\.|\bdocument\.|\bandroid\b|\bFlutter\b",
    re.IGNORECASE)


def es_interactivo(codigo: str) -> bool:
    """Programas que esperan teclado, abren ventana o levantan un servidor: probarlos solos no tiene sentido."""
    return bool(_INTERACTIVO.search(codigo))


def archivos_de_respuesta(texto: str) -> list[tuple[str, Bloque]]:
    """(ruta, bloque) de cada archivo de código de la respuesta. Un bloque cuenta si declara su ruta
    («# archivo: src/x.py») o es código real de varias líneas; comandos sueltos (pip install…) no."""
    salida, usados = [], set()
    for i, b in enumerate(bloques(texto)):
        declarado = _NOMBRE_EN_PRIMERA_LINEA.match((b.codigo.splitlines() or [""])[0])
        lineas = len([x for x in b.codigo.splitlines() if x.strip()])
        if b.lenguaje not in _LENGUAJES_CODIGO and not declarado:
            continue
        if not declarado and (lineas < 3 or b.lenguaje in ("bash", "sh")):
            continue
        ruta = nombre_sugerido(b, len(salida), usados)
        salida.append((ruta, b))
    return salida


def archivo_principal(archivos: list[tuple[str, Bloque]]) -> tuple[str, Bloque] | None:
    """El archivo que conviene ejecutar: main/app/index o el primero que el sandbox sabe correr y no es interactivo."""
    ejecutables = [(r, b) for r, b in archivos if b.lenguaje in EJECUTABLES and not es_interactivo(b.codigo)]
    for r, b in ejecutables:
        if re.search(r"(^|/)(main|app|index|run|program|programa)\.\w+$", r, re.IGNORECASE):
            return r, b
    return ejecutables[0] if ejecutables else None


def ruta_declarada(codigo: str) -> str | None:
    """La ruta que el código declara en su primera línea («# archivo: src/x.py»), si la hay."""
    m = _NOMBRE_EN_PRIMERA_LINEA.match((codigo.splitlines() or [""])[0])
    return m.group(1).strip() if m else None


def extraer_corregido(texto: str, lenguaje: str) -> str | None:
    """El código corregido que devolvió el modelo: el primer bloque del mismo lenguaje (o el más largo)."""
    candidatos = bloques(texto)
    mismos = [b for b in candidatos if b.lenguaje == lenguaje] or candidatos
    return max(mismos, key=lambda b: len(b.codigo)).codigo if mismos else None


def pide_programar(mensaje: str) -> bool:
    """¿La persona pidió que se CREE un programa (no una explicación)?"""
    f = _plano(mensaje)
    return bool(re.search(r"\b(crea(me)?|haz(me)?|hacer|programa(me)?|desarrolla(me)?|escribe(me)?|genera(me)?|"
                          r"construye(me)?|codifica(me)?|implementa(me)?|arma(me)?|necesito|quiero|dame)\b", f)
                and re.search(r"\b(codigo|programa|script|aplicacion|app|sistema|juego|bot|api|sitio web|pagina web|"
                              r"calculadora|software|funcion|clase|automatizacion|extension)\b", f))
