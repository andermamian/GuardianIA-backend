"""Estudio de creación: convierte una instrucción en un archivo real.

Qué genera y con qué (todo en el servidor, sin servicios externos):

| Tipo      | Resultado                  | Librería        |
|-----------|----------------------------|-----------------|
| docx      | Word con títulos y tablas  | python-docx     |
| xlsx      | Excel con fórmulas y gráfico | openpyxl      |
| pptx      | PowerPoint con notas       | python-pptx     |
| pdf       | PDF paginado               | reportlab       |
| csv / md  | datos y texto              | estándar        |
| grafico   | PNG de barras, líneas o torta | matplotlib   |
| imagen    | SVG o código QR            | qrcode          |
| musica    | melodía MIDI               | midiutil        |
| codigo    | archivo de código verificado | ast/compile   |
| video     | presentación en MP4        | matplotlib + ffmpeg |

Qué NO genera, y por qué se dice en vez de fingirlo: video o imágenes fotorrealistas por IA
(difusión) necesitan GPU y varios GB de modelos; un equipo de escritorio típico no los corre. El
video aquí es una presentación animada con voz en off ausente, no «texto a video».

El modelo de lenguaje solo produce el plan en JSON; la construcción del archivo la hace este módulo
con código determinista. Así, un modelo pequeño que alucina no puede romper el archivo ni ejecutar
nada: si el plan no valida, se rechaza.
"""
from __future__ import annotations

import csv
import io
import json
import re
import shutil
import subprocess
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path

TIPOS = ("docx", "xlsx", "pptx", "pdf", "csv", "md", "grafico", "imagen", "musica", "codigo", "video", "zip")

MIMES = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "pdf": "application/pdf", "csv": "text/csv", "md": "text/markdown", "grafico": "image/png",
    "imagen": "image/png", "musica": "audio/midi", "codigo": "text/plain", "video": "video/mp4",
    "zip": "application/zip",
}
EXTENSIONES = {**{t: t for t in TIPOS}, "grafico": "png", "imagen": "png", "musica": "mid", "video": "mp4"}
CATEGORIAS = {"grafico": "photos", "imagen": "photos", "video": "videos", "musica": "videos"}

MAX_BYTES = 50 * 1024 * 1024
MAX_SECCIONES_DOC = 250        # un documento de 300 páginas cabe de sobra
MAX_PARRAFOS = 400
MAX_VINETAS = 200
MAX_FILAS = 5000
MAX_DIAPOSITIVAS = 40
MAX_COMPASES = 64


class PlanInvalido(ValueError):
    """El plan no cumple el formato esperado. Nunca se construye un archivo con datos dudosos."""


@dataclass
class Creacion:
    tipo: str
    nombre: str
    mime: str
    datos: bytes
    resumen: str
    categoria: str = "documents"


# ───────────────────────────────────────────────────────────── utilidades
def _texto(valor, maximo: int = 2000) -> str:
    if valor is None:
        return ""
    return str(valor).replace("\x00", "")[:maximo]


def _lista(valor, maximo: int) -> list:
    return list(valor)[:maximo] if isinstance(valor, list) else []


def nombre_seguro(titulo: str, tipo: str) -> str:
    """Nombre de archivo sin rutas ni sorpresas: solo letras, números, espacios y guiones.

    Los puntos también se quitan: dejarlos permitiría «..» (recorrido de directorios) y dobles
    extensiones del tipo «factura.pdf.exe».
    """
    base = re.sub(r"[^\w áéíóúñÁÉÍÓÚÑ-]", " ", _texto(titulo, 80))
    base = re.sub(r"\s+", " ", base).strip(" -") or "GuardianIA"
    return f"{base[:60]}.{EXTENSIONES[tipo]}"


def capacidades() -> dict:
    """Lo que este servidor puede generar aquí y ahora; la interfaz solo ofrece lo disponible."""
    disponible = {}
    for tipo, modulo in (("docx", "docx"), ("xlsx", "openpyxl"), ("pptx", "pptx"), ("pdf", "reportlab"),
                         ("grafico", "matplotlib"), ("imagen", "qrcode"), ("musica", "midiutil")):
        try:
            __import__(modulo)
            disponible[tipo] = True
        except ImportError:
            disponible[tipo] = False
    disponible["csv"] = disponible["md"] = disponible["codigo"] = disponible["zip"] = True
    disponible["video"] = bool(shutil.which("ffmpeg")) and disponible["grafico"]
    return disponible


# ───────────────────────────────────────────────────────── constructores
def _campo_pagina(parrafo, prefijo: str = "Página ") -> None:
    """«Página N» con el campo PAGE de Word: se numera solo, sin pedir actualizar nada al abrir."""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    parrafo.add_run(prefijo)
    run = parrafo.add_run()
    for tipo, texto in (("begin", None), (None, " PAGE "), ("end", None)):
        if tipo:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), tipo)
        else:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = texto
        run._r.append(el)


def _encabezados_indice(plan: dict) -> list[tuple[int, str]]:
    return [(int(sec.get("nivel", 1) or 1), _texto(sec["encabezado"], 120))
            for sec in _lista(plan.get("secciones"), MAX_SECCIONES_DOC)
            if isinstance(sec, dict) and sec.get("encabezado")]


def _docx_basico(plan: dict) -> bytes:
    from datetime import date

    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Pt, RGBColor

    doc = Document()
    titulo = _texto(plan.get("titulo"), 120) or "Documento"
    doc.core_properties.title = titulo
    doc.core_properties.author = "GuardianIA"
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(11)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.15
    for nivel, tam in ((1, 16), (2, 13), (3, 12)):
        h = doc.styles[f"Heading {nivel}"]
        h.font.name = "Calibri"
        h.font.size = Pt(tam)
        h.font.color.rgb = RGBColor(0x1F, 0x3A, 0x5F)
        h.paragraph_format.space_before = Pt(14 if nivel == 1 else 10)
        h.paragraph_format.keep_with_next = True

    secciones = [sec for sec in _lista(plan.get("secciones"), MAX_SECCIONES_DOC) if isinstance(sec, dict)]
    largo = len(secciones) >= 6 or plan.get("portada")

    if largo:       # portada + contenido: lo que se espera de un documento de decenas de páginas
        for _ in range(7):
            doc.add_paragraph()
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(titulo)
        r.bold = True
        r.font.size = Pt(30)
        r.font.color.rgb = RGBColor(0x1F, 0x3A, 0x5F)
        if plan.get("subtitulo"):
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.add_run(_texto(plan["subtitulo"], 300)).font.size = Pt(14)
        for _ in range(8):
            doc.add_paragraph()
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run(f"Elaborado con GuardianIA · {date.today():%d/%m/%Y}").font.size = Pt(11)
        doc.add_page_break()
        if plan.get("resumen"):
            doc.add_heading("Resumen ejecutivo", level=1)
            doc.add_paragraph(_texto(plan["resumen"], 4000))
            doc.add_page_break()
        indice = _encabezados_indice(plan)
        if indice:
            doc.add_heading("Contenido", level=1)
            for nivel, texto in indice:
                p = doc.add_paragraph(texto)
                p.paragraph_format.left_indent = Pt(18 * (nivel - 1))
                p.paragraph_format.space_after = Pt(2)
            doc.add_page_break()
    else:
        doc.add_heading(titulo, level=0)
        if plan.get("subtitulo"):
            p = doc.add_paragraph(_texto(plan["subtitulo"], 300))
            p.runs[0].font.size = Pt(12)
        if plan.get("resumen"):
            doc.add_paragraph(_texto(plan["resumen"], 1500), style="Intense Quote")

    for sec_ in doc.sections:
        _campo_pagina(sec_.footer.paragraphs[0])               # pie de página con numeración
        sec_.footer.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        sec_.header.paragraphs[0].text = titulo[:80]
        sec_.header.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT
        for run in sec_.header.paragraphs[0].runs:
            run.font.size = Pt(9)
            run.font.color.rgb = RGBColor(0x66, 0x66, 0x66)

    for seccion in secciones:
        if seccion.get("encabezado"):
            doc.add_heading(_texto(seccion["encabezado"], 120), level=min(3, max(1, int(seccion.get("nivel", 1) or 1))))
        for parrafo in _lista(seccion.get("parrafos"), MAX_PARRAFOS):
            doc.add_paragraph(_texto(parrafo, 6000))
        for vineta in _lista(seccion.get("vinetas"), MAX_VINETAS):
            doc.add_paragraph(_texto(vineta, 800), style="List Bullet")
        tabla = seccion.get("tabla")
        if isinstance(tabla, dict) and _lista(tabla.get("encabezados"), 20):
            encabezados = [_texto(c, 60) for c in _lista(tabla["encabezados"], 20)]
            filas = _lista(tabla.get("filas"), 500)
            t = doc.add_table(rows=1, cols=len(encabezados))
            t.style = "Light Grid Accent 1"
            for i, c in enumerate(encabezados):
                t.rows[0].cells[i].text = c
            for fila in filas:
                celdas = t.add_row().cells
                for i, valor in enumerate(_lista(fila, len(encabezados))):
                    celdas[i].text = _texto(valor, 400)
            doc.add_paragraph()
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _xlsx_basico(plan: dict) -> bytes:
    from openpyxl import Workbook
    from openpyxl.chart import BarChart, LineChart, Reference
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    wb.remove(wb.active)
    hojas = _lista(plan.get("hojas"), 10) or [{"nombre": "Datos", "encabezados": [], "filas": []}]
    for hoja in hojas:
        if not isinstance(hoja, dict):
            continue
        ws = wb.create_sheet(_texto(hoja.get("nombre"), 30) or "Hoja")
        encabezados = [_texto(c, 60) for c in _lista(hoja.get("encabezados"), 40)]
        if encabezados:
            ws.append(encabezados)
            for celda in ws[1]:
                celda.font = Font(bold=True, color="FFFFFF")
                celda.fill = PatternFill("solid", fgColor="1565C0")
                celda.alignment = Alignment(horizontal="center")
            ws.freeze_panes = "A2"
            ws.auto_filter.ref = f"A1:{get_column_letter(len(encabezados))}1"
        for fila in _lista(hoja.get("filas"), MAX_FILAS):
            ws.append([v if isinstance(v, (int, float)) else _texto(v, 500)
                       for v in _lista(fila, len(encabezados) or 40)])
        # Fórmulas: en el archivo SIEMPRE van con los nombres en inglés, aunque Excel las muestre
        # traducidas. Escribir «=PROMEDIO(...)» produce el error #¿NOMBRE? al abrir.
        for ref, formula in (hoja.get("formulas") or {}).items():
            if re.fullmatch(r"[A-Z]{1,3}\d{1,5}", str(ref)) and str(formula).startswith("="):
                ws[ref] = traducir_formula(_texto(formula, 200))
        for i, encabezado in enumerate(encabezados, start=1):
            largo = max([len(encabezado)] + [len(str(ws.cell(row=r, column=i).value or ""))
                                             for r in range(2, min(ws.max_row, 200) + 1)])
            ws.column_dimensions[get_column_letter(i)].width = min(45, max(10, largo + 2))
        # Fila de totales: lo primero que hace cualquiera con una planilla es sumar o promediar.
        if ws.max_row > 1 and hoja.get("totales", True) and len(encabezados) >= 2:
            fila_total = ws.max_row + 1
            ws.cell(row=fila_total, column=1, value="TOTAL / PROMEDIO").font = Font(bold=True)
            for col in range(2, len(encabezados) + 1):
                valores = [ws.cell(row=r, column=col).value for r in range(2, ws.max_row)]
                numericos = [v for v in valores if isinstance(v, (int, float))]
                if len(numericos) >= 2:
                    letra = get_column_letter(col)
                    entero = all(float(v).is_integer() for v in numericos)
                    celda = ws.cell(row=fila_total, column=col,
                                    value=f"={'SUM' if entero else 'AVERAGE'}({letra}2:{letra}{ws.max_row - 1})")
                    celda.font = Font(bold=True)
                    celda.number_format = "#,##0" if entero else "0.0"
        # Formato condicional: los valores bajos se ven de inmediato, sin leer fila por fila.
        if hoja.get("semaforo") and ws.max_row > 2:
            from openpyxl.formatting.rule import ColorScaleRule
            for col in range(2, len(encabezados) + 1):
                letra = get_column_letter(col)
                ws.conditional_formatting.add(
                    f"{letra}2:{letra}{ws.max_row - 1}",
                    ColorScaleRule(start_type="min", start_color="F8696B",
                                   mid_type="percentile", mid_value=50, mid_color="FFEB84",
                                   end_type="max", end_color="63BE7B"))
        grafico = hoja.get("grafico")
        if isinstance(grafico, dict) and ws.max_row > 1 and len(encabezados) >= 2:
            ch = LineChart() if grafico.get("clase") == "lineas" else BarChart()
            ch.title = _texto(grafico.get("titulo"), 80) or ws.title
            ch.add_data(Reference(ws, min_col=2, min_row=1, max_col=len(encabezados), max_row=ws.max_row),
                        titles_from_data=True)
            ch.set_categories(Reference(ws, min_col=1, min_row=2, max_row=ws.max_row))
            ch.height, ch.width = 8, 16
            ws.add_chart(ch, f"{get_column_letter(len(encabezados) + 2)}2")
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# Excel guarda las fórmulas en inglés y las muestra en el idioma del usuario. Un modelo que escribe
# en español propone «=PROMEDIO(B2:B9)», que al abrirse da #¿NOMBRE?. Aquí se traduce de vuelta.
FUNCIONES_ES_EN = {
    "PROMEDIO": "AVERAGE", "SUMA": "SUM", "CONTAR": "COUNT", "CONTARA": "COUNTA",
    "CONTAR.SI": "COUNTIF", "CONTAR.SI.CONJUNTO": "COUNTIFS", "SUMAR.SI": "SUMIF",
    "SUMAR.SI.CONJUNTO": "SUMIFS", "PROMEDIO.SI": "AVERAGEIF", "SI": "IF", "SI.ERROR": "IFERROR",
    "Y": "AND", "O": "OR", "NO": "NOT", "MAX": "MAX", "MIN": "MIN", "REDONDEAR": "ROUND",
    "REDONDEAR.MAS": "ROUNDUP", "REDONDEAR.MENOS": "ROUNDDOWN", "ABS": "ABS", "HOY": "TODAY",
    "AHORA": "NOW", "CONCATENAR": "CONCATENATE", "BUSCARV": "VLOOKUP", "BUSCARH": "HLOOKUP",
    "INDICE": "INDEX", "COINCIDIR": "MATCH", "MEDIANA": "MEDIAN", "MODA": "MODE", "DESVEST": "STDEV",
    "ENTERO": "INT", "RESIDUO": "MOD", "LARGO": "LEN", "IZQUIERDA": "LEFT", "DERECHA": "RIGHT",
    "EXTRAE": "MID", "MAYUSC": "UPPER", "MINUSC": "LOWER", "ESPACIOS": "TRIM", "TEXTO": "TEXT",
    "JERARQUIA": "RANK", "CONTAR.BLANCO": "COUNTBLANK", "VERDADERO": "TRUE", "FALSO": "FALSE",
}


def traducir_formula(formula: str) -> str:
    """Convierte nombres de función en español a inglés y «;» a «,» dentro de una fórmula."""
    def cambiar(m: re.Match) -> str:
        nombre = m.group(0).upper()
        return FUNCIONES_ES_EN.get(nombre, m.group(0))

    # Solo se tocan los identificadores seguidos de «(»: así no se altera el texto entre comillas.
    traducida = re.sub(r"\b[A-ZÁÉÍÓÚÑa-záéíóúñ][A-ZÁÉÍÓÚÑa-záéíóúñ.]*(?=\s*\()", cambiar, formula)
    dentro, resultado = False, []
    for ch in traducida:
        if ch == '"':
            dentro = not dentro
        resultado.append("," if (ch == ";" and not dentro) else ch)
    return "".join(resultado)


def _pptx_basico(plan: dict) -> bytes:
    from pptx import Presentation
    from pptx.dml.color import RGBColor
    from pptx.util import Inches, Pt

    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)  # 16:9
    portada = prs.slides.add_slide(prs.slide_layouts[0])
    portada.shapes.title.text = _texto(plan.get("titulo"), 120) or "Presentación"
    if len(portada.placeholders) > 1:
        portada.placeholders[1].text = _texto(plan.get("subtitulo"), 200)
    for diapositiva in _lista(plan.get("diapositivas"), MAX_DIAPOSITIVAS):
        if not isinstance(diapositiva, dict):
            continue
        s = prs.slides.add_slide(prs.slide_layouts[1])
        s.shapes.title.text = _texto(diapositiva.get("titulo"), 120)
        cuerpo = s.placeholders[1].text_frame
        cuerpo.clear()
        vinetas = _lista(diapositiva.get("vinetas"), 8) or [_texto(diapositiva.get("texto"), 400)]
        for i, vineta in enumerate(v for v in vinetas if v):
            parrafo = cuerpo.paragraphs[0] if i == 0 else cuerpo.add_paragraph()
            parrafo.text = _texto(vineta, 300)
            parrafo.font.size = Pt(22)
            parrafo.font.color.rgb = RGBColor(0x10, 0x2A, 0x43)
        if diapositiva.get("notas"):
            s.notes_slide.notes_text_frame.text = _texto(diapositiva["notas"], 1500)
    buf = io.BytesIO()
    prs.save(buf)
    return buf.getvalue()


def _latin(texto: str) -> str:
    """El PDF usa Helvetica (WinAnsi): tildes, ñ y ¿¡ salen bien; lo que no existe en esa fuente (emojis,
    símbolos raros) se cambia por «?» en vez de salir como un cuadro negro."""
    return texto.encode("cp1252", "replace").decode("cp1252")


def _para(texto: str) -> str:
    """Escapa para el mini-HTML de reportlab: un «<» o «&» en el texto antes rompía todo el PDF."""
    from xml.sax.saxutils import escape
    return escape(_latin(texto))


def _pdf_basico(plan: dict) -> bytes:
    from datetime import date

    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (ListFlowable, ListItem, PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                    Table, TableStyle)

    titulo = _texto(plan.get("titulo"), 120) or "Documento"
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=_latin(titulo), author="GuardianIA",
                            leftMargin=2.2 * cm, rightMargin=2.2 * cm, topMargin=2.2 * cm, bottomMargin=2.2 * cm)
    estilos = getSampleStyleSheet()
    azul = colors.HexColor("#1F3A5F")
    cuerpo = ParagraphStyle("cuerpo", parent=estilos["BodyText"], alignment=TA_LEFT, leading=15, spaceAfter=8)
    celda = ParagraphStyle("celda", parent=cuerpo, fontSize=8.5, leading=10.5, spaceAfter=0)
    h1 = ParagraphStyle("h1", parent=estilos["Heading1"], textColor=azul, fontSize=17, spaceBefore=14, spaceAfter=8)
    h2 = ParagraphStyle("h2", parent=estilos["Heading2"], textColor=azul, fontSize=13.5, spaceBefore=10, spaceAfter=6)
    h3 = ParagraphStyle("h3", parent=estilos["Heading3"], textColor=azul, fontSize=12, spaceBefore=8, spaceAfter=4)
    portada = ParagraphStyle("portada", parent=estilos["Title"], textColor=azul, fontSize=30, leading=36,
                             alignment=TA_CENTER)
    centro = ParagraphStyle("centro", parent=cuerpo, alignment=TA_CENTER, fontSize=13)

    secciones = [sec for sec in _lista(plan.get("secciones"), MAX_SECCIONES_DOC) if isinstance(sec, dict)]
    largo = len(secciones) >= 6 or plan.get("portada")
    partes: list = []
    if largo:
        partes += [Spacer(1, 6 * cm), Paragraph(_para(titulo), portada)]
        if plan.get("subtitulo"):
            partes += [Spacer(1, 12), Paragraph(_para(_texto(plan["subtitulo"], 300)), centro)]
        partes += [Spacer(1, 8 * cm), Paragraph(_para(f"Elaborado con GuardianIA · {date.today():%d/%m/%Y}"), centro),
                   PageBreak()]
        if plan.get("resumen"):
            partes += [Paragraph("Resumen ejecutivo", h1), Paragraph(_para(_texto(plan["resumen"], 4000)), cuerpo),
                       PageBreak()]
        indice = _encabezados_indice(plan)
        if indice:
            partes.append(Paragraph("Contenido", h1))
            for nivel, texto in indice:
                estilo = ParagraphStyle(f"i{nivel}", parent=cuerpo, leftIndent=14 * (nivel - 1), spaceAfter=2)
                partes.append(Paragraph(_para(texto), estilo))
            partes.append(PageBreak())
    else:
        partes.append(Paragraph(_para(titulo), estilos["Title"]))
        if plan.get("subtitulo"):
            partes.append(Paragraph(_para(_texto(plan["subtitulo"], 300)), estilos["Italic"]))
        partes.append(Spacer(1, 10))

    for seccion in secciones:
        if seccion.get("encabezado"):
            nivel = min(3, max(1, int(seccion.get("nivel", 1) or 1)))
            partes.append(Paragraph(_para(_texto(seccion["encabezado"], 120)), {1: h1, 2: h2, 3: h3}[nivel]))
        for parrafo in _lista(seccion.get("parrafos"), MAX_PARRAFOS):
            partes.append(Paragraph(_para(_texto(parrafo, 6000)), cuerpo))
        vinetas = _lista(seccion.get("vinetas"), MAX_VINETAS)
        if vinetas:
            partes.append(ListFlowable([ListItem(Paragraph(_para(_texto(v, 800)), cuerpo)) for v in vinetas],
                                       bulletType="bullet", start="•"))
        tabla = seccion.get("tabla")
        if isinstance(tabla, dict) and _lista(tabla.get("encabezados"), 12):
            enc = [_texto(c, 60) for c in _lista(tabla["encabezados"], 12)]
            filas = [[Paragraph(_para(_texto(v, 300)), celda) for v in _lista(f, len(enc))]
                     for f in _lista(tabla.get("filas"), 300)]
            datos = [[Paragraph(f"<b>{_para(c)}</b>", celda) for c in enc]] + [
                f + [Paragraph("", celda)] * (len(enc) - len(f)) for f in filas]
            t = Table(datos, repeatRows=1)
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE6F2")),
                                   ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            partes += [t, Spacer(1, 8)]

    def pie(canvas, documento):
        canvas.saveState()
        canvas.setFont("Helvetica", 8.5)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawCentredString(letter[0] / 2, 1.2 * cm, f"Página {documento.page}")
        canvas.drawRightString(letter[0] - 2.2 * cm, letter[1] - 1.3 * cm, _latin(titulo[:70]))
        canvas.restoreState()

    doc.build(partes, onFirstPage=pie if not largo else lambda c, d: None, onLaterPages=pie)
    return buf.getvalue()


def _con_diseno(nombre: str, plan: dict) -> bytes:
    """Diseño profesional (app/ai/oficina.py); si algo fallara, el diseño básico: un archivo sencillo antes que un error."""
    try:
        from app.ai import oficina
        return getattr(oficina, nombre)(plan)
    except Exception:  # noqa: BLE001
        import logging
        logging.getLogger("guardian").exception("falló el diseño de %s; se usa el básico", nombre)
        return {"docx": _docx_basico, "xlsx": _xlsx_basico, "pptx": _pptx_basico, "pdf": _pdf_basico}[nombre](plan)


def _docx(plan: dict) -> bytes:
    return _con_diseno("docx", plan)


def _xlsx(plan: dict) -> bytes:
    return _con_diseno("xlsx", plan)


def _pptx(plan: dict) -> bytes:
    return _con_diseno("pptx", plan)


def _pdf(plan: dict) -> bytes:
    return _con_diseno("pdf", plan)


def _csv(plan: dict) -> bytes:
    salida = io.StringIO()
    escritor = csv.writer(salida)
    encabezados = [_texto(c, 60) for c in _lista(plan.get("encabezados"), 40)]
    if encabezados:
        escritor.writerow(encabezados)
    for fila in _lista(plan.get("filas"), MAX_FILAS):
        escritor.writerow([_texto(v, 500) for v in _lista(fila, len(encabezados) or 40)])
    return salida.getvalue().encode("utf-8-sig")  # BOM: Excel en Windows abre bien las tildes


def _md(plan: dict) -> bytes:
    lineas = [f"# {_texto(plan.get('titulo'), 120) or 'Documento'}", ""]
    if plan.get("subtitulo"):
        lineas += [f"_{_texto(plan['subtitulo'], 300)}_", ""]
    for seccion in _lista(plan.get("secciones"), MAX_SECCIONES_DOC):
        if not isinstance(seccion, dict):
            continue
        if seccion.get("encabezado"):
            marca = "#" * (1 + min(3, max(1, int(seccion.get("nivel", 1) or 1))))
            lineas += [f"{marca} {_texto(seccion['encabezado'], 120)}", ""]
        for parrafo in _lista(seccion.get("parrafos"), MAX_PARRAFOS):
            lineas += [_texto(parrafo, 6000), ""]
        for destacado in _lista(seccion.get("destacados"), 20):
            lineas += [f"> {_texto(destacado, 1500)}", ""]
        for vineta in _lista(seccion.get("vinetas"), MAX_VINETAS):
            lineas.append(f"- {_texto(vineta, 800)}")
        tabla = seccion.get("tabla")
        if isinstance(tabla, dict) and _lista(tabla.get("encabezados"), 20):
            enc = [_texto(c, 60) for c in _lista(tabla["encabezados"], 20)]
            lineas += ["", "| " + " | ".join(enc) + " |", "|" + "---|" * len(enc)]
            for fila in _lista(tabla.get("filas"), 500):
                lineas.append("| " + " | ".join(_texto(v, 300).replace("|", "/") for v in _lista(fila, len(enc))) + " |")
        lineas.append("")
    return "\n".join(lineas).encode("utf-8")


def _figura(plan: dict):
    import matplotlib
    matplotlib.use("Agg")  # sin ventana: es un servidor
    import matplotlib.pyplot as plt

    etiquetas = [_texto(e, 40) for e in _lista(plan.get("etiquetas"), 60)]
    series = [s for s in _lista(plan.get("series"), 6) if isinstance(s, dict)]
    if not series or not etiquetas:
        raise PlanInvalido("Un gráfico necesita 'etiquetas' y al menos una serie con 'valores'")
    fig, ax = plt.subplots(figsize=(9, 5), dpi=130)
    clase = plan.get("clase", "barras")
    if clase == "torta":
        valores = [float(v) for v in _lista(series[0].get("valores"), len(etiquetas))]
        ax.pie(valores, labels=etiquetas[:len(valores)], autopct="%1.1f%%", startangle=90)
        ax.axis("equal")
    else:
        ancho = 0.8 / max(1, len(series))
        for i, serie in enumerate(series):
            valores = [float(v) for v in _lista(serie.get("valores"), len(etiquetas))]
            nombre = _texto(serie.get("nombre"), 40) or f"Serie {i + 1}"
            if clase == "lineas":
                ax.plot(etiquetas[:len(valores)], valores, marker="o", label=nombre)
            else:
                posiciones = [x + i * ancho for x in range(len(valores))]
                ax.bar(posiciones, valores, width=ancho, label=nombre)
        if clase == "barras":
            ax.set_xticks([x + 0.4 - ancho / 2 for x in range(len(etiquetas))])
            ax.set_xticklabels(etiquetas, rotation=30, ha="right")
        if len(series) > 1:
            ax.legend()
        ax.grid(axis="y", alpha=0.3)
        ax.set_ylabel(_texto(plan.get("eje_y"), 40))
    ax.set_title(_texto(plan.get("titulo"), 90) or "Gráfico")
    fig.tight_layout()
    return fig, plt


def _grafico(plan: dict) -> bytes:
    fig, plt = _figura(plan)
    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    return buf.getvalue()


def _imagen(plan: dict) -> bytes:
    """Imagen útil sin modelos de difusión: código QR o tarjeta con texto."""
    if plan.get("clase") == "qr" or plan.get("texto_qr"):
        import qrcode
        img = qrcode.make(_texto(plan.get("texto_qr") or plan.get("texto"), 800) or "GuardianIA")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import textwrap

    fig, ax = plt.subplots(figsize=(10, 5.6), dpi=130)
    ax.set_facecolor("#102a43")
    fig.patch.set_facecolor("#102a43")
    ax.axis("off")
    ax.text(0.5, 0.68, "\n".join(textwrap.wrap(_texto(plan.get("titulo"), 120) or "GuardianIA", 26)),
            ha="center", va="center", color="white", fontsize=30, fontweight="bold")
    if plan.get("texto"):
        ax.text(0.5, 0.3, "\n".join(textwrap.wrap(_texto(plan["texto"], 300), 46)),
                ha="center", va="center", color="#9fbad2", fontsize=15)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", facecolor=fig.get_facecolor())
    plt.close(fig)
    return buf.getvalue()


ESCALAS = {
    "do_mayor": [60, 62, 64, 65, 67, 69, 71, 72],
    "la_menor": [57, 59, 60, 62, 64, 65, 67, 69],
    "sol_mayor": [55, 57, 59, 60, 62, 64, 66, 67],
    "re_menor": [62, 64, 65, 67, 69, 70, 72, 74],
}


def _musica(plan: dict) -> bytes:
    """Melodía MIDI por reglas: grados de la escala, frases de 4 compases y cadencia final.

    No es un modelo generativo de audio (eso pide GPU y modelos de gigabytes); es composición
    algorítmica, suena musical y pesa unos pocos KB. Se abre con cualquier reproductor o editor.
    """
    import random

    from midiutil import MIDIFile

    escala = ESCALAS.get(_texto(plan.get("escala"), 20), ESCALAS["do_mayor"])
    compases = max(2, min(MAX_COMPASES, int(plan.get("compases") or 8)))
    tempo = max(50, min(200, int(plan.get("tempo") or 96)))
    semilla = _texto(plan.get("titulo"), 60) or "guardian"
    rng = random.Random(semilla)  # mismo título, misma melodía: reproducible

    midi = MIDIFile(2)
    midi.addTempo(0, 0, tempo)
    midi.addProgramChange(0, 0, 0, int(plan.get("instrumento") or 0))
    midi.addProgramChange(1, 1, 0, 48)  # cuerdas para el acompañamiento

    tiempo = 0.0
    grado = 0
    for compas in range(compases):
        duraciones = rng.choice([[1, 1, 1, 1], [2, 1, 1], [1, 1, 2], [2, 2], [0.5, 0.5, 1, 1, 1]])
        for duracion in duraciones:
            salto = rng.choice([-2, -1, -1, 1, 1, 2, 3])
            grado = max(0, min(len(escala) - 1, grado + salto))
            if compas == compases - 1:
                grado = 0  # cadencia: termina en la tónica
            midi.addNote(0, 0, escala[grado], tiempo, duracion, rng.randint(85, 110))
            tiempo += duracion
        acorde = [escala[0], escala[2], escala[4]] if compas % 2 == 0 else [escala[3], escala[5], escala[0] + 12]
        for nota in acorde:
            midi.addNote(1, 1, nota, compas * 4, 4, 55)
    buf = io.BytesIO()
    midi.writeFile(buf)
    return buf.getvalue()


EXT_CODIGO = {
    "python": "py", "javascript": "js", "typescript": "ts", "java": "java", "kotlin": "kt", "swift": "swift",
    "dart": "dart", "go": "go", "rust": "rs", "ruby": "rb", "php": "php", "c": "c", "cpp": "cpp", "csharp": "cs",
    "c#": "cs", "objectivec": "m", "scala": "scala", "perl": "pl", "lua": "lua", "r": "R", "matlab": "m",
    "sql": "sql", "html": "html", "css": "css", "scss": "scss", "bash": "sh", "powershell": "ps1",
    "json": "json", "yaml": "yaml", "xml": "xml", "markdown": "md", "vba": "bas", "assembly": "asm",
}


def _codigo(plan: dict) -> tuple[bytes, str, str]:
    """Guarda el código y verifica su sintaxis cuando se puede. Nunca lo ejecuta."""
    lenguaje = _texto(plan.get("lenguaje"), 20).lower() or "python"
    codigo = _texto(plan.get("codigo"), 200000)
    if not codigo.strip():
        raise PlanInvalido("El plan de código no trae contenido")
    nota = ""
    if lenguaje == "python":
        try:
            compile(codigo, "generado.py", "exec")  # solo compila, no ejecuta
            nota = "Sintaxis de Python verificada."
        except SyntaxError as e:
            nota = f"Atención: el código tiene un error de sintaxis en la línea {e.lineno}."
    nombre = _texto(plan.get("nombre"), 60) or f"codigo.{EXT_CODIGO.get(lenguaje, 'txt')}"
    if "." not in nombre:
        nombre += f".{EXT_CODIGO.get(lenguaje, 'txt')}"
    return codigo.encode("utf-8"), nombre, nota


MAX_ARCHIVOS_ZIP = 300
MAX_BYTES_ARCHIVO_ZIP = 2 * 1024 * 1024
_RUTA_ZIP_MALA = re.compile(r"(^|/)\.\.?(/|$)|[<>:\"|?*\x00-\x1f]")


def ruta_zip_segura(ruta) -> str | None:
    """Ruta relativa y limpia dentro del ZIP, o None si es peligrosa (absoluta, con «..», unidad, etc.).

    Un ZIP con «../» o «C:\\» escribiría fuera de su carpeta al descomprimirlo (zip-slip): nunca se arma."""
    r = _texto(ruta, 300).replace("\\", "/").strip().strip("/")
    r = re.sub(r"/{2,}", "/", r)
    if not r or r.startswith("~") or _RUTA_ZIP_MALA.search(r) or len(r) > 200:
        return None
    if any(parte.strip() in ("", ".", "..") or parte.endswith((" ", ".")) for parte in r.split("/")):
        return None
    return r


def _zip(plan: dict) -> tuple[bytes, str]:
    """Empaqueta los archivos del plan en un ZIP ordenado. Rutas validadas; nunca ejecuta nada."""
    import io
    import zipfile
    crudos = [a for a in _lista(plan.get("archivos"), MAX_ARCHIVOS_ZIP) if isinstance(a, dict)]
    archivos: dict[str, str] = {}
    descartados = 0
    for a in crudos:
        ruta = ruta_zip_segura(a.get("ruta"))
        contenido = a.get("contenido")
        if not ruta or not isinstance(contenido, str):
            descartados += 1
            continue
        if len(contenido.encode("utf-8")) > MAX_BYTES_ARCHIVO_ZIP or ruta in archivos:
            descartados += 1
            continue
        archivos[ruta] = contenido.replace("\x00", "")
    if not archivos:
        raise PlanInvalido("El plan del ZIP no trae archivos válidos")
    raiz = ruta_zip_segura(plan.get("carpeta")) if plan.get("carpeta") else None
    if not any(r.lower() in ("readme.md", "léeme.md", "leeme.md") or r.lower().endswith("/readme.md") for r in archivos):
        archivos["README.md"] = _readme_zip(plan, list(archivos))
    errores = []
    for ruta, contenido in archivos.items():
        if ruta.endswith(".py"):
            try:
                compile(contenido, ruta, "exec")
            except SyntaxError as e:
                errores.append(f"{ruta} (línea {e.lineno})")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for ruta in sorted(archivos, key=lambda r: (r.count("/"), r)):
            z.writestr(f"{raiz}/{ruta}" if raiz else ruta, archivos[ruta].encode("utf-8"))
    nota = f"{len(archivos)} archivos organizados."
    if descartados:
        nota += f" Se omitieron {descartados} con ruta o contenido no válido."
    if errores:
        nota += " Atención: error de sintaxis en " + ", ".join(errores[:5]) + "."
    return buf.getvalue(), nota


def _readme_zip(plan: dict, rutas: list[str]) -> str:
    titulo = _texto(plan.get("titulo"), 90) or "Proyecto"
    lineas = [f"# {titulo}", "", _texto(plan.get("descripcion"), 600) or "Proyecto organizado por GuardianIA.",
              "", "## Contenido", ""]
    lineas += [f"- `{r}`" for r in sorted(rutas, key=lambda r: (r.count("/"), r))]
    return "\n".join(lineas) + "\n"


def _video(plan: dict) -> bytes:
    """Presentación en video: cada diapositiva es un cuadro y ffmpeg las une.

    Es honesto llamarlo presentación: no es «texto a video» generativo, que requiere GPU y modelos
    de difusión. Para una sustentación o una clase, esto sirve y pesa poco.
    """
    if not shutil.which("ffmpeg"):
        raise PlanInvalido("Este servidor no tiene ffmpeg instalado, que es lo que arma el video. "
                           "Instálelo desde https://ffmpeg.org/download.html o genere una presentación (pptx).")
    diapositivas = [d for d in _lista(plan.get("diapositivas"), 30) if isinstance(d, dict)]
    if not diapositivas:
        raise PlanInvalido("Un video necesita al menos una diapositiva")
    segundos = max(2, min(15, int(plan.get("segundos_por_diapositiva") or 4)))
    with tempfile.TemporaryDirectory() as tmp:
        carpeta = Path(tmp)
        for i, diapositiva in enumerate(diapositivas):
            png = _imagen({"titulo": diapositiva.get("titulo") or plan.get("titulo"),
                           "texto": diapositiva.get("texto") or " ".join(_lista(diapositiva.get("vinetas"), 4))})
            (carpeta / f"{i:03d}.png").write_bytes(png)
        salida = carpeta / "video.mp4"
        cmd = ["ffmpeg", "-y", "-loglevel", "error", "-framerate", f"1/{segundos}",
               "-i", str(carpeta / "%03d.png"), "-c:v", "libx264", "-r", "25",
               "-pix_fmt", "yuv420p", "-vf", "scale=1280:-2", str(salida)]
        proceso = subprocess.run(cmd, capture_output=True, timeout=120)  # noqa: S603 - comando fijo
        if proceso.returncode or not salida.exists():
            raise PlanInvalido(f"ffmpeg no pudo crear el video: {proceso.stderr.decode()[:200]}")
        return salida.read_bytes()


# ──────────────────────────────────────────────────────────── entrada
def construir(plan: dict) -> Creacion:
    """Construye el archivo a partir del plan ya validado."""
    if not isinstance(plan, dict):
        raise PlanInvalido("El plan debe ser un objeto JSON")
    tipo = _texto(plan.get("tipo"), 20).lower()
    if tipo not in TIPOS:
        raise PlanInvalido(f"Tipo '{tipo}' no soportado. Disponibles: {', '.join(TIPOS)}")
    if not capacidades().get(tipo):
        raise PlanInvalido(f"Este servidor no puede generar '{tipo}' ahora mismo")

    nota = ""
    if tipo == "codigo":
        datos, nombre, nota = _codigo(plan)
    elif tipo == "zip":
        datos, nota = _zip(plan)
        nombre = nombre_seguro(plan.get("titulo") or "proyecto", tipo)
    else:
        constructor = {"docx": _docx, "xlsx": _xlsx, "pptx": _pptx, "pdf": _pdf, "csv": _csv, "md": _md,
                       "grafico": _grafico, "imagen": _imagen, "musica": _musica, "video": _video}[tipo]
        datos = constructor(plan)
        nombre = nombre_seguro(plan.get("titulo") or tipo, tipo)

    if len(datos) > MAX_BYTES:
        raise PlanInvalido("El archivo generado supera 20 MB")
    resumen = _resumen(tipo, plan, len(datos))
    if nota:
        resumen += f" {nota}"
    return Creacion(tipo=tipo, nombre=nombre, mime=MIMES[tipo], datos=datos, resumen=resumen,
                    categoria=CATEGORIAS.get(tipo, "documents"))


def palabras_del_plan(plan: dict) -> int:
    """Palabras de un plan de documento (párrafos, viñetas y tablas)."""
    total = 0
    for sec in _lista(plan.get("secciones"), MAX_SECCIONES_DOC):
        if not isinstance(sec, dict):
            continue
        for t in _lista(sec.get("parrafos"), MAX_PARRAFOS) + _lista(sec.get("vinetas"), MAX_VINETAS):
            total += len(str(t).split())
        tabla = sec.get("tabla")
        if isinstance(tabla, dict):
            total += sum(len(str(c).split()) for f in _lista(tabla.get("filas"), 500) for c in _lista(f, 20))
    return total


def contar_paginas(datos: bytes, tipo: str, palabras: int = 0, palabras_por_pagina: int = 420) -> tuple[int, str]:
    """Páginas REALES del archivo cuando se pueden medir; si no, una estimación por palabras.

    Devuelve (páginas, método): «pdf» (contadas), «libreoffice» (Word convertido a PDF para contarlas) o
    «estimado» (palabras ÷ palabras por página)."""
    try:
        if tipo == "pdf":
            from pypdf import PdfReader
            return len(PdfReader(io.BytesIO(datos)).pages), "pdf"
        if tipo == "docx":
            soffice = shutil.which("soffice") or shutil.which("libreoffice")
            if soffice:
                with tempfile.TemporaryDirectory() as carpeta:
                    origen = Path(carpeta) / "doc.docx"
                    origen.write_bytes(datos)
                    subprocess.run([soffice, "--headless", "--convert-to", "pdf", "--outdir", carpeta, str(origen)],
                                   capture_output=True, timeout=180, check=True,
                                   env={**__import__("os").environ, "HOME": carpeta})
                    from pypdf import PdfReader
                    return len(PdfReader(str(Path(carpeta) / "doc.pdf")).pages), "libreoffice"
    except Exception:  # noqa: BLE001 - medir es un extra: si falla se estima
        pass
    return max(1, round(palabras / max(1, palabras_por_pagina))), "estimado"


def _detalle_documento(plan: dict) -> str:
    n = len([s for s in _lista(plan.get("secciones"), MAX_SECCIONES_DOC) if isinstance(s, dict)])
    paginas = plan.get("paginas_estimadas")
    return f"{n} secciones" + (f", ~{paginas} páginas" if paginas else "")


def _resumen(tipo: str, plan: dict, tamano: int) -> str:
    kb = max(1, tamano // 1024)
    detalle = {
        "docx": lambda: _detalle_documento(plan),
        "pdf": lambda: _detalle_documento(plan),
        "md": lambda: _detalle_documento(plan),
        "xlsx": lambda: f"{len(_lista(plan.get('hojas'), 10))} hoja(s)",
        "pptx": lambda: f"{len(_lista(plan.get('diapositivas'), MAX_DIAPOSITIVAS)) + 1} diapositivas",
        "video": lambda: f"{len(_lista(plan.get('diapositivas'), 30))} escenas",
        "csv": lambda: f"{len(_lista(plan.get('filas'), MAX_FILAS))} filas",
        "musica": lambda: f"{plan.get('compases') or 8} compases a {plan.get('tempo') or 96} BPM",
        "codigo": lambda: _texto(plan.get("lenguaje"), 20) or "texto",
        "zip": lambda: f"{len(_lista(plan.get('archivos'), MAX_ARCHIVOS_ZIP))} archivos",
    }.get(tipo, lambda: "listo")
    return f"{detalle()}, {kb} KB."


# ───────────────────────────── detección de intención desde el chat
# Para que el asistente cree archivos sin que la persona vaya a otra sección. Se usa una lista de
# patrones y no el modelo: un modelo pequeño confunde «háblame de Excel» con «hazme un Excel», y
# crear un archivo que nadie pidió es más molesto que no crearlo.
INTENCIONES: list[tuple[str, str]] = [
    (r"\b(zip|comprimid[oa]|carpeta comprimida|empaquet\w+)\b", "zip"),
    (r"\b(hoja de c[áa]lculo|excel|xlsx|planilla|tabla de datos|presupuesto|inventario)\b", "xlsx"),
    (r"\b(presentaci[óo]n|diapositivas?|powerpoint|pptx|slides?)\b", "pptx"),
    (r"\b(documento de word|word|docx|carta|oficio|acta|circular|informe escrito)\b", "docx"),
    (r"\b(pdf)\b", "pdf"),
    (r"\b(gr[áa]fic[oa]|diagrama de barras|estad[íi]stica visual|chart)\b", "grafico"),
    (r"\b(c[óo]digo qr|qr)\b", "imagen"),
    (r"\b(imagen|afiche|cartel|poster|banner|portada|dibujo|ilustraci[óo]n)\b", "imagen"),
    (r"\b(canci[óo]n|melod[íi]a|m[úu]sica|himno|tonada|midi)\b", "musica"),
    (r"\b(video|animaci[óo]n|clip)\b", "video"),
    (r"\b(csv)\b", "csv"),
]
# Se compara contra el texto ya sin tildes, por eso los patrones van sin ellas.
VERBOS_CREAR = re.compile(
    r"\b(crea(me)?|genera(me)?|haz(me)?|hacer|arma(me)?|disena(me)?|elabora(me)?|prepara(me)?|"
    r"escribe(me)?|constru(ye|ir)|produce|redacta(me)?|necesito|quiero|dame|pasame|"
    r"me gustaria|puedes (crear|hacer|generar|disenar|armar))\b")
# Verbos que solo cuentan cuando lo pedido es un ZIP («organízame mi presupuesto» no es crear un Excel).
VERBOS_ZIP = re.compile(r"\b(organiza(me|r)?|ordena(me|r)?|agrupa(me|r)?|junta(me|r)?|empaqueta(me|r)?|"
                        r"comprime(me)?|guarda(me)?|mete(me)?|pon(me)?|exporta(me)?|"
                        r"puedes (organizar|empaquetar|comprimir|agrupar))\b")


def _sin_tildes(texto: str) -> str:
    plano = unicodedata.normalize("NFKD", texto.lower())
    return "".join(c for c in plano if not unicodedata.combining(c))


def detectar_intencion(mensaje: str) -> str | None:
    """¿La persona está pidiendo un archivo? Devuelve el tipo o None.

    Dos capas, y en este orden a propósito:

    1. **Reglas**: verbo de creación + formato. Es precisa y no se equivoca en lo evidente.
    2. **Red neuronal**: cuando aparece el formato pero el verbo no encaja —«un excel de notas pa
       mañana», «ocupo una presentacion»—, la red decide. Tolera erratas y giros que una expresión
       regular no cubre.

    La red solo puede AÑADIR una detección que la regla no vio, nunca cancelar una que sí vio: así
    un fallo del modelo no rompe algo que ya funcionaba.
    """
    folded = _sin_tildes(mensaje)
    formato = next((t for p, t in INTENCIONES if re.search(_sin_tildes(p), folded)), None)
    if formato == "zip" and VERBOS_ZIP.search(folded):
        return "zip"
    if formato and VERBOS_CREAR.search(folded):
        return formato if capacidades().get(formato) else None
    if formato and _red_dice_crear(mensaje):
        return formato if capacidades().get(formato) else None
    return None


def _red_dice_crear(mensaje: str, minimo: float = 0.7) -> bool:
    """Consulta la red de intención, si hay una entrenada. Sin modelo, no cambia nada."""
    try:
        from app.ml import asistente as ml_asistente
        from app.ml.entrenamiento import modelo_activo
        intencion, confianza = ml_asistente.clasificar(mensaje, modelo_activo("intencion"))
        return intencion == "crear_archivo" and confianza >= minimo
    except Exception:  # noqa: BLE001 - sin modelo o con error, mandan las reglas
        return False


# ───────────────────────────────────── plan por reglas (sin modelo de IA)
VERBOS_TITULO = re.compile(
    r"^\s*(por favor\s+)?(cr[eé]a(me)?|gen[eé]ra(me)?|h[aá]z(me)?|hacer|arma(me)?|dise[ñn][aá](me)?|"
    r"elabora(me)?|prepara(me)?|escribe(me)?|redacta(me)?|necesito|quiero|dame|p[aá]same|"
    r"me gustar[íi]a|puedes (crear|hacer|generar|dise[ñn]ar|armar))\s+", re.IGNORECASE)
FORMATO_TITULO = re.compile(
    r"^\s*(un[oa]?s?\s+)?(documento( de word)?|word|docx|archivo|hoja de c[áa]lculo|excel|xlsx|planilla|"
    r"presentaci[óo]n|diapositivas?|powerpoint|pptx|pdf|gr[áa]fic[oa]|imagen|afiche|cartel|video|"
    r"canci[óo]n|melod[íi]a|m[úu]sica|csv)\s*(con|sobre|de|para|que)?\s*", re.IGNORECASE)


def titulo_desde(instruccion: str) -> str:
    """Convierte «crea un word con un plan de clase de La Bella y la Bestia» en un título decente.

    Poner la instrucción cruda como título del documento —con el error de tipeo incluido— es lo que
    delata a un generador descuidado.
    """
    texto = _texto(instruccion, 200).strip()
    anterior = None
    while texto != anterior:                 # se quitan verbo y formato, en cualquier orden
        anterior = texto
        texto = VERBOS_TITULO.sub("", texto)
        texto = FORMATO_TITULO.sub("", texto)
    texto = texto.strip(" .,:;-\n")
    if not texto:
        return "Documento"
    return (texto[0].upper() + texto[1:])[:90]


def titulo_corto(instruccion: str, maximo: int = 42) -> str:
    """Título breve para nombrar un archivo: corta en una palabra completa y no deja «de», «con»… colgando."""
    t = titulo_desde(instruccion)
    if len(t) > maximo:
        t = t[:maximo].rsplit(" ", 1)[0]
    t = re.sub(r"(\s+(de|del|con|para|que|en|y|e|o|un|una|el|la|los|las|por|a))+$", "", t, flags=re.IGNORECASE)
    return t.strip(" ,.;:-") or "Proyecto"


def plan_desde_texto(texto: str, tipo: str, titulo: str) -> dict | None:
    """Convierte la respuesta en prosa del modelo en un plan estructurado.

    Un modelo pequeño falla a menudo al producir JSON, pero escribe muy bien en Markdown. En vez de
    descartar ese contenido y entregar un archivo vacío —el defecto que tenía—, aquí se aprovecha:
    los encabezados se vuelven secciones o diapositivas, las viñetas viñetas y las tablas, tablas.
    """
    if not texto or len(texto.strip()) < 40:
        return None
    lineas = [l.rstrip() for l in texto.strip().splitlines()]
    # Word, PDF y Markdown dibujan **negrita**, *cursiva* y recuadros; los demás formatos necesitan el texto limpio.
    limpiar = (lambda x: x.strip()) if tipo in ("docx", "pdf", "md") else _limpiar_marcas
    secciones: list[dict] = []
    actual = {"encabezado": "", "nivel": 1, "parrafos": [], "vinetas": []}
    tabla_cruda: list[list[str]] = []

    def cerrar() -> None:
        nonlocal actual, tabla_cruda
        if tabla_cruda and len(tabla_cruda) >= 2:
            encabezados = tabla_cruda[0]
            filas = [f for f in tabla_cruda[1:] if not all(set(c) <= set("-: ") for c in f)]
            actual["tabla"] = {"encabezados": encabezados, "filas": filas}
        tabla_cruda = []
        if actual["encabezado"] or actual["parrafos"] or actual["vinetas"] or actual.get("tabla") or actual.get("destacados"):
            secciones.append(actual)
        actual = {"encabezado": "", "nivel": 1, "parrafos": [], "vinetas": []}

    for linea in lineas:
        limpia = linea.strip()
        if not limpia:
            continue
        if limpia.startswith("|") and limpia.endswith("|"):
            tabla_cruda.append([c.strip() for c in limpia.strip("|").split("|")])
            continue
        cita = re.match(r"^>\s?(.+)$", limpia)
        if cita:
            texto_cita = limpiar(cita.group(1))
            if tipo in ("docx", "pdf"):
                actual.setdefault("destacados", []).append(texto_cita)
            elif tipo == "md":
                actual["parrafos"].append("> " + texto_cita)
            else:
                actual["parrafos"].append(sin_marcas_md(texto_cita))
            continue
        marcado = re.match(r"^(#{1,6})\s+(.+)$", limpia)
        negrita = None if marcado else re.match(r"^\*\*(.{3,80}?):?\*\*:?\s*$", limpia)
        if marcado or negrita:
            texto_encabezado = _limpiar_marcas(marcado.group(2) if marcado else negrita.group(1))
            # El «# » de nivel 1 al principio es el título del documento, no una sección: ponerlo
            # como sección deja una primera página con el título repetido y vacío.
            if marcado and len(marcado.group(1)) == 1 and not secciones and not actual["parrafos"]:
                titulo = texto_encabezado or titulo
                continue
            cerrar()
            actual["encabezado"] = texto_encabezado
            # «##» = capítulo (nivel 1), «###» = apartado (nivel 2), «####» = nivel 3
            actual["nivel"] = min(3, max(1, len(marcado.group(1)) - 1)) if marcado else 2
            continue
        vineta = re.match(r"^\s*([-*•]|\d+[.)])\s+(.+)$", limpia)
        if vineta:
            actual["vinetas"].append(limpiar(vineta.group(2)))
            continue
        actual["parrafos"].append(limpiar(limpia))
    cerrar()

    if not secciones:
        return None
    if tipo == "pptx":
        diapositivas = []
        for seccion in secciones[:MAX_DIAPOSITIVAS]:
            vinetas = seccion["vinetas"] or [p for p in seccion["parrafos"]][:5]
            diapositivas.append({"titulo": seccion["encabezado"] or titulo,
                                 "vinetas": [v[:200] for v in vinetas[:6]],
                                 "notas": " ".join(seccion["parrafos"])[:1200]})
        return {"tipo": tipo, "titulo": titulo, "diapositivas": diapositivas}
    if tipo in ("xlsx", "csv"):
        tabla = next((s["tabla"] for s in secciones if s.get("tabla")), None)
        if not tabla:
            return None
        return ({"tipo": tipo, "titulo": titulo, "hojas": [{"nombre": "Datos", **tabla}]}
                if tipo == "xlsx" else {"tipo": tipo, "titulo": titulo, **tabla})
    return {"tipo": tipo, "titulo": titulo, "secciones": secciones}


def sin_marcas_md(texto: str) -> str:
    return _limpiar_marcas(texto)


def _limpiar_marcas(texto: str) -> str:
    """Quita el marcado de Markdown: en un .docx los asteriscos se ven como asteriscos."""
    texto = re.sub(r"\*\*(.+?)\*\*", r"\1", texto)
    texto = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"\1", texto)
    texto = re.sub(r"`(.+?)`", r"\1", texto)
    return texto.strip()


def plan_basico(instruccion: str, tipo: str) -> dict:
    """Plan mínimo cuando no hay modelo o su respuesta no es válida.

    Prefiero entregar un archivo correcto y sencillo, con la instrucción dentro, antes que fallar:
    la persona puede editarlo. Nunca inventa datos que no dio.
    """
    titulo = titulo_desde(instruccion)
    if tipo in ("docx", "pdf", "md"):
        return {"tipo": tipo, "titulo": titulo,
                "secciones": [{"encabezado": "Contenido",
                               "parrafos": [_texto(instruccion, 3000),
                                            "Documento generado por GuardianIA. Edítelo a su gusto."]}]}
    if tipo == "pptx":
        return {"tipo": tipo, "titulo": titulo,
                "diapositivas": [{"titulo": "Contenido", "vinetas": [_texto(instruccion, 300)]}]}
    if tipo in ("xlsx", "csv"):
        base = {"encabezados": ["Elemento", "Detalle"], "filas": [[titulo, _texto(instruccion, 400)]]}
        return {"tipo": tipo, "titulo": titulo, **({"hojas": [{"nombre": "Datos", **base}]} if tipo == "xlsx" else base)}
    if tipo == "grafico":
        return {"tipo": tipo, "titulo": titulo, "clase": "barras", "etiquetas": ["A", "B", "C"],
                "series": [{"nombre": "Valores", "valores": [1, 2, 3]}]}
    if tipo == "musica":
        return {"tipo": tipo, "titulo": titulo, "escala": "do_mayor", "compases": 8, "tempo": 96}
    if tipo == "imagen":
        return {"tipo": tipo, "titulo": titulo, "texto": _texto(instruccion, 200)}
    if tipo == "video":
        return {"tipo": tipo, "titulo": titulo,
                "diapositivas": [{"titulo": titulo, "texto": _texto(instruccion, 200)}]}
    if tipo == "zip":
        return {"tipo": "zip", "titulo": titulo, "descripcion": _texto(instruccion, 600),
                "archivos": [{"ruta": "main.py", "contenido": f'"""{_texto(instruccion, 300)}"""\n\nprint("Escriba aquí su solución")\n'}]}
    return {"tipo": "codigo", "lenguaje": "python", "nombre": "generado.py",
            "codigo": f'"""{_texto(instruccion, 300)}"""\n\nprint("Escriba aquí su solución")\n'}


def extraer_plan(texto: str) -> dict:
    """Saca el JSON de la respuesta del modelo, que suele venir con explicaciones o ```json alrededor."""
    if not texto:
        raise PlanInvalido("El modelo no devolvió nada")
    limpio = re.sub(r"^```(?:json)?|```$", "", texto.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(limpio)
    except ValueError:
        pass
    inicio, fin = limpio.find("{"), limpio.rfind("}")
    if inicio >= 0 and fin > inicio:
        try:
            return json.loads(limpio[inicio:fin + 1])
        except ValueError as e:
            raise PlanInvalido(f"El modelo no devolvió JSON válido: {e}") from e
    raise PlanInvalido("El modelo no devolvió JSON")


INSTRUCCIONES_PLAN = """Eres el planificador del estudio de creación de GuardianIA.
Devuelves SOLO un objeto JSON, sin explicaciones ni ```.

Formato según "tipo":
- docx / pdf / md: {"tipo","titulo","subtitulo","resumen","paleta":"oceano|esmeralda|atardecer|violeta|carbon|tierra",
  "secciones":[{"encabezado","parrafos":[],"destacados":["Nota: recuadro destacado"],"vinetas":[],
  "tabla":{"encabezados":[],"filas":[[]]}}]}. En los textos puedes usar **negrita** y *cursiva*.
- xlsx: {"tipo","titulo","hojas":[{"nombre","encabezados":[],"filas":[[]],"formulas":{"B10":"=SUMA(B2:B9)"},
  "grafico":{"clase":"barras|lineas","titulo"}}]}
- pptx: {"tipo","titulo","subtitulo","paleta":"oceano|esmeralda|atardecer|violeta|carbon|tierra",
  "diapositivas":[{"titulo","vinetas":[],"notas"}]}. Varía el diseño con "tipo" en cada diapositiva:
  «seccion» (portada de bloque, 1 vineta de apoyo), «cifra» ({"tipo":"cifra","titulo","cifra":"85%","vinetas":["qué significa"]}),
  «cita» ({"tipo":"cita","vinetas":["frase"],"autor"}); y datos con "grafico":{"clase":"barras|lineas|torta","etiquetas":[],
  "series":[{"nombre","valores":[]}]}. Una diapositiva con 2 a 4 ideas cortas se muestra como tarjetas; máximo 6 ideas por diapositiva.
- csv: {"tipo","titulo","encabezados":[],"filas":[[]]}
- grafico: {"tipo","titulo","clase":"barras|lineas|torta","etiquetas":[],"series":[{"nombre","valores":[]}]}
- imagen: {"tipo","titulo","texto"} o {"tipo","clase":"qr","texto_qr"}
- musica: {"tipo","titulo","escala":"do_mayor|la_menor|sol_mayor|re_menor","compases":8,"tempo":96}
- codigo: {"tipo","lenguaje","nombre","codigo"}
- video: {"tipo","titulo","diapositivas":[{"titulo","texto"}],"segundos_por_diapositiva":4}

Reglas: escribe en español; contenido real y útil, no de relleno; si te piden datos que no tienes,
usa ejemplos claramente marcados; no inventes cifras presentándolas como reales."""
