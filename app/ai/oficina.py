"""Diseño profesional de los archivos de Office: paletas, portadas, tarjetas, tablas con bandas y llamadas.

Cada constructor recibe el mismo ``plan`` que los básicos de app/ai/estudio.py y devuelve los bytes del archivo.
Si algo del diseño fallara, estudio.py cae al constructor básico: un archivo sencillo siempre es mejor que un error."""
from __future__ import annotations

import hashlib
import io
import re
from datetime import date

# ───────────────────────────────────────────────────────────── paletas
PALETAS = {
    "oceano":    {"primario": "0B3C5D", "acento": "1D8FE1", "acento2": "F2A541", "claro": "E8F3FC", "texto": "1B2B3A"},
    "esmeralda": {"primario": "0F5132", "acento": "1FA971", "acento2": "F2B705", "claro": "E6F6EE", "texto": "16291F"},
    "atardecer": {"primario": "7A1F3D", "acento": "E4572E", "acento2": "F5B700", "claro": "FCEEE8", "texto": "33202A"},
    "violeta":   {"primario": "3B1F6B", "acento": "7B4DD6", "acento2": "FFB400", "claro": "F0EAFB", "texto": "26193F"},
    "carbon":    {"primario": "1F2933", "acento": "3E7CB1", "acento2": "F0A202", "claro": "EEF1F4", "texto": "1C242C"},
    "tierra":    {"primario": "5B3A29", "acento": "C8793A", "acento2": "3E8E7E", "claro": "F7EEE4", "texto": "33261E"},
}
_TEMAS = (
    ("esmeralda", r"ambient|agro|ecolog|natur|verde|reciclaj|salud|medic|enfermer|bienestar|prae|campo|planta|agua"),
    ("oceano", r"segur|ciber|tecnolog|software|datos|digital|red(es)?\b|internet|inform[aá]tic|inteligencia artificial|\bia\b|sistema"),
    ("atardecer", r"ni[ñn]os|infantil|cuento|escuela|colegio|clase|aula|did[aá]ctic|lectoescritura|juego|fiesta|cumplea"),
    ("violeta", r"arte|m[úu]sic|cultur|dise[ñn]o|creativ|teatro|danza|cine|poes"),
    ("carbon", r"financ|contab|presupuest|banco|inversi|n[oó]mina|impuesto|auditor|legal|juridic|contrato|empresa"),
    ("tierra", r"construc|obra|arquitect|ingenier|mec[aá]nic|taller|artesan|caf[eé]|gastronom|cocina|restaurante"),
)


def paleta(plan: dict) -> dict:
    """La que pide el plan o, si no, una acorde al tema del trabajo (y estable: el mismo título, la misma paleta)."""
    nombre = str(plan.get("paleta") or "").lower()
    if nombre in PALETAS:
        return PALETAS[nombre]
    base = f"{plan.get('titulo', '')} {plan.get('subtitulo', '')}".lower()
    for clave, patron in _TEMAS:
        if re.search(patron, base):
            return PALETAS[clave]
    claves = list(PALETAS)
    return PALETAS[claves[int(hashlib.md5(base.encode()).hexdigest(), 16) % len(claves)]]


MESES = ("enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre",
         "noviembre", "diciembre")


def fecha_larga() -> str:
    hoy = date.today()
    return f"{hoy.day} de {MESES[hoy.month - 1]} de {hoy.year}"


def _hex(h: str):
    from docx.shared import RGBColor
    return RGBColor.from_string(h)


_MARCAS = re.compile(r"(\*\*.+?\*\*|(?<![*\w])\*(?!\*)[^*\n]+?(?<!\*)\*(?![*\w]))")


def trozos_marcados(texto: str):
    """Divide «texto **negrita** y *cursiva*» en (texto, negrita, cursiva)."""
    for t in _MARCAS.split(texto or ""):
        if not t:
            continue
        if t.startswith("**") and t.endswith("**") and len(t) > 4:
            yield t[2:-2], True, False
        elif t.startswith("*") and t.endswith("*") and len(t) > 2:
            yield t[1:-1], False, True
        else:
            yield t, False, False


def sin_marcas(texto: str) -> str:
    return "".join(t for t, _, _ in trozos_marcados(texto))


def miles(v) -> str:
    """1200000 → «1.200.000» (formato colombiano) para números de verdad; el texto queda igual."""
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, int) or (isinstance(v, float) and v.is_integer()):
        return f"{int(v):,}".replace(",", ".")
    if isinstance(v, float):
        return f"{v:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return str(v)


def _es_numero(v) -> bool:
    return isinstance(v, (int, float)) or bool(re.fullmatch(r"[-+]?\$?\s?[\d.,]+%?", str(v).strip() or "x"))


# ═════════════════════════════════════════════════════════════════ WORD
def docx(plan: dict) -> bytes:
    from docx import Document
    from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Cm, Pt

    from app.ai import estudio as E

    c = paleta(plan)
    doc = Document()
    titulo = E._texto(plan.get("titulo"), 120) or "Documento"
    doc.core_properties.title = titulo
    doc.core_properties.author = "GuardianIA"
    sec0 = doc.sections[0]
    sec0.left_margin = sec0.right_margin = Cm(2.3)
    sec0.top_margin, sec0.bottom_margin = Cm(2.3), Cm(2.0)
    ancho = sec0.page_width - sec0.left_margin - sec0.right_margin

    normal = doc.styles["Normal"]
    normal.font.name, normal.font.size = "Calibri", Pt(11)
    normal.font.color.rgb = _hex(c["texto"])
    normal.paragraph_format.space_after = Pt(7)
    normal.paragraph_format.line_spacing = 1.2
    for nivel, tam, color in ((1, 20, c["primario"]), (2, 15, c["acento"]), (3, 12.5, c["primario"])):
        h = doc.styles[f"Heading {nivel}"]
        h.font.name, h.font.size, h.font.bold = "Calibri", Pt(tam), True
        h.font.color.rgb = _hex(color)
        h.paragraph_format.space_before = Pt({1: 20, 2: 14, 3: 10}[nivel])
        h.paragraph_format.space_after = Pt({1: 8, 2: 5, 3: 4}[nivel])
        h.paragraph_format.keep_with_next = True
    doc.styles["Title"].font.name = "Calibri"

    def sombrear(celda, fill):
        tcPr = celda._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), fill)
        tcPr.append(shd)

    def bordes(celda, **lados):          # lado=(grosor_octavos_pt, color) ; None = sin borde
        tcPr = celda._tc.get_or_add_tcPr()
        b = OxmlElement("w:tcBorders")
        for lado in ("top", "left", "bottom", "right"):
            el = OxmlElement(f"w:{lado}")
            v = lados.get(lado)
            if v:
                el.set(qn("w:val"), "single"); el.set(qn("w:sz"), str(v[0])); el.set(qn("w:color"), v[1])
            else:
                el.set(qn("w:val"), "nil")
            b.append(el)
        tcPr.append(b)

    def margenes(celda, arriba=60, abajo=60, izq=110, der=110):
        tcPr = celda._tc.get_or_add_tcPr()
        m = OxmlElement("w:tcMar")
        for lado, v in (("top", arriba), ("left", izq), ("bottom", abajo), ("right", der)):
            el = OxmlElement(f"w:{lado}")
            el.set(qn("w:w"), str(v)); el.set(qn("w:type"), "dxa")
            m.append(el)
        tcPr.append(m)

    def linea_inferior(p, color, grosor=10):
        pPr = p._p.get_or_add_pPr()
        pb = OxmlElement("w:pBdr")
        b = OxmlElement("w:bottom")
        b.set(qn("w:val"), "single"); b.set(qn("w:sz"), str(grosor)); b.set(qn("w:space"), "3"); b.set(qn("w:color"), color)
        pb.append(b)
        pPr.append(pb)

    def runs(p, texto, tam=None, color=None, negrita=False):
        for t, b, i in trozos_marcados(texto):
            r = p.add_run(t)
            r.bold = b or negrita or None
            r.italic = i or None
            if tam:
                r.font.size = Pt(tam)
            if color:
                r.font.color.rgb = _hex(color)

    def parrafo(texto, estilo=None):
        p = doc.add_paragraph(style=estilo)
        runs(p, texto)
        return p

    def caja(texto):
        """Llamada destacada: recuadro suave con barra de color a la izquierda."""
        t = doc.add_table(rows=1, cols=1)
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        cel = t.rows[0].cells[0]
        sombrear(cel, c["claro"])
        bordes(cel, left=(36, c["acento"]))
        margenes(cel, 110, 110, 200, 160)
        p = cel.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        m = re.match(r"^\s*(nota|consejo|importante|atenci[oó]n|ejemplo|tip|recuerda|advertencia)\s*:\s*(.*)$", texto, re.IGNORECASE | re.DOTALL)
        if m:
            r = p.add_run(m.group(1).capitalize() + ": ")
            r.bold = True
            r.font.color.rgb = _hex(c["acento"])
            runs(p, m.group(2))
        else:
            runs(p, texto)
        doc.add_paragraph().paragraph_format.space_after = Pt(2)

    secciones = [s for s in E._lista(plan.get("secciones"), E.MAX_SECCIONES_DOC) if isinstance(s, dict)]
    largo = len(secciones) >= 6 or plan.get("portada")

    if largo:
        # Portada: bloque de color a todo el ancho con el título, y debajo la ficha del documento.
        t = doc.add_table(rows=1, cols=1)
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        t.autofit = False
        cel = t.rows[0].cells[0]
        cel.width = ancho
        sombrear(cel, c["primario"])
        bordes(cel, bottom=(60, c["acento2"]))
        margenes(cel, 0, 0, 500, 500)
        fila = t.rows[0]
        trPr = fila._tr.get_or_add_trPr()
        alto = OxmlElement("w:trHeight")
        alto.set(qn("w:val"), str(int(Cm(10) / 635))); alto.set(qn("w:hRule"), "exact")
        trPr.append(alto)
        cel.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p = cel.paragraphs[0]
        p.paragraph_format.space_after = Pt(10)
        runs(p, titulo, tam=32, color="FFFFFF", negrita=True)
        if plan.get("subtitulo"):
            p2 = cel.add_paragraph()
            runs(p2, E._texto(plan["subtitulo"], 300), tam=15, color=c["claro"])
        for _ in range(3):
            doc.add_paragraph()
        p = doc.add_paragraph()
        runs(p, "Elaborado con GuardianIA", tam=12, color=c["acento"], negrita=True)
        p = doc.add_paragraph()
        runs(p, fecha_larga(), tam=11, color="6B7785")
        doc.add_page_break()
        if plan.get("resumen"):
            h = doc.add_heading("Resumen ejecutivo", level=1)
            linea_inferior(h, c["acento"])
            caja(E._texto(plan["resumen"], 4000))
            doc.add_page_break()
        indice = E._encabezados_indice(plan)
        if indice:
            h = doc.add_heading("Contenido", level=1)
            linea_inferior(h, c["acento"])
            for nivel, texto in indice:
                p = doc.add_paragraph()
                p.paragraph_format.left_indent = Pt(18 * (nivel - 1))
                p.paragraph_format.space_after = Pt(3)
                runs(p, texto, tam=11 if nivel > 1 else 11.5, negrita=nivel == 1, color=c["primario"] if nivel == 1 else c["texto"])
            doc.add_page_break()
    else:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(4)
        runs(p, titulo, tam=26, color=c["primario"], negrita=True)
        linea_inferior(p, c["acento"], 18)
        if plan.get("subtitulo"):
            p = doc.add_paragraph()
            runs(p, E._texto(plan["subtitulo"], 300), tam=13, color=c["acento"])
        if plan.get("resumen"):
            caja(E._texto(plan["resumen"], 1500))

    doc.styles["Footer"].font.size = Pt(9)
    doc.styles["Footer"].font.color.rgb = _hex("6B7785")
    for s_ in doc.sections:                        # encabezado discreto y pie con numeración
        s_.different_first_page_header_footer = bool(largo)      # la portada va limpia
        enc = s_.header.paragraphs[0]
        enc.text = ""
        runs(enc, titulo[:80], tam=9, color="6B7785")
        enc.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        linea_inferior(enc, "D5DCE4", 4)
        pie = s_.footer.paragraphs[0]
        pie.alignment = WD_ALIGN_PARAGRAPH.CENTER
        E._campo_pagina(pie)
        for r in pie.runs:
            r.font.size = Pt(9)
            r.font.color.rgb = _hex("6B7785")

    for seccion in secciones:
        if seccion.get("encabezado"):
            nivel = min(3, max(1, int(seccion.get("nivel", 1) or 1)))
            h = doc.add_heading(sin_marcas(E._texto(seccion["encabezado"], 120)), level=nivel)
            if nivel == 1:
                linea_inferior(h, c["acento"], 8)
        for texto in E._lista(seccion.get("parrafos"), E.MAX_PARRAFOS):
            parrafo(E._texto(texto, 6000))
        for texto in E._lista(seccion.get("destacados"), 20):
            caja(E._texto(texto, 1500))
        for texto in E._lista(seccion.get("vinetas"), E.MAX_VINETAS):
            p = parrafo(E._texto(texto, 800), "List Bullet")
            p.paragraph_format.space_after = Pt(3)
        tabla = seccion.get("tabla")
        if isinstance(tabla, dict) and E._lista(tabla.get("encabezados"), 20):
            enc = [E._texto(x, 60) for x in E._lista(tabla["encabezados"], 20)]
            t = doc.add_table(rows=1, cols=len(enc))
            t.alignment = WD_TABLE_ALIGNMENT.CENTER
            for i, texto in enumerate(enc):
                cel = t.rows[0].cells[i]
                sombrear(cel, c["primario"])
                bordes(cel, bottom=(12, c["acento2"]))
                margenes(cel)
                cel.paragraphs[0].paragraph_format.space_after = Pt(0)
                runs(cel.paragraphs[0], texto, tam=10, color="FFFFFF", negrita=True)
            for n, fila in enumerate(E._lista(tabla.get("filas"), 500)):
                celdas = t.add_row().cells
                for i, valor in enumerate(E._lista(fila, len(enc))):
                    cel = celdas[i]
                    if n % 2 == 1:
                        sombrear(cel, c["claro"])
                    bordes(cel, bottom=(4, "D5DCE4"))
                    margenes(cel)
                    p = cel.paragraphs[0]
                    p.paragraph_format.space_after = Pt(0)
                    if _es_numero(valor):
                        p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
                    runs(p, miles(valor) if isinstance(valor, (int, float)) else E._texto(valor, 400), tam=10)
            doc.add_paragraph().paragraph_format.space_after = Pt(4)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ═════════════════════════════════════════════════════════════════ POWERPOINT
def pptx(plan: dict) -> bytes:
    from pptx import Presentation
    from pptx.dml.color import RGBColor
    from pptx.enum.shapes import MSO_SHAPE
    from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
    from pptx.util import Inches, Pt

    from app.ai import estudio as E

    c = paleta(plan)
    rgb = RGBColor.from_string
    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
    W, H = 13.333, 7.5
    titulo_pres = E._texto(plan.get("titulo"), 120) or "Presentación"

    def forma(s, x, y, w, h, fill, tipo=MSO_SHAPE.RECTANGLE, linea=None):
        f = s.shapes.add_shape(tipo, Inches(x), Inches(y), Inches(w), Inches(h))
        f.fill.solid()
        f.fill.fore_color.rgb = rgb(fill)
        if linea:
            f.line.color.rgb = rgb(linea)
            f.line.width = Pt(0.75)
        else:
            f.line.fill.background()
        f.shadow.inherit = False
        return f

    def texto(s, x, y, w, h, contenido, tam, color, negrita=False, alinea=PP_ALIGN.LEFT, ancla=MSO_ANCHOR.TOP,
              cursiva=False, espacio=None):
        cuadro = s.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
        tf = cuadro.text_frame
        tf.word_wrap = True
        tf.vertical_anchor = ancla
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.alignment = alinea
        if espacio:
            p.line_spacing = espacio
        for t, b, i in trozos_marcados(contenido):
            r = p.add_run()
            r.text = t
            r.font.size, r.font.name = Pt(tam), "Calibri"
            r.font.bold = bool(negrita or b)
            r.font.italic = bool(cursiva or i)
            r.font.color.rgb = rgb(color)
        return cuadro

    def fondo(s, color):
        forma(s, 0, 0, W, H, color)

    def pie(s, n):
        forma(s, 0.7, 6.95, W - 1.4, 0.012, "D5DCE4")
        texto(s, 0.7, 7.05, 8, 0.3, titulo_pres, 10, "7A8794")
        texto(s, W - 1.7, 7.05, 1.0, 0.3, str(n), 10, c["acento"], True, PP_ALIGN.RIGHT)

    def titulo_slide(s, t, y=0.55):
        t = E._texto(t, 120)
        tam = 34 if len(t) <= 42 else 28 if len(t) <= 70 else 24
        forma(s, 0.7, y + 0.04, 0.09, 0.62, c["acento"])
        texto(s, 1.0, y, W - 1.7, 0.75, t, tam, c["primario"], True, ancla=MSO_ANCHOR.MIDDLE)

    nuevas = []

    def nueva():
        s = prs.slides.add_slide(prs.slide_layouts[6])
        nuevas.append(s)
        return s

    # ---- portada
    s = nueva()
    fondo(s, c["primario"])
    forma(s, 8.6, -1.6, 7.2, 7.2, c["acento"], MSO_SHAPE.OVAL)
    forma(s, 10.9, 4.2, 3.4, 3.4, c["acento2"], MSO_SHAPE.OVAL)
    forma(s, 0.9, 2.25, 1.4, 0.09, c["acento2"])
    texto(s, 0.9, 2.5, 8.2, 2.2, titulo_pres, 46 if len(titulo_pres) < 45 else 36, "FFFFFF", True, ancla=MSO_ANCHOR.TOP)
    if plan.get("subtitulo"):
        texto(s, 0.9, 4.75, 7.8, 1.0, E._texto(plan["subtitulo"], 200), 22, c["claro"])
    texto(s, 0.9, 6.7, 8, 0.4, f"GuardianIA · {date.today():%d/%m/%Y}", 12, c["claro"])

    diapositivas = [d for d in E._lista(plan.get("diapositivas"), E.MAX_DIAPOSITIVAS) if isinstance(d, dict)]
    n_sec = 0
    for idx, d in enumerate(diapositivas):
        tipo = str(d.get("tipo") or "").lower()
        t = E._texto(d.get("titulo"), 120)
        vinetas = [sin_marcas(E._texto(v, 300)) for v in (E._lista(d.get("vinetas"), 8) or [E._texto(d.get("texto"), 500)]) if v]
        s = nueva()
        n = len(nuevas)
        if tipo == "seccion":
            n_sec += 1
            fondo(s, c["primario"])
            forma(s, 0, 0, 0.35, H, c["acento"])
            texto(s, 1.0, 2.2, 3.0, 1.6, f"{n_sec:02d}", 80, c["acento2"], True)
            texto(s, 1.0, 3.9, 11, 1.4, t, 40, "FFFFFF", True)
            if vinetas:
                texto(s, 1.0, 5.3, 10, 0.9, vinetas[0], 20, c["claro"])
        elif tipo == "cifra":
            fondo(s, c["claro"])
            titulo_slide(s, t)
            texto(s, 0.9, 2.2, 6.2, 2.6, E._texto(d.get("cifra"), 14) or "—", 96, c["acento"], True, ancla=MSO_ANCHOR.MIDDLE)
            forma(s, 7.3, 2.4, 0.06, 2.2, c["acento2"])
            texto(s, 7.7, 2.3, 4.9, 2.4, vinetas[0] if vinetas else "", 24, c["texto"], ancla=MSO_ANCHOR.MIDDLE)
            pie(s, n)
        elif tipo == "cita":
            fondo(s, c["primario"])
            texto(s, 1.0, 1.0, 2.0, 2.0, "“", 160, c["acento2"], True)
            texto(s, 1.6, 2.6, 10.2, 2.8, vinetas[0] if vinetas else t, 34, "FFFFFF", cursiva=True, ancla=MSO_ANCHOR.MIDDLE)
            if d.get("autor") or (vinetas and t):
                texto(s, 1.6, 5.6, 10, 0.5, "— " + E._texto(d.get("autor") or t, 100), 18, c["claro"])
        else:
            fondo(s, "FFFFFF")
            forma(s, 0, 0, W, 0.18, c["primario"])
            titulo_slide(s, t)
            grafico = d.get("grafico")
            png = None
            if isinstance(grafico, dict) and grafico.get("etiquetas") and grafico.get("series"):
                try:
                    png = E._grafico({"titulo": grafico.get("titulo") or t, "clase": grafico.get("clase", "barras"),
                                      "etiquetas": grafico["etiquetas"], "series": grafico["series"]})
                except Exception:  # noqa: BLE001 - un gráfico roto no debe tumbar la presentación
                    png = None
            area_top, area_h = 1.75, 4.9
            largo_max = max((len(v) for v in vinetas), default=0)
            if png:
                for k, v in enumerate(vinetas[:5]):
                    y = area_top + 0.2 + k * 1.0
                    forma(s, 0.7, y + 0.1, 0.16, 0.16, c["acento"])
                    texto(s, 1.05, y, 5.4, 0.9, v, 19, c["texto"])
                s.shapes.add_picture(io.BytesIO(png), Inches(6.8), Inches(area_top), width=Inches(5.9))
            elif 2 <= len(vinetas) <= 4 and largo_max <= 95:           # tarjetas con número
                k = len(vinetas)
                gap = 0.35
                ancho = (W - 1.4 - gap * (k - 1)) / k
                for j, v in enumerate(vinetas):
                    x = 0.7 + j * (ancho + gap)
                    alto = 3.4
                    forma(s, x, 2.2, ancho, alto, c["claro"], MSO_SHAPE.ROUNDED_RECTANGLE).adjustments[0] = 0.06
                    forma(s, x, 2.2, ancho, 0.1, c["acento"])
                    forma(s, x + 0.3, 2.6, 0.7, 0.7, c["primario"], MSO_SHAPE.OVAL)
                    texto(s, x + 0.3, 2.6, 0.7, 0.7, str(j + 1), 22, "FFFFFF", True, PP_ALIGN.CENTER, MSO_ANCHOR.MIDDLE)
                    texto(s, x + 0.3, 3.5, ancho - 0.6, 2.0, v, 22 if k <= 2 else 20 if k == 3 else 18, c["texto"])
            else:
                columnas = [vinetas] if len(vinetas) <= 5 else [vinetas[:(len(vinetas) + 1) // 2], vinetas[(len(vinetas) + 1) // 2:]]
                ancho_col = (W - 1.4 - (0.5 if len(columnas) == 2 else 0)) / len(columnas)
                tam = 22 if len(columnas) == 1 and largo_max <= 80 else 19 if len(columnas) == 1 else 17
                for ci, col in enumerate(columnas):
                    x0 = 0.7 + ci * (ancho_col + 0.5)
                    paso = min(1.05, area_h / max(len(col), 1))
                    for k, v in enumerate(col):
                        y = area_top + k * paso
                        forma(s, x0, y + 0.1, 0.17, 0.17, c["acento"] if k % 2 == 0 else c["acento2"])
                        texto(s, x0 + 0.4, y, ancho_col - 0.5, paso, v, tam, c["texto"])
            pie(s, n)
        if d.get("notas"):
            s.notes_slide.notes_text_frame.text = E._texto(d["notas"], 1500)

    if len(diapositivas) >= 5 and plan.get("cierre", True):
        s = nueva()
        fondo(s, c["primario"])
        forma(s, -1.8, 4.6, 6.0, 6.0, c["acento"], MSO_SHAPE.OVAL)
        texto(s, 1.0, 2.4, 11, 1.4, "¡Gracias!", 60, "FFFFFF", True, PP_ALIGN.CENTER)
        texto(s, 1.0, 4.0, 11, 0.8, E._texto(plan.get("cierre") if isinstance(plan.get("cierre"), str) else "", 160)
              or "Preguntas y comentarios", 22, c["claro"], alinea=PP_ALIGN.CENTER)
    buf = io.BytesIO()
    prs.save(buf)
    return buf.getvalue()


# ═════════════════════════════════════════════════════════════════ EXCEL
def xlsx(plan: dict) -> bytes:
    from openpyxl import Workbook
    from openpyxl.chart import BarChart, LineChart, Reference
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter

    from app.ai import estudio as E

    c = paleta(plan)
    wb = Workbook()
    wb.remove(wb.active)
    hojas = E._lista(plan.get("hojas"), 10) or [{"nombre": "Datos", "encabezados": [], "filas": []}]
    fino = Side(style="thin", color="D5DCE4")
    colores_hoja = [c["acento"], c["primario"], c["acento2"]]
    for n_hoja, hoja in enumerate(hojas):
        if not isinstance(hoja, dict):
            continue
        ws = wb.create_sheet(E._texto(hoja.get("nombre"), 30) or "Hoja")
        ws.sheet_properties.tabColor = colores_hoja[n_hoja % 3]
        ws.sheet_view.showGridLines = False
        ws.sheet_view.zoomScale = 110
        encabezados = [E._texto(x, 60) for x in E._lista(hoja.get("encabezados"), 40)]
        if encabezados:
            ws.append(encabezados)
            ws.row_dimensions[1].height = 26
            for celda in ws[1]:
                celda.font = Font(bold=True, color="FFFFFF", size=11, name="Calibri")
                celda.fill = PatternFill("solid", fgColor=c["primario"])
                celda.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
                celda.border = Border(bottom=Side(style="medium", color=c["acento2"]))
            ws.freeze_panes = "A2"
            ws.auto_filter.ref = f"A1:{get_column_letter(len(encabezados))}1"
        for fila in E._lista(hoja.get("filas"), E.MAX_FILAS):
            ws.append([v if isinstance(v, (int, float)) else E._texto(v, 500)
                       for v in E._lista(fila, len(encabezados) or 40)])
        for ref, formula in (hoja.get("formulas") or {}).items():
            if re.fullmatch(r"[A-Z]{1,3}\d{1,5}", str(ref)) and str(formula).startswith("="):
                ws[ref] = E.traducir_formula(E._texto(formula, 200))
        # Fila de totales (como el diseño básico: suma o promedio de las columnas numéricas)
        fila_total = None
        if ws.max_row > 1 and hoja.get("totales", True) and len(encabezados) >= 2:
            fila_total = ws.max_row + 1
            ws.cell(row=fila_total, column=1, value="TOTAL / PROMEDIO")
            for col in range(2, len(encabezados) + 1):
                valores = [ws.cell(row=r, column=col).value for r in range(2, fila_total)]
                numericos = [v for v in valores if isinstance(v, (int, float))]
                if len(numericos) >= 2:
                    letra = get_column_letter(col)
                    entero = all(float(v).is_integer() for v in numericos)
                    ws.cell(row=fila_total, column=col,
                            value=f"={'SUM' if entero else 'AVERAGE'}({letra}2:{letra}{fila_total - 1})")
        # Estilo del cuerpo: bandas, bordes, alineación y formato numérico según la columna
        ultima = ws.max_row
        for r in range(2, ultima + 1):
            total = fila_total == r
            for col in range(1, len(encabezados) + 1):
                celda = ws.cell(row=r, column=col)
                celda.border = Border(left=fino, right=fino, bottom=fino,
                                      top=Side(style="medium", color=c["primario"]) if total else fino)
                celda.font = Font(name="Calibri", size=11, bold=total, color=c["primario"] if total else c["texto"])
                if total:
                    celda.fill = PatternFill("solid", fgColor=c["claro"])
                elif r % 2 == 1:
                    celda.fill = PatternFill("solid", fgColor="F7F9FB")
                v = celda.value
                es_formula = isinstance(v, str) and v.startswith("=")
                if isinstance(v, (int, float)) or es_formula:
                    celda.alignment = Alignment(horizontal="right", vertical="center")
                    nombre_col = encabezados[col - 1].lower() if col <= len(encabezados) else ""
                    entero = isinstance(v, int) or (isinstance(v, float) and v.is_integer()) or (es_formula and "SUM(" in v)
                    if re.search(r"precio|valor|costo|coste|total|presupuesto|ingreso|gasto|pago|salario|monto", nombre_col):
                        celda.number_format = '"$"#,##0' if entero else '"$"#,##0.00'
                    elif "%" in nombre_col or "porcentaje" in nombre_col:
                        celda.number_format = "0.0"
                    else:
                        celda.number_format = "#,##0" if entero else "#,##0.0"
                else:
                    celda.alignment = Alignment(vertical="center", wrap_text=True)
        for i, encabezado in enumerate(encabezados, start=1):
            largo = max([len(encabezado)] + [len(str(ws.cell(row=r, column=i).value or "")) for r in range(2, min(ultima, 200) + 1)])
            ws.column_dimensions[get_column_letter(i)].width = min(48, max(12, largo + 3))
        ws.page_setup.orientation = "landscape"
        ws.page_setup.fitToWidth = 1
        ws.page_setup.fitToHeight = 0
        ws.sheet_properties.pageSetUpPr.fitToPage = True
        if hoja.get("semaforo") and ws.max_row > 2:
            from openpyxl.formatting.rule import ColorScaleRule
            for col in range(2, len(encabezados) + 1):
                letra = get_column_letter(col)
                ws.conditional_formatting.add(
                    f"{letra}2:{letra}{(fila_total or ws.max_row + 1) - 1}",
                    ColorScaleRule(start_type="min", start_color="F8696B", mid_type="percentile", mid_value=50,
                                   mid_color="FFEB84", end_type="max", end_color="63BE7B"))
        grafico = hoja.get("grafico")
        if isinstance(grafico, dict) and ws.max_row > 1 and len(encabezados) >= 2:
            ch = LineChart() if grafico.get("clase") == "lineas" else BarChart()
            ch.title = E._texto(grafico.get("titulo"), 80) or ws.title
            ch.add_data(Reference(ws, min_col=2, min_row=1, max_col=len(encabezados), max_row=(fila_total or ws.max_row + 1) - 1),
                        titles_from_data=True)
            ch.set_categories(Reference(ws, min_col=1, min_row=2, max_row=(fila_total or ws.max_row + 1) - 1))
            ch.height, ch.width = 9, 17
            for serie, color in zip(ch.series, (c["acento"], c["acento2"], c["primario"], "7FB8E8", "9AD0B4")):
                serie.graphicalProperties.solidFill = color
                serie.graphicalProperties.line.solidFill = color
            ws.add_chart(ch, f"{get_column_letter(len(encabezados) + 2)}2")
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# ═════════════════════════════════════════════════════════════════ PDF
def pdf(plan: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (HRFlowable, ListFlowable, ListItem, PageBreak, Paragraph,
                                    SimpleDocTemplate, Spacer, Table, TableStyle)

    from app.ai import estudio as E

    c = paleta(plan)
    hx = lambda h: colors.HexColor("#" + h)  # noqa: E731
    titulo = E._texto(plan.get("titulo"), 120) or "Documento"
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=E._latin(titulo), author="GuardianIA",
                            leftMargin=2.2 * cm, rightMargin=2.2 * cm, topMargin=2.3 * cm, bottomMargin=2.1 * cm)
    est = getSampleStyleSheet()
    cuerpo = ParagraphStyle("cuerpo", parent=est["BodyText"], alignment=TA_LEFT, leading=15.5, spaceAfter=8,
                            textColor=hx(c["texto"]), fontSize=10.5)
    celda = ParagraphStyle("celda", parent=cuerpo, fontSize=8.8, leading=11, spaceAfter=0)
    celda_enc = ParagraphStyle("celda_enc", parent=celda, textColor=colors.white, fontName="Helvetica-Bold")
    h1 = ParagraphStyle("h1", parent=est["Heading1"], textColor=hx(c["primario"]), fontSize=19, leading=23, spaceBefore=16, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=est["Heading2"], textColor=hx(c["acento"]), fontSize=14, spaceBefore=12, spaceAfter=5)
    h3 = ParagraphStyle("h3", parent=est["Heading3"], textColor=hx(c["primario"]), fontSize=12, spaceBefore=8, spaceAfter=4)
    for estilo_h in (h1, h2, h3):
        estilo_h.keepWithNext = 1
    caja_est = ParagraphStyle("caja", parent=cuerpo, spaceAfter=0, leading=14.5)
    portada_t = ParagraphStyle("portada", parent=est["Title"], textColor=colors.white, fontSize=30, leading=36, alignment=TA_LEFT)
    portada_s = ParagraphStyle("portada_s", parent=cuerpo, textColor=hx(c["claro"]), fontSize=15, leading=20)

    def md(texto: str) -> str:
        """Texto con **negrita** y *cursiva* → mini-HTML de reportlab, escapado."""
        partes = []
        for t, b, i in trozos_marcados(E._texto(texto, 6000)):
            seguro = E._para(t)
            partes.append(f"<b>{seguro}</b>" if b else f"<i>{seguro}</i>" if i else seguro)
        return "".join(partes)

    secciones = [s for s in E._lista(plan.get("secciones"), E.MAX_SECCIONES_DOC) if isinstance(s, dict)]
    largo = len(secciones) >= 6 or plan.get("portada")
    partes: list = []

    def regla(color=c["acento"], grosor=1.2, espacio=6):
        return HRFlowable(width="100%", thickness=grosor, color=hx(color), spaceBefore=0, spaceAfter=espacio)

    def llamada(texto):
        m = re.match(r"^\s*(nota|consejo|importante|atenci[oó]n|ejemplo|tip|recuerda|advertencia)\s*:\s*(.*)$", texto, re.IGNORECASE | re.DOTALL)
        html = (f"<b><font color='#{c['acento']}'>{E._para(m.group(1).capitalize())}:</font></b> {md(m.group(2))}" if m else md(texto))
        t = Table([[Paragraph(html, caja_est)]], colWidths=[letter[0] - 4.4 * cm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), hx(c["claro"])), ("LINEBEFORE", (0, 0), (0, -1), 3.5, hx(c["acento"])),
                               ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                               ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
        return [t, Spacer(1, 9)]

    if largo:
        sub = [Paragraph(E._para(E._texto(plan["subtitulo"], 300)), portada_s)] if plan.get("subtitulo") else []
        bloque = Table([[[Spacer(1, 3 * cm), Paragraph(E._para(titulo), portada_t), Spacer(1, 10)] + sub + [Spacer(1, 3 * cm)]]],
                       colWidths=[letter[0] - 4.4 * cm])
        bloque.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), hx(c["primario"])), ("LEFTPADDING", (0, 0), (-1, -1), 26),
                                    ("RIGHTPADDING", (0, 0), (-1, -1), 26), ("LINEBELOW", (0, 0), (-1, -1), 5, hx(c["acento2"]))]))
        partes += [Spacer(1, 3 * cm), bloque, Spacer(1, 2.5 * cm),
                   Paragraph(f"<font color='#{c['acento']}'><b>Elaborado con GuardianIA</b></font>", cuerpo),
                   Paragraph(E._para(f"{date.today():%d/%m/%Y}"), cuerpo), PageBreak()]
        if plan.get("resumen"):
            partes += [Paragraph("Resumen ejecutivo", h1), regla()] + llamada(E._texto(plan["resumen"], 4000)) + [PageBreak()]
        indice = E._encabezados_indice(plan)
        if indice:
            partes += [Paragraph("Contenido", h1), regla()]
            for nivel, texto in indice:
                estilo = ParagraphStyle(f"i{nivel}", parent=cuerpo, leftIndent=14 * (nivel - 1), spaceAfter=3,
                                        fontName="Helvetica-Bold" if nivel == 1 else "Helvetica",
                                        textColor=hx(c["primario"] if nivel == 1 else c["texto"]))
                partes.append(Paragraph(E._para(texto), estilo))
            partes.append(PageBreak())
    else:
        t_sim = ParagraphStyle("t_sim", parent=est["Title"], textColor=hx(c["primario"]), fontSize=25, leading=30, alignment=TA_LEFT)
        partes += [Paragraph(E._para(titulo), t_sim), regla(grosor=2.5, espacio=8)]
        if plan.get("subtitulo"):
            partes.append(Paragraph(f"<font color='#{c['acento']}'>{E._para(E._texto(plan['subtitulo'], 300))}</font>", cuerpo))
        if plan.get("resumen"):
            partes += llamada(E._texto(plan["resumen"], 1500))
        partes.append(Spacer(1, 6))

    for seccion in secciones:
        if seccion.get("encabezado"):
            nivel = min(3, max(1, int(seccion.get("nivel", 1) or 1)))
            partes.append(Paragraph(E._para(sin_marcas(E._texto(seccion["encabezado"], 120))), {1: h1, 2: h2, 3: h3}[nivel]))
            if nivel == 1:
                partes.append(regla(grosor=0.8))
        for parrafo in E._lista(seccion.get("parrafos"), E.MAX_PARRAFOS):
            partes.append(Paragraph(md(parrafo), cuerpo))
        for texto in E._lista(seccion.get("destacados"), 20):
            partes += llamada(E._texto(texto, 1500))
        vinetas = E._lista(seccion.get("vinetas"), E.MAX_VINETAS)
        if vinetas:
            partes.append(ListFlowable([ListItem(Paragraph(md(v), cuerpo)) for v in vinetas], bulletType="bullet", start="•",
                                       bulletColor=hx(c["acento"])))
        tabla = seccion.get("tabla")
        if isinstance(tabla, dict) and E._lista(tabla.get("encabezados"), 12):
            enc = [E._texto(x, 60) for x in E._lista(tabla["encabezados"], 12)]
            filas = [[Paragraph(md(miles(v) if isinstance(v, (int, float)) else E._texto(v, 300)), celda) for v in E._lista(f, len(enc))]
                     for f in E._lista(tabla.get("filas"), 300)]
            datos = [[Paragraph(E._para(x), celda_enc) for x in enc]] + [f + [Paragraph("", celda)] * (len(enc) - len(f)) for f in filas]
            t = Table(datos, repeatRows=1)
            estilo = [("BACKGROUND", (0, 0), (-1, 0), hx(c["primario"])), ("LINEBELOW", (0, 0), (-1, 0), 2, hx(c["acento2"])),
                      ("LINEBELOW", (0, 1), (-1, -1), 0.4, hx("D5DCE4")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                      ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]
            estilo += [("BACKGROUND", (0, i), (-1, i), hx(c["claro"])) for i in range(2, len(datos), 2)]
            t.setStyle(TableStyle(estilo))
            partes += [t, Spacer(1, 10)]

    def pie(canvas, documento):
        canvas.saveState()
        canvas.setStrokeColor(hx("D5DCE4"))
        canvas.setLineWidth(0.6)
        canvas.line(2.2 * cm, 1.55 * cm, letter[0] - 2.2 * cm, 1.55 * cm)
        canvas.setFont("Helvetica", 8.5)
        canvas.setFillColor(hx("6B7785"))
        canvas.drawString(2.2 * cm, 1.05 * cm, E._latin(titulo[:70]))
        canvas.setFillColor(hx(c["acento"]))
        canvas.drawRightString(letter[0] - 2.2 * cm, 1.05 * cm, f"Página {documento.page}")
        canvas.restoreState()

    doc.build(partes, onFirstPage=(lambda cv, d: None) if largo else pie, onLaterPages=pie)
    return buf.getvalue()
