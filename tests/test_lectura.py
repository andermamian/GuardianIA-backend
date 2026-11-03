"""Lectura de archivos adjuntos: extracción, recuperación por relevancia y uso en el chat."""
import io

import pytest

from app.ai import lectura


def _docx(parrafos, tabla=None):
    from docx import Document
    d = Document()
    for p in parrafos:
        d.add_paragraph(p)
    if tabla:
        t = d.add_table(rows=len(tabla), cols=len(tabla[0]))
        for i, fila in enumerate(tabla):
            for j, valor in enumerate(fila):
                t.rows[i].cells[j].text = valor
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


def _pdf(paginas):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    for texto in paginas:
        c.drawString(72, 700, texto)
        c.showPage()
    c.save()
    return buf.getvalue()


def _xlsx():
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Notas"
    ws.append(["Estudiante", "Nota"])
    ws.append(["Ana", 4.5])
    ws.append(["Luis", 3.2])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_lee_word_incluyendo_tablas():
    doc = lectura.extraer("acta.docx", lectura.EXTRACTORES["application/vnd.openxmlformats-officedocument."
                                                           "wordprocessingml.document"] and
                          "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                          _docx(["Acta de reunión", "Se aprobó el plan lector."], [["Tema", "Responsable"],
                                                                                   ["Lectura", "Anderson"]]))
    assert "plan lector" in doc.texto and "Responsable" in doc.texto and doc.fragmentos


def test_lee_pdf_con_numero_de_pagina():
    doc = lectura.extraer("informe.pdf", "application/pdf",
                          _pdf(["Resumen del proyecto", "El presupuesto aprobado fue de 12 millones"]))
    assert "[Página 2]" in doc.texto and "12 millones" in doc.texto and doc.paginas == 2


def test_lee_excel_con_valores():
    doc = lectura.extraer("notas.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", _xlsx())
    assert "Hoja «Notas»" in doc.texto and "Ana | 4.5" in doc.texto


def test_pdf_escaneado_lo_dice_en_vez_de_devolver_vacio():
    from pypdf import PdfWriter
    escritor = PdfWriter()
    escritor.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    escritor.write(buf)
    with pytest.raises(lectura.NoSePuedeLeer) as e:
        lectura.extraer("escaneo.pdf", "application/pdf", buf.getvalue())
    assert "escaneo" in str(e.value).lower()


def test_tipo_no_soportado_se_rechaza():
    with pytest.raises(lectura.NoSePuedeLeer):
        lectura.extraer("programa.exe", "application/x-msdownload", b"MZ\x90\x00")


def test_busqueda_encuentra_el_fragmento_correcto_en_un_documento_largo():
    """Lo esencial: con 60 fragmentos de relleno, debe traer el que responde la pregunta."""
    fragmentos = [f"Sección {i}: generalidades del reglamento estudiantil y convivencia escolar." for i in range(60)]
    fragmentos.insert(37, "El valor de la matrícula para el año 2026 es de 380.000 pesos, pagaderos en febrero.")
    mejores = lectura.buscar("¿cuánto vale la matrícula?", fragmentos, k=3)
    assert "380.000" in mejores[0][1]  # el más relevante, no uno cualquiera
    assert mejores[0][2] > 0


def test_contexto_cita_el_documento_y_respeta_el_presupuesto():
    doc = lectura.Documento(nombre="reglamento.pdf", mime="application/pdf", texto="")
    doc.fragmentos = ["La matrícula cuesta 380.000 pesos." ] + ["Texto de relleno." * 50 for _ in range(20)]
    contexto, usados = lectura.contexto_para("precio de la matrícula", [doc], presupuesto=2000)
    assert "reglamento.pdf" in contexto and "380.000" in contexto
    assert len(contexto) <= 2600 and usados[0]["documento"] == "reglamento.pdf"


def test_fragmentar_no_corta_a_mitad_de_parrafo():
    texto = "\n\n".join(f"Párrafo {i} con contenido suficiente para ocupar espacio." for i in range(40))
    fragmentos = lectura.fragmentar(texto, tamano=300)
    assert len(fragmentos) > 1 and all(len(f) <= 400 for f in fragmentos)
    assert fragmentos[0].startswith("Párrafo 0")


# ─────────────────────────────────────────────────────────── API
def test_subir_adjunto_y_responder_con_su_contenido(client, auth, monkeypatch):
    archivo = ("reglamento.pdf", _pdf(["Reglamento del colegio",
                                       "El valor de la matricula 2026 es de 380000 pesos"]), "application/pdf")
    r = client.post("/v1/assistant/attachments", headers=auth, files={"file": archivo})
    assert r.status_code == 201, r.text
    subido = r.json()
    assert subido["paginas"] == 2 and subido["caracteres"] > 20 and subido["metodo"] == "texto del PDF"

    # El modelo recibe el fragmento correcto: se captura lo que se le manda.
    enviado = {}
    from app.ai import assistant
    from app.core.config import Settings
    s = Settings(env="test", llm_provider="openai", llm_base_url="http://localhost:11434/v1",
                 llm_model="llama3", web_browsing_enabled=False)
    monkeypatch.setattr(assistant, "get_settings", lambda: s)
    import app.api.v1.assistant as api_a
    monkeypatch.setattr(api_a, "get_settings", lambda: s)

    def falso_stream(client_, s_, system, turns):
        enviado["system"] = system
        enviado["turns"] = turns
        yield "Según el reglamento, 380000 pesos."

    monkeypatch.setattr(assistant, "_stream_llm", falso_stream)
    with client.stream("POST", "/v1/assistant/chat/stream", headers=auth,
                       json={"message": "cuánto vale la matrícula", "conversation_id": subido["conversation_id"],
                             "allow_web": False}) as resp:
        eventos = [line for line in resp.iter_lines() if line.startswith("data:")]
    import json as _json
    tipos = [_json.loads(e[5:])["tipo"] for e in eventos]
    assert "archivos" in tipos  # avisa qué documentos consultó
    contenido = enviado["turns"][-1]["content"]
    assert "380000" in contenido and "reglamento.pdf" in contenido
    assert "adjuntó archivos" in enviado["system"]


def test_adjunto_ajeno_no_se_puede_ver_ni_borrar(client, auth):
    r = client.post("/v1/assistant/attachments", headers=auth,
                    files={"file": ("nota.txt", b"contenido privado del usuario", "text/plain")})
    adj = r.json()
    otro = client.post("/v1/auth/register", json={"email": "otro@example.com", "full_name": "Otro Usuario",
                                                  "password": "Clave larga distinta 2026", "accept_terms": True})
    h = {"Authorization": f"Bearer {otro.json()['access_token']}"}
    assert client.get(f"/v1/assistant/conversations/{adj['conversation_id']}/attachments", headers=h).status_code == 404
    assert client.delete(f"/v1/assistant/attachments/{adj['id']}", headers=h).status_code == 404


def test_archivo_no_legible_responde_con_motivo(client, auth):
    r = client.post("/v1/assistant/attachments", headers=auth,
                    files={"file": ("a.7z", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 100, "application/x-7z-compressed")})
    assert r.status_code == 422 and r.json()["code"] == "no_legible"
    # Un binario desconocido ya no se rechaza: se admite diciendo con honestidad que no se puede leer.
    r = client.post("/v1/assistant/attachments", headers=auth,
                    files={"file": ("raro.exe", b"MZ\x90\x00" + b"\x00" * 100, "application/x-msdownload")})
    assert r.status_code == 201 and "no sé leer" in r.json()["vista_previa"]


def test_solo_se_envian_imagenes_a_modelos_de_vision(monkeypatch):
    import app.api.v1.assistant as api_a
    from app.core.config import Settings
    for modelo, espera in [("llama3", False), ("llava:13b", True), ("llama3.2-vision", True)]:
        monkeypatch.setattr(api_a, "get_settings", lambda m=modelo: Settings(
            env="test", llm_provider="openai", llm_base_url="http://x/v1", llm_model=m))
        assert api_a._modelo_ve_imagenes() is espera


def test_libreria_faltante_explica_que_instalar(monkeypatch):
    """«No module named pypdf» no le sirve a quien usa la app: debe decir qué ejecutar."""
    import builtins
    real = builtins.__import__

    def falso(nombre, *a, **k):
        if nombre in ("pypdf", "docx", "openpyxl", "pptx"):
            raise ImportError(f"No module named '{nombre}'")
        return real(nombre, *a, **k)

    monkeypatch.setattr(builtins, "__import__", falso)
    casos = [("x.pdf", "application/pdf", "PDF"),
             ("x.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Word"),
             ("x.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Excel")]
    for nombre, mime, etiqueta in casos:
        with pytest.raises(lectura.NoSePuedeLeer) as e:
            lectura.extraer(nombre, mime, b"PK\x03\x04")
        mensaje = str(e.value)
        assert etiqueta in mensaje and "instalar-lectura" in mensaje
        assert "ModuleNotFoundError" not in mensaje
