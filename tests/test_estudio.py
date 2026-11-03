"""El estudio debe producir archivos que Office, un reproductor o Python abran de verdad."""
import io

import pytest

from app.ai import estudio

PLANES = {
    "docx": {"tipo": "docx", "titulo": "Plan lector 2026", "subtitulo": "Segundo grado",
             "secciones": [{"encabezado": "Objetivos", "parrafos": ["Mejorar la fluidez lectora."],
                            "vinetas": ["Leer 15 minutos diarios"],
                            "tabla": {"encabezados": ["Mes", "Meta"], "filas": [["Marzo", "20 palabras/min"]]}}]},
    "xlsx": {"tipo": "xlsx", "titulo": "Notas", "hojas": [{
        "nombre": "Primer periodo", "encabezados": ["Estudiante", "Nota"],
        "filas": [["Ana", 4.5], ["Luis", 3.8]], "formulas": {"B5": "=PROMEDIO(B2:B3)"},
        "grafico": {"clase": "barras", "titulo": "Notas"}}]},
    "pptx": {"tipo": "pptx", "titulo": "GuardianIA", "subtitulo": "Sustentación",
             "diapositivas": [{"titulo": "Problema", "vinetas": ["Seguridad", "Salud"], "notas": "Hablar 2 min"}]},
    "pdf": {"tipo": "pdf", "titulo": "Informe", "secciones": [{"encabezado": "Resumen",
                                                               "parrafos": ["Todo en orden."], "vinetas": ["Punto"]}]},
    "csv": {"tipo": "csv", "titulo": "Datos", "encabezados": ["a", "b"], "filas": [[1, "ñandú"]]},
    "md": {"tipo": "md", "titulo": "Guía", "secciones": [{"encabezado": "Uso", "parrafos": ["Texto"]}]},
    "grafico": {"tipo": "grafico", "titulo": "Ventas", "clase": "barras", "etiquetas": ["Ene", "Feb"],
                "series": [{"nombre": "2026", "valores": [3, 5]}]},
    "imagen": {"tipo": "imagen", "titulo": "Aviso", "texto": "Cuidado con el phishing"},
    "musica": {"tipo": "musica", "titulo": "Marcha", "escala": "do_mayor", "compases": 4, "tempo": 100},
    "codigo": {"tipo": "codigo", "lenguaje": "python", "nombre": "suma.py",
               "codigo": "def suma(a, b):\n    return a + b\n"},
}


@pytest.mark.parametrize("tipo", list(PLANES))
def test_cada_tipo_genera_un_archivo_valido(tipo):
    c = estudio.construir(PLANES[tipo])
    esperada = "py" if tipo == "codigo" else estudio.EXTENSIONES[tipo]
    assert c.datos and c.nombre.endswith(esperada) and c.mime == estudio.MIMES[tipo]
    # Firma real del formato: no basta con la extensión
    if tipo in ("docx", "xlsx", "pptx"):
        assert c.datos[:4] == b"PK\x03\x04"
    if tipo == "pdf":
        assert c.datos[:5] == b"%PDF-"
    if tipo in ("grafico", "imagen"):
        assert c.datos[:8] == b"\x89PNG\r\n\x1a\n"
    if tipo == "musica":
        assert c.datos[:4] == b"MThd"


def test_word_se_abre_y_conserva_el_contenido():
    from docx import Document
    doc = Document(io.BytesIO(estudio.construir(PLANES["docx"]).datos))
    texto = "\n".join(p.text for p in doc.paragraphs)
    assert "Plan lector 2026" in texto and "Objetivos" in texto
    assert doc.tables and doc.tables[0].rows[1].cells[0].text == "Marzo"


def test_excel_conserva_numeros_formula_y_grafico():
    from openpyxl import load_workbook
    wb = load_workbook(io.BytesIO(estudio.construir(PLANES["xlsx"]).datos))
    ws = wb["Primer periodo"]
    assert ws["A2"].value == "Ana" and ws["B2"].value == 4.5  # número, no texto
    # Dentro del archivo las funciones van en inglés; Excel las muestra traducidas. Escribirlas en
    # español producía el error #¿NOMBRE? al abrir la planilla.
    assert ws["B5"].value == "=AVERAGE(B2:B3)"
    assert ws.freeze_panes == "A2" and len(ws._charts) == 1


def test_powerpoint_incluye_notas_del_expositor():
    from pptx import Presentation
    prs = Presentation(io.BytesIO(estudio.construir(PLANES["pptx"]).datos))
    assert len(prs.slides) == 2  # portada + una
    assert prs.slides[1].notes_slide.notes_text_frame.text == "Hablar 2 min"


def test_codigo_avisa_si_la_sintaxis_esta_mal():
    c = estudio.construir({"tipo": "codigo", "lenguaje": "python", "nombre": "malo.py",
                           "codigo": "def suma(a, b)\n    return a+b"})
    assert "error de sintaxis" in c.resumen
    ok = estudio.construir(PLANES["codigo"])
    assert "verificada" in ok.resumen


def test_rechaza_planes_invalidos_en_vez_de_inventar():
    with pytest.raises(estudio.PlanInvalido):
        estudio.construir({"tipo": "inexistente"})
    with pytest.raises(estudio.PlanInvalido):
        estudio.construir({"tipo": "grafico", "titulo": "sin datos"})


def test_nombre_de_archivo_saneado():
    # sin rutas, sin «..» y sin doble extensión
    assert estudio.nombre_seguro("../../etc/passwd", "docx") == "etc passwd.docx"
    assert estudio.nombre_seguro("factura.pdf.exe", "pdf") == "factura pdf exe.pdf"
    assert estudio.nombre_seguro("   ", "csv") == "GuardianIA.csv"


def test_extrae_json_aunque_el_modelo_lo_envuelva():
    plan = estudio.extraer_plan('Claro, aquí tienes:\n```json\n{"tipo":"csv","titulo":"X"}\n```\n¡Listo!')
    assert plan["titulo"] == "X"
    with pytest.raises(estudio.PlanInvalido):
        estudio.extraer_plan("no hay json aquí")


def test_musica_es_reproducible_con_el_mismo_titulo():
    a = estudio.construir(PLANES["musica"]).datos
    b = estudio.construir(PLANES["musica"]).datos
    assert a == b


def test_api_crea_y_guarda_en_la_boveda(client, auth):
    r = client.post("/v1/estudio/crear", headers=auth,
                    json={"instruccion": "tabla de notas de mi curso", "tipo": "xlsx"})
    assert r.status_code == 201, r.text
    creado = r.json()
    assert creado["archivo_id"] and creado["plan_de"] == "reglas"  # sin modelo configurado en pruebas
    descarga = client.get(creado["descarga"], headers=auth)
    assert descarga.status_code == 200 and descarga.content[:4] == b"PK\x03\x04"
    listado = client.get("/v1/estudio/creaciones", headers=auth).json()
    assert any(c["id"] == creado["archivo_id"] for c in listado)


def test_api_rechaza_tipo_desconocido(client, auth):
    r = client.post("/v1/estudio/crear", headers=auth, json={"instruccion": "algo", "tipo": "hologramas"})
    assert r.status_code == 422 and r.json()["code"] == "tipo_no_soportado"


def test_capacidades_reporta_lo_disponible(client, auth):
    caps = client.get("/v1/estudio/capacidades", headers=auth).json()
    assert caps["tipos"]["docx"] is True and "tipos" in caps
    assert "GPU" in caps["nota_imagen"]  # se dice con claridad qué no puede hacer


@pytest.mark.parametrize("lenguaje,extension", [("go", "go"), ("rust", "rs"), ("csharp", "cs"), ("swift", "swift"),
                                                ("r", "R"), ("powershell", "ps1"), ("dart", "dart")])
def test_codigo_en_muchos_lenguajes(lenguaje, extension):
    c = estudio.construir({"tipo": "codigo", "lenguaje": lenguaje, "codigo": "// hola\n"})
    assert c.nombre.endswith(extension)


def test_el_asistente_crea_el_archivo_desde_el_chat(client, auth, monkeypatch):
    """Pedir «hazme un excel» en el chat debe devolver el archivo, no una explicación."""
    import json as _json

    from app.ai import assistant
    from app.core.config import Settings
    s = Settings(env="test", llm_provider="openai", llm_base_url="http://localhost:11434/v1",
                 llm_model="llama3", web_browsing_enabled=False)
    monkeypatch.setattr(assistant, "get_settings", lambda: s)
    import app.api.v1.assistant as api_a
    monkeypatch.setattr(api_a, "get_settings", lambda: s)
    monkeypatch.setattr(assistant, "_stream_llm", lambda *a, **k: iter(["Listo, ahí tiene la planilla."]))

    eventos = []
    with client.stream("POST", "/v1/assistant/chat/stream", headers=auth,
                       json={"message": "hazme un excel con las notas de mi curso", "allow_web": False}) as r:
        for linea in r.iter_lines():
            if linea.startswith("data:"):
                eventos.append(_json.loads(linea[5:]))

    archivo = next(e for e in eventos if e["tipo"] == "archivo")
    assert archivo["formato"] == "xlsx" and archivo["nombre"].endswith(".xlsx")
    descarga = client.get(archivo["descarga"], headers=auth)
    assert descarga.status_code == 200 and descarga.content[:4] == b"PK\x03\x04"


def test_una_pregunta_no_genera_archivos(client, auth, monkeypatch):
    import json as _json

    from app.ai import assistant
    from app.core.config import Settings
    s = Settings(env="test", web_browsing_enabled=False)
    monkeypatch.setattr(assistant, "get_settings", lambda: s)
    import app.api.v1.assistant as api_a
    monkeypatch.setattr(api_a, "get_settings", lambda: s)
    eventos = []
    with client.stream("POST", "/v1/assistant/chat/stream", headers=auth,
                       json={"message": "explícame para qué sirve Excel", "allow_web": False}) as r:
        for linea in r.iter_lines():
            if linea.startswith("data:"):
                eventos.append(_json.loads(linea[5:]))
    assert not any(e["tipo"] in ("archivo", "creando") for e in eventos)


def test_titulo_limpio_en_vez_de_la_instruccion():
    """El título del documento no puede ser la frase que escribió la persona."""
    assert estudio.titulo_desde("hazme un excel con las notas de segundo") == "Las notas de segundo"
    assert estudio.titulo_desde("necesito una presentación sobre el PRAE") == "El PRAE"
    assert estudio.titulo_desde("") == "Documento"


def test_el_contenido_del_modelo_llega_al_archivo_aunque_no_sea_json():
    """El defecto que tenía: el modelo escribía el plan en el chat y el Word salía vacío."""
    markdown = """# Plan de clase: La Bella y la Bestia

## Objetivos
- Comprender la estructura narrativa del cuento
- Identificar los valores de respeto y amistad

## Momentos de la clase

| Momento | Tiempo | Actividad |
|---|---|---|
| Inicio | 15 min | Lectura en voz alta |
| Desarrollo | 25 min | Dramatización por grupos |

## Evaluación
La evaluación es formativa y se registra en una lista de cotejo."""
    plan = estudio.plan_desde_texto(markdown, "docx", "Plan de clase")
    assert plan and [s["encabezado"] for s in plan["secciones"]][:2] == ["Objetivos", "Momentos de la clase"]

    import io

    from docx import Document
    doc = Document(io.BytesIO(estudio.construir(plan).datos))
    texto = "\n".join(p.text for p in doc.paragraphs)
    assert "estructura narrativa" in texto and "lista de cotejo" in texto
    assert "**" not in texto                      # sin marcas de Markdown crudas
    assert doc.tables and doc.tables[0].rows[1].cells[2].text == "Lectura en voz alta"


def test_el_mismo_contenido_sirve_para_una_presentacion():
    markdown = "# Sustentación\n\n## Problema\n- Seguridad\n- Salud\n\n## Solución\n- GuardianIA"
    plan = estudio.plan_desde_texto(markdown, "pptx", "Sustentación")
    assert [d["titulo"] for d in plan["diapositivas"]] == ["Problema", "Solución"]
    from pptx import Presentation
    import io
    prs = Presentation(io.BytesIO(estudio.construir(plan).datos))
    assert len(prs.slides) == 3   # portada + dos


@pytest.mark.parametrize("entrada,esperado", [
    ("=PROMEDIO(B2:B9)", "=AVERAGE(B2:B9)"),
    ("=SI(B2>=3;\"Aprobó\";\"Reprobó\")", "=IF(B2>=3,\"Aprobó\",\"Reprobó\")"),
    ("=CONTAR.SI(B2:B20;\">=3\")", "=COUNTIF(B2:B20,\">=3\")"),
    ("=AVERAGE(B2:B9)", "=AVERAGE(B2:B9)"),
])
def test_formulas_se_guardan_en_ingles(entrada, esperado):
    assert estudio.traducir_formula(entrada) == esperado


def test_la_busqueda_web_alimenta_el_documento(client, auth, monkeypatch):
    """Con «buscar en internet» activo, lo encontrado debe llegar al modelo que arma el archivo."""
    import json as _json

    from app.ai import assistant, web_browser
    from app.core.config import Settings
    s = Settings(env="test", llm_provider="openai", llm_base_url="http://x/v1", llm_model="llama3",
                 web_browsing_enabled=True)
    monkeypatch.setattr(assistant, "get_settings", lambda: s)
    import app.api.v1.assistant as api_a
    import app.api.v1.estudio as api_e
    monkeypatch.setattr(api_a, "get_settings", lambda: s)
    monkeypatch.setattr(api_e, "get_settings", lambda: s)
    monkeypatch.setattr(web_browser, "search", lambda q, client, limit=4: [
        web_browser.SearchHit("Guía PRAE", "https://minambiente.gov.co/prae", "resumen")])
    monkeypatch.setattr(web_browser, "fetch", lambda url, client, max_chars=3500: web_browser.Page(
        url=url, title="Guía PRAE",
        text="El PRAE debe articularse con el plan de estudios y responder a un problema ambiental local.",
        truncated=False))

    visto = {}

    def falso_llm(client_, s_, system, turns):
        visto["contenido"] = turns[-1]["content"]
        return ("# Proyecto PRAE\n\n## Diagnóstico\n- Problema ambiental local identificado", "openai")

    monkeypatch.setattr(assistant, "_call_llm", falso_llm)
    monkeypatch.setattr(assistant, "_stream_llm", lambda *a, **k: iter(["Listo."]))

    eventos = []
    with client.stream("POST", "/v1/assistant/chat/stream", headers=auth,
                       json={"message": "hazme un word sobre el proyecto PRAE", "allow_web": True}) as r:
        for linea in r.iter_lines():
            if linea.startswith("data:"):
                eventos.append(_json.loads(linea[5:]))

    assert "plan de estudios" in visto["contenido"]      # el dato de internet llegó al modelo
    archivo = next(e for e in eventos if e["tipo"] == "archivo")
    assert archivo["plan_de"] == "modelo" and archivo["formato"] == "docx"


def test_el_excel_trae_totales_y_semaforo():
    """Una planilla sin totales obliga a la persona a hacer lo que la herramienta debía hacer."""
    import io

    from openpyxl import load_workbook
    plan = {"tipo": "xlsx", "titulo": "Notas", "hojas": [{
        "nombre": "Periodo", "encabezados": ["Estudiante", "Nota"],
        "filas": [["Ana", 4.5], ["Luis", 3.2], ["Sara", 4.8]], "semaforo": True}]}
    ws = load_workbook(io.BytesIO(estudio.construir(plan).datos))["Periodo"]
    assert ws["A5"].value == "TOTAL / PROMEDIO" and ws["B5"].value == "=AVERAGE(B2:B4)"
    assert ws["B5"].font.bold and len(ws.conditional_formatting._cf_rules) > 0


def test_el_asistente_no_repite_el_contenido_del_archivo(monkeypatch):
    """El documento ya se entregó: repetirlo llena la pantalla y gasta el modelo."""
    from app.ai import assistant
    from app.core.config import Settings
    monkeypatch.setattr(assistant, "get_settings", lambda: Settings(
        env="test", llm_provider="openai", llm_base_url="http://x/v1", llm_model="llama3",
        web_browsing_enabled=False))
    prep = assistant.prepare("hazme un word con el plan de clase", [], assistant.Persona(),
                             archivo_creado="Plan de clase.docx")
    contenido = prep.turns[-1]["content"]
    assert "NO repitas ese contenido" in contenido and "Máximo 60 palabras" in contenido


def test_el_codigo_recibe_el_doble_de_espacio():
    """Un programa cortado a la mitad no sirve: se le da más margen que a una charla."""
    from app.ai import assistant
    from app.core.config import Settings
    s = Settings(env="test")
    charla = assistant._limite_tokens(s, [{"role": "user", "content": "cuéntame sobre el clima"}])
    codigo = assistant._limite_tokens(s, [{"role": "user", "content": "escríbeme un programa en Python"}])
    assert codigo == charla * 2 == s.llm_max_tokens * 2


def _modelo_falso(llamadas, palabras_por_capitulo=60):
    """Un 'modelo' que responde el índice, los capítulos y las ampliaciones según el prompt que recibe."""
    def falso(client, settings, system, turns):
        if "Devuelves SOLO el índice" in system:
            llamadas["indice"] += 1
            return "\n".join(f"Capítulo temático {i}" for i in range(1, 40)), "openai"
        if "capítulos ADICIONALES" in system:
            llamadas["extra"] += 1
            n = llamadas["extra"]
            return "\n".join(f"Anexo práctico {n}.{i}" for i in range(1, 25)), "openai"
        seccion = system.split("Capítulo que debes escribir ahora: ")[1].split("\n")[0]
        llamadas["secciones"].append(seccion)
        cuerpo = " ".join(["palabra"] * palabras_por_capitulo)
        return (f"## {seccion}\n\n{cuerpo}\n\n### Apartado\n\n{cuerpo}\n\n- Punto uno\n- Punto dos\n\n"
                f"| Actividad | Tiempo |\n|---|---|\n| Juego | 15 min |"), "openai"
    return falso


def test_documento_extenso_se_genera_por_secciones(monkeypatch):
    """Un modelo no escribe decenas de páginas de una vez: se pide el índice y luego cada capítulo.
    Si la persona pide expresamente pocas páginas, esa petición manda sobre el mínimo."""
    from app.ai import assistant
    from app.core.config import Settings
    import app.api.v1.estudio as api_e

    s = Settings(env="test", llm_provider="openai", llm_base_url="http://x/v1", llm_model="llama3")
    monkeypatch.setattr(api_e, "get_settings", lambda: s)
    llamadas = {"indice": 0, "extra": 0, "secciones": []}
    monkeypatch.setattr(assistant, "_call_llm", _modelo_falso(llamadas, palabras_por_capitulo=450))
    plan, origen = api_e._planificar("hazme un plan de clase extenso de 6 páginas del cuarto periodo", "docx")

    assert origen == "modelo" and llamadas["indice"] == 1
    assert len(llamadas["secciones"]) >= 4            # una llamada por capítulo, no una sola
    encabezados = [x["encabezado"] for x in plan["secciones"] if x.get("nivel", 1) == 1]
    assert encabezados[:2] == ["1. Capítulo temático 1", "2. Capítulo temático 2"]
    creacion = estudio.construir(plan)
    assert creacion.datos[:4] == b"PK\x03\x04"

    import io

    from docx import Document
    doc = Document(io.BytesIO(creacion.datos))
    assert len(doc.tables) >= 4                        # cada capítulo aportó su tabla
    texto = "\n".join(p.text for p in doc.paragraphs)
    assert "Contenido" in texto and "1. Capítulo temático 1" in texto      # portada + índice


def test_con_minimo_fijo_el_documento_se_amplia_hasta_50_paginas(monkeypatch):
    """Con GUARDIAN_DOC_MIN_PAGINAS=50 (modo anterior) un Word/PDF se escribe, se mide y se amplía hasta 50."""
    from app.ai import assistant
    from app.core.config import Settings
    import app.api.v1.estudio as api_e

    s = Settings(env="test", llm_provider="openai", llm_base_url="http://x/v1", llm_model="llama3",
                 doc_min_paginas=50)
    monkeypatch.setattr(api_e, "get_settings", lambda: s)
    llamadas = {"indice": 0, "extra": 0, "secciones": []}
    # Capítulos de ~250 palabras (el modelo se queda corto): el sistema debe pedir capítulos adicionales.
    monkeypatch.setattr(assistant, "_call_llm", _modelo_falso(llamadas, palabras_por_capitulo=125))
    # Sin abrir LibreOffice en cada ronda (lento): se mide por palabras. La medición real tiene su propia prueba.
    monkeypatch.setattr(estudio, "contar_paginas", lambda datos, tipo, palabras=0, ppp=420: (round(palabras / ppp), "estimado"))
    progreso = []
    plan, origen = api_e._planificar("hazme un manual de ciberseguridad para una empresa", "docx",
                                     progreso=lambda h, t, n: progreso.append((h, t, n)))
    palabras = estudio.palabras_del_plan(plan)
    assert origen == "modelo"
    assert palabras >= 50 * s.doc_palabras_por_pagina * 0.95, palabras
    assert plan["paginas_estimadas"] >= 50
    assert llamadas["extra"] >= 1                      # amplió con capítulos adicionales
    assert progreso and progreso[-1][2] == "Armando el documento"


def test_pedir_pocas_paginas_se_respeta():
    import app.api.v1.estudio as api_e
    assert api_e.paginas_objetivo("un oficio de 2 páginas", "docx") == 2
    assert 20 <= api_e.paginas_objetivo("manual de seguridad", "pdf") <= 60      # automático, según el trabajo
    assert api_e.paginas_objetivo("manual de seguridad", "xlsx") == 0
    assert api_e.paginas_objetivo("presentación extensa", "pptx") == 12


def test_el_word_extenso_mide_50_paginas_reales_si_hay_libreoffice():
    """Contra el conversor real: ~22 000 palabras con portada e índice deben dar 50 páginas o más."""
    import shutil
    if not (shutil.which("soffice") or shutil.which("libreoffice")):
        pytest.skip("LibreOffice no está instalado")
    secciones = [{"encabezado": f"{i}. Capítulo {i}", "nivel": 1,
                  "parrafos": [" ".join(["texto de prueba para medir páginas"] * 40)] * 6} for i in range(1, 27)]
    plan = {"tipo": "docx", "titulo": "Manual de prueba", "portada": True, "secciones": secciones}
    paginas, metodo = estudio.contar_paginas(estudio.construir(plan).datos, "docx",
                                             estudio.palabras_del_plan(plan))
    assert metodo == "libreoffice" and paginas >= 50, (paginas, metodo)


def test_el_codigo_cortado_se_continua(monkeypatch):
    """Si el modelo corta por límite, se le pide seguir: un programa truncado no sirve."""
    import httpx

    from app.ai import assistant
    from app.core.config import Settings
    s = Settings(env="test", llm_provider="openai", llm_base_url="http://x/v1", llm_model="llama3")
    respuestas = [
        {"choices": [{"message": {"content": "def procesar():"}, "finish_reason": "length"}]},
        {"choices": [{"message": {"content": "    return True"}, "finish_reason": "stop"}]},
    ]
    llamadas = {"n": 0}

    def manejador(request):
        i = min(llamadas["n"], len(respuestas) - 1)
        llamadas["n"] += 1
        return httpx.Response(200, json=respuestas[i])

    client = httpx.Client(transport=httpx.MockTransport(manejador))
    texto, proveedor = assistant._call_llm(client, s, "sistema", [{"role": "user", "content": "un programa"}])
    assert llamadas["n"] == 2 and "def procesar():" in texto and "return True" in texto
