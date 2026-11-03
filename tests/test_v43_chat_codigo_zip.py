"""v4.3: probar código con el sandbox desde el chat y organizar trabajos de código en un ZIP."""
import io
import json as _json
import zipfile

from app.ai import assistant, estudio, pruebas
from app.core.config import Settings


def _ajustes(monkeypatch, **extra):
    s = Settings(env="test", web_browsing_enabled=False, **extra)
    monkeypatch.setattr(assistant, "get_settings", lambda: s)
    import app.api.v1.assistant as api_a
    import app.api.v1.estudio as api_e
    monkeypatch.setattr(api_a, "get_settings", lambda: s)
    monkeypatch.setattr(api_e, "get_settings", lambda: s)
    return s


def _stream(client, auth, mensaje, conversation_id=None):
    eventos = []
    cuerpo = {"message": mensaje, "allow_web": False}
    if conversation_id:
        cuerpo["conversation_id"] = conversation_id
    with client.stream("POST", "/v1/assistant/chat/stream", headers=auth, json=cuerpo) as r:
        for linea in r.iter_lines():
            if linea.startswith("data:"):
                eventos.append(_json.loads(linea[5:]))
    return eventos


LOCAL = dict(llm_provider="openai", llm_base_url="http://localhost:11434/v1", llm_model="llama3")


# ───────────────────────────────────────────── análisis de bloques (sin ejecutar nada)
def test_detecta_bloques_y_cuando_hay_que_probar():
    texto = "mira:\n```py\nprint(1)\n```\ny\n```sh\nls\n```\n```c++\nint main(){}\n```"
    bs = pruebas.bloques(texto)
    assert [b.lenguaje for b in bs] == ["python", "bash", "cpp"]
    assert pruebas.pide_probar("¿puedes probar este código?") and pruebas.pide_probar("ejecútalo por favor")
    assert not pruebas.pide_probar("explícame qué hace un bucle")
    # solo corre lenguajes del sandbox; sin petición expresa no corre nada
    assert pruebas.codigo_a_probar("prueba esto\n```html\n<b>x</b>\n```", []) is None
    assert pruebas.codigo_a_probar("hola\n```python\nprint(1)\n```", []) is None


def test_prueba_el_ultimo_codigo_del_chat_si_el_mensaje_no_trae():
    h = [assistant.Turn(role="assistant", content="Aquí va:\n```python\nprint('viejo')\n```"),
         assistant.Turn(role="assistant", content="Mejor así:\n```python\nprint('nuevo')\n```")]
    b = pruebas.codigo_a_probar("pruébalo", h)
    assert b and b.codigo == "print('nuevo')"


# ───────────────────────────────────────────── sandbox desde el chat
def test_el_chat_prueba_el_codigo_en_el_sandbox(client, auth, monkeypatch):
    _ajustes(monkeypatch, **LOCAL)
    vistos = {}

    def falso(*a, **k):                      # el modelo debe recibir el resultado real de la ejecución
        vistos["turnos"] = a[3] if len(a) > 3 else k
        return iter(["Funciona: imprime 42."])
    monkeypatch.setattr(assistant, "_stream_llm", falso)
    eventos = _stream(client, auth, "prueba este código:\n```python\nprint(6*7)\n```")
    fases = [e["fase"] for e in eventos if e["tipo"] == "probando"]
    assert fases[0] == "inicio" and fases[-1] == "fin"
    assert any(e["tipo"] == "probando" and e.get("texto", "").strip() == "42" for e in eventos)
    textos = "".join(e["texto"] for e in eventos if e["tipo"] == "texto")
    assert "Prueba en el sandbox" in textos and "42" in textos and "Terminó bien" in textos
    assert not any(e["tipo"] in ("archivo", "creando") for e in eventos)       # probar no crea archivos
    assert "42" in _json.dumps(vistos["turnos"], ensure_ascii=False)

    # y queda guardado: al reabrir la conversación el resultado sigue ahí
    conv = next(e for e in eventos if e["tipo"] == "trabajo")["conversation_id"]
    msgs = client.get(f"/v1/assistant/conversations/{conv}", headers=auth).json()
    assert "Prueba en el sandbox" in [m for m in msgs if m["role"] == "assistant"][-1]["content"]


def test_un_error_del_codigo_se_muestra_y_se_le_pasa_al_modelo(client, auth, monkeypatch):
    _ajustes(monkeypatch, **LOCAL)
    vistos = []
    monkeypatch.setattr(assistant, "_stream_llm", lambda *a, **k: (vistos.append(_json.dumps(a[3:], default=str)),
                                                                   iter(["Falta cerrar el paréntesis."]))[1])
    eventos = _stream(client, auth, "ejecuta esto\n```python\nprint(1/0)\n```")
    fin = next(e for e in eventos if e["tipo"] == "probando" and e["fase"] == "fin")
    assert fin["ok"] is False
    textos = "".join(e["texto"] for e in eventos if e["tipo"] == "texto")
    assert "ZeroDivisionError" in textos and "Falló" in textos
    assert "ZeroDivisionError" in vistos[0]


def test_sin_pedirlo_no_se_ejecuta_nada(client, auth, monkeypatch):
    _ajustes(monkeypatch, **LOCAL)
    monkeypatch.setattr(assistant, "_stream_llm", lambda *a, **k: iter(["Es un bucle."]))
    eventos = _stream(client, auth, "explícame este código\n```python\nprint('x')\n```")
    assert not any(e["tipo"] == "probando" for e in eventos)


def test_no_se_prueba_codigo_desde_otro_dispositivo(client, auth, monkeypatch):
    _ajustes(monkeypatch, **LOCAL)
    monkeypatch.setattr(assistant, "_stream_llm", lambda *a, **k: iter(["No lo ejecuté."]))
    import app.api.v1.assistant as api_a
    monkeypatch.setattr(api_a, "LOCALES", set())
    monkeypatch.setattr(api_a, "get_settings", lambda: Settings(env="produccion-simulada", web_browsing_enabled=False, **LOCAL))
    eventos = _stream(client, auth, "prueba esto\n```python\nprint(1)\n```")
    assert not any(e["tipo"] == "probando" for e in eventos)


# ───────────────────────────────────────────── ZIP de proyectos
def _abrir(datos):
    z = zipfile.ZipFile(io.BytesIO(datos))
    return z, z.namelist()


def test_el_zip_organiza_archivos_y_rechaza_rutas_peligrosas():
    plan = {"tipo": "zip", "titulo": "Mi proyecto", "descripcion": "Prueba", "archivos": [
        {"ruta": "src/main.py", "contenido": "print('hola')\n"},
        {"ruta": "../escapa.txt", "contenido": "mal"},
        {"ruta": "/abs/ruta.txt", "contenido": "ok-relativa"},
        {"ruta": "C:/windows/x.txt", "contenido": "mal"},
        {"ruta": "src/main.py", "contenido": "duplicado"},
        {"ruta": "tests/test_main.py", "contenido": "def test_x():\n    assert True\n"},
    ]}
    c = estudio.construir(plan)
    z, nombres = _abrir(c.datos)
    assert c.nombre.endswith(".zip") and c.mime == "application/zip" and z.testzip() is None
    assert "src/main.py" in nombres and "tests/test_main.py" in nombres and "README.md" in nombres
    assert "abs/ruta.txt" in nombres
    assert not any(n.startswith(("/", "..")) or ".." in n or ":" in n for n in nombres)
    assert z.read("src/main.py") == b"print('hola')\n"        # el primero gana, no se pisa
    assert "src/main.py" in z.read("README.md").decode()


def test_el_zip_avisa_si_un_python_no_compila():
    c = estudio.construir({"tipo": "zip", "titulo": "Roto", "archivos": [{"ruta": "a.py", "contenido": "def f(:\n"}]})
    assert "sintaxis" in c.resumen and "a.py" in c.resumen


def test_un_zip_sin_archivos_validos_no_se_construye():
    import pytest
    with pytest.raises(estudio.PlanInvalido):
        estudio.construir({"tipo": "zip", "titulo": "x", "archivos": [{"ruta": "../x", "contenido": "a"}]})


def test_se_pide_un_zip_desde_el_chat():
    assert estudio.detectar_intencion("organiza mis trabajos de python en un zip") == "zip"
    assert estudio.detectar_intencion("empaqueta el código en una carpeta comprimida") == "zip"
    assert estudio.detectar_intencion("crea un zip con el proyecto") == "zip"
    assert estudio.detectar_intencion("organízame mi presupuesto") != "zip"      # «organiza» solo cuenta con zip
    assert estudio.detectar_intencion("¿qué es un archivo zip?") is None


def test_el_chat_arma_el_zip_con_el_codigo_de_la_conversacion(client, auth, monkeypatch):
    _ajustes(monkeypatch)
    monkeypatch.setattr(assistant, "_stream_llm", lambda *a, **k: iter(["Listo."]))
    msg = ("organiza estos trabajos en un zip:\n```python\n# archivo: calculadora.py\ndef suma(a, b):\n    return a + b\n```\n"
           "```python\nprint('segundo')\n```\n```javascript\nconsole.log('js')\n```")
    eventos = _stream(client, auth, msg)
    archivo = next(e for e in eventos if e["tipo"] == "archivo")
    assert archivo["formato"] == "zip" and archivo["nombre"].endswith(".zip")
    datos = client.get(archivo["descarga"], headers=auth).content
    z, nombres = _abrir(datos)
    assert "calculadora.py" in nombres and "README.md" in nombres
    assert sum(n.endswith(".py") for n in nombres) == 2 and any(n.endswith(".js") for n in nombres)
    assert "def suma" in z.read("calculadora.py").decode()


def test_el_modelo_decide_carpetas_pero_el_codigo_no_se_reescribe(monkeypatch):
    import app.api.v1.estudio as api_e
    _ajustes(monkeypatch, anthropic_api_key="sk-ant-x")
    respuesta = _json.dumps({"titulo": "Calculadora", "descripcion": "Operaciones",
                             "archivos": [{"bloque": 1, "ruta": "src/calc.py"}, {"bloque": 2, "ruta": "../malo.py"}],
                             "extra": [{"ruta": "requirements.txt", "contenido": ""}],
                             "readme": "# Calculadora\nEjecute `python src/calc.py`."})
    monkeypatch.setattr(assistant, "_call_llm", lambda *a, **k: (respuesta, "anthropic"))
    bloques = [pruebas.Bloque("python", "def suma(a, b):\n    return a + b"), pruebas.Bloque("python", "print('x')")]
    plan, origen = api_e._planificar("organiza esto en un zip", "zip", bloques=bloques)
    assert origen == "modelo"
    rutas = {a["ruta"]: a["contenido"] for a in plan["archivos"]}
    assert rutas["src/calc.py"] == bloques[0].codigo                  # tal cual
    assert bloques[1].codigo in rutas.values()                        # el bloque con ruta mala no se pierde
    assert not any(".." in r for r in rutas) and "README.md" in rutas


def test_el_modelo_genera_un_proyecto_completo_si_no_hay_codigo(monkeypatch):
    import app.api.v1.estudio as api_e
    _ajustes(monkeypatch, anthropic_api_key="sk-ant-x")
    respuesta = _json.dumps({"titulo": "Hola", "archivos": [{"ruta": "app/main.py", "contenido": "print('hola')\n"}]})
    monkeypatch.setattr(assistant, "_call_llm", lambda *a, **k: (respuesta, "anthropic"))
    plan, origen = api_e._planificar("crea un proyecto en zip que salude", "zip")
    assert origen == "modelo" and plan["archivos"][0]["ruta"] == "app/main.py"
    z, nombres = _abrir(estudio.construir(plan).datos)
    assert "app/main.py" in nombres and z.read("app/main.py") == b"print('hola')\n"


# ───────────────────────────────────────────── v4.4: programar con ZIP automático, pruebas y pasos visibles
RESPUESTA_PROYECTO = (
    "Aquí tiene el proyecto:\n```python\n# archivo: src/calculo.py\ndef doble(x):\n    return x * 2\n\n\n"
    "def triple(x):\n    return x * 3\n```\n"
    "```python\n# archivo: main.py\nfrom src.calculo import doble\nprint('resultado', doble(21))\n```\n"
    "Para ejecutarlo: `python main.py`.")


def test_varios_scripts_se_organizan_solos_en_zip_y_se_prueba(client, auth, monkeypatch):
    _ajustes(monkeypatch, **LOCAL)
    monkeypatch.setattr(assistant, "_stream_llm", lambda *a, **k: iter([RESPUESTA_PROYECTO]))
    eventos = _stream(client, auth, "crea un programa en python que duplique números, con módulos separados")
    archivo = next(e for e in eventos if e["tipo"] == "archivo")
    assert archivo["formato"] == "zip"
    z, nombres = _abrir(client.get(archivo["descarga"], headers=auth).content)
    assert {"src/calculo.py", "main.py", "README.md"} <= set(nombres)
    # los pasos que ve la persona, en orden y bien cerrados
    pasos = [e for e in eventos if e["tipo"] == "paso"]
    titulos = [p["titulo"] for p in pasos]
    assert any(t.startswith("Redactando") for t in titulos) and any(t.startswith("Probando") for t in titulos)
    assert any(t.startswith("Organizando 2 archivos") for t in titulos)
    cerrados = {e["id"] for e in eventos if e["tipo"] == "paso_fin"}
    assert {p["id"] for p in pasos} == cerrados
    assert eventos[-1]["tipo"] == "fin"                          # el cliente solo termina cuando todo acabó
    textos = "".join(e.get("texto", "") for e in eventos if e["tipo"] == "texto")
    assert "Prueba en el sandbox" in textos and "resultado 42" in textos      # el proyecto completo corrió, con sus imports


def test_el_sandbox_ejecuta_proyectos_con_carpetas():
    from app.local import sandbox
    evs = list(sandbox.ejecutar("python", "from app.util import doble\nprint(doble(21))", 15,
                                extras={"app/util.py": "def doble(x):\n    return x * 2\n", "../escapa.py": "x=1"},
                                entrada="app_main.py"))
    assert evs[-1]["codigo"] == 0 and "42" in "".join(e.get("texto", "") for e in evs if e["tipo"] == "salida")


def test_un_solo_script_no_genera_zip(client, auth, monkeypatch):
    _ajustes(monkeypatch, **LOCAL)
    monkeypatch.setattr(assistant, "_stream_llm", lambda *a, **k: iter(
        ["Listo:\n```python\ndef saludo(n):\n    return f'hola {n}'\n\nprint(saludo('mundo'))\n```"]))
    eventos = _stream(client, auth, "escribe un script que salude")
    assert not any(e["tipo"] == "archivo" for e in eventos)


def test_si_el_codigo_falla_el_modelo_lo_corrige_con_el_error_real(client, auth, monkeypatch):
    _ajustes(monkeypatch, **LOCAL)
    roto = "```python\nvalor = 10\nprint(valor / 0)\nprint('fin')\n```"
    monkeypatch.setattr(assistant, "_stream_llm", lambda *a, **k: iter([roto]))
    vistos = []

    def corrige(client_, s, sistema, turnos):
        vistos.append(turnos[0]["content"])
        return "```python\nprint('arreglado', 6*7)\n```", "openai"
    monkeypatch.setattr(assistant, "_call_llm", corrige)
    eventos = _stream(client, auth, "hazme un programa en python que imprima algo")
    textos = "".join(e.get("texto", "") for e in eventos if e["tipo"] == "texto")
    assert "ZeroDivisionError" in vistos[0]                     # el modelo vio el error real
    assert "Versión corregida" in textos and "arreglado 42" in textos and "Terminó bien" in textos


def test_programas_interactivos_no_se_ejecutan_solos(client, auth, monkeypatch):
    _ajustes(monkeypatch, **LOCAL)
    monkeypatch.setattr(assistant, "_stream_llm", lambda *a, **k: iter(
        ["```python\nnombre = input('Nombre: ')\nprint('Hola', nombre)\nprint('adiós')\n```"]))
    eventos = _stream(client, auth, "crea un programa en python que pida el nombre")
    assert not any(e["tipo"] == "probando" for e in eventos)
    assert any(e["tipo"] == "paso" and e["titulo"] == "Prueba omitida" for e in eventos)


def test_el_sandbox_corre_varios_lenguajes():
    from app.local import sandbox
    import shutil
    casos = {"python": "print('ok')", "bash": "echo ok", "javascript": "console.log('ok')",
             "c": '#include <stdio.h>\nint main(){puts("ok");return 0;}'}
    for lenguaje, codigo in casos.items():
        if not sandbox._herramientas(lenguaje):
            continue
        evs = list(sandbox.ejecutar(lenguaje, codigo, 20))
        assert evs[-1]["codigo"] == 0 and "ok" in "".join(e.get("texto", "") for e in evs if e["tipo"] == "salida"), lenguaje
    if shutil.which("gcc"):
        evs = list(sandbox.ejecutar("c", "int main(){ return x; }", 20))
        assert evs[-1]["motivo"] == "compilacion" and any(e["tipo"] == "salida" for e in evs)
    disponibles = {l["id"]: l["disponible"] for l in sandbox.estado()["lenguajes"]}
    assert {"python", "javascript", "typescript", "go", "java", "rust", "c", "cpp", "bash", "php"} <= set(disponibles)


# ───────────────────────────────────────────── v4.4: diseño profesional de Office
def _plan_doc(tipo="docx"):
    return {"tipo": tipo, "titulo": "Manual de ciberseguridad escolar", "subtitulo": "Guía práctica",
            "resumen": "Resumen del manual.", "secciones": (
                [{"encabezado": "Introducción", "nivel": 1, "parrafos": ["Texto con **negrita** y *cursiva*."],
                  "destacados": ["Importante: no comparta contraseñas."], "vinetas": ["Uno", "Dos"]},
                 {"encabezado": "Riesgos", "nivel": 1, "parrafos": ["x"],
                  "tabla": {"encabezados": ["Riesgo", "Costo"], "filas": [["Phishing", 1200000], ["Ransomware", 5400000]]}}]
                + [{"encabezado": f"Capítulo {i}", "nivel": 1, "parrafos": ["texto " * 20]} for i in range(3, 7)])}


def test_word_con_diseno_profesional():
    import io
    from docx import Document
    from app.ai import oficina
    doc = Document(io.BytesIO(estudio.construir(_plan_doc("docx")).datos))
    texto = "\n".join(p.text for p in doc.paragraphs)
    assert "**" not in texto and "*cursiva*" not in texto           # el marcado se dibuja, no se muestra
    assert any(r.bold and r.text == "negrita" for p in doc.paragraphs for r in p.runs)
    assert len(doc.tables) >= 3                                       # portada + recuadro destacado + tabla de datos
    assert any("1.200.000" in c.text for t in doc.tables for row in t.rows for c in row.cells)
    assert oficina.paleta({"titulo": "Plan de gestión ambiental"}) == oficina.PALETAS["esmeralda"]
    assert oficina.paleta({"titulo": "x", "paleta": "violeta"}) == oficina.PALETAS["violeta"]


def test_pdf_pptx_y_xlsx_con_diseno():
    import io
    from openpyxl import load_workbook
    from pptx import Presentation
    pdf = estudio.construir(_plan_doc("pdf")).datos
    assert pdf[:5] == b"%PDF-"
    pp = estudio.construir({"tipo": "pptx", "titulo": "Mi proyecto", "diapositivas": [
        {"titulo": "Ideas", "vinetas": ["a", "b", "c"]}, {"titulo": "Bloque", "tipo": "seccion", "vinetas": ["x"]},
        {"titulo": "Impacto", "tipo": "cifra", "cifra": "85%", "vinetas": ["detectado"]},
        {"titulo": "Datos", "vinetas": ["x"], "grafico": {"etiquetas": ["a", "b"], "series": [{"nombre": "s", "valores": [1, 2]}]}},
        {"titulo": "Lista", "vinetas": ["uno " * 20] * 7}]}).datos
    prs = Presentation(io.BytesIO(pp))
    assert len(prs.slides) == 1 + 5 + 1                                # portada + 5 + cierre
    assert any(sh.shape_type == 13 for sl in prs.slides for sh in sl.shapes)       # el gráfico entró como imagen
    xl = estudio.construir({"tipo": "xlsx", "titulo": "Notas", "hojas": [{"nombre": "Notas", "encabezados": ["Alumno", "Nota", "Valor"],
                                                                         "filas": [["Ana", 4.5, 1000], ["Luis", 3.9, 1000]]}]}).datos
    ws = load_workbook(io.BytesIO(xl)).active
    assert ws["A1"].font.bold and ws["A1"].font.color.rgb.endswith("FFFFFF") and ws.freeze_panes == "A2"
    assert ws.sheet_view.showGridLines is False and ws.cell(row=4, column=2).value.startswith("=")


def test_si_el_diseno_falla_se_usa_el_basico(monkeypatch):
    from app.ai import oficina
    monkeypatch.setattr(oficina, "docx", lambda plan: (_ for _ in ()).throw(RuntimeError("boom")))
    assert estudio.construir(_plan_doc("docx")).datos[:4] == b"PK\x03\x04"


def test_el_markdown_conserva_negritas_y_recuadros_para_word():
    texto = "# Título\n\n## Sección\n\nUn término **clave** aquí.\n\n> Nota: revise esto.\n\n- punto *uno*\n"
    plan = estudio.plan_desde_texto(texto, "docx", "T")
    sec = plan["secciones"][0]
    assert "**clave**" in sec["parrafos"][0] and sec["destacados"] == ["Nota: revise esto."] and "*uno*" in sec["vinetas"][0]
    ppt = estudio.plan_desde_texto(texto, "pptx", "T")
    assert "**" not in str(ppt)                                       # PowerPoint recibe el texto limpio
