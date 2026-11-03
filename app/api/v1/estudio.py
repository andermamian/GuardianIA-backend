"""Estudio de creación: instrucción en español → archivo real, guardado cifrado en la bóveda.

Reparto de responsabilidades, que es lo que hace esto seguro con un modelo pequeño:

    modelo de lenguaje → plan en JSON → validación → construcción determinista (app/ai/estudio.py)

El modelo nunca toca el disco ni ejecuta nada. Si alucina, el plan no valida y se responde con un
plan básico por reglas: la persona recibe un archivo correcto, no un error.
"""
from __future__ import annotations

import math
import re
import time

import httpx
from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.ai import assistant, estudio
from app.api.deps import DB, CurrentUser, client_ip
from app.core import audit
from app.core.config import get_settings
from app.core.crypto import open_text
from app.core.errors import ApiError
from app.core.ratelimit import limiter
from app.db.models import VaultFile
from app.schemas.common import Out
from app.services import boveda

router = APIRouter(prefix="/estudio", tags=["Estudio de creación"])


class CrearIn(BaseModel):
    instruccion: str = Field(min_length=4, max_length=20000)
    tipo: str = Field(description="docx, xlsx, pptx, pdf, csv, md, grafico, imagen, musica, codigo, video o zip")
    guardar_en_boveda: bool = True


class CreacionOut(Out):
    archivo_id: str | None
    nombre: str
    tipo: str
    mime: str
    bytes: int
    resumen: str
    plan_de: str  # "modelo" o "reglas": de dónde salió el contenido
    descarga: str | None


@router.get("/capacidades")
def capacidades(p: CurrentUser):
    """Lo que este servidor puede generar. La interfaz solo ofrece lo disponible, en vez de fallar después."""
    s = get_settings()
    disponible = estudio.capacidades()
    return {
        "tipos": disponible,
        "modelo": s.llm_kind,
        "nota_video": ("El video se arma como presentación animada, no es «texto a video» generativo: "
                       "eso requiere GPU y modelos de varios GB." if disponible.get("video") else
                       "Falta ffmpeg en el servidor para armar videos; instálelo desde ffmpeg.org."),
        "nota_imagen": ("Las imágenes son tarjetas y códigos QR generados en el servidor. Para imágenes "
                        "fotorrealistas por IA se necesita un modelo de difusión con GPU."),
    }


@router.post("/crear", response_model=CreacionOut, status_code=201)
def crear(body: CrearIn, request: Request, p: CurrentUser, db: DB):
    limiter.hit(f"estudio:{p.user.id}", 20, 600)  # generar cuesta CPU: 20 cada 10 minutos
    tipo = body.tipo.lower().strip()
    if tipo not in estudio.TIPOS:
        raise ApiError(422, "tipo_no_soportado", f"Tipo no soportado. Use: {', '.join(estudio.TIPOS)}")

    plan, origen = _planificar(body.instruccion, tipo)
    try:
        creacion = estudio.construir(plan)
    except estudio.PlanInvalido as e:
        # El plan del modelo no sirvió: se reintenta con el plan por reglas antes de rendirse.
        if origen == "modelo":
            try:
                creacion = estudio.construir(estudio.plan_basico(body.instruccion, tipo))
                origen = "reglas"
            except estudio.PlanInvalido as e2:
                raise ApiError(422, "plan_invalido", str(e2)) from e2
        else:
            raise ApiError(422, "plan_invalido", str(e)) from e

    archivo_id = descarga = None
    if body.guardar_en_boveda:
        f = boveda.guardar(db, p.user, categoria=creacion.categoria, nombre=creacion.nombre,
                           datos=creacion.datos, mime=creacion.mime)
        audit.record(db, "estudio.creado", actor_id=p.user.id, target_type="vault_file", target_id=f.id,
                     ip=client_ip(request), detail={"tipo": tipo, "bytes": len(creacion.datos), "plan": origen},
                     commit=False)
        db.commit()
        archivo_id, descarga = f.id, f"/v1/vault/files/{f.id}/download"

    return CreacionOut(archivo_id=archivo_id, nombre=creacion.nombre, tipo=creacion.tipo, mime=creacion.mime,
                       bytes=len(creacion.datos), resumen=creacion.resumen, plan_de=origen, descarga=descarga)


@router.get("/creaciones")
def creaciones(p: CurrentUser, db: DB, limit: int = Query(30, ge=1, le=100)):
    """Lo creado por el estudio vive en la bóveda, cifrado como cualquier otro archivo suyo."""
    rows = db.execute(select(VaultFile).where(VaultFile.user_id == p.user.id)
                      .order_by(VaultFile.created_at.desc()).limit(limit)).scalars().all()
    return [{"id": f.id, "nombre": open_text(f.filename_enc, boveda.ctx(p.user.id, f.id)),
             "mime": f.mime, "bytes": f.size_bytes, "creado": f.created_at,
             "descarga": f"/v1/vault/files/{f.id}/download"} for f in rows]


def _modelo_local(s) -> bool:
    return s.llm_kind == "openai" and any(h in s.llm_base_url for h in ("localhost", "127.0.0.1", "[::1]"))


def _redactar_en_vivo(client, s, sistema: str, peticion: str, progreso=None) -> str:
    """Una llamada en streaming que informa el avance (palabras escritas) mientras el modelo escribe: en un
    equipo sin GPU una pieza larga tarda minutos y sin esto la pantalla parecía congelada."""
    piezas: list[str] = []
    ultimo = 0
    inicio = time.perf_counter()
    for trozo in assistant._stream_con_continuacion(client, s, sistema, [{"role": "user", "content": peticion}]):
        piezas.append(trozo)
        if progreso and len(piezas) % 8 == 0:
            palabras = sum(len(x.split()) for x in piezas)
            if palabras - ultimo >= 25:
                ultimo = palabras
                try:
                    progreso(palabras, 0, f"{palabras} palabras · {int(time.perf_counter() - inicio)} s")
                except Exception:  # noqa: BLE001 - informar nunca debe romper la creación
                    pass
    return "".join(piezas).strip()


INSTRUCCIONES_ZIP_ORGANIZAR = """Organizas trabajos y código en un proyecto ZIP ordenado. Te llegan bloques de código
numerados y la petición de la persona. NO reescribas el código: solo decide la estructura.
Devuelve SOLO un JSON, sin texto alrededor:
{"titulo": "nombre-corto-del-proyecto", "descripcion": "una o dos frases",
 "archivos": [{"bloque": 1, "ruta": "src/main.py"}, {"bloque": 2, "ruta": "src/utils.py"}],
 "extra": [{"ruta": "requirements.txt", "contenido": "..."}], "readme": "texto en Markdown: qué es y cómo ejecutarlo"}
Reglas: rutas relativas con «/», sin «..» ni unidades; carpetas con sentido (src, tests, docs, data);
un archivo por bloque; si un bloque es una prueba, va en tests/; añade requirements.txt solo si el código importa
paquetes externos; el README explica cómo ejecutar. Nombres claros, sin espacios."""

INSTRUCCIONES_ZIP_GENERAR = """Eres un ingeniero de software. Entregas un PROYECTO COMPLETO y funcional como lista de archivos.
Devuelve SOLO un JSON, sin texto alrededor:
{"titulo": "nombre-corto", "descripcion": "una o dos frases",
 "archivos": [{"ruta": "src/main.py", "contenido": "código completo"}, {"ruta": "README.md", "contenido": "..."}]}
Reglas: rutas relativas con «/», sin «..»; código completo y sin marcadores tipo «aquí va...»; estructura de carpetas
con sentido; incluye README.md con cómo ejecutarlo y requirements.txt si usa paquetes externos; máximo 25 archivos."""


def _plan_zip(instruccion: str, bloques: list, progreso=None, skills: str = "") -> tuple[dict, str]:
    """Plan de un ZIP. Con código en la conversación se ORGANIZA tal cual (sin reescribirlo: no se pierde ni se
    inventa nada); sin código, el modelo genera el proyecto. Sin modelo, se ordena por reglas."""
    from app.ai import pruebas
    s = get_settings()
    titulo = estudio.titulo_corto(instruccion) if instruccion else "Proyecto"
    titulo = re.sub(r"(?i)\b(en|dentro de|como)\s+(un|una)\s+(zip|carpeta comprimida)\b.*$", "", titulo).strip() or "Proyecto"
    usados: set[str] = set()
    por_reglas = {"tipo": "zip", "titulo": titulo, "descripcion": instruccion[:400],
                  "archivos": [{"ruta": pruebas.nombre_sugerido(b, i, usados), "contenido": b.codigo}
                               for i, b in enumerate(bloques)]}
    if s.llm_kind == "ninguno":
        return (por_reglas if bloques else estudio.plan_basico(instruccion, "zip")), "reglas"
    limpio, _ = assistant.redact(instruccion)
    try:
        with httpx.Client(timeout=httpx.Timeout(30.0, read=float(s.llm_read_timeout))) as client:
            if bloques:
                lista = "\n\n".join(f"[Bloque {i + 1}] lenguaje: {b.lenguaje or 'texto'}\n{b.codigo[:1500]}"
                                     for i, b in enumerate(bloques[:40]))
                texto, _ = assistant._call_llm(client, s, INSTRUCCIONES_ZIP_ORGANIZAR + skills,
                                               [{"role": "user", "content": f"Petición: {limpio}\n\n{lista}"}])
                datos = estudio.extraer_plan(texto)
                archivos, rutas, colocados = [], set(), set()
                for item in datos.get("archivos") or []:
                    try:
                        indice = int(item.get("bloque")) - 1
                        b = bloques[indice]
                    except (TypeError, ValueError, IndexError, AttributeError):
                        continue
                    ruta = estudio.ruta_zip_segura(item.get("ruta"))
                    if ruta and ruta not in rutas and indice >= 0 and indice not in colocados:
                        rutas.add(ruta)
                        colocados.add(indice)
                        archivos.append({"ruta": ruta, "contenido": b.codigo})
                for i, b in enumerate(bloques):                     # lo que el modelo olvidó no se pierde
                    if i not in colocados:
                        nombre = pruebas.nombre_sugerido(b, i, {r.lower() for r in rutas})
                        rutas.add(nombre)
                        archivos.append({"ruta": nombre, "contenido": b.codigo})
                for extra in datos.get("extra") or []:
                    ruta = estudio.ruta_zip_segura(extra.get("ruta")) if isinstance(extra, dict) else None
                    if ruta and ruta not in rutas and isinstance(extra.get("contenido"), str):
                        rutas.add(ruta)
                        archivos.append({"ruta": ruta, "contenido": extra["contenido"]})
                if isinstance(datos.get("readme"), str) and datos["readme"].strip() and "README.md" not in rutas:
                    archivos.append({"ruta": "README.md", "contenido": datos["readme"]})
                if archivos:
                    return {"tipo": "zip", "titulo": str(datos.get("titulo") or titulo)[:80],
                            "descripcion": str(datos.get("descripcion") or "")[:600], "archivos": archivos}, "modelo"
                return por_reglas, "reglas"
            texto, _ = assistant._call_llm(client, s, INSTRUCCIONES_ZIP_GENERAR + skills,
                                           [{"role": "user", "content": limpio}])
            plan = estudio.extraer_plan(texto)
            plan["tipo"] = "zip"
            plan.setdefault("titulo", titulo)
            if plan.get("archivos"):
                return plan, "modelo"
    except (httpx.HTTPError, ValueError, KeyError, AttributeError):
        pass
    return (por_reglas if bloques else estudio.plan_basico(instruccion, "zip")), "reglas"


def _planificar(instruccion: str, tipo: str, contexto_web: str = "", progreso=None,
                skills: str = "", bloques: list | None = None) -> tuple[dict, str]:
    """Obtiene el plan del archivo con el modelo, en dos intentos y con un respaldo.

    1. Se le pide el plan en JSON. Es lo ideal: control total de la estructura.
    2. Si no devuelve JSON válido —algo frecuente en modelos pequeños como llama3.2:3b— se le pide
       el CONTENIDO en Markdown y se convierte aquí. Antes se descartaba esa respuesta y el archivo
       salía con la instrucción adentro, mientras el contenido bueno se quedaba en el chat.
    3. Solo si ambos fallan se usa el plan por reglas.

    Los documentos (Word, PDF, Markdown) siempre se escriben por capítulos y salen con el mínimo de
    extensión que cada trabajo necesita (automática); ``progreso(hecho, total, seccion)`` informa el avance.
    """
    s = get_settings()
    if tipo == "zip":
        return _plan_zip(instruccion, bloques or [], progreso, skills)
    if s.llm_kind == "ninguno":
        plan = estudio.plan_basico(instruccion, tipo)
        if tipo in ("docx", "pdf", "md"):
            plan["nota_sin_modelo"] = True       # el aviso lo muestra el chat: sin modelo solo hay una plantilla básica
        return plan, "reglas"

    paginas = paginas_objetivo(instruccion, tipo, usar_modelo=True)
    if paginas and paginas > (s.doc_paginas_una_llamada if tipo in TIPOS_DOCUMENTO else 0):
        extenso = _plan_extenso(instruccion, tipo, contexto_web, paginas, progreso, skills)
        if extenso:
            return extenso

    limpio, _ = assistant.redact(instruccion)   # los datos personales no salen hacia el modelo
    peticion = f"Tipo solicitado: {tipo}\nPetición: {limpio}"
    if tipo in TIPOS_DOCUMENTO and paginas:
        peticion += f"\nExtensión adecuada: unas {paginas} página(s); ni más ni menos de lo que el trabajo necesita."
    if contexto_web:
        peticion += ("\n\nInformación recuperada de internet para enriquecer el contenido "
                     "(úsala y menciona la fuente cuando aporte un dato concreto):\n" + contexto_web)

    directo = (s.doc_directo_markdown and tipo in TIPOS_DOCUMENTO and _modelo_local(s))
    with httpx.Client(timeout=assistant._tiempos(s)) as client:
        if directo:
            try:
                texto = _redactar_en_vivo(client, s, INSTRUCCIONES_CONTENIDO + skills, peticion, progreso)
                plan = estudio.plan_desde_texto(texto, tipo, estudio.titulo_desde(instruccion))
                if plan:
                    return plan, "modelo"
            except (httpx.HTTPError, ValueError, KeyError):
                pass
            return estudio.plan_basico(instruccion, tipo), "reglas"
        try:
            texto, _ = assistant._call_llm(client, s, estudio.INSTRUCCIONES_PLAN + skills,
                                           [{"role": "user", "content": peticion +
                                             "\nDevuelve solo el JSON del plan para ese tipo."}])
            plan = estudio.extraer_plan(texto)
            plan["tipo"] = tipo                                   # el tipo lo manda la persona
            plan.setdefault("titulo", estudio.titulo_desde(instruccion))
            return plan, "modelo"
        except (httpx.HTTPError, estudio.PlanInvalido, ValueError, KeyError):
            pass

        # Segundo intento: contenido en prosa, que es lo que un modelo pequeño hace bien.
        try:
            texto, _ = assistant._call_llm(client, s, INSTRUCCIONES_CONTENIDO + skills,
                                           [{"role": "user", "content": peticion}])
        except (httpx.HTTPError, ValueError, KeyError):
            return estudio.plan_basico(instruccion, tipo), "reglas"

    plan = estudio.plan_desde_texto(texto, tipo, estudio.titulo_desde(instruccion))
    if plan:
        return plan, "modelo"
    return estudio.plan_basico(instruccion, tipo), "reglas"


# ─────────────────────── documentos largos: índice y luego sección por sección
# Un modelo no escribe 50 páginas de una sola vez: se le acaba el espacio de respuesta y entrega un resumen
# genérico. Se hace como lo haría un autor: primero el índice, después cada capítulo completo, y al final se
# arma el documento. Luego se MIDE el resultado (páginas reales con LibreOffice/pypdf, o por palabras) y,
# si queda corto, se piden capítulos adicionales (casos, listas de verificación, anexos) hasta alcanzar el mínimo.
EXTENSION = re.compile(r"\b(extens\w*|detallad\w*|complet\w*|ampli\w*|profund\w*|exhaustiv\w*|"
                       r"\d{1,3}\s*(hojas|p[áa]ginas))", re.IGNORECASE)
TIPOS_DOCUMENTO = ("docx", "pdf", "md")
RONDAS_DE_AMPLIACION = 6
MAX_CAPITULOS_POR_RONDA = 20
_PAGINAS_EXPLICITAS = re.compile(r"(\d{1,3})\s*(hojas|p[áa]ginas)", re.IGNORECASE)


def paginas_pedidas(instruccion: str) -> int:
    """Cuántas páginas pidió la persona de forma explícita (0 si no dijo)."""
    m = _PAGINAS_EXPLICITAS.search(instruccion)
    return max(1, int(m.group(1))) if m else 0


# Piezas que son cortas por naturaleza: forzarles 50 páginas no mejora nada y tarda horas.
_PIEZA_CORTA = re.compile(r"\b(cuento|f[áa]bula|poema|poes[íi]a|canci[óo]n|adivinanza|trabalenguas?|taller|"
                          r"evaluaci[óo]n|examen|quiz|cuestionario|preguntas|prueba|carta|oficio|circular|acta|"
                          r"constancia|certificado|invitaci[óo]n|comunicado|memorando|formato|planilla|ficha|"
                          r"receta|horario|lista(do)?|r[úu]brica|hoja de vida|curr[íi]culum|cv|resumen|"
                          r"gu[íi]a de (trabajo|clase|estudio)|actividad(es)?|ejercicios)\b", re.IGNORECASE)


def es_pieza_corta(instruccion: str) -> bool:
    return bool(_PIEZA_CORTA.search(instruccion)) and not EXTENSION.search(instruccion)


# Géneros por extensión típica (páginas). Orden: de lo más específico a lo más general.
_GENEROS = (
    (re.compile(r"\b(tesis|monograf[íi]a|trabajo de grado|proyecto de grado|libro|manual de convivencia|"
                r"p\.?e\.?i\.?|proyecto educativo institucional|plan estrat[ée]gico|plan de desarrollo)\b",
                re.IGNORECASE), 60),
    (re.compile(r"\b(manual|protocolo|reglamento|diagn[óo]stico|caracterizaci[óo]n|plan de (seguridad|gesti[óo]n|"
                r"negocios?|mejoramiento|convivencia|emergencia)|programa|curr[íi]culo|malla curricular|"
                r"gu[íi]a (completa|did[áa]ctica|metodol[óo]gica)|investigaci[óo]n|estado del arte)\b",
                re.IGNORECASE), 25),
    (re.compile(r"\b(proyecto|informe|propuesta|an[áa]lisis|estudio|ensayo|art[íi]culo|plan|secuencia did[áa]ctica|"
                r"unidad did[áa]ctica|estrategia|pol[íi]tica|procedimiento|gu[íi]a)\b", re.IGNORECASE), 8),
)
_ESCALA_EXTENSION = re.compile(r"\b(extens\w*|detallad\w*|exhaustiv\w*|profund\w*|a fondo|muy completo)\b",
                               re.IGNORECASE)


def dimensionar_heuristico(instruccion: str) -> int:
    """Páginas que probablemente necesita el trabajo, sin gastar una llamada al modelo."""
    if es_pieza_corta(instruccion):
        return 2
    base = next((n for patron, n in _GENEROS if patron.search(instruccion)), 3)
    if _ESCALA_EXTENSION.search(instruccion):
        base = max(base * 2, 12)
    return base


def _dimensionar_con_modelo(instruccion: str, s) -> int | None:
    """El modelo decide la extensión que pide el trabajo (una cifra, llamada muy corta). None si no responde."""
    sistema = ("Decides cuántas páginas (tamaño carta, texto normal) necesita un documento para cumplir bien su "
               "propósito, sin relleno ni quedarse corto. Referencias: carta, oficio, circular, acta o ficha: 1; "
               "cuento infantil, taller o evaluación: 1 a 3; resumen o guía corta: 2 a 5; informe o propuesta: 6 a 20; "
               "proyecto de aula o plan: 8 a 25; manual o protocolo: 20 a 60; tesis, monografía o libro: 60 a 200. "
               f"Responde SOLO un número entero entre 1 y {s.doc_max_paginas}.")
    limpio, _ = assistant.redact(instruccion)
    try:
        with httpx.Client(timeout=httpx.Timeout(20.0, read=60.0)) as client:
            texto, _ = assistant._call_llm(client, s, sistema, [{"role": "user", "content": limpio}])
    except (httpx.HTTPError, ValueError, KeyError):
        return None
    m = re.search(r"\d{1,3}", texto or "")
    return int(m.group(0)) if m else None


def paginas_objetivo(instruccion: str, tipo: str, usar_modelo: bool = False) -> int:
    """Páginas que debe tener el archivo.

    Documentos (Word/PDF/Markdown): si la persona dijo cuántas, esas. Si no, la extensión la decide el
    trabajo: el modelo (con un modelo en la nube) o una estimación por género (con uno local, para no gastar
    una llamada). Antes todo salía con 50 páginas mínimo, incluso un cuento o una carta.
    Si ``doc_min_paginas`` > 0 se vuelve a exigir ese mínimo (salvo piezas cortas). Presentaciones: solo si
    pidió extensión."""
    s = get_settings()
    pedidas = paginas_pedidas(instruccion)
    if tipo in TIPOS_DOCUMENTO:
        if pedidas:
            return min(s.doc_max_paginas, pedidas)
        if s.doc_min_paginas > 0:
            if s.doc_cortos_sin_minimo and es_pieza_corta(instruccion):
                return 0
            return min(s.doc_max_paginas, s.doc_min_paginas)
        estimadas = dimensionar_heuristico(instruccion)
        if usar_modelo and s.llm_kind != "ninguno" and not s.llm_es_local:
            decidido = _dimensionar_con_modelo(instruccion, s)
            if decidido:
                estimadas = decidido
        return max(1, min(s.doc_max_paginas, estimadas))
    if tipo == "pptx" and (pedidas or EXTENSION.search(instruccion)):
        return min(s.doc_max_paginas, pedidas or 12)
    return 0


INSTRUCCIONES_INDICE = """Eres un autor profesional con doctorado en el tema. Devuelves SOLO el índice del documento pedido,
una línea por capítulo, sin numerar y sin explicaciones.

Reglas:
- Entre {minimo} y {maximo} capítulos, en el orden correcto del documento. El documento debe llegar a unas {paginas}
  páginas, así que cada capítulo debe poder desarrollarse a fondo.
- Estructura de un documento extenso: resumen ejecutivo, introducción (contexto, objetivos, alcance, metodología),
  marco teórico o normativo, desarrollo por temas, casos prácticos, análisis, riesgos, plan de acción o
  implementación, indicadores, conclusiones, recomendaciones, glosario, anexos y referencias.
- Títulos concretos y propios del tema, no genéricos: «Competencias y DBA del periodo», no «Sección 1».
- Una línea por capítulo. Nada más."""

INSTRUCCIONES_INDICE_EXTRA = """Eres un autor profesional con doctorado en el tema. El documento ya tiene estos capítulos:
{indice}

Propón {cantidad} capítulos ADICIONALES que aporten contenido nuevo y útil (casos prácticos, procedimientos
detallados, listas de verificación, plantillas, preguntas frecuentes, errores comunes, anexos técnicos,
profundización de los temas más complejos). No repitas ni reformules los existentes.
Devuelve SOLO los títulos, una línea por capítulo, sin numerar y sin explicaciones."""

INSTRUCCIONES_SECCION = """Eres un autor profesional con doctorado escribiendo UN capítulo de un documento extenso.

Documento: {titulo}
Capítulo que debes escribir ahora: {seccion}
Índice completo: {indice}
Lo ya cubierto en capítulos anteriores (no lo repitas, conéctalo): {cubierto}

Reglas:
- Empieza con «## {seccion}» y desarróllalo por completo: entre {minimo} y {maximo} palabras. Usa apartados «### » dentro del capítulo.
- Da formato profesional: **negrita** en los términos clave, tablas Markdown para comparar o planificar y, cuando aporte, un recuadro «> Nota: …», «> Consejo: …» o «> Importante: …».
- Escribe en español de Colombia, con el vocabulario del oficio y la normativa vigente aplicable. Explica, da ejemplos
  concretos, casos límite, errores frecuentes y cómo verificar cada punto.
- Usa viñetas y tablas Markdown (| col | col |) cuando aporten: cronogramas, criterios, riesgos, responsables.
- Contenido real y usable, nada de relleno, de «aquí iría» ni de frases vacías; si falta un dato, usa un marcador [así].
- NO escribas el título del documento ni otros capítulos. Solo este."""


def _hilos_documento(s) -> int:
    """Capítulos simultáneos: configurable; en automático, 4 con modelo en la nube y 1 con uno local."""
    if s.doc_paralelo > 0:
        return min(8, s.doc_paralelo)
    local = s.llm_kind == "openai" and any(h in s.llm_base_url for h in ("localhost", "127.0.0.1", "[::1]"))
    return 1 if local or s.llm_kind == "ninguno" else 4


def _titulos(texto: str, tope: int) -> list[str]:
    ts = [re.sub(r"^[\s#*\-\d.)]+", "", l).strip(" :*#") for l in texto.splitlines() if len(l.strip()) > 3]
    return [t for t in ts if 3 < len(t) <= 90][:tope]


def _palabras(texto: str) -> int:
    return len(texto.split())


def _plan_extenso(instruccion: str, tipo: str, contexto_web: str, paginas: int, progreso=None,
                  skills: str = "") -> tuple[dict, str] | None:
    """Genera el documento por capítulos y lo amplía hasta el mínimo de páginas. None si el modelo no coopera."""
    s = get_settings()
    objetivo_palabras = paginas * s.doc_palabras_por_pagina
    por_seccion = s.doc_palabras_por_seccion
    n_objetivo = max(4, min(estudio.MAX_SECCIONES_DOC, math.ceil(objetivo_palabras / por_seccion) + 1))
    limpio, _ = assistant.redact(instruccion)
    peticion = f"Documento pedido: {limpio}"
    if contexto_web:
        peticion += "\n\nInformación de internet para apoyarse:\n" + contexto_web[:4000]

    inicio = time.perf_counter()
    skills = skills[:s.doc_skills_max_chars]      # cada capítulo reprocesa el prompt: skills resumidas = capítulos más rápidos
    titulo = estudio.titulo_desde(instruccion)
    escribir = {"minimo": int(por_seccion * 0.85), "maximo": int(por_seccion * 1.3)}

    def avisar(hecho: int, total: int, nombre: str) -> None:
        if progreso:
            try:
                progreso(hecho, total, nombre)
            except Exception:  # noqa: BLE001 - informar el avance nunca debe romper la creación
                pass

    with httpx.Client(timeout=assistant._tiempos(s)) as client:
        def pedir(sistema: str, usuario: str) -> str:
            try:
                texto, _ = assistant._call_llm(client, s, sistema + skills, [{"role": "user", "content": usuario}])
                return texto.strip()
            except (httpx.HTTPError, ValueError, KeyError):
                return ""

        indice_txt = pedir(INSTRUCCIONES_INDICE.format(minimo=max(4, n_objetivo - 2), maximo=n_objetivo,
                                                       paginas=paginas), peticion)
        titulos = _titulos(indice_txt, n_objetivo)
        if len(titulos) < 3:
            return None

        partes: dict[str, str] = {}

        def escribir_seccion(nombre: str) -> None:
            cubierto = " · ".join(f"{t}: {partes[t].split(chr(10), 2)[-1][:140].strip()}"
                                  for t in list(partes)[-14:])[:3500] or "(nada todavía)"
            sistema = INSTRUCCIONES_SECCION.format(titulo=titulo, seccion=nombre, indice=" · ".join(titulos)[:3500],
                                                   cubierto=cubierto, **escribir)
            texto = ""
            for intento in range(2):                       # un capítulo corto se pide una vez más, más largo
                extra = "" if intento == 0 else "\n\nLa versión anterior quedó corta: desarróllalo con mucha más profundidad."
                texto = pedir(sistema + extra, peticion)
                if _palabras(texto) >= escribir["minimo"] * 0.5:
                    break
            if not texto:
                return
            if not texto.lstrip().startswith("#"):
                texto = f"## {nombre}\n\n{texto}"
            partes[nombre] = texto

        def armar() -> dict | None:
            cuerpo = "\n\n".join(partes[t] for t in titulos if t in partes)
            plan = estudio.plan_desde_texto(cuerpo, tipo, titulo)
            if plan:
                plan["portada"] = True
                capitulo = 0
                for sec in plan["secciones"]:                           # numeración de capítulos (nivel 1)
                    if sec.get("nivel", 1) == 1 and sec.get("encabezado"):
                        capitulo += 1
                        if not re.match(r"^\d+[.)]\s", sec["encabezado"]):
                            sec["encabezado"] = f"{capitulo}. {sec['encabezado']}"
            return plan

        total = len(titulos)
        hilos = _hilos_documento(s)

        def escribir_varias(nombres: list[str]) -> None:
            """Escribe los capítulos de a `hilos` a la vez (con un modelo en la nube es varias veces más rápido)."""
            if hilos <= 1:
                for t in nombres:
                    if time.perf_counter() - inicio > s.doc_presupuesto_segundos:
                        break      # se entrega lo escrito: mejor un documento sólido que una espera sin fin
                    avisar(len(partes), total, t)
                    escribir_seccion(t)
                return
            from concurrent.futures import ThreadPoolExecutor

            def uno(t: str) -> None:
                if time.perf_counter() - inicio > s.doc_presupuesto_segundos:
                    return
                escribir_seccion(t)
                avisar(len(partes), total, t)
            with ThreadPoolExecutor(max_workers=hilos) as pool:
                list(pool.map(uno, nombres))

        escribir_varias(list(titulos))
        if len(partes) < 3:
            return None

        # Medir y ampliar hasta el mínimo de páginas.
        plan = armar()
        for ronda in range(RONDAS_DE_AMPLIACION):
            if not plan or time.perf_counter() - inicio > s.doc_presupuesto_segundos:
                break
            palabras = estudio.palabras_del_plan(plan)
            plan["paginas_estimadas"] = max(1, round(palabras / s.doc_palabras_por_pagina))
            if tipo == "md" or palabras < objetivo_palabras * 0.6:
                reales = plan["paginas_estimadas"]
            else:
                try:
                    reales, _metodo = estudio.contar_paginas(estudio.construir({**plan, "tipo": tipo}).datos, tipo,
                                                             palabras, s.doc_palabras_por_pagina)
                except estudio.PlanInvalido:
                    reales = plan["paginas_estimadas"]
            plan["paginas_estimadas"] = reales
            if reales >= paginas:
                break
            # Cuántos capítulos faltan, según lo que de verdad está escribiendo el modelo (no lo que se le pidió):
            # un modelo que se queda en 300 palabras por capítulo necesita el triple de capítulos.
            promedio = max(200, palabras / max(1, len(partes)))
            faltan = max(1, math.ceil(max(0, objetivo_palabras - palabras) / promedio))
            cantidad = min(faltan + 1, MAX_CAPITULOS_POR_RONDA)
            extra_txt = pedir(INSTRUCCIONES_INDICE_EXTRA.format(indice=" · ".join(titulos)[:3500],
                                                                cantidad=cantidad), peticion)
            nuevos = [t for t in _titulos(extra_txt, cantidad) if t not in partes]
            if not nuevos:
                break
            total += len(nuevos)
            titulos.extend(nuevos)
            escribir_varias(nuevos)
            plan = armar()
        avisar(total, total, "Armando el documento")

    if not plan:
        return None
    plan["tipo"] = tipo
    if "paginas_estimadas" not in plan:
        plan["paginas_estimadas"] = max(1, round(estudio.palabras_del_plan(plan) / s.doc_palabras_por_pagina))
    return plan, "modelo"


INSTRUCCIONES_CONTENIDO = """Eres un redactor profesional con experiencia en la profesión que la
petición requiera (docencia, derecho, contaduría, ingeniería, salud, administración, construcción,
agronomía, lo que sea). Escribes el CONTENIDO COMPLETO, listo para entregar, en español de Colombia
y en Markdown.

Reglas:
- Empieza con «# » y un título profesional. Usa «## » para cada sección.
- Desarrolla de verdad: mínimo 5 secciones y contenido sustancial en cada una. Nada de «aquí va el
  contenido», plantillas vacías ni texto de relleno.
- Viñetas para listas; tablas Markdown (| columna | columna |) siempre que haya datos comparables,
  cronogramas, presupuestos o responsables.
- Diseño: **negrita** para los términos clave, *cursiva* para énfasis suave, y recuadros destacados con
  «> Nota: …», «> Consejo: …», «> Importante: …» (1 o 2 por sección, solo cuando aportan de verdad).
- Usa el vocabulario y la normativa del oficio: NTC y RETIE en ingeniería, UVT y NIIF en contaduría,
  DBA y competencias del MEN en educación, CIE-10 en salud, Código Sustantivo del Trabajo en laboral.
- Cierra con lo que esa profesión espera: conclusiones y recomendaciones en un informe; evaluación e
  indicadores en un plan de clase; presupuesto y cronograma en un proyecto; firmas en un acta.
- Si faltan datos, escribe el documento igual con marcadores claros entre corchetes, como
  [nombre del responsable]: nunca dejes secciones sin desarrollar.
- No escribas JSON, ni pidas permiso, ni te presentes: solo el documento.
"""
