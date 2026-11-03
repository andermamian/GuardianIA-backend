"""Asistente de IA con navegación web — interfaces AI Communication / Personality Designer.

La IA responde preguntas y, cuando hace falta, busca en internet y lee páginas para dar una
respuesta con fuentes (defensa SSRF en web_browser.py). El historial se guarda cifrado.
"""
from __future__ import annotations

import io
import json
import logging
import tempfile
import time
from pathlib import Path
from datetime import timedelta

import httpx
from fastapi import APIRouter, File, Form, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from app.ai import archivos, aprendizaje, assistant, estudio, lectura, pruebas, skills as skills_ai
from app.api.deps import DB, CurrentUser, client_ip
from app.api.v1.local import LOCALES
from app.core import audit
from app.core.config import get_settings
from app.core.crypto import open_text, seal_text
from app.api.v1.vault import safe_filename, sniff_mime
from app.core.errors import ApiError, conflict, not_found
from app.core.ratelimit import limiter
from app.services.pasos import Pasos
from pydantic import BaseModel, Field

from app.db.models import (Attachment, AssistantSkill, AuditLog, Conversation, Message, PersonalityProfile,
                           VaultFile)
from app.db.session import SessionLocal
from app.services import boveda, chat_trabajos
from app.schemas.common import Msg
from app.schemas.security import (ChatIn, ChatMessageOut, ChatOut, ConversationOut, PersonalityIO, SourceOut)

log = logging.getLogger("guardian")
router = APIRouter(tags=["Asistente de IA"])


def _persona(db, user_id: str) -> tuple[PersonalityProfile, assistant.Persona]:
    pp = db.get(PersonalityProfile, user_id)
    if pp is None:
        pp = PersonalityProfile(user_id=user_id)
        db.add(pp)
        db.flush()
    persona = assistant.Persona(name=pp.assistant_name, friendliness=pp.friendliness, protection=pp.protection,
                                proactivity=pp.proactivity, verbosity=pp.verbosity, humor=pp.humor, mode=pp.mode)
    return pp, persona


MAX_MENSAJES_HISTORIAL = 400      # tope de lectura; el recorte fino lo hace assistant.recortar_historial


def _historial(db, conversation_id: str) -> list[assistant.Turn]:
    """Los mensajes MÁS RECIENTES de la conversación, en orden cronológico.

    Antes: ``order_by(created_at).limit(24)`` traía los 24 más VIEJOS. En cuanto una conversación pasaba
    de 24 mensajes el asistente ya no veía lo último que se había dicho y respondía fuera de contexto."""
    filas = db.execute(select(Message).where(Message.conversation_id == conversation_id)
                       .order_by(Message.created_at.desc()).limit(MAX_MENSAJES_HISTORIAL)).scalars().all()
    return [assistant.Turn(role=m.role, content=open_text(m.content_enc, f"msg:{m.id}") or "")
            for m in reversed(filas)]


def _skills_de(db, user_id: str) -> list[skills_ai.Skill]:
    """Integradas (salvo las que la persona apagó) + las propias que tenga encendidas."""
    filas = db.execute(select(AssistantSkill).where(AssistantSkill.user_id == user_id)).scalars().all()
    apagadas = {f.builtin_ref for f in filas if f.builtin_ref and not f.enabled}
    salida = [s_ for s_ in skills_ai.integradas() if s_.id.split(":", 1)[1] not in apagadas]
    for f in filas:
        if f.builtin_ref or not f.enabled:
            continue
        salida.append(skills_ai.Skill(nombre=f.name, descripcion=f.description, contenido=f.content,
                                      triggers=list(f.triggers or []), tipos=list(f.tipos or []),
                                      siempre=bool(f.always), id=f.id))
    return salida


def _bloque_skills(db, user_id: str, mensaje: str, tipo_archivo: str | None = None) -> str:
    s = get_settings()
    # Modelo local: pocas skills y cortas (cada carácter es tiempo de espera antes de la primera palabra).
    presupuesto = s.skills_chars_local if s.llm_es_local else skills_ai.PRESUPUESTO_PROMPT
    return skills_ai.bloque_para_prompt(skills_ai.seleccionar(_skills_de(db, user_id), mensaje, tipo_archivo,
                                                              presupuesto=presupuesto))


@router.post("/assistant/chat", response_model=ChatOut)
def chat(body: ChatIn, p: CurrentUser, db: DB):
    limiter.hit(f"chat:{p.user.id}", 30)
    _, persona = _persona(db, p.user.id)
    if body.conversation_id:
        conv = db.get(Conversation, body.conversation_id)
        if conv is None or conv.user_id != p.user.id:
            raise not_found("conversación")
    else:
        conv = Conversation(user_id=p.user.id, title=body.message[:60])
        db.add(conv)
        db.flush()
    history = _historial(db, conv.id)

    s = get_settings()
    prev = s.web_browsing_enabled
    client = httpx.Client(timeout=max(s.llm_read_timeout, s.web_timeout_seconds))
    try:
        if not body.allow_web:
            # Respeta el interruptor por-mensaje sin tocar la configuración global.
            object.__setattr__(s, "web_browsing_enabled", False)
        docs = _documentos(db, conv.id)
        doc_context, usados = lectura.contexto_para(body.message, docs) if docs else ("", [])
        lecciones = aprendizaje.bloque_para_prompt(db, p.user.id, body.message)
        reply = assistant.respond(body.message, history, persona, doc_context=doc_context, client=client,
                                  lecciones=lecciones, skills=_bloque_skills(db, p.user.id, body.message))
    finally:
        object.__setattr__(s, "web_browsing_enabled", prev)
        client.close()

    user_msg = Message(conversation_id=conv.id, role="user",
                       content_enc=seal_text(body.message, "msg:pending"))
    db.add(user_msg)
    db.flush()
    user_msg.content_enc = seal_text(body.message, f"msg:{user_msg.id}")
    bot_msg = Message(conversation_id=conv.id, role="assistant", content_enc=seal_text(reply.text, "msg:pending"),
                      safety=reply.safety, provider=reply.provider, latency_ms=reply.latency_ms)
    db.add(bot_msg)
    db.flush()
    bot_msg.content_enc = seal_text(reply.text, f"msg:{bot_msg.id}")
    db.commit()
    return ChatOut(conversation_id=conv.id, respuesta=reply.text, proveedor=reply.provider,
                   busco_en_web=reply.searched_web, fuentes=[SourceOut(**s) for s in reply.sources],
                   acciones_sugeridas=reply.suggested_actions, seguridad=reply.safety)


MAX_ADJUNTOS = 10


def _conversacion(db, user_id: str, conversation_id: str | None, titulo: str):
    if conversation_id:
        conv = db.get(Conversation, conversation_id)
        if conv is None or conv.user_id != user_id:
            raise not_found("conversación")
        return conv
    conv = Conversation(user_id=user_id, title=titulo[:60])
    db.add(conv)
    db.flush()
    return conv


def _documentos(db, conversation_id: str) -> list[lectura.Documento]:
    """Carga los adjuntos de la conversación ya descifrados, listos para buscar en ellos."""
    docs = []
    for a in db.execute(select(Attachment).where(Attachment.conversation_id == conversation_id)
                        .order_by(Attachment.created_at)).scalars():
        texto = open_text(a.text_enc, f"adj:{a.id}") or ""
        if not texto:
            continue
        doc = lectura.Documento(nombre=a.filename, mime=a.mime, texto=texto, paginas=a.pages,
                                truncado=a.truncated, metodo=a.method)
        doc.fragmentos = lectura.fragmentar(texto)
        docs.append(doc)
    return docs


@router.post("/assistant/attachments", status_code=201)
async def subir_adjunto(p: CurrentUser, db: DB, request: Request,
                        conversation_id: str | None = Form(None), file: UploadFile = File(...)):
    """Lee un archivo para que el asistente pueda responder sobre su contenido.

    Se guarda el texto extraído, cifrado, no el archivo. Las imágenes guardan además una copia
    reducida en base64 por si el modelo es de visión.
    """
    limiter.hit(f"adjunto:{p.user.id}", 20, 600)
    s = get_settings()
    maximo = s.adjunto_max_mb * 1024 * 1024
    nombre = safe_filename(file.filename or "archivo")
    conv = _conversacion(db, p.user.id, conversation_id, f"Sobre {nombre}")
    if db.execute(select(func.count()).select_from(Attachment)
                  .where(Attachment.conversation_id == conv.id)).scalar_one() >= MAX_ADJUNTOS:
        raise conflict("demasiados_adjuntos", f"Máximo {MAX_ADJUNTOS} archivos por conversación")

    # El archivo se recibe por partes y se guarda en disco temporal: un video de varios GB no pasa por la memoria.
    with tempfile.TemporaryDirectory(prefix="guardian_adj_") as tmp:
        ruta = Path(tmp) / "entrada.bin"
        total = 0
        with open(ruta, "wb") as out:
            while True:
                trozo = await file.read(1024 * 1024)
                if not trozo:
                    break
                total += len(trozo)
                if total > maximo:
                    raise ApiError(413, "file_too_large", f"El archivo supera {s.adjunto_max_mb} MB")
                out.write(trozo)
        if total == 0:
            raise ApiError(422, "empty_file", "El archivo está vacío")
        with open(ruta, "rb") as f:
            cabeza = f.read(64)
        mime = sniff_mime(cabeza, nombre) or file.content_type or ""
        try:
            res = await run_in_threadpool(archivos.leer, ruta, nombre, mime)
        except lectura.NoSePuedeLeer as e:
            raise ApiError(422, "no_legible", str(e)) from e
    doc = res.documento
    if not doc.fragmentos:
        doc.fragmentos = lectura.fragmentar(doc.texto)

    a = Attachment(conversation_id=conv.id, user_id=p.user.id, filename=nombre, mime=mime,
                   size_bytes=total, pages=doc.paginas, method=doc.metodo, truncated=doc.truncado,
                   chars=len(doc.texto), text_enc="")
    db.add(a)
    db.flush()
    a.text_enc = seal_text(doc.texto, f"adj:{a.id}")
    if res.imagenes:
        a.image_enc = seal_text(json.dumps(res.imagenes[:archivos.MAX_IMAGENES]), f"img:{a.id}")
    audit.record(db, "assistant.adjunto", actor_id=p.user.id, target_type="attachment", target_id=a.id,
                 ip=client_ip(request), detail={"mime": mime, "bytes": total, "metodo": doc.metodo, "clase": res.clase},
                 commit=False)
    db.commit()
    return {"id": a.id, "conversation_id": conv.id, "nombre": nombre, "mime": mime,
            "bytes": total, "clase": res.clase, "imagenes": len(res.imagenes), "paginas": doc.paginas, "caracteres": len(doc.texto),
            "metodo": doc.metodo, "truncado": doc.truncado, "fragmentos": len(doc.fragmentos),
            "vista_previa": doc.texto[:400]}


def _imagenes_adjuntas(db, conversation_id: str, tope: int = 8) -> list[str]:
    """Imágenes y fotogramas de los adjuntos (los más recientes primero), con un tope total."""
    salida: list[str] = []
    for a in db.execute(select(Attachment).where(Attachment.conversation_id == conversation_id, Attachment.image_enc != "")
                        .order_by(Attachment.created_at.desc())).scalars():
        crudo = open_text(a.image_enc, f"img:{a.id}") or ""
        try:
            lista = json.loads(crudo) if crudo.startswith("[") else [crudo]
        except ValueError:
            lista = []
        for img in lista:
            if img and len(salida) < tope:
                salida.append(img)
    return salida


def _miniatura(datos: bytes, mime: str) -> str:
    """Reduce la imagen antes de mandarla a un modelo de visión: menos memoria y más rapidez."""
    try:
        import base64

        from PIL import Image
        img = Image.open(io.BytesIO(datos))
        img.thumbnail((1024, 1024))
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=80)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception:  # noqa: BLE001 - si falla, simplemente no hay visión para esa imagen
        return ""


@router.get("/assistant/conversations/{conversation_id}/attachments")
def listar_adjuntos(conversation_id: str, p: CurrentUser, db: DB):
    conv = db.get(Conversation, conversation_id)
    if conv is None or conv.user_id != p.user.id:
        raise not_found("conversación")
    return [{"id": a.id, "nombre": a.filename, "mime": a.mime, "bytes": a.size_bytes,
             "paginas": a.pages, "caracteres": a.chars, "metodo": a.method, "creado": a.created_at}
            for a in db.execute(select(Attachment).where(Attachment.conversation_id == conv.id)
                                .order_by(Attachment.created_at)).scalars()]


@router.delete("/assistant/attachments/{attachment_id}", response_model=Msg)
def borrar_adjunto(attachment_id: str, p: CurrentUser, db: DB):
    a = db.get(Attachment, attachment_id)
    if a is None or a.user_id != p.user.id:
        raise not_found("adjunto")
    db.delete(a)
    db.commit()
    return Msg(mensaje="Archivo retirado de la conversación")


@router.post("/assistant/chat/stream")
def chat_stream(body: ChatIn, request: Request, p: CurrentUser, db: DB):
    """Igual que /assistant/chat, pero enviando el texto a medida que el modelo lo produce.

    Un modelo local en CPU puede tardar minutos; sin esto la pantalla se queda vacía y el navegador
    corta. Aquí el primer trozo llega en segundos.

    Detalles que importan:
    - La conversación y el historial se leen ANTES de empezar a transmitir, y la sesión de base de
      datos se cierra: mantenerla abierta durante minutos agotaría el pool con pocos usuarios.
    - El mensaje del usuario se guarda de una vez; la respuesta, al terminar, con su propia sesión.
    - La respuesta se genera en un trabajo propio (services/chat_trabajos.py): si la persona cambia de
      app, gira la pantalla o cambia de chat, la respuesta SIGUE y queda guardada. El primer evento
      trae ``trabajo_id`` para reconectarse con /assistant/chat/trabajos/{id}/stream?desde=N.
    """
    limiter.hit(f"chat:{p.user.id}", 30)
    _, persona = _persona(db, p.user.id)
    if body.conversation_id:
        conv = db.get(Conversation, body.conversation_id)
        if conv is None or conv.user_id != p.user.id:
            raise not_found("conversación")
    else:
        conv = Conversation(user_id=p.user.id, title=body.message[:60])
        db.add(conv)
        db.flush()
    history = _historial(db, conv.id)
    user_msg = Message(conversation_id=conv.id, role="user", content_enc=seal_text(body.message, "msg:pending"))
    db.add(user_msg)
    db.flush()
    user_msg.content_enc = seal_text(body.message, f"msg:{user_msg.id}")
    docs = _documentos(db, conv.id)
    doc_context, usados = lectura.contexto_para(body.message, docs) if docs else ("", [])
    imagenes = _imagenes_adjuntas(db, conv.id) if _modelo_ve_imagenes() else []
    lecciones = aprendizaje.bloque_para_prompt(db, p.user.id, body.message)
    tipo_archivo = estudio.detectar_intencion(body.message) if body.crear_archivos else None
    # Probar código con el sandbox: solo si lo pidió expresamente y la petición viene de este mismo equipo
    # (el sandbox ejecuta código de verdad; desde otro dispositivo no se ofrece).
    desde_este_equipo = bool(request.client and (request.client.host in LOCALES or (
        request.client.host == "testclient" and get_settings().env == "test")))
    a_probar = pruebas.codigo_a_probar(body.message, history) if desde_este_equipo else None
    if a_probar and tipo_archivo != "zip":
        tipo_archivo = None             # «prueba este código» no es «créame un archivo»
    bloques_zip = pruebas.codigo_de_la_conversacion(body.message, history) if tipo_archivo == "zip" else []
    bloque_skills = _bloque_skills(db, p.user.id, body.message, tipo_archivo)
    conversation_id, user_id = conv.id, p.user.id
    db.commit()

    s = get_settings()
    allow_web = body.allow_web and s.web_browsing_enabled

    def generar(t: chat_trabajos.Trabajo) -> None:
        """Corre en un hilo propio: sigue aunque el cliente se desconecte, y guarda al terminar."""
        piezas: list[str] = []
        reply = None
        t_inicio = time.perf_counter()
        archivos_creados: list[dict] = []     # se guardan EN el mensaje: al reabrir el chat siguen ahí
        creado_nombre = ""          # (antes se reiniciaba DESPUÉS de crear el archivo y se perdía)
        contexto_prueba = ""
        pasos = Pasos(t)                      # alimenta la pantalla de progreso del chat
        if a_probar:
            contexto_prueba = _probar_en_sandbox(t, pasos, a_probar, piezas, "Probando el código")["contexto"]
        # Si la persona pidió un archivo, se crea antes de responder: así el chat entrega el
        # resultado y no una explicación de cómo hacerlo a mano.
        if tipo_archivo:
            try:
                t.agregar({"tipo": "creando", "formato": tipo_archivo})
                pasos.abrir(f"Creando el archivo {tipo_archivo.upper()}", "estudio.crear",
                            {"tipo": tipo_archivo, "instruccion": body.message[:300]})

                def avance(hecho: int, total: int, seccion: str) -> None:
                    t.agregar({"tipo": "progreso", "hecho": hecho, "total": total, "seccion": seccion})
                    pasos.info((f"Capítulo {min(hecho + 1, total)} de {total}" + (f": {seccion}" if seccion else ""))
                               if total else seccion)
                creado = _crear_archivo(body.message, tipo_archivo, user_id, allow_web, avance, bloques_zip)
                creado_nombre = creado["nombre"]
                archivos_creados.append(creado)
                t.agregar({"tipo": "archivo", **creado})
                pasos.cerrar(True, f"{creado['nombre']} · {creado['resumen']}")
            except ApiError as e:
                pasos.cerrar(False, e.message)
                t.agregar({"tipo": "error", "mensaje": f"No pude crear el archivo: {e.message}"})
            except Exception as e:  # noqa: BLE001 - un fallo aquí no debe tumbar la conversación
                log.exception("fallo creando archivo desde el asistente")
                pasos.cerrar(False, type(e).__name__)
                t.agregar({"tipo": "error", "mensaje": f"No pude crear el archivo ({type(e).__name__}). "
                                                       "Puede pedírmelo de nuevo con más detalle."})
        prev = s.web_browsing_enabled
        if not allow_web:
            object.__setattr__(s, "web_browsing_enabled", False)
        try:
            if usados:
                t.agregar({"tipo": "archivos", "usados": usados})
                pasos.abrir("Leyendo tus documentos", "documentos.leer",
                            {"documentos": sorted({u["documento"] for u in usados})[:6]})
                pasos.cerrar(True, f"{len(usados)} fragmento(s) relevantes")
            # Con el archivo ya entregado, la respuesta es de 2-3 frases: sin skills y con poco historial el
            # modelo arranca antes (en un equipo sin GPU, procesar el prompt es lo que más tarda).
            historial_respuesta = history[-4:] if creado_nombre else history
            eventos_respuesta = (_respuesta_de_plantilla(creados=archivos_creados, inicio=t_inicio)
                                 if (creado_nombre and s.respuesta_rapida_archivo and not usados and not doc_context)
                                 else assistant.stream(body.message, historial_respuesta, persona,
                                           doc_context=(contexto_prueba + doc_context) if contexto_prueba else doc_context,
                                           imagenes=imagenes, archivo_creado=creado_nombre,
                                           lecciones=lecciones, skills="" if creado_nombre else bloque_skills))
            redactando = False
            fin_evento = None
            cancelado = False
            for evento in eventos_respuesta:
                if t.cancelado:
                    pasos.cerrar(False, "Detenido por la persona")
                    t.agregar({"tipo": "cancelado", "mensaje": "Respuesta detenida"})
                    cancelado = True
                    break
                if evento["tipo"] == "preparando" and evento.get("busco_en_la_web"):
                    pasos.abrir("Buscando en internet", "web.buscar", {"consulta": body.message[:200]})
                    pasos.cerrar(True, "Fuentes consultadas")
                if evento["tipo"] == "texto":
                    if not redactando:
                        redactando = True
                        pasos.abrir("Redactando la respuesta", "modelo.responder",
                                    {"modelo": s.llm_model if s.llm_kind != "anthropic" else s.anthropic_model})
                    piezas.append(evento["texto"])
                if evento["tipo"] == "fin":
                    reply = evento["reply"]
                    fin_evento = {"tipo": "fin", "conversation_id": conversation_id, "archivos_usados": usados,
                                  "proveedor": reply.provider, "busco_en_web": reply.searched_web,
                                  "fuentes": reply.sources, "acciones_sugeridas": reply.suggested_actions,
                                  "seguridad": reply.safety, "latencia_ms": reply.latency_ms}
                else:
                    t.agregar(evento)
            pasos.cerrar(True)
            if fin_evento and not cancelado and not creado_nombre:
                # Con la respuesta ya escrita: si trae varios archivos de código se organizan en un ZIP, y si la
                # persona pidió un programa se prueba en el sandbox (y se corrige solo si falla).
                try:
                    _post_codigo(t, pasos, s, body.message, "".join(piezas), desde_este_equipo, user_id, piezas,
                                 archivos_creados)
                except Exception:  # noqa: BLE001 - esto es un extra: nunca debe romper la respuesta
                    log.exception("fallo en el post-proceso del código")
                    pasos.cerrar(False, "Error interno")
            if fin_evento:
                t.agregar(fin_evento)
        finally:
            if pasos.abierto is not None:
                pasos.cerrar(False, "Interrumpido")
            object.__setattr__(s, "web_browsing_enabled", prev)
            _guardar_respuesta(conversation_id, user_id, "".join(piezas), reply, archivos_creados)

    try:
        trabajo = chat_trabajos.iniciar(user_id, conversation_id, generar)
    except chat_trabajos.Ocupado:
        raise ApiError(429, "chat_ocupado", "Ya hay varias respuestas generándose. Espere a que termine alguna.")
    return _transmitir(trabajo, 0, primero={"tipo": "trabajo", "trabajo_id": trabajo.id,
                                             "conversation_id": conversation_id})


def _probar_en_sandbox(t, pasos, bloque: "pruebas.Bloque", piezas: list[str], titulo: str = "Probando el código",
                       extras: dict | None = None, entrada: str | None = None) -> dict:
    """Ejecuta el código en el sandbox con la salida EN VIVO en la pantalla de progreso y deja el resultado en el
    mensaje. Nunca lanza: si el sandbox no puede correr (sin el lenguaje instalado, código largo…) se avisa y sigue.

    Devuelve ``{"ok": True/False/None, "salida": str, "contexto": str, "texto": str}``; ok=None si no corrió."""
    from app.local import sandbox
    pasos.abrir(titulo, "sandbox.ejecutar", {"lenguaje": bloque.lenguaje, "caracteres": len(bloque.codigo),
                                             **({"archivos": 1 + len(extras)} if extras else {})})
    t.agregar({"tipo": "probando", "lenguaje": bloque.lenguaje, "fase": "inicio"})
    salida: list[str] = []
    fin: dict = {}
    try:
        for ev in sandbox.ejecutar(bloque.lenguaje, bloque.codigo, 20, "auto", cancelado=lambda: t.cancelado,
                                   extras=extras, entrada=entrada):
            if ev.get("tipo") == "etapa":
                pasos.info("Compilando…" if ev["etapa"] == "compilando" else "Ejecutando…")
            elif ev.get("tipo") == "salida":
                salida.append(ev.get("texto", ""))
                pasos.salida(ev.get("texto", ""), ev.get("canal", "stdout"))
                t.agregar({"tipo": "probando", "lenguaje": bloque.lenguaje, "fase": "salida",
                           "texto": ev.get("texto", ""), "canal": ev.get("canal", "stdout")})
            elif ev.get("tipo") == "fin":
                fin = ev
    except sandbox.ErrorSandbox as e:
        texto = f"🧪 **No pude probar el código:** {e}\n\n"
        piezas.append(texto)
        t.agregar({"tipo": "texto", "texto": texto})
        pasos.cerrar(False, str(e))
        return {"ok": None, "salida": "", "contexto": "", "texto": texto}
    except Exception:  # noqa: BLE001 - probar nunca debe tumbar la conversación
        log.exception("fallo probando código en el sandbox")
        texto = "🧪 **No pude probar el código** por un error interno del sandbox.\n\n"
        piezas.append(texto)
        t.agregar({"tipo": "texto", "texto": texto})
        pasos.cerrar(False, "Error interno del sandbox")
        return {"ok": None, "salida": "", "contexto": "", "texto": texto}
    cuerpo = "".join(salida)
    resultado = pruebas.resumen_resultado(bloque.lenguaje, cuerpo, fin.get("codigo"), float(fin.get("segundos") or 0),
                                          fin.get("motivo") or "")
    piezas.append(resultado)
    ok = fin.get("codigo") == 0
    t.agregar({"tipo": "probando", "lenguaje": bloque.lenguaje, "fase": "fin", "codigo": fin.get("codigo"), "ok": ok})
    t.agregar({"tipo": "texto", "texto": resultado})
    pasos.cerrar(ok, "Terminó bien" if ok else (fin.get("motivo") or f"Falló (código {fin.get('codigo')})"))
    return {"ok": ok, "salida": cuerpo, "texto": resultado, "motivo": fin.get("motivo") or "",
            "contexto": pruebas.contexto_para_modelo(bloque.lenguaje, bloque.codigo, resultado) + "\n"}


def _corregir_codigo(s, lenguaje: str, ruta: str, proyecto: dict[str, str], error: str, peticion: str) -> tuple[str, str] | None:
    """Pide al modelo el archivo corregido a partir del error REAL de la ejecución. Devuelve (ruta, código) o None.

    El modelo ve todo el proyecto: el error puede estar en un módulo distinto del que se ejecutó."""
    if s.llm_kind == "ninguno":
        return None
    sistema = ("Eres un ingeniero de software senior. Corriges proyectos que fallaron al ejecutarse en un sandbox. "
               "Devuelve el archivo que contiene el defecto, COMPLETO y corregido, en un único bloque ``` con el lenguaje "
               "indicado y con la primera línea «# archivo: ruta» (o «// archivo: ruta»). Nada más: sin explicaciones, sin "
               "recortes, sin «...». Conserva lo que ya funcionaba.")
    resto = "\n\n".join(f"[{r}]\n{c[:6000]}" for r, c in proyecto.items() if r != ruta)[:30000]
    pedido = (f"Petición original: {peticion[:600]}\n\nArchivo que se ejecuta ({ruta}, {lenguaje}):\n```{lenguaje}\n"
              f"{proyecto[ruta][:20000]}\n```\n" + (f"\nOtros archivos del proyecto:\n{resto}\n" if resto else "") +
              f"\nError al ejecutarlo:\n{error[-3000:]}")
    try:
        with httpx.Client(timeout=httpx.Timeout(30.0, read=float(s.llm_read_timeout))) as client:
            texto, _ = assistant._call_llm(client, s, sistema, [{"role": "user", "content": pedido}])
    except (httpx.HTTPError, ValueError, KeyError):
        return None
    codigo = pruebas.extraer_corregido(texto or "", lenguaje)
    if not codigo:
        return None
    declarado = pruebas.ruta_declarada(codigo)
    destino = declarado if declarado in proyecto else ruta
    return destino, codigo


def _post_codigo(t, pasos, s, mensaje: str, respuesta: str, desde_equipo: bool, user_id: str, piezas: list[str],
                 archivos_creados: list[dict]) -> None:
    """Después de que el asistente escribe código:

    1. Si la persona pidió un programa y está en este equipo, se PRUEBA en el sandbox; si falla, el modelo recibe el
       error real y lo corrige (hasta 2 veces), mostrando cada versión.
    2. Si son 2 o más archivos, se organizan solos en un ZIP con carpetas y README, listo para descargar."""
    archivos = pruebas.archivos_de_respuesta(respuesta)
    if not archivos:
        return
    pide = pruebas.pide_programar(mensaje)
    if pide and desde_equipo:
        from app.local import sandbox
        principal = pruebas.archivo_principal(archivos)
        if principal is not None and len(archivos) > 1 and sandbox.normalizar(principal[1].lenguaje) not in sandbox.MULTIARCHIVO:
            principal = None                                    # p. ej. Java o Go con varios archivos: no se arma solo
        if principal is None:
            pasos.abrir("Prueba omitida", "sandbox.ejecutar", {"motivo": "interactivo, sin lenguaje instalado o proyecto no ejecutable solo"})
            pasos.cerrar(True, "El programa necesita teclado, ventana o servidor (o su lenguaje no está instalado): "
                               "pruébalo en tu equipo.")
        else:
            ruta, bloque = principal
            proyecto = {r: b.codigo for r, b in archivos}
            lenguaje = bloque.lenguaje
            for intento in range(3):
                extras = {r: c for r, c in proyecto.items() if r != ruta}
                r = _probar_en_sandbox(t, pasos, pruebas.Bloque(lenguaje, proyecto[ruta]), piezas,
                                       f"Probando {ruta}" + (f" (versión corregida {intento})" if intento else ""),
                                       extras=extras, entrada=ruta)
                if r["ok"] is not False or r.get("motivo") in ("timeout", "cancelado") or intento == 2:
                    break
                pasos.abrir(f"Corrigiendo el error (intento {intento + 1} de 2)", "modelo.corregir",
                            {"archivo": ruta, "error": r["salida"][-300:]})
                arreglo = _corregir_codigo(s, lenguaje, ruta, proyecto, r["salida"], mensaje)
                if not arreglo or arreglo[1].strip() == proyecto[arreglo[0]].strip():
                    pasos.cerrar(False, "El modelo no propuso ningún cambio")
                    break
                destino, nuevo = arreglo
                proyecto[destino] = nuevo
                texto = f"### 🔧 Versión corregida de `{destino}`\n```{lenguaje}\n{nuevo}\n```\n\n"
                piezas.append(texto)
                t.agregar({"tipo": "texto", "texto": texto})
                pasos.cerrar(True, f"Corregí {destino}")
            archivos = [(r_, pruebas.Bloque(b.lenguaje, proyecto.get(r_, b.codigo))) for r_, b in archivos]
    if len(archivos) >= 2:
        rutas = [r for r, _ in archivos]
        pasos.abrir(f"Organizando {len(archivos)} archivos en un ZIP", "zip.crear", {"archivos": rutas})
        plan = {"tipo": "zip", "titulo": estudio.titulo_corto(mensaje), "descripcion": mensaje[:400],
                "archivos": [{"ruta": r, "contenido": b.codigo} for r, b in archivos]}
        try:
            creacion = estudio.construir(plan)
            creado = _guardar_creacion(creacion, "zip", "respuesta", user_id)
        except estudio.PlanInvalido as e:
            pasos.cerrar(False, str(e))
            return
        archivos_creados.append(creado)
        t.agregar({"tipo": "archivo", **creado})
        pasos.cerrar(True, f"{creado['nombre']} · {creado['resumen']}")
        aviso = (f"\n\n📦 Organicé los {len(archivos)} archivos en **{creado['nombre']}** (carpetas y README incluidos): "
                 "descárguelo en la tarjeta de arriba.\n")
        piezas.append(aviso)
        t.agregar({"tipo": "texto", "texto": aviso})


def _respuesta_de_plantilla(creados: list[dict], inicio: float):
    """Aviso de «archivo listo» sin gastar otra generación del modelo (en CPU eran minutos para 2 frases)."""
    c = creados[-1]
    paginas = f" (unas {c['paginas']} páginas)" if c.get("paginas") else ""
    texto = (f"Listo: creé «{c['nombre']}»{paginas}. Puede descargarlo en la tarjeta de arriba; también queda "
             "cifrado en su Bóveda. Si quiere cambios (más extenso, otro tono, otra estructura), dígame cuáles "
             "y lo rehago.")
    if c.get("aviso"):
        texto += f"\n\n{c['aviso']}"
    yield {"tipo": "texto", "texto": texto}
    yield {"tipo": "fin", "reply": assistant.Reply(texto, "plantilla", {"categoria": None, "datos_ocultados": 0}, [], [],
                                                    False, int((time.perf_counter() - inicio) * 1000))}


def _transmitir(trabajo: chat_trabajos.Trabajo, desde: int, primero: dict | None = None) -> StreamingResponse:
    """SSE que sigue un trabajo. Si el cliente se va, el trabajo NO se detiene: solo deja de mirarlo."""
    def eventos():
        if primero:
            yield _sse(primero)
        for i, ev in trabajo.seguir(desde):
            if ev is None:
                yield ": latido\n\n"          # mantiene viva la conexión en redes que cortan lo inactivo
            else:
                yield _sse({**ev, "i": i})

    return StreamingResponse(eventos(), media_type="text/event-stream", headers={
        "Cache-Control": "no-store",
        "X-Accel-Buffering": "no",  # evita que un proxy acumule la respuesta y anule el efecto
    })


@router.get("/assistant/chat/trabajos")
def trabajos_recientes(p: CurrentUser):
    """Respuestas en curso o recién terminadas: al volver a la app, el cliente sabe qué retomar."""
    return [t.resumen() for t in chat_trabajos.recientes(p.user.id)]


@router.get("/assistant/chat/trabajos/{trabajo_id}/stream")
def retomar_trabajo(trabajo_id: str, p: CurrentUser, desde: int = Query(0, ge=0)):
    """Reconecta a una respuesta: entrega los eventos desde ``desde`` y sigue en vivo si no terminó."""
    limiter.hit(f"chat-retomar:{p.user.id}", 60)      # reconexiones razonables, no un martilleo
    t = chat_trabajos.obtener(trabajo_id, p.user.id)
    if t is None:
        raise not_found("respuesta en curso")
    return _transmitir(t, desde)


@router.post("/assistant/chat/trabajos/{trabajo_id}/detener", response_model=Msg)
def detener_trabajo(trabajo_id: str, p: CurrentUser):
    """Detiene una respuesta: ya no basta con cerrar la conexión, porque la generación sigue sola."""
    if not chat_trabajos.cancelar(trabajo_id, p.user.id):
        raise not_found("respuesta en curso")
    return Msg(mensaje="Deteniendo la respuesta")


MODELOS_CON_VISION = ("llava", "vision", "gpt-4o", "gpt-4.1", "claude", "qwen2.5vl", "moondream", "minicpm-v",
                      "gemma3", "pixtral")


def _modelo_ve_imagenes() -> bool:
    """Solo se manda la imagen si el modelo puede verla; a uno de texto le llegaría basura."""
    s = get_settings()
    if s.llm_kind == "anthropic":
        return True
    nombre = (s.llm_model or "").lower()
    return any(marca in nombre for marca in MODELOS_CON_VISION)


def _crear_archivo(instruccion: str, tipo: str, user_id: str, buscar_web: bool = False, progreso=None,
                   bloques: list | None = None) -> dict:
    """Genera el archivo y lo guarda cifrado en la bóveda. Devuelve lo que el chat debe mostrar.

    Cuando la búsqueda está activa, lo encontrado en internet se pasa al modelo para que el contenido
    tenga datos reales y no solo lo que el modelo recuerde.
    """
    from app.api.v1.estudio import _planificar
    contexto = ""
    if buscar_web:
        try:
            with httpx.Client(timeout=12.0) as client:
                contexto, _fuentes = assistant.gather_web_context(instruccion, client)
        except Exception:  # noqa: BLE001 - sin internet se crea igual, con lo que el modelo sabe
            contexto = ""
    plan, origen = _planificar(instruccion, tipo, contexto, progreso=progreso,
                               skills=_bloque_skills_usuario(user_id, instruccion, tipo), bloques=bloques)
    try:
        creacion = estudio.construir(plan)
    except estudio.PlanInvalido:
        creacion = estudio.construir(estudio.plan_basico(instruccion, tipo))
        origen = "reglas"
    salida = _guardar_creacion(creacion, tipo, origen, user_id, plan.get("paginas_estimadas"))
    if plan.get("nota_sin_modelo"):
        salida["aviso"] = ("No hay un modelo de lenguaje conectado, así que este documento es solo una plantilla "
                           "básica. Para un documento completo conecte el modelo "
                           "(python -m app.cli usar-ollama o una clave de Anthropic) y vuelva a pedirlo.")
    return salida


def _guardar_creacion(creacion, tipo: str, origen: str, user_id: str, paginas=None) -> dict:
    """Guarda lo creado en la Bóveda (cifrado) y devuelve la tarjeta que muestra el chat."""
    db = SessionLocal()
    try:
        from app.db.models import User
        usuario = db.get(User, user_id)
        f = boveda.guardar(db, usuario, categoria=creacion.categoria, nombre=creacion.nombre,
                           datos=creacion.datos, mime=creacion.mime)
        audit.record(db, "asistente.archivo_creado", actor_id=user_id, target_type="vault_file",
                     target_id=f.id, detail={"tipo": tipo, "plan": origen}, commit=False)
        db.commit()
        return {"archivo_id": f.id, "nombre": creacion.nombre, "formato": tipo, "bytes": len(creacion.datos),
                "resumen": creacion.resumen, "plan_de": origen, "paginas": paginas,
                "descarga": f"/v1/vault/files/{f.id}/download"}
    finally:
        db.close()


def _bloque_skills_usuario(user_id: str, mensaje: str, tipo: str) -> str:
    """Skills para el documento que se está creando (sesión propia: esto corre en el hilo del trabajo)."""
    db = SessionLocal()
    try:
        return _bloque_skills(db, user_id, mensaje, tipo)
    finally:
        db.close()


def _sse(evento: dict) -> str:
    return f"data: {json.dumps(evento, ensure_ascii=False, default=str)}\n\n"


def _guardar_respuesta(conversation_id: str, user_id: str, texto: str, reply, archivos: list[dict] | None = None) -> None:
    """Guarda la respuesta con una sesión propia: la del request ya se cerró al empezar a transmitir.

    Los archivos creados se guardan DENTRO del mensaje. Antes solo viajaban como evento en vivo, y al
    reabrir la conversación la tarjeta con la descarga desaparecía («se borran los archivos»). Incluso
    si el modelo no escribió texto, el mensaje se guarda cuando hay archivos."""
    archivos = archivos or []
    if not texto.strip() and not archivos:
        return
    if not texto.strip():
        texto = "Archivo creado: " + ", ".join(a["nombre"] for a in archivos)
    db = SessionLocal()
    try:
        conv = db.get(Conversation, conversation_id)
        if conv is None or conv.user_id != user_id:
            return
        msg = Message(conversation_id=conversation_id, role="assistant",
                      content_enc=seal_text(texto, "msg:pending"),
                      safety=getattr(reply, "safety", {}) or {},
                      provider=getattr(reply, "provider", "desconocido"),
                      latency_ms=getattr(reply, "latency_ms", 0),
                      files=[_archivo_para_guardar(a) for a in archivos],
                      sources=list(getattr(reply, "sources", []) or [])[:8])
        db.add(msg)
        db.flush()
        msg.content_enc = seal_text(texto, f"msg:{msg.id}")
        db.commit()
    finally:
        db.close()


def _archivo_para_guardar(a: dict) -> dict:
    campos = ("archivo_id", "nombre", "formato", "bytes", "resumen", "plan_de", "paginas", "descarga")
    return {k: a.get(k) for k in campos if a.get(k) is not None}


@router.get("/assistant/conversations", response_model=list[ConversationOut])
def conversations(p: CurrentUser, db: DB, limit: int = Query(300, ge=1, le=1000)):
    """Todas las conversaciones, la más reciente (por último mensaje) primero. Antes solo se veían 30,
    ordenadas por fecha de creación: las antiguas parecían haberse borrado."""
    ultima = (select(func.max(Message.created_at)).where(Message.conversation_id == Conversation.id)
              .correlate(Conversation).scalar_subquery())
    return db.execute(select(Conversation).where(Conversation.user_id == p.user.id)
                      .order_by(func.coalesce(ultima, Conversation.created_at).desc()).limit(limit)).scalars().all()


@router.get("/assistant/conversations/{conversation_id}", response_model=list[ChatMessageOut])
def conversation_messages(conversation_id: str, p: CurrentUser, db: DB):
    conv = db.get(Conversation, conversation_id)
    if conv is None or conv.user_id != p.user.id:
        raise not_found("conversación")
    rows = db.execute(select(Message).where(Message.conversation_id == conv.id)
                      .order_by(Message.created_at)).scalars().all()
    _recuperar_archivos_antiguos(db, p.user.id, rows)
    disponibles = {f for (f,) in db.execute(select(VaultFile.id).where(VaultFile.user_id == p.user.id)).all()}
    salida = []
    for m in rows:
        archivos = [{**f, "disponible": f.get("archivo_id") in disponibles} for f in (m.files or [])]
        salida.append(ChatMessageOut(id=m.id, role=m.role, content=open_text(m.content_enc, f"msg:{m.id}") or "",
                                     created_at=m.created_at, files=archivos, sources=list(m.sources or [])))
    return salida


def _recuperar_archivos_antiguos(db, user_id: str, mensajes: list[Message]) -> None:
    """Reasocia a su mensaje los archivos creados ANTES de que los mensajes los guardaran.

    La bitácora (``asistente.archivo_creado``) registró cuándo se creó cada archivo. Un archivo pertenece
    a la respuesta del asistente cuyo intervalo —desde el mensaje anterior hasta el suyo— contiene esa
    hora. Lo recuperado se guarda en el mensaje: las lecturas siguientes ya lo traen sin recalcular."""
    pendientes = [i for i, m in enumerate(mensajes) if m.role == "assistant" and not (m.files or [])]
    if not pendientes or not mensajes:
        return
    desde = mensajes[0].created_at - timedelta(minutes=5)
    hasta = mensajes[-1].created_at + timedelta(seconds=30)
    eventos = db.execute(select(AuditLog).where(
        AuditLog.actor_id == user_id, AuditLog.action == "asistente.archivo_creado",
        AuditLog.ts >= desde, AuditLog.ts <= hasta).order_by(AuditLog.ts)).scalars().all()
    if not eventos:
        return
    existentes = {f.id: f for f in db.execute(select(VaultFile).where(
        VaultFile.user_id == user_id, VaultFile.id.in_([e.target_id for e in eventos if e.target_id]))).scalars()}
    ya_asignados = {f.get("archivo_id") for m in mensajes for f in (m.files or [])}
    cambios = False
    for i in pendientes:
        m = mensajes[i]
        inicio = mensajes[i - 1].created_at if i > 0 else m.created_at - timedelta(hours=1)
        hallados = []
        for e in eventos:
            if e.target_id in ya_asignados or not (inicio <= e.ts <= m.created_at + timedelta(seconds=5)):
                continue
            f = existentes.get(e.target_id)
            if f is None:
                continue
            hallados.append({"archivo_id": f.id, "nombre": open_text(f.filename_enc, boveda.ctx(user_id, f.id)) or "archivo",
                             "formato": (e.detail or {}).get("tipo"), "bytes": f.size_bytes,
                             "resumen": "Recuperado del historial", "descarga": f"/v1/vault/files/{f.id}/download"})
            ya_asignados.add(e.target_id)
        if hallados:
            m.files = hallados
            cambios = True
    if cambios:
        db.commit()


@router.delete("/assistant/conversations/{conversation_id}", response_model=Msg)
def delete_conversation(conversation_id: str, p: CurrentUser, db: DB):
    conv = db.get(Conversation, conversation_id)
    if conv is None or conv.user_id != p.user.id:
        raise not_found("conversación")
    db.delete(conv)
    db.commit()
    return Msg(mensaje="Conversación eliminada")


@router.get("/assistant/personality", response_model=PersonalityIO)
def get_personality(p: CurrentUser, db: DB):
    pp, _ = _persona(db, p.user.id)
    db.commit()
    return PersonalityIO(friendliness=pp.friendliness, protection=pp.protection, proactivity=pp.proactivity,
                         verbosity=pp.verbosity, humor=pp.humor, mode=pp.mode, assistant_name=pp.assistant_name)


@router.put("/assistant/personality", response_model=PersonalityIO)
def set_personality(body: PersonalityIO, p: CurrentUser, db: DB):
    pp, _ = _persona(db, p.user.id)
    for k, v in body.model_dump().items():
        setattr(pp, k, v)
    db.commit()
    return body


# ─────────────────────────────────────────────── lo que el asistente aprendió de la persona
class LeccionIn(BaseModel):
    cuando: str = Field("", max_length=400)
    haz: str = Field(..., min_length=3, max_length=400)


@router.get("/assistant/aprendizaje")
def lecciones(p: CurrentUser, db: DB):
    return {"lecciones": aprendizaje.listar(db, p.user.id), "maximo": aprendizaje.MAX_LECCIONES}


@router.post("/assistant/aprendizaje")
def ensenar(body: LeccionIn, p: CurrentUser, db: DB):
    limiter.hit(f"aprendizaje:{p.user.id}", 30)
    try:
        lec = aprendizaje.crear(db, p.user.id, body.cuando, body.haz)
    except ValueError as e:
        raise ApiError(422, "leccion_invalida", str(e)) from None
    return {"ok": True, "id": lec.id, "mensaje": "Aprendido. Lo aplicaré en preguntas parecidas."}


@router.delete("/assistant/aprendizaje/{leccion_id}", response_model=Msg)
def olvidar(leccion_id: str, p: CurrentUser, db: DB):
    if not aprendizaje.borrar(db, p.user.id, leccion_id):
        raise not_found("lección")
    return Msg(mensaje="Olvidado")


# ─────────────────────────────────────────────────────────────── skills
class SkillIn(BaseModel):
    name: str = Field(min_length=3, max_length=skills_ai.MAX_NOMBRE)
    description: str = Field("", max_length=skills_ai.MAX_DESCRIPCION)
    content: str = Field(min_length=20, max_length=skills_ai.MAX_CUERPO)
    triggers: list[str] | str = Field(default_factory=list)
    tipos: list[str] | str = Field(default_factory=list)
    always: bool = False
    enabled: bool = True


class SkillEstadoIn(BaseModel):
    enabled: bool


def _skill_a_salida(sk: skills_ai.Skill, activa: bool, completo: bool = False) -> dict:
    salida = {"id": sk.id, "nombre": sk.nombre, "descripcion": sk.descripcion, "triggers": sk.triggers,
              "tipos": sk.tipos, "siempre": sk.siempre, "integrada": sk.integrada, "activa": activa,
              "caracteres": len(sk.contenido)}
    if completo:
        salida["contenido"] = sk.contenido
    return salida


def _skill_propia(db, user_id: str, skill_id: str) -> AssistantSkill:
    f = db.get(AssistantSkill, skill_id)
    if f is None or f.user_id != user_id or f.builtin_ref:
        raise not_found("skill")
    return f


@router.get("/assistant/skills")
def listar_skills(p: CurrentUser, db: DB):
    """Skills integradas (con su interruptor) y las propias. Las integradas vienen activas por defecto."""
    filas = db.execute(select(AssistantSkill).where(AssistantSkill.user_id == p.user.id)
                       .order_by(AssistantSkill.created_at)).scalars().all()
    apagadas = {f.builtin_ref for f in filas if f.builtin_ref and not f.enabled}
    salida = [_skill_a_salida(sk, sk.id.split(":", 1)[1] not in apagadas) for sk in skills_ai.integradas()]
    for f in filas:
        if f.builtin_ref:
            continue
        sk = skills_ai.Skill(nombre=f.name, descripcion=f.description, contenido=f.content,
                             triggers=list(f.triggers or []), tipos=list(f.tipos or []), siempre=bool(f.always),
                             id=f.id)
        salida.append(_skill_a_salida(sk, bool(f.enabled)))
    return {"skills": salida, "maximo_propias": skills_ai.MAX_SKILLS_PROPIAS, "maximo_caracteres": skills_ai.MAX_CUERPO}


@router.get("/assistant/skills/{skill_id}")
def ver_skill(skill_id: str, p: CurrentUser, db: DB):
    if skill_id.startswith("integrada:"):
        for sk in skills_ai.integradas():
            if sk.id == skill_id:
                return _skill_a_salida(sk, True, completo=True)
        raise not_found("skill")
    f = _skill_propia(db, p.user.id, skill_id)
    sk = skills_ai.Skill(nombre=f.name, descripcion=f.description, contenido=f.content,
                         triggers=list(f.triggers or []), tipos=list(f.tipos or []), siempre=bool(f.always), id=f.id)
    return _skill_a_salida(sk, bool(f.enabled), completo=True)


def _crear_skill(db, user_id: str, sk: skills_ai.Skill, enabled: bool = True) -> AssistantSkill:
    propias = db.execute(select(func.count()).select_from(AssistantSkill)
                         .where(AssistantSkill.user_id == user_id, AssistantSkill.builtin_ref.is_(None))).scalar_one()
    if propias >= skills_ai.MAX_SKILLS_PROPIAS:
        raise conflict("demasiadas_skills", f"Máximo {skills_ai.MAX_SKILLS_PROPIAS} skills propias")
    ya = db.execute(select(AssistantSkill).where(AssistantSkill.user_id == user_id,
                                                  AssistantSkill.name == sk.nombre)).scalar()
    if ya is not None:
        raise conflict("skill_repetida", f"Ya tiene una skill llamada «{sk.nombre}»")
    f = AssistantSkill(user_id=user_id, name=sk.nombre, description=sk.descripcion, content=sk.contenido,
                       triggers=sk.triggers, tipos=sk.tipos, always=sk.siempre, enabled=enabled)
    db.add(f)
    db.flush()
    return f


@router.post("/assistant/skills", status_code=201)
def crear_skill(body: SkillIn, p: CurrentUser, db: DB):
    limiter.hit(f"skills:{p.user.id}", 30, 600)
    try:
        sk = skills_ai.construir(body.name, body.description, body.content, body.triggers, body.tipos, body.always)
    except skills_ai.SkillInvalida as e:
        raise ApiError(422, "skill_invalida", str(e)) from None
    f = _crear_skill(db, p.user.id, sk, body.enabled)
    audit.record(db, "assistant.skill_creada", actor_id=p.user.id, target_type="assistant_skill", target_id=f.id,
                 commit=False)
    db.commit()
    return {"ok": True, "id": f.id, "mensaje": "Skill guardada. El asistente la usará cuando venga al caso."}


@router.post("/assistant/skills/importar", status_code=201)
async def importar_skill(p: CurrentUser, db: DB, file: UploadFile = File(...)):
    """Importa un archivo .md con frontmatter (name, description, triggers…): el mismo formato de las skills de Claude."""
    limiter.hit(f"skills:{p.user.id}", 30, 600)
    datos = await file.read(skills_ai.MAX_CUERPO * 2 + 1)
    if len(datos) > skills_ai.MAX_CUERPO * 2:
        raise ApiError(413, "file_too_large", "El archivo de la skill es demasiado grande")
    try:
        texto = datos.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ApiError(422, "skill_invalida", "El archivo debe ser texto UTF-8 (.md)") from None
    base = (file.filename or "skill").rsplit(".", 1)[0]
    try:
        sk = skills_ai.parsear(texto, nombre_defecto=base)
    except skills_ai.SkillInvalida as e:
        raise ApiError(422, "skill_invalida", str(e)) from None
    f = _crear_skill(db, p.user.id, sk)
    audit.record(db, "assistant.skill_importada", actor_id=p.user.id, target_type="assistant_skill", target_id=f.id,
                 commit=False)
    db.commit()
    return {"ok": True, "id": f.id, "nombre": f.name}


@router.put("/assistant/skills/{skill_id}/estado")
def cambiar_estado_skill(skill_id: str, body: SkillEstadoIn, p: CurrentUser, db: DB):
    """Enciende o apaga una skill (integrada o propia)."""
    if skill_id.startswith("integrada:"):
        ref = skill_id.split(":", 1)[1]
        if not any(sk.id == skill_id for sk in skills_ai.integradas()):
            raise not_found("skill")
        fila = db.execute(select(AssistantSkill).where(AssistantSkill.user_id == p.user.id,
                                                       AssistantSkill.builtin_ref == ref)).scalar()
        if fila is None:
            fila = AssistantSkill(user_id=p.user.id, builtin_ref=ref, name=f"@{ref}"[:60])
            db.add(fila)
        fila.enabled = body.enabled
    else:
        _skill_propia(db, p.user.id, skill_id).enabled = body.enabled
    db.commit()
    return {"ok": True, "activa": body.enabled}


@router.put("/assistant/skills/{skill_id}")
def editar_skill(skill_id: str, body: SkillIn, p: CurrentUser, db: DB):
    f = _skill_propia(db, p.user.id, skill_id)
    try:
        sk = skills_ai.construir(body.name, body.description, body.content, body.triggers, body.tipos, body.always)
    except skills_ai.SkillInvalida as e:
        raise ApiError(422, "skill_invalida", str(e)) from None
    if sk.nombre != f.name and db.execute(select(AssistantSkill).where(
            AssistantSkill.user_id == p.user.id, AssistantSkill.name == sk.nombre)).scalar() is not None:
        raise conflict("skill_repetida", f"Ya tiene una skill llamada «{sk.nombre}»")
    f.name, f.description, f.content = sk.nombre, sk.descripcion, sk.contenido
    f.triggers, f.tipos, f.always, f.enabled = sk.triggers, sk.tipos, sk.siempre, body.enabled
    db.commit()
    return {"ok": True}


@router.delete("/assistant/skills/{skill_id}", response_model=Msg)
def borrar_skill(skill_id: str, p: CurrentUser, db: DB):
    if skill_id.startswith("integrada:"):
        raise ApiError(409, "skill_integrada", "Las skills integradas no se borran; puede apagarlas.")
    db.delete(_skill_propia(db, p.user.id, skill_id))
    db.commit()
    return Msg(mensaje="Skill eliminada")
