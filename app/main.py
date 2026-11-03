"""GuardianIA — API.

IA antivirus + protección de dispositivos + monitoreo de signos vitales + asistente con
navegación web + VPN inteligente. Backend seguro para la app Android I.A-guardián.
"""
from __future__ import annotations

import os

import asyncio
import contextlib
import logging

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import (admin, agente, antivirus, assistant, auth, devices, emergency, estudio, local,
                        ml, notifications, proteccion, sandbox, vault, vpn, web_auth)
from app import web
from app.core import errors, rbac
from app.core.blocklist import BlockedIPMiddleware
from app.core.config import get_settings
from app.core.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from app.core.security import AUD_ADMIN, AUD_APP, decode_access_token, utcnow
from app.db.session import SessionLocal, init_db
from app.services import emergency as emergency_svc
from app.db.models import AuthSession, User
from app.services.realtime import STAFF_CHANNEL, device_channel, hub, user_channel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("guardian")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    generated_keys = []
    if s.is_production:
        s.validate_for_runtime()
    elif generated := s.ensure_dev_secrets():
        generated_keys = generated
        log.warning(
            "Faltan %s en el archivo .env; se generaron claves temporales solo para esta ejecución.\n"
            "    Al reiniciar el servidor se cerrarán las sesiones y no se podrá descifrar lo ya guardado.\n"
            "    Para trabajo real: python -m app.cli generate-keys  y pegue el resultado en .env",
            " y ".join(generated))
    init_db()
    renombrados = migrar_nombre_asistente()
    if renombrados:
        log.info("Asistente renombrado a «Asistente AI» en %s cuenta(s) que tenían el nombre anterior", renombrados)
    log.info("GuardianIA %s (%s) | .env: %s | claves: %s | base: %s",
             s.version, s.env, s.env_file_in_use() or "no encontrado",
             "temporales (se pierden al reiniciar)" if not s.env_file_in_use() or generated_keys else "propias",
             s.database_url)
    base = os.environ.get("GUARDIAN_URL_PUBLICA")
    if base:
        log.info("App: %s/app/  ·  Consola: %s/consola/  ·  API: %s/docs", base, base, base)
    else:
        # Arrancado con «uvicorn …» a mano: no se sabe si lleva TLS. Se orienta al arranque oficial.
        log.warning("Arranque sin el lanzador: para HTTPS (GPS del celular, cookies seguras) use "
                    "«python -m app.servidor» o INICIAR_GUARDIANIA.bat")
    borrados = limpiar_servidores_de_ejemplo()
    if borrados:
        log.info("Se limpiaron %d servidores de VPN de ejemplo (sin túnel real) y sus sesiones colgadas", borrados)
    arrancar_proteccion_local(s)
    stop = asyncio.Event()
    task = asyncio.create_task(_emergency_loop(stop))
    try:
        yield
    finally:
        detener_proteccion_local()
        stop.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def _emergency_loop(stop: asyncio.Event):
    """Escala incidentes cuya ventana de cancelación venció (cada 5 s)."""
    while not stop.is_set():
        with contextlib.suppress(Exception):
            await asyncio.to_thread(_process_due_once)
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=5)


def _process_due_once():
    db = SessionLocal()
    try:
        n = emergency_svc.process_due(db)
        if n:
            log.info("Escalados %d incidentes de emergencia", n)
    finally:
        db.close()


settings = get_settings()
app = FastAPI(
    title="GuardianIA API",
    version=settings.version,
    description="IA antivirus, protección de dispositivos, signos vitales, asistente con navegación web y VPN "
                "inteligente. Autor original: Anderson Mamián Chicangana.",
    lifespan=lifespan,
    docs_url="/docs" if not settings.is_production else None,
)

errors.install(app)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_upload_mb * 1024 * 1024)
app.add_middleware(BlockedIPMiddleware)  # se agrega de último → corre primero: una IP bloqueada no llega a nada
if settings.cors_origins:
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"], max_age=600)

V1 = "/v1"
for r in (auth.router, auth.admin_router, emergency.router, antivirus.router, assistant.router,
          vpn.router, devices.router, vault.router, admin.router, notifications.router, web_auth.router, estudio.router,
          proteccion.router, agente.router, ml.router, local.router, sandbox.router):
    app.include_router(r, prefix=V1)


@app.get("/health", tags=["Sistema"])
def healthcheck():
    return {"status": "ok", "version": settings.version, "env": settings.env}


@app.get("/", include_in_schema=False)
def root():
    return {"servicio": "GuardianIA API", "documentacion": "/docs" if not settings.is_production else "deshabilitada",
            "salud": "/health", "app": "/app/", "consola": "/consola/"}


def arrancar_proteccion_local(s) -> None:
    """Tiempo real y análisis programados arrancan con el servidor: nadie tiene que abrir nada."""
    if s.env == "test":
        return
    from app.local import ajustes
    from app.local.escaner import escaner
    from app.local.tiempo_real import vigilante
    conf = ajustes.leer()
    if conf.get("propietario"):
        if conf["tiempo_real"]:
            vigilante.iniciar(conf["propietario"])
        escaner.iniciar_programador()
        log.info("Protección local activa: tiempo real %s, análisis automáticos cada %s h / %s días",
                 "encendido" if conf["tiempo_real"] else "apagado", conf["auto_rapido_horas"],
                 conf["auto_completo_dias"])
    else:
        log.info("Protección local lista: se activa al entrar a Protección → Antivirus")
    # La VPN (servidor propio / Tor) se retoma sola: el vigilante repara lo que se cayó al reiniciar.
    try:
        from app.local import privacidad
        if privacidad.config()["modo"] != "apagado":
            privacidad._asegurar_vigilante()
    except Exception:  # noqa: BLE001 - la privacidad nunca impide que arranque el servidor
        log.exception("no se pudo retomar la privacidad")


def detener_proteccion_local() -> None:
    from app.local.escaner import escaner
    from app.local.tiempo_real import vigilante
    vigilante.detener()
    escaner.detener()


def limpiar_servidores_de_ejemplo() -> int:
    """Borra de la base los servidores de demostración: no tienen WireGuard real y confundían.

    Se reconocen por su host inventado (…vpn.guardianai.dev) o por no tener clave ni endpoint. La
    lista real de servidores sale ahora de lo que de verdad conecta (WARP y el .conf importado), no
    de esta tabla. Cierra también cualquier sesión que aún colgara contra ellos.
    """
    from sqlalchemy import select

    from app.db.models import VpnServer, VpnSession
    db = SessionLocal()
    try:
        n = 0
        for sesion in db.execute(select(VpnSession).where(VpnSession.estado.in_(("conectando", "sin_verificar")))).scalars():
            servidor = db.get(VpnServer, sesion.server_id)
            if servidor is None or not servidor.endpoint:
                sesion.estado, sesion.cerrada_at = "cerrada", utcnow()
                sesion.motivo_cierre = "servidor de ejemplo sin túnel"
                n += 1
        for servidor in db.execute(select(VpnServer)).scalars():
            de_ejemplo = ("guardianai.dev" in (servidor.host or "")) or not servidor.public_key or not servidor.endpoint
            # Se conservan los túneles locales reales (WARP/importado) que sí tienen endpoint y clave.
            if de_ejemplo and not str(servidor.id).startswith("local-"):
                db.delete(servidor)
                n += 1
        db.commit()
        return n
    except Exception:  # noqa: BLE001
        db.rollback()
        return 0
    finally:
        db.close()


def migrar_nombre_asistente() -> int:
    """Cambia el nombre anterior por defecto («Guardian») al nuevo, una sola vez.

    Solo toca filas que conservan exactamente el valor por defecto viejo: si alguien eligió su
    propio nombre desde Personalidad, se respeta.
    """
    from sqlalchemy import update

    from app.db.models import PersonalityProfile
    from app.db.session import SessionLocal
    db = SessionLocal()
    try:
        r = db.execute(update(PersonalityProfile).where(PersonalityProfile.assistant_name == "Guardian")
                       .values(assistant_name="Asistente AI"))
        db.commit()
        return r.rowcount or 0
    except Exception:  # noqa: BLE001 - nunca impedir el arranque por una migración cosmética
        db.rollback()
        return 0
    finally:
        db.close()


web.install(app)


def _session_valid(claims: dict, staff: bool) -> bool:
    """El WebSocket vive horas: se valida la sesión en BD, no solo la firma del token."""
    db = SessionLocal()
    try:
        s = db.get(AuthSession, claims.get("sid"))
        u = db.get(User, claims.get("sub"))
        return (s is not None and s.revoked_at is None and s.expires_at > utcnow() and u is not None
                and u.status == "active" and (not staff or u.role in rbac.STAFF_ROLES))
    finally:
        db.close()


async def _ws_auth(ws: WebSocket, audience: str) -> dict | None:
    # El token va en el primer mensaje, no en la URL: las URL terminan en logs de proxies.
    await ws.accept()
    try:
        auth_msg = await asyncio.wait_for(ws.receive_json(), timeout=10)
        claims = decode_access_token(auth_msg.get("token", ""), audience)
        if not await asyncio.to_thread(_session_valid, claims, audience == AUD_ADMIN):
            raise PermissionError
        return claims
    except Exception:
        await ws.close(code=4401)
        return None


@app.websocket("/v1/admin/ws")
async def admin_websocket(ws: WebSocket):
    """Canal del personal: alertas altas y críticas en vivo (btn_refresh_live del dashboard)."""
    claims = await _ws_auth(ws, AUD_ADMIN)
    if claims is None:
        return
    await _pump(ws, STAFF_CHANNEL, {"tipo": "conectado", "canal": "staff"})


@app.websocket("/v1/ws")
async def websocket_endpoint(ws: WebSocket):
    """Eventos en tiempo real del usuario (alertas, notificaciones, incidentes).

    Autenticación por primer mensaje: {"token": "<access token de la app>"}.
    """
    claims = await _ws_auth(ws, AUD_APP)
    if claims is None:
        return
    await _pump(ws, user_channel(claims["sub"]), {"tipo": "conectado", "canal": "usuario"})


def _device_de_token(raw: str):
    from app.db.models import Device
    from app.core.security import token_hash
    db = SessionLocal()
    try:
        d = db.query(Device).filter(Device.device_token_hash == token_hash(raw or "")).first()
        return None if d is None or d.status == "wiped" else (d.id, d.user_id, d.name)
    finally:
        db.close()


@app.websocket("/v1/ws/equipo")
async def device_websocket(ws: WebSocket):
    """Canal en vivo del teléfono vinculado por navegador.

    Sin esto, una orden del dueño («Sonar alarma») esperaba al siguiente latido (hasta 30 s).
    Con el canal abierto llega en menos de un segundo. Además, cuando el canal se cierra (pestaña
    cerrada, teléfono apagado, sin señal) el PC lo sabe al instante en vez de esperar a que venza
    el latido. Autenticación: primer mensaje {"device_token": "..."}.
    """
    await ws.accept()
    try:
        msg = await asyncio.wait_for(ws.receive_json(), timeout=10)
        equipo = await asyncio.to_thread(_device_de_token, str(msg.get("device_token", "")))
    except Exception:
        equipo = None
    if equipo is None:
        await ws.close(code=4401)
        return
    device_id, user_id, nombre = equipo
    aviso = {"tipo": "dispositivo_conexion", "device_id": device_id, "nombre": nombre}
    hub.publish(user_channel(user_id), {**aviso, "conectado": True})
    try:
        await _pump(ws, device_channel(device_id), {"tipo": "conectado", "canal": "equipo"})
    finally:
        hub.publish(user_channel(user_id), {**aviso, "conectado": False})


async def _pump(ws: WebSocket, channel: str, hello: dict) -> None:
    """Reenvía los eventos del canal al socket hasta que el cliente se vaya.

    Se escucha también el lado de lectura: sin eso, un cliente que cierra la pestaña solo se
    detectaba al fallar el siguiente envío (hasta 30 s después, con el «ping»). Se usa un task group
    de anyio (no asyncio.create_task) para que la cancelación del servidor alcance a ambas tareas.
    """
    import anyio

    queue = hub.subscribe(channel)
    try:
        async with anyio.create_task_group() as tg:
            async def enviar():
                try:
                    await ws.send_json(hello)
                    while True:
                        try:
                            event = await asyncio.wait_for(queue.get(), timeout=30)
                        except asyncio.TimeoutError:
                            event = {"tipo": "ping"}
                        await ws.send_json(event)
                except (WebSocketDisconnect, RuntimeError, OSError):
                    pass                      # el cliente ya se fue
                tg.cancel_scope.cancel()

            async def escuchar():
                try:
                    while (await ws.receive()).get("type") != "websocket.disconnect":
                        pass
                except (WebSocketDisconnect, RuntimeError, OSError):
                    pass
                tg.cancel_scope.cancel()

            tg.start_soon(enviar)
            tg.start_soon(escuchar)
    finally:
        hub.unsubscribe(channel, queue)
