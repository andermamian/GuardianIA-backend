"""Protección de dispositivos y antirrobo — interfaz activity_guardian_antitheft_system.xml.

Decisiones de diseño (revisión de seguridad y legal):

* Se conserva lo que protege al dueño: localizar, sonar, bloquear, mensaje en pantalla,
  modo perdido y borrado remoto. Localizar y bloquear son gratis (ALWAYS_FREE).
* Se ELIMINA lo que la maqueta original mostraba sobre "sospechosos": reconocimiento facial,
  grabación de voz y perfilado de terceros. Capturar biometría de otra persona sin
  consentimiento vulnera la Ley 1581 de 2012 (habeas data) y convierte la app en una
  herramienta de vigilancia. La evidencia se entrega a la Policía, no se procesa aquí.
* El dispositivo se autentica con su propio token (no con el JWT del usuario): si roban
  el teléfono y cierran la sesión de la app, el agente antirrobo sigue reportando.
* Cada comando lleva una firma HMAC; el acuse del dispositivo debe devolverla, de modo que
  un comando alterado en tránsito o en la base de datos no se da por ejecutado.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
from datetime import UTC, timedelta, timezone

from fastapi import APIRouter, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select

from app.api.deps import DB, CurrentUser, client_ip
from app.core import audit, crypto
from app.core.config import get_settings
from app.core.errors import ApiError, conflict, not_found
from app.core.ratelimit import limiter
import secrets
from urllib.parse import quote

from app.core.security import new_opaque_token, token_hash, utcnow
from app.db.models import Device, DeviceCommand, DeviceLocation, DevicePhoto, PairingCode, User
from app.schemas.common import Msg
from app.schemas.devices import (DeviceCommandIn, DeviceCommandOut, DeviceOut, DeviceRegisterIn, DeviceRegisterOut,
                                 IdentificacionIn, LostModeIn, PendingCommandOut, TelemetryIn, TrackingIn)
from app.services import emergency as emergency_svc
from app.services.alerts import notify, raise_alert
from app.services.realtime import device_channel, hub, user_channel
from app.ai import device_insights

router = APIRouter(tags=["Dispositivos y antirrobo"])

MAX_DEVICES = 10
COMMAND_TTL = {"ring": 10, "locate": 10, "message": 60, "photo": 60, "lock": 24 * 60, "sos": 10,
               "wipe": 7 * 24 * 60}  # minutos
MAX_FOTO_BYTES = 1_500_000      # una foto de cámara frontal reducida pesa ~150-400 kB
DEVICE_HISTORY_RETENTION_DAYS = 365
LOCATION_RETENTION_DAYS = DEVICE_HISTORY_RETENTION_DAYS
MAX_PLAUSIBLE_KMH = 900  # por encima, la posición es falsa (GPS spoofing) o un error del sensor


# ------------------------------------------------------------------ utilidades
def purge_expired_device_history(db, now=None) -> int:
    """Elimina ubicaciones y fotos con más de 365 días de antigüedad."""
    now = now or utcnow()
    cutoff = now - timedelta(days=DEVICE_HISTORY_RETENTION_DAYS)
    locations = db.execute(delete(DeviceLocation).where(DeviceLocation.recorded_at < cutoff)).rowcount or 0
    photos = db.execute(delete(DevicePhoto).where(DevicePhoto.created_at < cutoff)).rowcount or 0
    return locations + photos


def _own_device(db, user_id: str, device_id: str) -> Device:
    d = db.get(Device, device_id)
    if d is None or d.user_id != user_id:
        raise not_found("dispositivo")
    return d


def _sign(cmd_id: str, device_id: str, kind: str, payload: dict, expires_iso: str) -> str:
    key = hmac.new(get_settings().jwt_secret.encode(), b"device-command-v1", hashlib.sha256).digest()
    msg = json.dumps([cmd_id, device_id, kind, payload, expires_iso], sort_keys=True, separators=(",", ":"))
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


def _device_by_token(db, raw: str) -> Device:
    d = db.execute(select(Device).where(Device.device_token_hash == token_hash(raw))).scalar()
    if d is None or d.status == "wiped":
        raise ApiError(401, "invalid_device_token", "Dispositivo no reconocido")
    return d


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _publicar(d: Device, evento: str = "actualizado", **extra) -> None:
    """Empuja el estado del equipo a las pantallas abiertas del dueño (WebSocket)."""
    hub.publish(user_channel(d.user_id), {"tipo": "dispositivo", "evento": evento,
                                          "dispositivo": DeviceOut.model_validate(d).model_dump(mode="json"),
                                          **extra})


def _avisar_equipo(d: Device, **evento) -> None:
    """Despierta al teléfono por su canal en vivo: consulta comandos o aplica la pausa al instante."""
    hub.publish(device_channel(d.id), {"tipo": "orden", "estado": d.status, "seguimiento": d.tracking_enabled,
                                       **evento})


def _publicar_comando(d: Device, c: DeviceCommand) -> None:
    hub.publish(user_channel(d.user_id), {"tipo": "dispositivo_comando", "device_id": d.id, "nombre": d.name,
                                          "comando": {"id": c.id, "kind": c.kind, "status": c.status,
                                                      "result": c.result or {}}})


# ------------------------------------------------------- lado del usuario (app)
@router.post("/devices", response_model=DeviceRegisterOut, status_code=201)
def register_device(body: DeviceRegisterIn, p: CurrentUser, db: DB):
    count = db.execute(select(func.count()).select_from(Device).where(Device.user_id == p.user.id)).scalar_one()
    if count >= MAX_DEVICES:
        raise conflict("too_many_devices", f"Máximo {MAX_DEVICES} dispositivos por cuenta")
    raw = new_opaque_token()
    d = Device(user_id=p.user.id, name=body.name, platform=body.platform, model=body.model,
               os_version=body.os_version, device_token_hash=token_hash(raw))
    db.add(d)
    db.flush()
    audit.record(db, "device.registered", actor_id=p.user.id, target_type="device", target_id=d.id, commit=False)
    db.commit()
    return DeviceRegisterOut(id=d.id, device_token=raw)


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(p: CurrentUser, db: DB):
    return db.execute(select(Device).where(Device.user_id == p.user.id)
                      .order_by(Device.created_at)).scalars().all()


@router.get("/devices/overview")
def overview(p: CurrentUser, db: DB):
    """Tarjetas superiores de la pantalla: reemplaza los contadores ficticios («147 capturados», «98.7%»)
    por cifras reales de la cuenta."""
    devices = db.execute(select(Device).where(Device.user_id == p.user.id)).scalars().all()
    stale = utcnow() - timedelta(hours=24)
    return {
        "total": len(devices),
        "protegidos": sum(d.status == "ok" for d in devices),
        "perdidos_o_robados": sum(d.status in ("lost", "stolen") for d in devices),
        "sin_reporte_24h": sum(1 for d in devices if not d.last_seen_at or d.last_seen_at < stale),
        "casos_activos": [
            {"id": d.id, "nombre": d.name, "estado": d.status, "bateria": d.battery,
             "ultima_ubicacion": emergency_svc.map_link(d.last_lat, d.last_lon) if d.last_lat is not None else None,
             "visto": d.last_seen_at}
            for d in devices if d.status in ("lost", "stolen")],
    }


@router.delete("/devices/{device_id}", response_model=Msg)
def remove_device(device_id: str, p: CurrentUser, db: DB):
    d = _own_device(db, p.user.id, device_id)
    if d.status in ("lost", "stolen"):
        # Evita que un ladrón con la sesión abierta desvincule el equipo para dejar de ser rastreado.
        raise conflict("device_reported", "Marque el dispositivo como recuperado antes de eliminarlo")
    audit.record(db, "device.removed", actor_id=p.user.id, target_type="device", target_id=d.id, commit=False)
    db.delete(d)
    db.commit()
    return Msg(mensaje="Dispositivo eliminado")


@router.put("/devices/{device_id}/status", response_model=DeviceOut)
def set_status(device_id: str, body: LostModeIn, p: CurrentUser, db: DB):
    """Modo perdido / robado / recuperado (botones emergency_button y fab_panic_button)."""
    d = _own_device(db, p.user.id, device_id)
    if d.status == "wiped":
        raise conflict("device_wiped", "El dispositivo fue borrado y ya no puede gestionarse")
    previous, d.status = d.status, body.status
    if body.status in ("lost", "stolen") and previous == "ok":
        _queue(db, d, p.user.id, "lock", {"mensaje": body.message or "Este equipo está reportado como perdido."})
        _queue(db, d, p.user.id, "locate", {})
        if body.status == "stolen":
            # Alerta, no incidente: reportar un robo desde otro equipo no implica peligro físico, y
            # escalar a la familia por un celular robado genera pánico. Si hay riesgo, está el SOS.
            raise_alert(db, user_id=p.user.id, category="device", severity="high",
                        title=f"Robo reportado: {d.name}",
                        description="Bloqueo y localización enviados. Denuncie en la Policía (línea 123) o en "
                                    "adenunciar.policia.gov.co; el IMEI queda en el historial del equipo.",
                        data={"device_id": d.id}, engine="antitheft")
    audit.record(db, "device.status", actor_id=p.user.id, target_type="device", target_id=d.id,
                 level="warning" if body.status != "ok" else "info",
                 detail={"de": previous, "a": body.status}, commit=False)
    if body.status in ("lost", "stolen"):
        d.tracking_enabled = True   # un equipo reportado siempre se sigue: nadie puede «desconectarlo»
    db.commit()
    _publicar(d)
    _avisar_equipo(d, comandos=body.status in ("lost", "stolen"))
    return d


@router.put("/devices/{device_id}/seguimiento", response_model=DeviceOut)
def set_tracking(device_id: str, body: TrackingIn, request: Request, p: CurrentUser, db: DB):
    """Conectar / desconectar: reanuda o pausa el envío de GPS del equipo.

    Solo el dueño, desde su sesión, puede pausarlo; la página del teléfono no tiene ese botón a
    propósito: si alguien se roba el celular, no puede apagar el rastreo desde el propio equipo.
    """
    d = _own_device(db, p.user.id, device_id)
    if d.status == "wiped":
        raise conflict("device_wiped", "El dispositivo fue borrado y ya no puede gestionarse")
    if not body.activo and d.status in ("lost", "stolen"):
        raise conflict("device_reported", "Un equipo reportado como perdido o robado no se puede desconectar. "
                                          "Márquelo como recuperado primero.")
    if d.tracking_enabled != body.activo:
        d.tracking_enabled = body.activo
        d.gps_status = None if body.activo else "paused"
        audit.record(db, "device.tracking", actor_id=p.user.id, target_type="device", target_id=d.id,
                     ip=client_ip(request), detail={"activo": body.activo}, commit=False)
        db.commit()
    _publicar(d)
    _avisar_equipo(d)
    return d


def _ctx_ident(d: Device) -> str:
    # El contexto ata el texto cifrado a ESTE equipo y a su dueño: copiarlo a otro registro no descifra.
    return f"device-ident:{d.user_id}:{d.id}"


def _leer_ident(d: Device) -> dict:
    if d.ident_blob is None:
        return {}
    raw = crypto.open_sealed(d.ident_key_version, d.ident_wrapped_dek, d.ident_blob, _ctx_ident(d))
    return json.loads(raw)


@router.get("/devices/{device_id}/identificacion")
def get_identificacion(device_id: str, p: CurrentUser, db: DB):
    d = _own_device(db, p.user.id, device_id)
    return {"registrada": d.ident_blob is not None, **_leer_ident(d)}


@router.put("/devices/{device_id}/identificacion")
def put_identificacion(device_id: str, body: IdentificacionIn, request: Request, p: CurrentUser, db: DB):
    """Guarda IMEI, número, operador y señas CIFRADOS. En la auditoría no queda ningún valor."""
    d = _own_device(db, p.user.id, device_id)
    sellado = crypto.seal(json.dumps(body.model_dump(), ensure_ascii=False).encode(), _ctx_ident(d))
    d.ident_key_version, d.ident_wrapped_dek, d.ident_blob = (sellado.key_version, sellado.wrapped_dek,
                                                              sellado.ciphertext)
    audit.record(db, "device.identificacion", actor_id=p.user.id, target_type="device", target_id=d.id,
                 ip=client_ip(request), level="security", commit=False)
    db.commit()
    _publicar(d)
    return {"registrada": True, **body.model_dump()}


@router.get("/devices/{device_id}/denuncia")
def expediente_denuncia(device_id: str, p: CurrentUser, db: DB):
    """Todo lo que piden la Policía y el operador, en un solo lugar y listo para copiar.

    No envía nada a nadie: la denuncia la presenta el dueño en adenunciar.policia.gov.co o en el 123.
    """
    d = _own_device(db, p.user.id, device_id)
    ident = _leer_ident(d)
    ahora = utcnow()
    filas = db.execute(select(DeviceLocation).where(
        DeviceLocation.device_id == d.id, DeviceLocation.recorded_at >= ahora - timedelta(hours=72))
        .order_by(DeviceLocation.recorded_at.desc()).limit(30)).scalars().all()

    def enlace(lat, lon):
        return {"google_maps": f"https://www.google.com/maps?q={lat},{lon}",
                "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=18/{lat}/{lon}"}

    ultima = None
    if d.last_lat is not None:
        ultima = {"lat": d.last_lat, "lon": d.last_lon, "precision_m": d.last_accuracy_m,
                  "hora": d.last_fix_at or d.last_seen_at, **enlace(d.last_lat, d.last_lon)}
    faltan = [n for n, v in (("IMEI", ident.get("imei")), ("número", ident.get("numero")),
                             ("operador", ident.get("operador"))) if not v]
    estado = {"ok": "En poder del dueño", "lost": "Perdido", "stolen": "Hurtado", "wiped": "Borrado"}[d.status]
    fmt_hora = lambda t: t.astimezone(timezone(timedelta(hours=-5))).strftime("%d/%m/%Y %I:%M %p") if t else "—"
    lineas = [
        f"Denunciante: {p.user.full_name} ({p.user.email})",
        f"Equipo: {d.name} — {d.model or 'modelo no registrado'} ({d.platform})",
        f"IMEI 1: {ident.get('imei') or 'NO REGISTRADO'}",
    ]
    if ident.get("imei2"):
        lineas.append(f"IMEI 2: {ident['imei2']}")
    lineas += [
        f"Línea: {ident.get('numero') or 'no registrada'} — Operador: {ident.get('operador') or 'no registrado'}",
        f"Color / señas: {', '.join(x for x in (ident.get('color'), ident.get('senas')) if x) or '—'}",
        f"Estado: {estado}",
    ]
    if ultima:
        lineas.append(f"Última ubicación GPS: {ultima['lat']:.6f}, {ultima['lon']:.6f} "
                      f"(±{round(ultima['precision_m'] or 0)} m) a las {fmt_hora(ultima['hora'])} — {ultima['google_maps']}")
    else:
        lineas.append("Última ubicación GPS: no disponible")
    if filas:
        lineas.append("Recorrido reciente (hora de Colombia):")
        lineas += [f"  {fmt_hora(f.recorded_at)} — {f.lat:.6f}, {f.lon:.6f}" for f in filas[:15]]
    return {
        "equipo": {"nombre": d.name, "modelo": d.model, "plataforma": d.platform, "estado": d.status},
        "identificacion": ident, "faltan": faltan, "ultima_ubicacion": ultima,
        "recorrido": [{"lat": f.lat, "lon": f.lon, "precision_m": f.accuracy_m, "hora": f.recorded_at} for f in filas],
        "texto": "\n".join(lineas),
        "pasos": [
            {"titulo": "Denuncie ante la Policía",
             "detalle": "En línea en adenunciar.policia.gov.co, o llamando al 123. Pegue el resumen de abajo: "
                        "la ubicación y el IMEI son lo que más ayuda.", "url": "https://adenunciar.policia.gov.co"},
            {"titulo": f"Bloquee el IMEI con {ident.get('operador') or 'su operador'}",
             "detalle": "Llame a la línea de atención de su operador desde otro teléfono y pida el bloqueo por hurto "
                        "o pérdida con el IMEI. Así el equipo queda inservible en todas las redes de Colombia.",
             "url": None},
            {"titulo": "Cambie sus contraseñas",
             "detalle": "Correo, banco y redes sociales, desde otro dispositivo.", "url": None},
            {"titulo": "No intente recuperarlo por su cuenta",
             "detalle": "Entregue la ubicación a la Policía; ir al lugar puede ponerlo en peligro.", "url": None},
        ],
        "generado": ahora,
    }


@router.get("/devices/{device_id}/analisis")
def device_analysis(device_id: str, p: CurrentUser, db: DB):
    """Análisis automático con los datos reales del equipo (ver app/ai/device_insights.py)."""
    d = _own_device(db, p.user.id, device_id)
    ahora = utcnow()
    filas = db.execute(select(DeviceLocation).where(
        DeviceLocation.device_id == d.id, DeviceLocation.recorded_at >= ahora - timedelta(days=30))
        .order_by(DeviceLocation.recorded_at)).scalars().all()
    puntos = [device_insights.Punto(lat=f.lat, lon=f.lon, t=f.recorded_at, precision_m=f.accuracy_m,
                                    bateria=f.battery, velocidad_ms=f.speed_ms) for f in filas]
    hace_24h = ahora - timedelta(hours=24)
    ult_24h = [pt for pt in puntos if (pt.t if pt.t.tzinfo else pt.t.replace(tzinfo=UTC)) >= hace_24h]
    return device_insights.analizar(
        estado=d.status, en_linea=d.en_linea, visto=d.last_seen_at, bateria=d.battery, cargando=d.charging,
        lat=d.last_lat, lon=d.last_lon, precision_m=d.last_accuracy_m, gps_status=d.gps_status,
        seguimiento=d.tracking_enabled, puntos_24h=ult_24h, historial_30d=puntos, ahora=ahora)


def _queue(db, d: Device, requested_by: str, kind: str, payload: dict) -> DeviceCommand:
    # Un solo comando pendiente por tipo: repetir «sonar» cinco veces no encola cinco alarmas.
    existing = db.execute(select(DeviceCommand).where(
        DeviceCommand.device_id == d.id, DeviceCommand.kind == kind,
        DeviceCommand.status.in_(("pending", "delivered")), DeviceCommand.expires_at > utcnow())).scalar()
    if existing:
        return existing
    expires = utcnow() + timedelta(minutes=COMMAND_TTL[kind])
    cmd = DeviceCommand(device_id=d.id, kind=kind, payload=payload, requested_by=requested_by,
                        expires_at=expires, signature="")
    db.add(cmd)
    db.flush()
    cmd.signature = _sign(cmd.id, d.id, kind, payload, expires.isoformat())
    return cmd


@router.post("/devices/{device_id}/commands", response_model=DeviceCommandOut, status_code=201)
def send_command(device_id: str, body: DeviceCommandIn, request: Request, p: CurrentUser, db: DB):
    d = _own_device(db, p.user.id, device_id)
    if d.status == "wiped":
        raise conflict("device_wiped", "El dispositivo ya fue borrado")
    limiter.hit(f"device-cmd:{p.user.id}", 30, 600)
    payload: dict = {}
    if body.kind == "message":
        if not body.message:
            raise ApiError(422, "message_required", "Escriba el mensaje que se mostrará en pantalla")
        payload["mensaje"] = body.message
    if body.kind == "photo" and d.status not in ("lost", "stolen"):
        # Fotografiar a quien tiene el teléfono solo se justifica si el dueño lo reportó: con el equipo
        # en su poder, sería vigilar a su familia. Misma regla que las apps antirrobo comerciales.
        raise conflict("photo_requires_report", "Primero marque el dispositivo como perdido o robado")
    if body.kind == "wipe":
        # Acción irreversible: confirmación explícita, solo con el equipo reportado y máximo una por día.
        if not body.confirm_wipe:
            raise ApiError(422, "wipe_not_confirmed", "Confirme que entiende que el borrado es irreversible")
        if d.status not in ("lost", "stolen"):
            raise conflict("wipe_requires_report", "Primero marque el dispositivo como perdido o robado")
        limiter.hit(f"device-wipe:{p.user.id}", 1, 86400)
    if body.kind == "sos":
        # El teléfono mandará SMS reales a los contactos de emergencia con su SIM: se confirma siempre,
        # se limita (3 cada 10 min) y queda en la auditoría con la IP de quien lo pidió.
        if not body.confirm_sos:
            raise ApiError(422, "sos_not_confirmed", "Confirme que quiere enviar el SOS desde el teléfono")
        limiter.hit(f"device-sos:{p.user.id}", 3, 600)
        payload["origen"] = "pc"
    cmd = _queue(db, d, p.user.id, body.kind, payload)
    audit.record(db, f"device.command.{body.kind}", actor_id=p.user.id, target_type="device", target_id=d.id,
                 ip=client_ip(request), level="security" if body.kind in ("wipe", "sos") else "info", commit=False)
    if body.kind == "sos":
        notify(db, p.user.id, "SOS remoto enviado",
               f"Se ordenó a «{d.name}» avisar por SMS a sus contactos de emergencia. Si no fue usted, "
               "cambie su contraseña ahora.", kind="device.sos", severity="high", data={"device_id": d.id})
    if body.kind == "wipe":
        notify(db, p.user.id, "Borrado remoto solicitado",
               f"Se ordenó borrar «{d.name}». Si no fue usted, cambie su contraseña ahora.",
               kind="device.wipe", severity="high", data={"device_id": d.id})
    db.commit()
    _publicar_comando(d, cmd)
    _avisar_equipo(d, comandos=True)
    return cmd


@router.post("/devices/{device_id}/conectar")
def reconnect(device_id: str, p: CurrentUser, db: DB):
    """Botón «Conectar» del PC: pide al teléfono que reporte ya y reabra su canal en vivo.

    Si el canal está abierto, la orden llega al instante. Si no, queda un «Localizar» en cola que el
    teléfono recoge en su próximo reporte; al hacerlo reabre el canal. Un teléfono apagado o sin red no
    puede despertarse desde aquí: se dice claramente.
    """
    d = _own_device(db, p.user.id, device_id)
    if d.status == "wiped":
        raise conflict("device_wiped", "El equipo fue borrado")
    limiter.hit(f"conectar:{d.id}", 12, 60)
    cmd = _queue(db, d, p.user.id, "locate", {"motivo": "conectar"})
    db.commit()
    _avisar_equipo(d, comandos=True, reconectar=True)
    _publicar_comando(d, cmd)
    en_vivo = d.canal_en_vivo
    return {"en_vivo": en_vivo, "comando_id": cmd.id,
            "mensaje": "Conectado: el teléfono responde al instante." if en_vivo else
            (f"Pedido enviado. El teléfono se reconecta en su próximo reporte (≤ {d.report_interval_s or 30} s). "
             "Si no vuelve, puede estar apagado, sin señal o con la batería restringida.")}


@router.get("/devices/{device_id}/commands", response_model=list[DeviceCommandOut])
def command_history(device_id: str, p: CurrentUser, db: DB, limit: int = Query(20, le=100)):
    d = _own_device(db, p.user.id, device_id)
    return db.execute(select(DeviceCommand).where(DeviceCommand.device_id == d.id)
                      .order_by(DeviceCommand.created_at.desc()).limit(limit)).scalars().all()


@router.get("/devices/{device_id}/locations")
def location_history(device_id: str, p: CurrentUser, db: DB,
                     hours: int = Query(24, ge=1, le=24 * DEVICE_HISTORY_RETENTION_DAYS)):
    d = _own_device(db, p.user.id, device_id)
    since = utcnow() - timedelta(hours=hours)
    rows = db.execute(select(DeviceLocation).where(DeviceLocation.device_id == d.id,
                                                   DeviceLocation.recorded_at >= since)
                      .order_by(DeviceLocation.recorded_at)).scalars().all()
    return {"dispositivo": d.id, "retencion_dias": LOCATION_RETENTION_DAYS,
            "puntos": [{"lat": r.lat, "lon": r.lon, "precision_m": r.accuracy_m, "t": r.recorded_at} for r in rows]}


def _ip_lan() -> str | None:
    """La IP de este PC que el celular puede alcanzar, evitando la de la VPN.

    Reto real: si la VPN WARP está activa, el truco del socket «sale» por el túnel y devuelve la IP
    del túnel (172.16.0.x), que el celular no puede alcanzar. Por eso aquí se listan TODAS las
    interfaces y se prefiere una IP de red local de verdad (WiFi de casa 192.168.x, anclaje USB, o
    una privada 10.x que no sea la del túnel de GuardianIA). Se descartan loopback, enlace-local y
    la interfaz «guardiania» de WARP.
    """
    import socket
    candidatas: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                candidatas.append(ip)
    except OSError:
        pass
    # Respaldo: el truco del socket (por si getaddrinfo no lista todo).
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if not ip.startswith("127.") and ip not in candidatas:
            candidatas.append(ip)
    except OSError:
        pass

    def rango(ip: str) -> int:
        # Preferencia: WiFi de casa (192.168) > anclaje USB (192.168.42 ya cae aquí) > otras privadas.
        if ip.startswith("192.168."):
            return 0
        if ip.startswith("10.") and not ip.startswith("10.0.0."):
            return 1
        if ip.startswith("172.") and not ip.startswith("172.16.0."):   # 172.16.0.x suele ser el túnel WARP
            return 2
        return 3

    candidatas = [ip for ip in dict.fromkeys(candidatas)]
    if not candidatas:
        return None
    candidatas.sort(key=rango)
    return candidatas[0]


def _base_lan(request: Request) -> str:
    """La URL con la que el celular puede llegar a este servidor: prioriza la IP de la red local."""
    puerto = request.url.port or 8000
    # Se respeta el esquema: el GPS del navegador SOLO funciona en https (o en localhost).
    esquema = request.url.scheme or "http"
    ip = _ip_lan()
    if ip:
        return f"{esquema}://{ip}:{puerto}"
    return str(request.base_url).rstrip("/")


# ───────────────────────────────── vinculación por código o QR
# Copiar un token de 43 caracteres entre el navegador y una terminal es la parte donde la mayoría de
# la gente abandona. El código corto hace lo mismo sin pedirle nada difícil, y se protege con:
# vencimiento de 10 minutos, un solo uso, máximo 5 intentos y límite por IP.
VIGENCIA_CODIGO_MINUTOS = 10
MAX_INTENTOS = 5


class CodigoIn(BaseModel):
    nombre_sugerido: str | None = Field(None, max_length=80)


def _huella_ca_hex() -> str | None:
    try:
        from app import tls
        return tls.huella_ca().replace(":", "").lower()
    except Exception:  # noqa: BLE001 - sin CA local (dominio público con Let's Encrypt): no hace falta
        return None


@router.post("/devices/vinculacion", status_code=201)
def crear_codigo(body: CodigoIn, request: Request, p: CurrentUser, db: DB):
    """Genera un código de 6 dígitos (y su QR) para vincular un equipo nuevo."""
    limiter.hit(f"vinculacion:{p.user.id}", 10, 600)
    codigo = f"{secrets.randbelow(1000000):06d}"
    expira = utcnow() + timedelta(minutes=VIGENCIA_CODIGO_MINUTOS)
    # Se guarda el hash, no el código: si alguien lee la base, no puede vincular equipos.
    db.add(PairingCode(user_id=p.user.id, code_hash=token_hash(codigo),
                       nombre_sugerido=body.nombre_sugerido, expires_at=expira))
    audit.record(db, "device.codigo_vinculacion", actor_id=p.user.id, ip=client_ip(request), commit=False)
    db.commit()
    base_local = str(request.base_url).rstrip("/")
    base_lan = _base_lan(request)
    # El QR lleva a una PÁGINA WEB que el celular abre en su navegador (sin instalar ninguna app).
    url_movil = f"{base_lan}/vincular?codigo={codigo}"
    # QR para la APP NATIVA: esquema propio con servidor + código, para vincular escaneando en vez de
    # teclear. La app lo reconoce; un navegador lo ignora. Se ofrecen ambos QR y el cliente elige.
    url_app = f"guardiania://vincular?servidor={quote(base_lan, safe='')}&codigo={codigo}"
    # Huella de la CA dentro del QR: la app descarga ca.crt por http (aún no confía en nada) y la
    # compara con esta huella antes de fijarla. Así un atacante en el mismo WiFi no puede colarle
    # su propia CA durante la vinculación (el QR se lee de la pantalla del PC, fuera de su alcance).
    huella = _huella_ca_hex()
    if huella:
        url_app += f"&ca={huella}"
    return {"codigo": codigo, "expira": expira, "vigencia_minutos": VIGENCIA_CODIGO_MINUTOS,
            "servidor": base_local, "servidor_movil": base_lan, "url_movil": url_movil,
            "url_app": url_app, "qr": _qr(url_movil), "qr_app": _qr(url_app),
            "misma_red": base_lan != base_local,
            "instrucciones": "Escanee el QR con la cámara (abre la página web) o desde la app GuardianIA "
                             "(la vincula al instante). El celular y este PC deben estar en el mismo WiFi. "
                             "Vence en 10 minutos."}


def _qr(texto: str) -> str | None:
    """QR como data URI. Si falta la librería, la interfaz muestra solo el código."""
    try:
        import base64
        import io

        import qrcode
        img = qrcode.make(texto)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:  # noqa: BLE001
        return None


class CanjearIn(BaseModel):
    codigo: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")
    nombre: str = Field(max_length=80)
    platform: str = Field("windows", pattern="^(android|ios|windows|macos|linux|other)$")
    model: str | None = Field(None, max_length=80)
    os_version: str | None = Field(None, max_length=40)


@router.post("/devices/vinculacion/canjear", status_code=201)
def canjear_codigo(body: CanjearIn, request: Request, db: DB):
    """El equipo nuevo entrega el código y recibe su token. No requiere sesión: el código es el secreto."""
    limiter.hit(f"canjear:{client_ip(request)}", 10, 600)   # frena la fuerza bruta desde una IP
    fila = db.execute(select(PairingCode).where(PairingCode.code_hash == token_hash(body.codigo))).scalar()
    if fila is None or fila.usado_por or fila.intentos >= MAX_INTENTOS or _vencido(fila):
        # Mismo error para código inválido, usado o vencido: no se confirma cuáles existen.
        for otra in db.execute(select(PairingCode).where(PairingCode.usado_por.is_(None))).scalars():
            otra.intentos += 1        # todo intento fallido cuenta contra los códigos vivos
        db.commit()
        raise ApiError(400, "codigo_invalido", "El código no es válido, ya se usó o venció. Genere uno nuevo.")

    usuario = db.get(User, fila.user_id)
    if usuario is None or usuario.status != "active":
        raise ApiError(403, "cuenta_inactiva", "La cuenta no está activa")
    count = db.execute(select(func.count()).select_from(Device).where(Device.user_id == usuario.id)).scalar_one()
    if count >= MAX_DEVICES:
        raise conflict("too_many_devices", f"Máximo {MAX_DEVICES} dispositivos por cuenta")

    raw = new_opaque_token()
    dispositivo = Device(user_id=usuario.id, name=body.nombre or fila.nombre_sugerido or "Equipo",
                         platform=body.platform, model=body.model, os_version=body.os_version,
                         device_token_hash=token_hash(raw))
    db.add(dispositivo)
    db.flush()
    fila.usado_por = dispositivo.id
    audit.record(db, "device.vinculado", actor_id=usuario.id, target_type="device", target_id=dispositivo.id,
                 ip=client_ip(request), level="security",
                 detail={"nombre": dispositivo.name, "plataforma": body.platform}, commit=False)
    notify(db, usuario.id, "Equipo vinculado",
           f"«{dispositivo.name}» quedó vinculado a su cuenta. Si no fue usted, elimínelo en Dispositivos.",
           kind="device.vinculado", severity="medium", data={"device_id": dispositivo.id})
    db.commit()
    _publicar(dispositivo, "vinculado")
    return {"device_id": dispositivo.id, "device_token": raw, "nombre": dispositivo.name,
            "usuario": usuario.email}


def _vencido(fila: PairingCode) -> bool:
    expira = fila.expires_at if fila.expires_at.tzinfo else fila.expires_at.replace(tzinfo=UTC)
    return expira < utcnow()


# ------------------------------------------------ lado del agente en el equipo
class DeviceAuthIn(BaseModel):
    device_token: str = Field(min_length=20)


class CommandAckIn(DeviceAuthIn):
    signature: str = Field(min_length=64, max_length=64)
    status: str = Field(pattern="^(completed|failed)$")
    result: dict = Field(default_factory=dict)


# Guardar TODAS las lecturas del GPS (una cada pocos segundos) llenaría la base de ruido sin aportar:
# se guarda un punto si el equipo se movió más que el error del GPS, o si pasó un rato sin guardar.
GUARDAR_CADA_S = {"ok": 300, "lost": 20, "stolen": 20}
INTERVALO_REPORTE_S = {"ok": 30, "lost": 15, "stolen": 15}
INTERVALO_PAUSADO_S = 60


def _debe_guardar(ultimo: DeviceLocation | None, estado: str, lat: float, lon: float,
                  precision: float | None, ahora) -> bool:
    if ultimo is None:
        return True
    t = ultimo.recorded_at if ultimo.recorded_at.tzinfo else ultimo.recorded_at.replace(tzinfo=UTC)
    if (ahora - t).total_seconds() >= GUARDAR_CADA_S.get(estado, 300):
        return True
    umbral_m = max(15.0, (precision or 0) / 2, (ultimo.accuracy_m or 0) / 2)
    return _haversine_km(ultimo.lat, ultimo.lon, lat, lon) * 1000 >= umbral_m


@router.post("/devices/telemetry")
def telemetry(body: TelemetryIn, db: DB):
    """Latido del equipo: batería, red, estado del GPS y (si hay) ubicación. Autenticado por su token.

    Cada latido se empuja por WebSocket a la cuenta del dueño: la pantalla Dispositivos se actualiza
    sola, sin recargar.
    """
    d = _device_by_token(db, body.device_token)
    limiter.hit(f"telemetry:{d.id}", 12)  # 1 cada 5 s como máximo
    now = utcnow()
    bateria_antes = d.battery
    if body.battery is not None:
        d.battery = body.battery
    if body.charging is not None:
        d.charging = body.charging
    if body.info is not None:
        info = body.info.model_dump(exclude_none=True)
        d.device_info = {**(d.device_info or {}), **info}
        if info.get("modelo") and not d.model:
            d.model = info["modelo"][:80]
        if info.get("version_sistema"):
            d.os_version = info["version_sistema"][:20]
    # Pausado desde el PC: se respeta aunque el equipo mande coordenadas (privacidad del dueño).
    d.gps_status = "paused" if not d.tracking_enabled else (body.gps or d.gps_status)
    if d.tracking_enabled and body.lat is not None and body.lon is not None:
        ultimo = db.execute(select(DeviceLocation).where(DeviceLocation.device_id == d.id)
                            .order_by(DeviceLocation.recorded_at.desc()).limit(1)).scalar()
        if ultimo is not None:
            t = ultimo.recorded_at if ultimo.recorded_at.tzinfo else ultimo.recorded_at.replace(tzinfo=UTC)
            hours = max((now - t).total_seconds() / 3600, 1 / 3600)
            speed = _haversine_km(ultimo.lat, ultimo.lon, body.lat, body.lon) / hours
            if speed > MAX_PLAUSIBLE_KMH:
                raise_alert(db, user_id=d.user_id, category="device", severity="low",
                            title="Ubicación inconsistente",
                            description=f"«{d.name}» reportó un salto imposible (~{speed:.0f} km/h). "
                                        "Posible GPS falso o error del sensor.",
                            data={"device_id": d.id}, engine="geo-plausibility", notify=False)
        d.last_lat, d.last_lon, d.last_accuracy_m, d.last_fix_at = body.lat, body.lon, body.accuracy_m, now
        d.gps_status = "ok"
        if _debe_guardar(ultimo, d.status, body.lat, body.lon, body.accuracy_m, now):
            db.add(DeviceLocation(device_id=d.id, lat=body.lat, lon=body.lon, accuracy_m=body.accuracy_m,
                                  battery=body.battery, speed_ms=body.speed_ms, recorded_at=now))
            if d.status in ("lost", "stolen"):
                notify(db, d.user_id, f"Nueva ubicación de {d.name}",
                       emergency_svc.map_link(body.lat, body.lon), kind="device.location", severity="medium",
                       data={"device_id": d.id, "lat": body.lat, "lon": body.lon})
            # Mantener la limpieza por equipo evita que un dispositivo muy activo acumule datos viejos.
            db.execute(delete(DeviceLocation).where(
                DeviceLocation.device_id == d.id,
                DeviceLocation.recorded_at < now - timedelta(days=DEVICE_HISTORY_RETENTION_DAYS)))
    # Un solo aviso al cruzar el 10 %, no uno por cada latido.
    if d.status in ("lost", "stolen") and body.battery is not None and body.battery <= 10 \
            and (bateria_antes is None or bateria_antes > 10):
        notify(db, d.user_id, f"{d.name} se está quedando sin batería",
               "Es probable que deje de reportar pronto. Revise la última ubicación.",
               kind="device.battery", severity="high", data={"device_id": d.id})
    d.last_seen_at = now
    d.report_interval_s = (INTERVALO_REPORTE_S.get(d.status, 30) if d.tracking_enabled
                           else INTERVALO_PAUSADO_S)
    pending = db.execute(select(func.count()).select_from(DeviceCommand).where(
        DeviceCommand.device_id == d.id, DeviceCommand.status == "pending",
        DeviceCommand.expires_at > now)).scalar_one()
    db.commit()
    _publicar(d)
    # El equipo solo consulta comandos si hay alguno: ahorra batería y peticiones.
    # «canal_vivo»: si el servidor NO tiene abierto el canal en vivo del teléfono, la app lo reabre
    # al instante (antes esperaba su propio reintento, hasta 60 s, y las órdenes llegaban tarde).
    return {"estado": d.status, "seguimiento": d.tracking_enabled, "comandos_pendientes": pending,
            "siguiente_reporte_s": d.report_interval_s, "canal_vivo": d.canal_en_vivo}


class SelfTrackingIn(DeviceAuthIn):
    activo: bool


@router.post("/devices/self/seguimiento")
def self_tracking(body: SelfTrackingIn, db: DB):
    """El propio teléfono pausa o reanuda su envío de ubicación (botón conectar/desconectar en la app).

    Va por el token del dispositivo, no por sesión del dueño. Un equipo reportado como perdido o
    robado NO puede desconectarse desde aquí: así el ladrón tampoco podría, aunque abriera la app.
    """
    d = _device_by_token(db, body.device_token)
    if d.status in ("lost", "stolen") and not body.activo:
        raise conflict("device_reported", "Un equipo reportado no se puede desconectar")
    if d.tracking_enabled != body.activo:
        d.tracking_enabled = body.activo
        d.gps_status = None if body.activo else "paused"
        db.commit()
        _publicar(d)
        _avisar_equipo(d)
    return {"seguimiento": d.tracking_enabled, "estado": d.status}


@router.post("/devices/commands/pending", response_model=list[PendingCommandOut])
def pending_commands(body: DeviceAuthIn, db: DB):
    d = _device_by_token(db, body.device_token)
    limiter.hit(f"cmd-poll:{d.id}", 20)
    now = utcnow()
    rows = db.execute(select(DeviceCommand).where(DeviceCommand.device_id == d.id,
                                                  DeviceCommand.status.in_(("pending", "delivered")))
                      .order_by(DeviceCommand.created_at)).scalars().all()
    out = []
    for c in rows:
        if c.expires_at <= now:
            c.status = "expired"
            continue
        if c.status == "pending":
            c.status, c.delivered_at = "delivered", now
        out.append(PendingCommandOut(id=c.id, kind=c.kind, payload={**c.payload, "expira": c.expires_at.isoformat()},
                                     signature=c.signature))
    db.commit()
    for c in rows:
        _publicar_comando(d, c)
    return out


@router.post("/devices/commands/{command_id}/ack", response_model=Msg)
def ack_command(command_id: str, body: CommandAckIn, db: DB):
    d = _device_by_token(db, body.device_token)
    c = db.get(DeviceCommand, command_id)
    if c is None or c.device_id != d.id:
        raise not_found("comando")
    if c.status not in ("pending", "delivered"):
        raise conflict("command_closed", "El comando ya fue cerrado")
    if not hmac.compare_digest(c.signature, body.signature):
        audit.record(db, "device.command.bad_signature", target_type="device", target_id=d.id, level="security",
                     detail={"comando": c.id}, commit=False)
        db.commit()
        raise ApiError(409, "signature_mismatch", "La firma del comando no coincide")
    c.status, c.completed_at, c.result = body.status, utcnow(), body.result
    if c.kind == "wipe" and body.status == "completed":
        d.status = "wiped"
        d.device_token_hash = token_hash(new_opaque_token())  # el token viejo queda inservible
        notify(db, d.user_id, "Borrado completado", f"«{d.name}» fue borrado de forma remota.",
               kind="device.wipe", severity="high", data={"device_id": d.id})
    db.commit()
    _publicar_comando(d, c)
    _publicar(d)
    return Msg(mensaje="Acuse registrado")


# ------------------------------------------------------- foto del intruso (app Android)
class SelfPhotoIn(DeviceAuthIn):
    imagen_b64: str = Field(min_length=100, max_length=MAX_FOTO_BYTES * 4 // 3 + 8)
    motivo: str = Field("comando", max_length=40)
    lat: float | None = Field(None, ge=-90, le=90)
    lon: float | None = Field(None, ge=-180, le=180)


def _ctx_foto(foto_id: str, device_id: str) -> str:
    return f"device-photo:{device_id}:{foto_id}"


@router.post("/devices/self/foto", status_code=201)
def self_photo(body: SelfPhotoIn, db: DB):
    """La app sube la foto de la cámara frontal tomada al ejecutar el comando «photo».

    Solo se acepta con el equipo reportado (perdido o robado): una foto no pedida por el dueño se
    rechaza aunque venga con el token correcto. La imagen se guarda CIFRADA (AES-256-GCM con la
    clave del servidor), se valida que sea un JPEG real y se conserva durante 365 días.
    """
    import base64
    import binascii
    d = _device_by_token(db, body.device_token)
    limiter.hit(f"device-photo:{d.id}", 12, 3600)
    if d.status not in ("lost", "stolen"):
        raise conflict("photo_requires_report", "El equipo no está reportado como perdido o robado")
    try:
        datos = base64.b64decode(body.imagen_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ApiError(422, "invalid_image", "La imagen no es base64 válido") from e
    if len(datos) > MAX_FOTO_BYTES:
        raise ApiError(413, "image_too_large", "La foto supera 1,5 MB")
    if not datos.startswith(b"\xff\xd8\xff"):
        raise ApiError(422, "invalid_image", "Solo se aceptan fotos JPEG")
    foto = DevicePhoto(device_id=d.id, user_id=d.user_id, motivo=body.motivo[:40], lat=body.lat, lon=body.lon,
                       size_bytes=len(datos), key_version="", wrapped_dek="", blob=b"")
    db.add(foto)
    db.flush()
    sellado = crypto.seal(datos, _ctx_foto(foto.id, d.id))
    foto.key_version, foto.wrapped_dek, foto.blob = sellado.key_version, sellado.wrapped_dek, sellado.ciphertext
    db.execute(delete(DevicePhoto).where(
        DevicePhoto.device_id == d.id,
        DevicePhoto.created_at < utcnow() - timedelta(days=DEVICE_HISTORY_RETENTION_DAYS)))
    notify(db, d.user_id, "Foto del teléfono reportado",
           f"«{d.name}» envió una foto de la cámara frontal. Entréguela a la Policía; no confronte a nadie.",
           kind="device.photo", severity="high", data={"device_id": d.id, "foto_id": foto.id})
    audit.record(db, "device.photo", target_type="device", target_id=d.id, level="security",
                 detail={"bytes": len(datos)}, commit=False)
    db.commit()
    _publicar(d, "foto", foto_id=foto.id)
    return {"id": foto.id, "bytes": len(datos)}


@router.get("/devices/{device_id}/fotos")
def list_photos(device_id: str, p: CurrentUser, db: DB):
    d = _own_device(db, p.user.id, device_id)
    filas = db.execute(select(DevicePhoto).where(DevicePhoto.device_id == d.id)
                       .order_by(DevicePhoto.created_at.desc())).scalars().all()
    return [{"id": f.id, "creada": f.created_at, "motivo": f.motivo, "lat": f.lat, "lon": f.lon,
             "bytes": f.size_bytes, "url": f"/v1/devices/{d.id}/fotos/{f.id}"} for f in filas]


@router.get("/devices/{device_id}/fotos/{foto_id}")
def get_photo(device_id: str, foto_id: str, p: CurrentUser, db: DB):
    d = _own_device(db, p.user.id, device_id)
    f = db.get(DevicePhoto, foto_id)
    if f is None or f.device_id != d.id:
        raise not_found("foto")
    datos = crypto.open_sealed(f.key_version, f.wrapped_dek, f.blob, _ctx_foto(f.id, d.id))
    return Response(datos, media_type="image/jpeg", headers={"Cache-Control": "no-store",
                                                             "Content-Disposition": f'inline; filename="intruso-{f.id[:8]}.jpg"'})


@router.delete("/devices/{device_id}/fotos/{foto_id}", response_model=Msg)
def delete_photo(device_id: str, foto_id: str, p: CurrentUser, db: DB):
    d = _own_device(db, p.user.id, device_id)
    f = db.get(DevicePhoto, foto_id)
    if f is None or f.device_id != d.id:
        raise not_found("foto")
    db.delete(f)
    db.commit()
    return Msg(mensaje="Foto eliminada")
