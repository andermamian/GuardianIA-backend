"""Escalamiento de emergencias (pantalla Contactos de Emergencia + Centro de Comando).

Estados: pending_cancel ──(vence ventana)──► escalating ──► resolved
                │                                              ▲
                └──(persona cancela: «estoy bien»)──► cancelled │ (operador cierra)

El envío real de SMS/llamadas se hace a través de un proveedor (Twilio, Infobip) detrás de la
interfaz `Messenger`. El plan de escalamiento es determinista y auditable.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import utcnow
from app.db.models import EmergencyContact, EmergencySettings, Incident, User
from app.services.alerts import raise_alert


class Messenger(Protocol):
    def send_sms(self, to: str, body: str) -> str: ...
    def call(self, to: str) -> str: ...


class LogMessenger:
    """Proveedor de desarrollo: no envía nada, registra lo que enviaría."""
    sent: list[tuple[str, str, str]] = []

    def send_sms(self, to: str, body: str) -> str:
        self.sent.append(("sms", to, body))
        return "simulado"

    def call(self, to: str) -> str:
        self.sent.append(("call", to, ""))
        return "simulado"


messenger: Messenger = LogMessenger()


def settings_for(db: Session, user_id: str) -> EmergencySettings:
    s = db.get(EmergencySettings, user_id)
    if s is None:
        s = EmergencySettings(user_id=user_id)
        db.add(s)
        db.flush()
    return s


def build_plan(contacts: list[EmergencyContact], s: EmergencySettings) -> list[dict]:
    plan, t = [], 0
    for c in sorted(contacts, key=lambda c: c.priority):
        if c.notify_sms:
            plan.append({"min": t, "accion": "sms", "contacto_id": c.id, "nombre": c.name})
        if c.notify_call and s.auto_call:
            plan.append({"min": t, "accion": "llamada", "contacto_id": c.id, "nombre": c.name})
        t += s.wait_minutes
    if s.auto_police:
        plan.append({"min": t, "accion": "linea_123", "nota": "Solo si ningún contacto confirmó"})
    return plan


def map_link(lat: float | None, lon: float | None) -> str:
    # La coma va codificada (%2C): con la coma literal, las apps de mensajes cortaban el enlace en dos.
    return f"https://maps.google.com/?q={lat:.5f}%2C{lon:.5f}" if lat is not None and lon is not None else "no disponible"


def open_incident(db: Session, user: User, *, kind: str, severity: str, summary: str,
                  lat: float | None = None, lon: float | None = None, immediate: bool = False,
                  sms_desde_telefono: list[str] | None = None) -> Incident:
    s = settings_for(db, user.id)
    active = db.execute(select(Incident).where(Incident.user_id == user.id, Incident.kind == kind,
                                               Incident.status.in_(("pending_cancel", "escalating")))).scalar()
    if active:  # idempotencia: el reloj puede reenviar la misma caída varias veces
        active.timeline = [*active.timeline, {"t": utcnow().isoformat(), "evento": "senal_repetida"}]
        return active
    contacts = list(db.execute(select(EmergencyContact).where(EmergencyContact.user_id == user.id)).scalars())
    now = utcnow()
    inc = Incident(user_id=user.id, kind=kind, severity=severity, summary=summary, lat=lat, lon=lon,
                   plan=build_plan(contacts, s),
                   status="escalating" if immediate else "pending_cancel",
                   cancel_deadline=None if immediate else now + timedelta(seconds=s.cancel_window_seconds),
                   timeline=[{"t": now.isoformat(), "evento": "abierto", "origen": kind}])
    # SMS que el teléfono ya envió desde su SIM: quedan en la línea de tiempo y el plan no los repite.
    por_id = {c.id: c for c in contacts}
    for cid in dict.fromkeys(sms_desde_telefono or []):
        if cid in por_id:
            inc.timeline = [*inc.timeline, {"t": now.isoformat(), "evento": "sms", "contacto": por_id[cid].name,
                                            "contacto_id": cid, "ref": "sim_telefono"}]
    db.add(inc)
    db.flush()
    raise_alert(db, user_id=user.id, category="vitals" if kind in ("vitals", "fall") else "device",
                severity="critical", title=f"Emergencia: {summary}", description=summary,
                data={"incident_id": inc.id}, engine="emergency")
    if immediate:
        escalate(db, inc, user)
    return inc


def escalate(db: Session, inc: Incident, user: User) -> None:
    s = settings_for(db, user.id)
    body = s.message_template.format(nombre=user.full_name.split()[0], mapa=map_link(inc.lat, inc.lon))
    contacts = {c.id: c for c in db.execute(
        select(EmergencyContact).where(EmergencyContact.user_id == user.id)).scalars()}
    events = []
    ya_sms = {e.get("contacto_id") for e in inc.timeline if e.get("evento") == "sms"}
    for step in inc.plan:
        if step["min"] != 0 or "contacto_id" not in step:
            continue  # los pasos diferidos los ejecuta el planificador (ver docs/ARQUITECTURA.md)
        c = contacts.get(step["contacto_id"])
        if not c:
            continue
        if step["accion"] == "sms" and c.id in ya_sms:
            continue  # ya le llegó por la SIM del teléfono
        ref = messenger.send_sms(c.phone_e164, body) if step["accion"] == "sms" else messenger.call(c.phone_e164)
        events.append({"t": utcnow().isoformat(), "evento": step["accion"], "contacto": c.name,
                       "contacto_id": c.id, "ref": ref})
    inc.status = "escalating"
    inc.timeline = [*inc.timeline, *events]


def process_due(db: Session) -> int:
    """Tarea periódica: incidentes cuya ventana de cancelación venció pasan a escalar."""
    due = db.execute(select(Incident).where(Incident.status == "pending_cancel",
                                            Incident.cancel_deadline <= utcnow())).scalars().all()
    for inc in due:
        escalate(db, inc, db.get(User, inc.user_id))
    db.commit()
    return len(due)
