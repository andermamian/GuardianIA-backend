"""Contactos de emergencia y SOS — interfaz activity_main.xml.

Gratis en todos los planes: la seguridad personal no se cobra.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.api.deps import DB, CurrentUser
from app.core import audit
from app.core.errors import ApiError, conflict, not_found
from app.core.ratelimit import limiter
from app.core.security import utcnow
from app.db.models import EmergencyContact, Incident
from app.schemas.common import Msg
from app.schemas.emergency import (ContactIn, ContactOut, ContactPatch, ContactsSummary, EmergencySettingsIO,
                                   ImportIn, ImportOut, IncidentOut, LocationPing, SosIn)
from app.services import emergency as svc

router = APIRouter(tags=["Emergencias"])


def _own_contact(db, user_id: str, contact_id: str) -> EmergencyContact:
    c = db.get(EmergencyContact, contact_id)
    if c is None or c.user_id != user_id:
        raise not_found("contacto")
    return c


@router.get("/emergency/contacts", response_model=ContactsSummary)
def list_contacts(p: CurrentUser, db: DB, relation: Literal["family", "friends", "work", "other"] | None = None,
                  q: str | None = Query(None, max_length=60),
                  sort: Literal["priority", "name", "last_test"] = "priority"):
    """Lista con chips (Todos/Familia/Amigos/Trabajo), búsqueda y orden (btn_sort)."""
    stmt = select(EmergencyContact).where(EmergencyContact.user_id == p.user.id)
    all_rows = db.execute(stmt).scalars().all()
    if relation:
        stmt = stmt.where(EmergencyContact.relation == relation)
    if q:
        stmt = stmt.where(EmergencyContact.name.ilike(f"%{q}%"))
    order = {"priority": EmergencyContact.priority, "name": EmergencyContact.name,
             "last_test": EmergencyContact.last_test_at.desc()}[sort]
    rows = db.execute(stmt.order_by(order)).scalars().all()
    s = svc.settings_for(db, p.user.id)
    counts: dict[str, int] = {}
    for c in all_rows:
        counts[c.relation] = counts.get(c.relation, 0) + 1
    tests = [c.last_test_at for c in all_rows if c.last_test_at]
    db.commit()
    return ContactsSummary(total=len(all_rows), por_relacion=counts,
                           tiempo_total_escalamiento_min=len(all_rows) * s.wait_minutes,
                           ultima_prueba=max(tests) if tests else None, contactos=rows)


@router.post("/emergency/contacts", response_model=ContactOut, status_code=201)
def add_contact(body: ContactIn, p: CurrentUser, db: DB):
    count = db.execute(select(func.count()).select_from(EmergencyContact)
                       .where(EmergencyContact.user_id == p.user.id)).scalar_one()
    if count >= 20:
        raise conflict("too_many_contacts", "Máximo 20 contactos de emergencia")
    c = EmergencyContact(user_id=p.user.id, name=body.name, phone_e164=body.phone, relation=body.relation,
                         priority=body.priority, notify_sms=body.notify_sms, notify_call=body.notify_call)
    db.add(c)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise conflict("duplicate_contact", "Ese número ya está en sus contactos")
    return c


@router.patch("/emergency/contacts/{contact_id}", response_model=ContactOut)
def update_contact(contact_id: str, body: ContactPatch, p: CurrentUser, db: DB):
    c = _own_contact(db, p.user.id, contact_id)
    data = body.model_dump(exclude_unset=True)
    if "phone" in data:
        data["phone_e164"] = data.pop("phone")
    for k, v in data.items():
        setattr(c, k, v)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise conflict("duplicate_contact", "Ese número ya está en sus contactos")
    return c


@router.delete("/emergency/contacts/{contact_id}", response_model=Msg)
def delete_contact(contact_id: str, p: CurrentUser, db: DB):
    db.delete(_own_contact(db, p.user.id, contact_id))
    db.commit()
    return Msg(mensaje="Contacto eliminado")


@router.post("/emergency/contacts/import", response_model=ImportOut)
def import_contacts(body: ImportIn, p: CurrentUser, db: DB):
    existing = set(db.execute(select(EmergencyContact.phone_e164)
                              .where(EmergencyContact.user_id == p.user.id)).scalars())
    created = skipped = 0
    for item in body.contacts:
        if item.phone in existing or len(existing) >= 20:
            skipped += 1
            continue
        db.add(EmergencyContact(user_id=p.user.id, name=item.name, phone_e164=item.phone, relation=item.relation,
                                priority=item.priority, notify_sms=item.notify_sms, notify_call=item.notify_call))
        existing.add(item.phone)
        created += 1
    db.commit()
    return ImportOut(creados=created, omitidos_duplicados=skipped)


@router.post("/emergency/contacts/test", response_model=Msg)
def test_contacts(p: CurrentUser, db: DB):
    """btn_test_all_contacts: envía un SMS de prueba claramente marcado como PRUEBA."""
    limiter.hit(f"contact-test:{p.user.id}", 3, 3600)
    rows = db.execute(select(EmergencyContact).where(EmergencyContact.user_id == p.user.id)).scalars().all()
    if not rows:
        raise ApiError(400, "no_contacts", "Agregue al menos un contacto")
    for c in rows:
        svc.messenger.send_sms(c.phone_e164, f"[PRUEBA GuardianIA] {p.user.full_name} lo tiene como contacto de "
                                             "emergencia. No requiere acción.")
        c.last_test_at, c.last_test_status = utcnow(), "enviado"
    db.commit()
    return Msg(mensaje=f"Mensaje de prueba enviado a {len(rows)} contactos")


@router.get("/emergency/settings", response_model=EmergencySettingsIO)
def get_settings_(p: CurrentUser, db: DB):
    s = svc.settings_for(db, p.user.id)
    db.commit()
    return EmergencySettingsIO.model_validate(s, from_attributes=True)


@router.put("/emergency/settings", response_model=EmergencySettingsIO)
def put_settings(body: EmergencySettingsIO, p: CurrentUser, db: DB):
    s = svc.settings_for(db, p.user.id)
    for k, v in body.model_dump().items():
        setattr(s, k, v)
    db.commit()
    return body


@router.post("/emergency/sos", response_model=IncidentOut, status_code=201)
def sos(body: SosIn, p: CurrentUser, db: DB):
    """Botón de pánico / fab_emergency_mode. El SOS manual escala de inmediato (sin ventana)."""
    limiter.hit(f"sos:{p.user.id}", 10, 600)
    inc = svc.open_incident(db, p.user, kind=body.kind, severity="critical",
                            summary=body.note or {"sos": "Botón de pánico activado", "fall": "Caída reportada",
                                                  "theft": "Reporte de robo"}[body.kind],
                            lat=body.lat, lon=body.lon, immediate=body.kind == "sos",
                            sms_desde_telefono=body.sms_desde_telefono)
    audit.record(db, "emergency.sos", actor_id=p.user.id, target_type="incident", target_id=inc.id,
                 level="warning", commit=False)
    db.commit()
    return inc


@router.get("/emergency/incidents", response_model=list[IncidentOut])
def my_incidents(p: CurrentUser, db: DB, limit: int = Query(20, le=100)):
    return db.execute(select(Incident).where(Incident.user_id == p.user.id)
                      .order_by(Incident.created_at.desc()).limit(limit)).scalars().all()


@router.post("/emergency/incidents/{incident_id}/cancel", response_model=IncidentOut)
def cancel_incident(incident_id: str, p: CurrentUser, db: DB):
    """«Estoy bien»: detiene el escalamiento y avisa a quien ya fue contactado."""
    inc = db.get(Incident, incident_id)
    if inc is None or inc.user_id != p.user.id:
        raise not_found("incidente")
    if inc.status not in ("pending_cancel", "escalating"):
        raise conflict("incident_closed", "El incidente ya está cerrado")
    was_escalating = inc.status == "escalating"
    inc.status, inc.resolved_at = "cancelled", utcnow()
    inc.timeline = [*inc.timeline, {"t": utcnow().isoformat(), "evento": "cancelado_por_usuario"}]
    if was_escalating:
        # A quien le escribió el teléfono por su SIM, el «estoy bien» también se lo manda el teléfono.
        contacted = {e.get("contacto") for e in inc.timeline
                     if e.get("evento") in ("sms", "llamada") and e.get("ref") != "sim_telefono"}
        for c in db.execute(select(EmergencyContact).where(EmergencyContact.user_id == p.user.id)).scalars():
            if c.name in contacted:
                svc.messenger.send_sms(c.phone_e164, f"GuardianIA: {p.user.full_name.split()[0]} confirmó que está bien.")
    db.commit()
    return inc


@router.post("/emergency/incidents/{incident_id}/location", response_model=Msg)
def incident_location(incident_id: str, body: LocationPing, p: CurrentUser, db: DB):
    """Ubicación en tiempo real cada 30 s mientras dura la emergencia (switch_live_location)."""
    inc = db.get(Incident, incident_id)
    if inc is None or inc.user_id != p.user.id or inc.status not in ("pending_cancel", "escalating"):
        raise not_found("incidente activo")
    inc.lat, inc.lon = body.lat, body.lon
    db.commit()
    return Msg(mensaje="Ubicación actualizada")
