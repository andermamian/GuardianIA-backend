"""Centro de notificaciones del usuario (alertas, ubicaciones de equipos perdidos, avisos masivos)."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Query
from sqlalchemy import func, select, update

from app.api.deps import DB, CurrentUser
from app.core.errors import not_found
from app.core.security import utcnow
from app.db.models import Notification
from app.schemas.common import Msg, Out

router = APIRouter(tags=["Notificaciones"])


class NotificationOut(Out):
    id: str
    kind: str
    severity: str
    title: str
    body: str
    data: dict
    read_at: datetime | None
    created_at: datetime


@router.get("/notifications")
def list_notifications(p: CurrentUser, db: DB, unread_only: bool = False, limit: int = Query(30, ge=1, le=100)):
    stmt = select(Notification).where(Notification.user_id == p.user.id)
    if unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    rows = db.execute(stmt.order_by(Notification.created_at.desc()).limit(limit)).scalars().all()
    unread = db.execute(select(func.count()).select_from(Notification).where(
        Notification.user_id == p.user.id, Notification.read_at.is_(None))).scalar_one()
    return {"sin_leer": unread, "items": [NotificationOut.model_validate(r) for r in rows]}


@router.post("/notifications/{notification_id}/read", response_model=Msg)
def mark_read(notification_id: str, p: CurrentUser, db: DB):
    n = db.get(Notification, notification_id)
    if n is None or n.user_id != p.user.id:
        raise not_found("notificación")
    n.read_at = n.read_at or utcnow()
    db.commit()
    return Msg(mensaje="Marcada como leída")


@router.post("/notifications/read-all", response_model=Msg)
def mark_all_read(p: CurrentUser, db: DB):
    db.execute(update(Notification).where(Notification.user_id == p.user.id, Notification.read_at.is_(None))
               .values(read_at=utcnow()))
    db.commit()
    return Msg(mensaje="Todas marcadas como leídas")
