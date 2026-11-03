from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.models import Notification, SecurityAlert
from app.services.realtime import STAFF_CHANNEL, hub, user_channel

NOTIFY_USER = {"medium", "high", "critical"}
NOTIFY_STAFF = {"high", "critical"}


def raise_alert(db: Session, *, user_id: str | None, category: str, severity: str, title: str, description: str,
                data: dict | None = None, engine: str | None = None, engine_version: str | None = None,
                source_ip: str | None = None, notify: bool = True) -> SecurityAlert:
    alert = SecurityAlert(user_id=user_id, category=category, severity=severity, title=title,
                          description=description, data=data or {}, engine=engine, engine_version=engine_version,
                          source_ip=source_ip)
    db.add(alert)
    db.flush()
    event = {"tipo": "alerta", "id": alert.id, "categoria": category, "severidad": severity, "titulo": title}
    if user_id and notify and severity in NOTIFY_USER:
        db.add(Notification(user_id=user_id, kind=f"alert.{category}", severity=severity, title=title,
                            body=description, data={"alert_id": alert.id}))
        hub.publish(user_channel(user_id), event)
    if severity in NOTIFY_STAFF:
        hub.publish(STAFF_CHANNEL, {**event, "usuario": user_id})
    return alert


def notify(db: Session, user_id: str, title: str, body: str, *, kind: str = "info", severity: str = "info",
           data: dict | None = None) -> Notification:
    n = Notification(user_id=user_id, kind=kind, severity=severity, title=title, body=body, data=data or {})
    db.add(n)
    db.flush()
    hub.publish(user_channel(user_id), {"tipo": "notificacion", "id": n.id, "titulo": title, "severidad": severity})
    return n
