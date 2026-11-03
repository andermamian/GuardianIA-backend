"""Bitácora de auditoría a prueba de manipulación (cadena de hashes SHA-256)."""
from __future__ import annotations

import hashlib
import json
import threading

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AuditLog
from app.core.security import utcnow

GENESIS = "0" * 64
_lock = threading.Lock()


def _digest(prev: str, ts: str, actor: str | None, action: str, target: str | None, detail: dict) -> str:
    payload = json.dumps([prev, ts, actor, action, target, detail], sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def record(db: Session, action: str, *, actor_id: str | None = None, actor_role: str | None = None,
           target_type: str | None = None, target_id: str | None = None, ip: str | None = None,
           detail: dict | None = None, level: str = "info", commit: bool = True) -> AuditLog:
    detail = detail or {}
    with _lock:
        last = db.execute(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1)).scalar()
        prev = last or GENESIS
        ts = utcnow()
        target = f"{target_type}:{target_id}" if target_type else None
        row = AuditLog(ts=ts, actor_id=actor_id, actor_role=actor_role, action=action, level=level,
                       target_type=target_type, target_id=target_id, ip=ip, detail=detail, prev_hash=prev,
                       hash=_digest(prev, ts.isoformat(), actor_id, action, target, detail))
        db.add(row)
        if commit:
            db.commit()
        else:
            db.flush()
    return row


def verify_chain(db: Session) -> dict:
    prev = GENESIS
    count = 0
    for row in db.execute(select(AuditLog).order_by(AuditLog.id)).scalars():
        target = f"{row.target_type}:{row.target_id}" if row.target_type else None
        expected = _digest(prev, row.ts.isoformat(), row.actor_id, row.action, target, row.detail)
        if row.prev_hash != prev or row.hash != expected:
            return {"integra": False, "registros_verificados": count, "primer_registro_alterado": row.id}
        prev = row.hash
        count += 1
    return {"integra": True, "registros_verificados": count, "primer_registro_alterado": None}
