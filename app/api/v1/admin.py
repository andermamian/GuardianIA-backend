"""Consola administrativa — interfaces activity_guardian_admin_dashboard.xml,
activity_admin_emergency_command.xml, activity_admin_system_diagnostics.xml,
activity_guardian_configuracion_center.xml y guardian_user_y_permissions_management_center.xml.

Principios aplicados:

* Mínimo privilegio: cada endpoint exige un permiso concreto de core/rbac.py, no solo «ser admin».
* Nadie se gestiona a sí mismo ni a alguien de su nivel (anti escalada horizontal), y siempre
  queda al menos un super_admin activo.
* Toda acción con efecto queda en la bitácora encadenada con hashes, con motivo obligatorio.
* Minimización de datos de salud: la consola ve incidentes y umbrales, nunca el historial de signos
  vitales de una persona. Cambiar un umbral clínico exige el consentimiento de salud del usuario
  y le llega una notificación.
* Las recomendaciones de la IA nunca se aplican solas: un humano aprueba, y las del área médica
  además requieren revisión de un profesional registrada.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import sqlite3
from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Query, Request
from sqlalchemy import case, func, or_, select

from app.api.deps import DB, Principal, client_ip, require
from app.core import audit, rbac
from app.core.blocklist import blocklist, normalize_ip
from app.core.config import get_settings
from app.core.crypto import open_text, rewrap, seal_text
from app.core.errors import ApiError, conflict, forbidden, not_found
from app.core.ratelimit import limiter
from app.core.security import utcnow
from app.db.models import (AuditLog, Backup, BlockedIP, ConfigSetting, Device, EngineMetric,
                           HealthProfile, Incident, LoginEvent, Notification, Recommendation, SecurityAlert, User,
                           VaultFile)
from app.db.session import engine
from app.schemas.admin import (AdminUserOut, AlertOut, AlertResolveIn, AuditOut, BlockIpIn, DashboardOut, DecisionIn,
                               RecommendationOut, RoleChangeIn, ThresholdIn, UserStatusIn)
from app.schemas.common import Msg, Page
from app.schemas.emergency import IncidentOut
from app.services import auth as auth_svc
from app.services.alerts import notify
from app.services.realtime import hub, user_channel

router = APIRouter(prefix="/admin", tags=["Consola administrativa"])

SEVERITIES = ("info", "low", "medium", "high", "critical")


def _target_user(db, user_id: str) -> User:
    u = db.get(User, user_id)
    if u is None:
        raise not_found("usuario")
    return u


def _guard_manage(staff: Principal, target: User) -> None:
    if staff.user.id == target.id:
        raise forbidden("No puede aplicar esta acción sobre su propia cuenta")
    if not rbac.can_manage(staff.role, target.role):
        raise forbidden("No puede gestionar a un usuario de su mismo nivel o superior")


def _active_super_admins(db) -> int:
    return db.execute(select(func.count()).select_from(User)
                      .where(User.role == "super_admin", User.status == "active")).scalar_one()


# ================================================================== sesión
@router.get("/permissions")
def my_permissions(staff: Principal = require("dashboard:read")):
    """La consola oculta lo que el rol no puede hacer. Es solo comodidad: cada endpoint vuelve a verificar."""
    return {"rol": staff.role, "permisos": sorted(rbac.MATRIX.get(staff.role, set()))}


# ================================================================ dashboard
@router.get("/dashboard", response_model=DashboardOut)
def dashboard(db: DB, staff: Principal = require("dashboard:read")):
    """Analítica real (nav_analytics / nav_system_health) en lugar de cifras decorativas."""
    now = utcnow()
    day, week = now - timedelta(days=1), now - timedelta(days=7)
    by_plan = dict(db.execute(select(User.plan, func.count()).where(User.role == "user")
                              .group_by(User.plan)).all())
    by_status = dict(db.execute(select(User.status, func.count()).group_by(User.status)).all())
    open_alerts = dict(db.execute(select(SecurityAlert.severity, func.count())
                                  .where(SecurityAlert.status != "resolved")
                                  .group_by(SecurityAlert.severity)).all())
    logins = dict(db.execute(select(LoginEvent.success, func.count()).where(LoginEvent.created_at >= day)
                             .group_by(LoginEvent.success)).all())
    resolved = db.execute(select(SecurityAlert.feedback, func.count())
                          .where(SecurityAlert.feedback.is_not(None), SecurityAlert.resolved_at >= week)
                          .group_by(SecurityAlert.feedback)).all()
    fb = dict(resolved)
    reviewed = sum(fb.values())
    engines = {}
    for name, n, avg, ok in db.execute(select(EngineMetric.engine, func.count(), func.avg(EngineMetric.latency_ms),
                                              func.sum(case((EngineMetric.ok, 1), else_=0)))
                                       .where(EngineMetric.created_at >= day).group_by(EngineMetric.engine)).all():
        engines[name] = {"llamadas_24h": n, "latencia_media_ms": round(avg or 0, 1),
                         "tasa_error": round(1 - (ok or 0) / n, 3) if n else 0}
    try:
        db.execute(select(1))
        db_ok = True
    except Exception:
        db_ok = False
    return DashboardOut(
        usuarios={"total": sum(by_status.values()), "por_estado": by_status, "por_plan": by_plan,
                  "nuevos_7d": db.execute(select(func.count()).select_from(User)
                                          .where(User.created_at >= week)).scalar_one()},
        seguridad={"alertas_abiertas": open_alerts,
                   "logins_24h": {"exitosos": logins.get(True, 0), "fallidos": logins.get(False, 0)},
                   "ips_bloqueadas": db.execute(select(func.count()).select_from(BlockedIP)).scalar_one(),
                   # Precisión medida con la retroalimentación de los analistas, no un número inventado.
                   "precision_alertas_7d": round(fb.get("true_positive", 0) / reviewed, 3) if reviewed else None,
                   "alertas_revisadas_7d": reviewed},
        salud_sistema={"base_de_datos": "ok" if db_ok else "error",
                       "incidentes_activos": db.execute(select(func.count()).select_from(Incident).where(
                           Incident.status.in_(("pending_cancel", "escalating")))).scalar_one(),
                       "dispositivos_reportados": db.execute(select(func.count()).select_from(Device).where(
                           Device.status.in_(("lost", "stolen")))).scalar_one(),
                       "claves_cifrado": {"activa": get_settings().active_key_version,
                                          "disponibles": sorted(get_settings().keys())}},
        motores_ia=engines,
    )


# ================================================================= usuarios
@router.get("/users", response_model=Page[AdminUserOut])
def list_users(db: DB, staff: Principal = require("users:read"), q: str | None = Query(None, max_length=80),
               role: str | None = Query(None, pattern="^(user|supervisor|admin|super_admin)$"),
               status: str | None = Query(None, pattern="^(active|suspended)$"),
               limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    stmt = select(User)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(User.email).like(like), func.lower(User.full_name).like(like)))
    if role:
        stmt = stmt.where(User.role == role)
    if status:
        stmt = stmt.where(User.status == status)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    items = db.execute(stmt.order_by(User.created_at.desc()).limit(limit).offset(offset)).scalars().all()
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.get("/users/{user_id}", response_model=AdminUserOut)
def get_user(user_id: str, db: DB, staff: Principal = require("users:read")):
    return _target_user(db, user_id)


@router.put("/users/{user_id}/status", response_model=AdminUserOut)
def set_user_status(user_id: str, body: UserStatusIn, request: Request, db: DB,
                    staff: Principal = require("users:write")):
    u = _target_user(db, user_id)
    _guard_manage(staff, u)
    if u.status == body.status:
        return u
    if body.status == "suspended" and u.role == "super_admin" and _active_super_admins(db) <= 1:
        raise conflict("last_super_admin", "No se puede suspender al último super administrador")
    u.status = body.status
    revoked = auth_svc.revoke_all(db, u.id, "suspended") if body.status == "suspended" else 0
    if body.status == "active":
        u.failed_logins, u.locked_until = 0, None
    audit.record(db, f"admin.user.{body.status}", actor_id=staff.user.id, actor_role=staff.role,
                 target_type="user", target_id=u.id, ip=client_ip(request), level="security",
                 detail={"motivo": body.reason, "sesiones_revocadas": revoked}, commit=False)
    db.commit()
    return u


@router.put("/users/{user_id}/role", response_model=AdminUserOut)
def change_role(user_id: str, body: RoleChangeIn, request: Request, db: DB,
                staff: Principal = require("users:roles")):
    u = _target_user(db, user_id)
    _guard_manage(staff, u)
    if not rbac.can_manage(staff.role, body.role) and staff.role != "super_admin":
        raise forbidden("No puede otorgar un rol igual o superior al suyo")
    if u.role == body.role:
        return u
    if u.role == "super_admin" and _active_super_admins(db) <= 1:
        raise conflict("last_super_admin", "Debe quedar al menos un super administrador")
    if body.role in rbac.STAFF_ROLES and not u.totp_enabled:
        raise conflict("mfa_required", "El usuario debe activar 2FA antes de recibir un rol administrativo")
    previous, u.role = u.role, body.role
    revoked = auth_svc.revoke_all(db, u.id, "role_changed")  # los tokens llevan el rol viejo
    audit.record(db, "admin.user.role", actor_id=staff.user.id, actor_role=staff.role, target_type="user",
                 target_id=u.id, ip=client_ip(request), level="security",
                 detail={"de": previous, "a": body.role, "motivo": body.reason, "sesiones_revocadas": revoked},
                 commit=False)
    db.commit()
    return u


@router.delete("/users/{user_id}/sessions", response_model=Msg)
def revoke_user_sessions(user_id: str, request: Request, db: DB, staff: Principal = require("security:respond")):
    u = _target_user(db, user_id)
    _guard_manage(staff, u)
    n = auth_svc.revoke_all(db, u.id, "admin_revoked")
    audit.record(db, "admin.user.sessions_revoked", actor_id=staff.user.id, actor_role=staff.role,
                 target_type="user", target_id=u.id, ip=client_ip(request), level="security",
                 detail={"sesiones": n}, commit=False)
    db.commit()
    return Msg(mensaje=f"{n} sesiones cerradas")


@router.get("/alerts", response_model=Page[AlertOut])
def list_alerts(db: DB, staff: Principal = require("security:read"),
                status: str | None = Query(None, pattern="^(open|acknowledged|resolved)$"),
                severity: str | None = Query(None, pattern="^(info|low|medium|high|critical)$"),
                category: str | None = Query(None, max_length=20),
                limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    stmt = select(SecurityAlert)
    if status:
        stmt = stmt.where(SecurityAlert.status == status)
    if severity:
        stmt = stmt.where(SecurityAlert.severity == severity)
    if category:
        stmt = stmt.where(SecurityAlert.category == category)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    items = db.execute(stmt.order_by(SecurityAlert.created_at.desc()).limit(limit).offset(offset)).scalars().all()
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge_alert(alert_id: str, db: DB, staff: Principal = require("security:read")):
    a = db.get(SecurityAlert, alert_id)
    if a is None:
        raise not_found("alerta")
    if a.status == "open":
        a.status = "acknowledged"
        db.commit()
    return a


@router.post("/alerts/{alert_id}/resolve", response_model=AlertOut)
def resolve_alert(alert_id: str, body: AlertResolveIn, request: Request, db: DB,
                  staff: Principal = require("security:respond")):
    """La etiqueta verdadero/falso positivo alimenta la precisión del dashboard y el reentrenamiento."""
    a = db.get(SecurityAlert, alert_id)
    if a is None:
        raise not_found("alerta")
    if a.status == "resolved":
        raise conflict("alert_resolved", "La alerta ya fue resuelta")
    a.status, a.feedback, a.resolved_by, a.resolved_at = "resolved", body.feedback, staff.user.id, utcnow()
    audit.record(db, "admin.alert.resolved", actor_id=staff.user.id, actor_role=staff.role, target_type="alert",
                 target_id=a.id, ip=client_ip(request), detail={"feedback": body.feedback, "nota": body.note},
                 commit=False)
    db.commit()
    return a


@router.get("/blocked-ips")
def list_blocked(db: DB, staff: Principal = require("security:read")):
    rows = db.execute(select(BlockedIP).order_by(BlockedIP.created_at.desc())).scalars().all()
    return [{"ip": r.ip, "motivo": r.reason, "expira": r.expires_at, "creado": r.created_at} for r in rows]


@router.post("/blocked-ips", response_model=Msg, status_code=201)
def block_ip(body: BlockIpIn, request: Request, db: DB, staff: Principal = require("security:respond")):
    try:
        ip = normalize_ip(body.ip)
    except ValueError:
        raise ApiError(422, "invalid_ip", "La dirección IP no es válida")
    if ip == client_ip(request):
        raise conflict("self_block", "No puede bloquear la IP desde la que está conectado")
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback or addr.is_private:
        # Bloquear 10.x o 127.0.0.1 detrás de un balanceador deja a todos los usuarios fuera.
        raise conflict("internal_ip", "No se bloquean IP internas; revise la configuración del proxy")
    row = db.get(BlockedIP, ip) or BlockedIP(ip=ip, reason=body.reason)
    row.reason, row.blocked_by = body.reason, staff.user.id
    row.expires_at = utcnow() + timedelta(hours=body.hours) if body.hours else None
    db.merge(row)
    audit.record(db, "admin.ip.blocked", actor_id=staff.user.id, actor_role=staff.role, target_type="ip",
                 target_id=ip, ip=client_ip(request), level="security",
                 detail={"motivo": body.reason, "horas": body.hours}, commit=False)
    db.commit()
    blocklist.invalidate()
    return Msg(mensaje=f"IP {ip} bloqueada")


@router.delete("/blocked-ips/{ip}", response_model=Msg)
def unblock_ip(ip: str, request: Request, db: DB, staff: Principal = require("security:respond")):
    row = db.get(BlockedIP, ip)
    if row is None:
        raise not_found("bloqueo")
    db.delete(row)
    audit.record(db, "admin.ip.unblocked", actor_id=staff.user.id, actor_role=staff.role, target_type="ip",
                 target_id=ip, ip=client_ip(request), level="security", commit=False)
    db.commit()
    blocklist.invalidate()
    return Msg(mensaje=f"IP {ip} desbloqueada")


@router.get("/audit", response_model=Page[AuditOut])
def audit_log(db: DB, staff: Principal = require("security:read"),
              level: str | None = Query(None, pattern="^(info|warning|error|security)$"),
              action: str | None = Query(None, max_length=60), actor_id: str | None = None,
              limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    stmt = select(AuditLog)
    if level:
        stmt = stmt.where(AuditLog.level == level)
    if action:
        stmt = stmt.where(AuditLog.action.startswith(action))
    if actor_id:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    items = db.execute(stmt.order_by(AuditLog.id.desc()).limit(limit).offset(offset)).scalars().all()
    return Page(items=[AuditOut.model_validate(i, from_attributes=True) for i in items],
                total=total, limit=limit, offset=offset)


@router.get("/audit/verify")
def verify_audit(db: DB, staff: Principal = require("security:read")):
    """Recalcula la cadena de hashes: detecta si alguien editó o borró registros directamente en la BD."""
    return audit.verify_chain(db)


# ========================================================= centro de comando
@router.get("/incidents", response_model=list[IncidentOut])
def list_incidents(db: DB, staff: Principal = require("incidents:read"), active_only: bool = True,
                   limit: int = Query(50, le=200)):
    stmt = select(Incident)
    if active_only:
        stmt = stmt.where(Incident.status.in_(("pending_cancel", "escalating")))
    return db.execute(stmt.order_by(Incident.created_at.desc()).limit(limit)).scalars().all()


@router.post("/incidents/{incident_id}/assign", response_model=IncidentOut)
def assign_incident(incident_id: str, request: Request, db: DB, staff: Principal = require("incidents:manage")):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise not_found("incidente")
    inc.assigned_to = staff.user.id
    inc.timeline = [*inc.timeline, {"t": utcnow().isoformat(), "evento": "asignado", "operador": staff.user.id}]
    audit.record(db, "admin.incident.assigned", actor_id=staff.user.id, actor_role=staff.role,
                 target_type="incident", target_id=inc.id, ip=client_ip(request), commit=False)
    db.commit()
    return inc


@router.post("/incidents/{incident_id}/resolve", response_model=IncidentOut)
def resolve_incident(incident_id: str, request: Request, db: DB, staff: Principal = require("incidents:manage"),
                     note: str = Query(..., min_length=3, max_length=300)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise not_found("incidente")
    if inc.status in ("resolved", "cancelled"):
        raise conflict("incident_closed", "El incidente ya está cerrado")
    inc.status, inc.resolved_at = "resolved", utcnow()
    inc.timeline = [*inc.timeline, {"t": utcnow().isoformat(), "evento": "resuelto", "operador": staff.user.id,
                                    "nota": note}]
    audit.record(db, "admin.incident.resolved", actor_id=staff.user.id, actor_role=staff.role,
                 target_type="incident", target_id=inc.id, ip=client_ip(request), detail={"nota": note},
                 commit=False)
    db.commit()
    return inc


@router.post("/broadcast", response_model=Msg, status_code=202)
def broadcast(request: Request, db: DB, staff: Principal = require("incidents:broadcast"),
              title: str = Query(..., min_length=5, max_length=120),
              body: str = Query(..., min_length=10, max_length=500),
              severity: str = Query("high", pattern="^(info|medium|high|critical)$"),
              reason: str = Query(..., min_length=5, max_length=200)):
    """btn_mass_alert. Limitado a 3 por hora: una cuenta admin comprometida no puede sembrar pánico masivo."""
    limiter.hit(f"broadcast:{staff.user.id}", 3, 3600)
    ids = db.execute(select(User.id).where(User.status == "active", User.role == "user")).scalars().all()
    for uid in ids:
        db.add(Notification(user_id=uid, kind="broadcast", severity=severity, title=title, body=body,
                            data={"emisor": "GuardianIA"}))
    audit.record(db, "admin.broadcast", actor_id=staff.user.id, actor_role=staff.role, ip=client_ip(request),
                 level="security", detail={"titulo": title, "destinatarios": len(ids), "motivo": reason},
                 commit=False)
    db.commit()
    for uid in ids:
        hub.publish(user_channel(uid), {"tipo": "notificacion", "titulo": title, "severidad": severity})
    return Msg(mensaje=f"Alerta enviada a {len(ids)} usuarios")


# ==================================================== recomendaciones de IA
@router.get("/recommendations", response_model=list[RecommendationOut])
def list_recommendations(db: DB, staff: Principal = require("config:read"),
                         status: str = Query("pending", pattern="^(pending|approved|rejected|modified)$"),
                         area: str | None = Query(None, pattern="^(medical|security|system)$")):
    stmt = select(Recommendation).where(Recommendation.status == status)
    if area:
        stmt = stmt.where(Recommendation.area == area)
    return db.execute(stmt.order_by(Recommendation.created_at.desc())).scalars().all()


@router.post("/recommendations/{rec_id}/decision", response_model=RecommendationOut)
def decide(rec_id: str, body: DecisionIn, request: Request, db: DB, staff: Principal = require("config:decide")):
    """btn_approve_recommendation / btn_reject_recommendation / btn_modify_parameters."""
    rec = db.get(Recommendation, rec_id)
    if rec is None:
        raise not_found("recomendación")
    if rec.status != "pending":
        raise conflict("already_decided", "Esta recomendación ya fue decidida")
    if body.decision in ("approve", "modify") and rec.area == "medical" and not rec.expert_review:
        raise conflict("expert_review_required",
                       "Los cambios médicos requieren la revisión registrada de un profesional de la salud")
    if body.decision == "modify" and not body.modified_value:
        raise ApiError(422, "modified_value_required", "Indique el valor modificado")
    if body.decision != "approve" and not body.note:
        raise ApiError(422, "note_required", "Explique el motivo del rechazo o la modificación")
    final = {"approve": rec.proposed_value, "modify": body.modified_value, "reject": None}[body.decision]
    rec.status = {"approve": "approved", "modify": "modified", "reject": "rejected"}[body.decision]
    rec.decided_by, rec.decided_at, rec.decision_note, rec.final_value = staff.user.id, utcnow(), body.note, final
    if final is not None:
        setting = db.get(ConfigSetting, rec.setting_key) or ConfigSetting(key=rec.setting_key, area=rec.area,
                                                                          value={})
        setting.value, setting.updated_by = final, staff.user.id
        db.merge(setting)
    audit.record(db, f"admin.recommendation.{rec.status}", actor_id=staff.user.id, actor_role=staff.role,
                 target_type="setting", target_id=rec.setting_key, ip=client_ip(request), level="warning",
                 detail={"recomendacion": rec.id, "antes": rec.current_value, "despues": final, "nota": body.note},
                 commit=False)
    db.commit()
    return rec


# ============================================================= operaciones
@router.get("/diagnostics")
def diagnostics(db: DB, staff: Principal = require("dashboard:read")):
    """btn_health_check / btn_test_apis: comprobaciones reales, sin exponer secretos."""
    s = get_settings()
    checks: dict[str, dict] = {}
    try:
        db.execute(select(func.count()).select_from(User)).scalar_one()
        checks["base_de_datos"] = {"ok": True, "motor": engine.dialect.name}
    except Exception as e:  # noqa: BLE001
        checks["base_de_datos"] = {"ok": False, "error": type(e).__name__}
    try:
        probe = seal_text("ping", "diagnostics")
        checks["cifrado"] = {"ok": open_text(probe, "diagnostics") == "ping", "clave_activa": s.active_key_version}
    except Exception as e:  # noqa: BLE001
        checks["cifrado"] = {"ok": False, "error": type(e).__name__}
    vault = Path(s.vault_dir)
    checks["boveda"] = {"ok": (not vault.exists()) or os.access(vault, os.W_OK), "existe": vault.exists()}
    checks["asistente_llm"] = {"ok": True, "proveedor": "anthropic" if s.anthropic_api_key else "local"}
    checks["cadena_auditoria"] = audit.verify_chain(db)
    checks["configuracion_produccion"] = {"ok": not s.is_production or bool(s.cors_origins), "entorno": s.env}
    return {"ok": all(c.get("ok", c.get("integra", True)) for c in checks.values()), "comprobaciones": checks}


def _sqlite_path() -> Path:
    url = get_settings().database_url
    if not url.startswith("sqlite:///") or url in ("sqlite://", "sqlite:///:memory:"):
        raise ApiError(501, "backup_external", "Con PostgreSQL use pg_dump/PITR del proveedor; "
                                               "este endpoint respalda solo SQLite")
    return Path(url.removeprefix("sqlite:///"))


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@router.post("/backups", status_code=201)
def create_backup(request: Request, db: DB, staff: Principal = require("ops:backups")):
    """btn_manual_backup. Usa la API de respaldo en caliente de SQLite (consistente con escrituras en curso).
    Los campos sensibles ya van cifrados; aun así el archivo queda con permisos 0600."""
    src = _sqlite_path()
    limiter.hit("backups", 6, 3600)
    out_dir = Path(get_settings().backup_dir)
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    b = Backup(filename=f"guardian-{utcnow():%Y%m%d-%H%M%S}.db", created_by=staff.user.id)
    db.add(b)
    db.commit()
    target = out_dir / b.filename
    try:
        with sqlite3.connect(src) as s_conn, sqlite3.connect(target) as t_conn:
            s_conn.backup(t_conn)
        os.chmod(target, 0o600)
        b.size_bytes, b.sha256, b.status = target.stat().st_size, _sha256_file(target), "completed"
    except Exception as e:  # noqa: BLE001
        b.status, b.error = "failed", type(e).__name__
        target.unlink(missing_ok=True)
    audit.record(db, "admin.backup.created", actor_id=staff.user.id, actor_role=staff.role, target_type="backup",
                 target_id=b.id, ip=client_ip(request), detail={"estado": b.status}, commit=False)
    db.commit()
    return {"id": b.id, "archivo": b.filename, "estado": b.status, "bytes": b.size_bytes, "sha256": b.sha256}


@router.get("/backups")
def list_backups(db: DB, staff: Principal = require("ops:backups"), limit: int = Query(20, le=100)):
    rows = db.execute(select(Backup).order_by(Backup.created_at.desc()).limit(limit)).scalars().all()
    return [{"id": b.id, "archivo": b.filename, "estado": b.status, "bytes": b.size_bytes, "sha256": b.sha256,
             "creado": b.created_at, "verificado": b.verified_at} for b in rows]


@router.post("/backups/{backup_id}/verify")
def verify_backup(backup_id: str, db: DB, staff: Principal = require("ops:backups")):
    """Un respaldo que nunca se probó no es un respaldo: verifica hash e integridad interna."""
    b = db.get(Backup, backup_id)
    if b is None:
        raise not_found("respaldo")
    path = Path(get_settings().backup_dir) / b.filename
    if not path.exists():
        raise ApiError(410, "backup_missing", "El archivo del respaldo no existe")
    hash_ok = _sha256_file(path) == b.sha256
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        users = conn.execute("SELECT count(*) FROM users").fetchone()[0]
    ok = hash_ok and integrity == "ok"
    if ok:
        b.status, b.verified_at = "verified", utcnow()
    db.commit()
    return {"verificado": ok, "hash_coincide": hash_ok, "integridad_sqlite": integrity, "usuarios_en_respaldo": users}


@router.post("/keys/rotate")
def rotate_keys(request: Request, db: DB, staff: Principal = require("ops:keys")):
    """Re-envuelve las claves de los archivos de la bóveda con la versión activa del anillo.

    Procedimiento: 1) agregar la nueva clave a GUARDIAN_KEYRING y marcarla activa, 2) reiniciar,
    3) llamar a este endpoint, 4) cuando `pendientes` sea 0, retirar la clave vieja del anillo.
    No recifra los archivos: solo sus DEK, por eso tarda segundos y no minutos.
    """
    active = get_settings().active_key_version
    rows = db.execute(select(VaultFile).where(VaultFile.key_version != active).limit(1000)).scalars().all()
    rotated = 0
    for f in rows:
        f.key_version, f.wrapped_dek = rewrap(f.key_version, f.wrapped_dek, f"vault:{f.user_id}:{f.id}")
        f.filename_enc = seal_text(open_text(f.filename_enc, f"vault:{f.user_id}:{f.id}"), f"vault:{f.user_id}:{f.id}")
        rotated += 1
    remaining = db.execute(select(func.count()).select_from(VaultFile)
                           .where(VaultFile.key_version != active)).scalar_one() - rotated
    audit.record(db, "admin.keys.rotated", actor_id=staff.user.id, actor_role=staff.role, ip=client_ip(request),
                 level="security", detail={"version_activa": active, "rotados": rotated, "pendientes": remaining},
                 commit=False)
    db.commit()
    return {"version_activa": active, "rotados": rotated, "pendientes": remaining}
