"""Antivirus / antimalware — interfaces AI Security Hub y Vigilancia de Aplicaciones.

El escaneo lo inicia el teléfono (que ya tiene acceso a los archivos y apps); manda aquí los
rasgos extraídos y el servidor los puntúa con el motor multicapa. Así el modelo y las firmas
se actualizan en el servidor sin publicar una nueva versión de la app.
"""
from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.ai import antivirus as av
from app.ai import app_risk
from app.api.deps import DB, CurrentUser
from app.core.errors import not_found
from app.core.plans import features_for
from app.core.ratelimit import limiter
from app.core.security import utcnow
from app.db.models import AppAssessment
from app.schemas.security import (AiPayloadIn, AppActionIn, AppAssessmentOut, AppOverview, AppScanBatchIn,
                                  PermissionScanIn, ScanIn, ScanOut)
from app.services.alerts import raise_alert

router = APIRouter(tags=["Antivirus y protección"])

# En producción estas listas vienen de un feed de inteligencia (MISP/abuse.ch) cargado al iniciar.
KNOWN_BAD_HASHES: set[str] = set()
KNOWN_GOOD_HASHES: set[str] = set()
KNOWN_BAD_CERTS: set[str] = set()


@router.post("/antivirus/scan", response_model=ScanOut)
def scan_file(body: ScanIn, p: CurrentUser, db: DB):
    limiter.hit(f"av-scan:{p.user.id}", 60)
    sample = av.FileSample(name=body.file.name, size=body.file.size, sha256=body.file.sha256.lower(),
                           kind=body.file.kind, header_hex=body.file.header_hex, strings=body.file.strings,
                           entropy=body.file.entropy, imports=body.file.imports, yara_hits=body.file.yara_hits,
                           is_signed=body.file.is_signed, signer=body.file.signer)
    behavior = None
    if body.behavior:
        behavior = av.Behavior(**body.behavior.model_dump())
    result = av.scan_file(sample, behavior, bad_hashes=KNOWN_BAD_HASHES, good_hashes=KNOWN_GOOD_HASHES)
    generated = False
    if result.level == "malicioso":
        raise_alert(db, user_id=p.user.id, category="app", severity="high",
                    title=f"Archivo malicioso detectado: {body.file.name}",
                    description=f"{result.family_guess or 'Amenaza'} — " + "; ".join(
                        d.reason for d in result.detections[:3]),
                    data={"sha256": result.sha256, "puntaje": result.score}, engine="antivirus",
                    engine_version=av.ENGINE_VERSION)
        generated = True
    elif result.level == "sospechoso":
        raise_alert(db, user_id=p.user.id, category="app", severity="medium",
                    title=f"Archivo sospechoso: {body.file.name}",
                    description="; ".join(d.reason for d in result.detections[:3]),
                    data={"sha256": result.sha256}, engine="antivirus", engine_version=av.ENGINE_VERSION,
                    notify=False)
        generated = True
    db.commit()
    return ScanOut(resultado=result.to_dict(), alerta_generada=generated)


@router.post("/antivirus/scan-ai", response_model=ScanOut)
def scan_ai(body: AiPayloadIn, p: CurrentUser, db: DB):
    """Evalúa un prompt/función de IA por inyección y fuga (equivalente a scanAISystem)."""
    limiter.hit(f"av-ai:{p.user.id}", 60)
    result = av.scan_ai_payload(body.text)
    return ScanOut(resultado=result.to_dict(), alerta_generada=False)


# ---------------------------------------------------- vigilancia de aplicaciones
def _assess(item: PermissionScanIn, plan_features: set[str]) -> app_risk.AppVerdict:
    sample = app_risk.AppSample(package=item.package, label=item.label, permissions=item.permissions,
                                installer=item.installer, cert_sha256=item.cert_sha256, category=item.category,
                                bytes_rx=item.bytes_rx, bytes_tx=item.bytes_tx, night_tx_ratio=item.night_tx_ratio,
                                target_sdk=item.target_sdk)
    return app_risk.assess_app(sample, known_bad_certs=KNOWN_BAD_CERTS)


@router.post("/apps/scan", response_model=AppOverview)
def scan_apps(body: AppScanBatchIn, p: CurrentUser, db: DB):
    """btn_scan_all_apps: evalúa el catálogo de apps del dispositivo."""
    limiter.hit(f"app-scan:{p.user.id}", 20)
    plan_features = features_for(p.user.plan)
    for item in body.apps:
        verdict = _assess(item, plan_features)
        existing = db.execute(select(AppAssessment).where(
            AppAssessment.user_id == p.user.id, AppAssessment.device_id == (body.device_id or item.device_id),
            AppAssessment.package == item.package)).scalar()
        payload = dict(label=item.label, version=item.version, installer=item.installer,
                       cert_sha256=item.cert_sha256, permissions=item.permissions, bytes_rx=item.bytes_rx,
                       bytes_tx=item.bytes_tx, night_tx_ratio=item.night_tx_ratio, score=verdict.score,
                       verdict=verdict.verdict, reasons=verdict.reasons, scanned_at=utcnow())
        if existing:
            for k, v in payload.items():
                setattr(existing, k, v)
        else:
            db.add(AppAssessment(user_id=p.user.id, device_id=body.device_id or item.device_id,
                                 package=item.package, **payload))
        if verdict.verdict == "peligrosa":
            raise_alert(db, user_id=p.user.id, category="app", severity="high",
                        title=f"Aplicación peligrosa: {item.label}",
                        description="; ".join(r["motivo"] for r in verdict.reasons[:3]),
                        data={"package": item.package}, engine="apprisk",
                        engine_version=app_risk.ENGINE_VERSION, notify=False)
    db.commit()
    return apps_overview(p, db, None, None)


@router.get("/apps", response_model=AppOverview)
def apps_overview(p: CurrentUser, db: DB, device_id: str | None = Query(None),
                  verdict: str | None = Query(None, pattern="^(segura|sospechosa|peligrosa)$")):
    stmt = select(AppAssessment).where(AppAssessment.user_id == p.user.id)
    if device_id:
        stmt = stmt.where(AppAssessment.device_id == device_id)
    rows = db.execute(stmt.order_by(AppAssessment.score.desc())).scalars().all()
    dist = app_risk.permission_distribution([(r.permissions, r.verdict) for r in rows])
    shown = [r for r in rows if not verdict or r.verdict == verdict]
    counts = {v: sum(1 for r in rows if r.verdict == v) for v in ("segura", "sospechosa", "peligrosa")}
    return AppOverview(total=len(rows), seguras=counts["segura"], sospechosas=counts["sospechosa"],
                       peligrosas=counts["peligrosa"], distribucion_permisos=dist, apps=shown)


@router.post("/apps/{assessment_id}/action", response_model=AppAssessmentOut)
def app_action(assessment_id: str, body: AppActionIn, p: CurrentUser, db: DB):
    """Botones Bloquear/Restringir/Cuarentena/Eliminar de cada app."""
    a = db.get(AppAssessment, assessment_id)
    if a is None or a.user_id != p.user.id:
        raise not_found("aplicación")
    a.user_action = body.action
    db.commit()
    return a
