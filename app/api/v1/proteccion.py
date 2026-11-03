"""Centro de protección: análisis del equipo, estado general y revisión de filtraciones.

Tres decisiones de diseño que vale la pena explicar:

1. **Los archivos no se suben.** El navegador calcula la huella SHA-256, la entropía, la cabecera y
   las cadenas legibles de cada archivo, y solo eso viaja. Un análisis de 300 archivos son unos
   pocos cientos de kilobytes en vez de gigabytes, y ningún documento privado sale del equipo.

2. **El análisis por lotes tiene tope y presupuesto de tiempo.** Un usuario podría mandar 10.000
   archivos y dejar el servidor ocupado; se aceptan 200 por lote y se corta por tiempo, devolviendo
   lo hecho. Es preferible un resultado parcial honesto a una petición que nunca responde.

3. **La revisión de filtraciones guarda el hash del correo, no el correo.** El historial sirve igual
   y no se acumula una lista de correos en claro, que sería un objetivo por sí misma.
"""
from __future__ import annotations

import hashlib
import time

import httpx

from app.core import red
from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select

from app.ai import antivirus as av
from app.api.deps import DB, CurrentUser, client_ip
from app.core import audit
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.plans import features_for
from app.core.ratelimit import limiter
from app.core.security import utcnow
from app.db.models import AppAssessment, ExposureCheck, ScanRun, SecurityAlert, VpnServer
from app.schemas.common import Out
from app.schemas.security import FileScanIn
from app.services.alerts import raise_alert

router = APIRouter(prefix="/proteccion", tags=["Centro de protección"])

MAX_LOTE = 200
PRESUPUESTO_SEGUNDOS = 20.0
CACHE_EXPOSICION_HORAS = 12


class LoteIn(BaseModel):
    origen: str = Field("carpeta", pattern="^(carpeta|archivo|descargas|usb)$")
    etiqueta: str | None = Field(None, max_length=120)
    archivos: list[FileScanIn] = Field(min_length=1, max_length=MAX_LOTE)
    omitidos: int = Field(0, ge=0, le=100000)


class HallazgoOut(Out):
    nombre: str
    nivel: str
    probabilidad: float
    familia: str | None
    motivos: list[str]
    sha256: str


class LoteOut(Out):
    id: str
    total: int
    limpios: int
    sospechosos: int
    maliciosos: int
    omitidos: int
    duracion_ms: int
    incompleto: bool
    hallazgos: list[HallazgoOut]
    engine_version: str


@router.post("/escaneo", response_model=LoteOut, status_code=201)
def escanear_lote(body: LoteIn, request: Request, p: CurrentUser, db: DB):
    """Analiza un lote de archivos ya procesados por el navegador."""
    limiter.hit(f"escaneo:{p.user.id}", 30, 600)
    inicio = time.perf_counter()
    limpios = sospechosos = maliciosos = 0
    hallazgos: list[dict] = []
    analizados = 0

    for archivo in body.archivos:
        if time.perf_counter() - inicio > PRESUPUESTO_SEGUNDOS:
            break   # se devuelve lo hecho; el cliente manda el resto en otro lote
        muestra = av.FileSample(name=archivo.name, size=archivo.size, sha256=archivo.sha256.lower(),
                                kind=archivo.kind, header_hex=archivo.header_hex, strings=archivo.strings,
                                entropy=archivo.entropy, imports=archivo.imports, yara_hits=archivo.yara_hits,
                                is_signed=archivo.is_signed, signer=archivo.signer)
        resultado = av.scan_file(muestra)
        analizados += 1
        if resultado.level == "malicioso":
            maliciosos += 1
        elif resultado.level == "sospechoso":
            sospechosos += 1
        else:
            limpios += 1
        if resultado.level != "limpio":
            hallazgos.append({
                "nombre": archivo.name[-60:], "nivel": resultado.level,
                "probabilidad": round(resultado.malicious_probability, 3),
                "familia": resultado.family_guess, "sha256": archivo.sha256.lower(),
                "motivos": [d.reason for d in resultado.detections][:4],
            })

    duracion = int((time.perf_counter() - inicio) * 1000)
    hallazgos.sort(key=lambda h: (h["nivel"] != "malicioso", -h["probabilidad"]))
    corrida = ScanRun(user_id=p.user.id, origen=body.origen, total=analizados, limpios=limpios,
                      sospechosos=sospechosos, maliciosos=maliciosos, omitidos=body.omitidos,
                      duracion_ms=duracion, hallazgos=hallazgos[:20])
    db.add(corrida)
    db.flush()

    if maliciosos:
        raise_alert(db, user_id=p.user.id, category="app", severity="high",
                    title=f"{maliciosos} archivo(s) malicioso(s) en su equipo",
                    description="Se detectaron archivos con alta probabilidad de ser malware: "
                                + ", ".join(h["nombre"] for h in hallazgos[:3])
                                + ". No los abra; elimínelos o póngalos en cuarentena.",
                    data={"scan_run": corrida.id}, engine=av.ENGINE_VERSION)
    audit.record(db, "proteccion.escaneo", actor_id=p.user.id, target_type="scan_run", target_id=corrida.id,
                 ip=client_ip(request), detail={"total": analizados, "maliciosos": maliciosos},
                 level="warning" if maliciosos else "info", commit=False)
    db.commit()
    return LoteOut(id=corrida.id, total=analizados, limpios=limpios, sospechosos=sospechosos,
                   maliciosos=maliciosos, omitidos=body.omitidos, duracion_ms=duracion,
                   incompleto=analizados < len(body.archivos),
                   hallazgos=[HallazgoOut(**h) for h in hallazgos[:20]], engine_version=av.ENGINE_VERSION)


@router.get("/escaneos")
def historial(p: CurrentUser, db: DB, limit: int = Query(10, ge=1, le=50)):
    filas = db.execute(select(ScanRun).where(ScanRun.user_id == p.user.id)
                       .order_by(ScanRun.created_at.desc()).limit(limit)).scalars().all()
    return [{"id": f.id, "origen": f.origen, "total": f.total, "limpios": f.limpios,
             "sospechosos": f.sospechosos, "maliciosos": f.maliciosos, "omitidos": f.omitidos,
             "duracion_ms": f.duracion_ms, "creado": f.created_at, "hallazgos": f.hallazgos}
            for f in filas]


@router.get("/estado")
def estado(p: CurrentUser, db: DB):
    """Lo que la pantalla necesita para decir, de un vistazo, cómo está protegida la persona."""
    ultimo = db.execute(select(ScanRun).where(ScanRun.user_id == p.user.id)
                        .order_by(ScanRun.created_at.desc()).limit(1)).scalar()
    alertas = db.execute(select(func.count()).select_from(SecurityAlert).where(
        SecurityAlert.user_id == p.user.id, SecurityAlert.status != "resolved",
        SecurityAlert.category.in_(("app", "web", "device")))).scalar_one()
    apps_riesgo = db.execute(select(func.count()).select_from(AppAssessment).where(
        AppAssessment.user_id == p.user.id, AppAssessment.verdict.in_(("sospechosa", "peligrosa")))).scalar_one()
    exposicion = db.execute(select(ExposureCheck).where(ExposureCheck.user_id == p.user.id)
                            .order_by(ExposureCheck.created_at.desc()).limit(1)).scalar()
    vpn_disponible = "basic_vpn" in features_for(p.user.plan)
    servidores = db.execute(select(func.count()).select_from(VpnServer)
                            .where(VpnServer.active.is_(True))).scalar_one()

    pendientes = []
    if ultimo is None:
        pendientes.append("Nunca ha analizado su equipo")
    elif (utcnow() - ultimo.created_at).days >= 7:
        pendientes.append("El último análisis tiene más de una semana")
    if exposicion is None:
        pendientes.append("No ha revisado si su correo aparece en filtraciones")
    if alertas:
        pendientes.append(f"{alertas} alerta(s) de seguridad sin resolver")
    if apps_riesgo:
        pendientes.append(f"{apps_riesgo} aplicación(es) con permisos de alto riesgo")

    return {
        "ultimo_escaneo": None if ultimo is None else {
            "id": ultimo.id, "creado": ultimo.created_at, "total": ultimo.total,
            "maliciosos": ultimo.maliciosos, "sospechosos": ultimo.sospechosos, "origen": ultimo.origen},
        "alertas_abiertas": alertas,
        "apps_riesgo": apps_riesgo,
        "exposicion": None if exposicion is None else {
            "revisado": exposicion.created_at, "filtraciones": exposicion.filtraciones,
            "riesgo": exposicion.riesgo, "proveedor": exposicion.proveedor},
        "vpn": {"disponible": vpn_disponible, "servidores": servidores, "plan": p.user.plan},
        "pendientes": pendientes,
        "motor": av.ENGINE_VERSION,
    }


# ────────────────────────────────────────── filtraciones de datos
class ExposicionIn(BaseModel):
    email: EmailStr


RIESGO_POR_DATOS = {"passwords": 3, "contraseñas": 3, "credit cards": 3, "bank": 3, "ssn": 3,
                    "phone numbers": 2, "physical addresses": 2, "dates of birth": 2, "names": 1}


@router.post("/exposicion")
def revisar_exposicion(body: ExposicionIn, request: Request, p: CurrentUser, db: DB):
    """¿El correo de la persona aparece en filtraciones publicadas?

    Se consulta un servicio especializado, no «la dark web» directamente: rastrearla no es algo que
    una app deba hacer, y quien dice hacerlo casi siempre está consultando estas mismas bases. Lo
    honesto es decir de dónde sale el dato.
    """
    limiter.hit(f"exposicion:{p.user.id}", 6, 3600)
    correo = body.email.lower().strip()
    huella = hashlib.sha256(correo.encode()).hexdigest()

    previo = db.execute(select(ExposureCheck).where(
        ExposureCheck.user_id == p.user.id, ExposureCheck.email_hash == huella)
        .order_by(ExposureCheck.created_at.desc()).limit(1)).scalar()
    if previo and (utcnow() - previo.created_at).total_seconds() < CACHE_EXPOSICION_HORAS * 3600:
        return _salida_exposicion(previo, cacheado=True)

    filtraciones, proveedor = _consultar_filtraciones(correo)
    riesgo = _riesgo(filtraciones)
    registro = ExposureCheck(user_id=p.user.id, email_hash=huella, proveedor=proveedor,
                             filtraciones=len(filtraciones), detalle=filtraciones[:25], riesgo=riesgo)
    db.add(registro)
    db.flush()
    if riesgo in ("alto", "critico"):
        raise_alert(db, user_id=p.user.id, category="web", severity="high" if riesgo == "alto" else "critical",
                    title="Su correo aparece en filtraciones de datos",
                    description=f"Encontrado en {len(filtraciones)} filtración(es). Cambie la contraseña de ese "
                                "correo y de los servicios donde la reutilizó, y active la verificación en dos pasos.",
                    data={"filtraciones": len(filtraciones)}, engine=proveedor)
    audit.record(db, "proteccion.exposicion", actor_id=p.user.id, ip=client_ip(request),
                 detail={"filtraciones": len(filtraciones), "proveedor": proveedor}, commit=False)
    db.commit()
    return _salida_exposicion(registro, cacheado=False)


@router.get("/exposicion")
def ultima_exposicion(p: CurrentUser, db: DB):
    previo = db.execute(select(ExposureCheck).where(ExposureCheck.user_id == p.user.id)
                        .order_by(ExposureCheck.created_at.desc()).limit(1)).scalar()
    return None if previo is None else _salida_exposicion(previo, cacheado=True)


def _salida_exposicion(registro: ExposureCheck, *, cacheado: bool) -> dict:
    return {"revisado": registro.created_at, "proveedor": registro.proveedor, "riesgo": registro.riesgo,
            "filtraciones": registro.filtraciones, "detalle": registro.detalle, "cacheado": cacheado,
            "recomendaciones": _recomendaciones(registro.detalle, registro.riesgo)}


def _consultar_filtraciones(correo: str) -> tuple[list[dict], str]:
    s = get_settings()
    proveedor = s.breach_provider
    try:
        if proveedor == "hibp":
            if not s.breach_api_key:
                raise ApiError(503, "sin_clave_hibp",
                               "El proveedor configurado (HIBP) requiere una clave de pago. Ponga "
                               "GUARDIAN_BREACH_API_KEY en el .env o use GUARDIAN_BREACH_PROVIDER=xposedornot")
            r = red.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{correo}",
                          params={"truncateResponse": "false"},
                          headers={"hibp-api-key": s.breach_api_key, "user-agent": "GuardianIA"}, timeout=12)
            if r.status_code == 404:
                return [], "hibp"
            r.raise_for_status()
            return [{"sitio": b.get("Name"), "fecha": b.get("BreachDate"),
                     "datos": b.get("DataClasses", [])[:8], "cuentas": b.get("PwnCount")}
                    for b in r.json()], "hibp"

        # XposedOrNot: API pública y gratuita, sin clave.
        r = red.get(f"https://api.xposedornot.com/v1/check-email/{correo}",
                      headers={"user-agent": "GuardianIA"}, timeout=12)
        if r.status_code == 404:
            return [], "xposedornot"
        r.raise_for_status()
        datos = r.json()
        sitios = (datos.get("breaches") or [[]])[0] if isinstance(datos.get("breaches"), list) else []
        return [{"sitio": s_, "fecha": None, "datos": [], "cuentas": None} for s_ in sitios], "xposedornot"
    except red.SinTor as e:
        raise ApiError(503, "tor_requerido", str(e)) from e
    except httpx.HTTPError as e:
        raise ApiError(502, "servicio_no_disponible",
                       "No se pudo consultar el servicio de filtraciones ahora mismo. "
                       "Revise su conexión e intente de nuevo en unos minutos.") from e


def _riesgo(filtraciones: list[dict]) -> str:
    if not filtraciones:
        return "bajo"
    peso = sum(RIESGO_POR_DATOS.get(str(d).lower(), 1) for f in filtraciones for d in (f.get("datos") or []))
    if peso >= 6 or len(filtraciones) >= 5:
        return "critico"
    if peso >= 3 or len(filtraciones) >= 2:
        return "alto"
    return "medio"


def _recomendaciones(filtraciones: list[dict], riesgo: str) -> list[str]:
    if riesgo == "bajo":
        return ["Su correo no aparece en las filtraciones consultadas. Aun así, use una contraseña distinta "
                "por servicio y active la verificación en dos pasos en su correo."]
    pasos = [
        "Cambie la contraseña de su correo primero: quien controla el correo recupera todo lo demás.",
        "Cambie la contraseña en los sitios de la lista y en cualquier otro donde haya usado la misma.",
        "Active la verificación en dos pasos, empezando por el correo y el banco.",
        "Guarde las contraseñas nuevas en la Bóveda: se generan al azar y se cifran en su equipo.",
    ]
    if any("password" in str(d).lower() or "contraseñ" in str(d).lower()
           for f in filtraciones for d in (f.get("datos") or [])):
        pasos.insert(0, "La filtración incluye contraseñas: hágalo hoy, no mañana.")
    if any("card" in str(d).lower() or "bank" in str(d).lower()
           for f in filtraciones for d in (f.get("datos") or [])):
        pasos.append("Incluye datos bancarios: revise sus movimientos y avise a su banco.")
    return pasos
