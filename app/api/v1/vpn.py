"""VPN del celular: su servidor GuardianIA VPN (Google Cloud) + Tor integrado en la app.

Desde v3.8 no hay catálogo de servidores de terceros: el celular se da de alta en SU servidor a través
del PC (/vpn/propio/alta), la IA del celular consulta /vpn/propio/salud, y las sesiones se registran
sin guardar la IP real (/vpn/conectar, /vpn/tunel, /vpn/desconectar).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.core import audit
from app.core.errors import ApiError, not_found
from app.core.plans import features_for
from app.core.ratelimit import limiter
from app.core.security import utcnow
from app.db.models import VpnPeer, VpnServer, VpnSession
from app.schemas.common import Out


router = APIRouter(prefix="/vpn", tags=["VPN: su servidor + Tor"])

def _premium_allowed(plan: str) -> bool:
    return "premium_vpn" in features_for(plan)


def _require_vpn(plan: str) -> None:
    if "basic_vpn" not in features_for(plan):
        raise ApiError(402, "plan_required", "La VPN requiere plan Premium o Enterprise",
                       {"plan_actual": plan})


# ─────────────────────────────────────────── sesiones: conectar y desconectar
# El túnel lo levanta el agente o la app de escritorio; un navegador no puede crear una VPN. Aquí se
# registra la sesión para poder mostrar el tiempo conectado, cortar desde cualquier dispositivo y
# dejar historial. Que el registro y el túnel sean cosas distintas es deliberado: así el usuario ve
# la verdad («pedido pero no confirmado») en vez de un botón verde que miente.
class ConectarIn(BaseModel):
    server_id: str = Field(max_length=40)
    proposito: str = Field("general", pattern="^(general|streaming|gaming|privacy|download|anonimato)$")
    device_id: str | None = Field(None, max_length=36)


class SesionOut(Out):
    id: str
    servidor: str
    ciudad: str
    pais: str
    estado: str
    proposito: str
    iniciada: datetime
    segundos_conectado: int
    latencia_ms: int
    ip_salida: str | None
    ip_previa: str | None
    verificada: bool


# ─────────────────────────── servidor VPN propio de GuardianIA: alta del celular
class AltaPropioIn(BaseModel):
    clave_publica: str = Field(min_length=44, max_length=44)
    nombre: str | None = Field(None, max_length=40)


@router.get("/propio")
def propio_estado(p: CurrentUser):
    """El celular pregunta si el PC tiene conectado un servidor GuardianIA VPN (sin datos secretos)."""
    from app.local import vpn_propio
    if not vpn_propio.configurado() or vpn_propio.dueno() != p.user.id:
        return {"configurado": False}
    e = vpn_propio.estado(consultar=False)
    return {"configurado": True, "region": e.get("region"), "pais": e.get("pais")}


@router.get("/propio/salud")
def propio_salud(p: CurrentUser):
    """Señales para la IA del celular: ¿su servidor responde?, latencia y cupo del mes usado.
    Solo el dueño; sin direcciones ni claves. Si el PC no puede consultar, los valores van en null."""
    from app.local import privacidad, vpn_propio
    if not vpn_propio.configurado() or vpn_propio.dueno() != p.user.id:
        return {"configurado": False}
    limiter.hit(f"vpn-propio-salud:{p.user.id}", 60, 600)
    return {"configurado": True, **privacidad.resumen_para_celular()}


@router.post("/propio/alta")
def propio_alta(body: AltaPropioIn, p: CurrentUser, db: DB):
    """Da de alta el celular en el servidor VPN propio. La ficha secreta NUNCA sale del PC: el celular
    solo envía su clave PÚBLICA y recibe su configuración. Solo el dueño del servidor puede hacerlo."""
    from app.local import vpn_propio
    if not vpn_propio.configurado():
        raise ApiError(409, "sin_servidor_propio", "Primero conecte su servidor GuardianIA VPN en el PC "
                       "(Protección → VPN → «Mi servidor GuardianIA VPN»).")
    if vpn_propio.dueno() != p.user.id:
        raise ApiError(403, "no_es_dueno", "Ese servidor VPN pertenece a otra cuenta de este PC.")
    limiter.hit(f"vpn-propio-alta:{p.user.id}", 10, 3600)
    try:
        r = vpn_propio.alta_dispositivo(body.clave_publica, body.nombre)
    except vpn_propio.ErrorPropio as e:
        raise ApiError(502, "servidor_propio", str(e))
    audit.record(db, "vpn.propio.alta_dispositivo", actor_id=p.user.id, detail={"region": r.get("region")})
    return r


# ─────────────────────────── política sin registros
# El servidor NO guarda la IP real del usuario: ni en la sesión ni en la auditoría. Solo se guarda si
# la IP cambió (verificada) y la IP de salida, que es la del servidor/proveedor. Las sesiones cerradas
# se borran a las 24 h. Un registro que une su identidad con su IP real es justo lo que una VPN que
# busca anonimato no debe tener.
RETENCION_SESIONES = timedelta(hours=24)


def purgar_registros(db, user_id: str) -> None:
    """Borra IPs reales guardadas por versiones anteriores y las sesiones cerradas de más de 24 h."""
    limite = utcnow() - RETENCION_SESIONES
    for s in db.execute(select(VpnSession).where(VpnSession.user_id == user_id)).scalars():
        s.ip_previa = None
        if s.estado in ("cerrada", "error") and s.cerrada_at is not None and _con_zona(s.cerrada_at) < limite:
            db.delete(s)


# Estados que cuentan como «hay algo en curso»: incluye la conexión no verificada, porque el
# usuario debe poder cerrarla desde la interfaz.
ACTIVAS = ("conectando", "conectada", "sin_verificar")


def _con_zona(momento: datetime) -> datetime:
    """SQLite devuelve fechas sin zona; restarlas contra una con zona revienta. Se normaliza a UTC."""
    return momento if momento.tzinfo else momento.replace(tzinfo=UTC)


def _duracion_s(inicio: datetime, fin: datetime | None) -> int:
    return max(0, int((_con_zona(fin or utcnow()) - _con_zona(inicio)).total_seconds()))


def _a_salida(sesion: VpnSession, servidor: VpnServer | None) -> SesionOut:
    fin = sesion.cerrada_at or utcnow()
    return SesionOut(id=sesion.id, servidor=sesion.server_id,
                     ciudad=servidor.city if servidor else "—", pais=servidor.country if servidor else "—",
                     estado=sesion.estado, proposito=sesion.proposito, iniciada=sesion.iniciada_at,
                     segundos_conectado=_duracion_s(sesion.iniciada_at, fin),
                     latencia_ms=sesion.latencia_ms, ip_salida=sesion.ip_salida,
                     ip_previa=None, verificada=sesion.verificada)   # la IP real nunca sale del equipo


@router.post("/conectar", response_model=SesionOut, status_code=201)
def conectar(body: ConectarIn, request: Request, p: CurrentUser, db: DB):
    _require_vpn(p.user.plan)
    limiter.hit(f"vpn-conectar:{p.user.id}", 20, 600)
    servidor = db.get(VpnServer, body.server_id)
    if servidor is None or not servidor.active:
        raise not_found("servidor")
    if servidor.is_premium and not _premium_allowed(p.user.plan):
        raise ApiError(402, "plan_required", "Ese servidor requiere plan Enterprise")
    if not servidor.public_key or not servidor.endpoint:
        # Antes se aceptaba y la sesión quedaba para siempre en «conectando»: no hay túnel posible
        # contra un servidor que no existe. Mejor decirlo de frente y ofrecer la salida real.
        raise ApiError(409, "servidor_sin_tunel",
                       f"«{servidor.city}» es un servidor de ejemplo, sin WireGuard real detrás. Use «Túnel de este "
                       "equipo» con Cloudflare WARP (gratis) o registre un servidor propio.")

    abierta = db.execute(select(VpnSession).where(VpnSession.user_id == p.user.id,
                                                  VpnSession.estado.in_(ACTIVAS))).scalar()
    if abierta:
        # Una sola sesión a la vez: dos túneles simultáneos confunden al usuario y falsean el tiempo.
        abierta.estado = "cerrada"
        abierta.cerrada_at = utcnow()
        abierta.motivo_cierre = "reemplazada"

    purgar_registros(db, p.user.id)
    sesion = VpnSession(user_id=p.user.id, server_id=servidor.id, device_id=body.device_id,
                        proposito=body.proposito, estado="conectando", latencia_ms=servidor.latency_ms)
    db.add(sesion)
    db.flush()
    # Sin IP en la auditoría de la VPN: quedaría como registro de su IP real.
    audit.record(db, "vpn.conectar", actor_id=p.user.id, target_type="vpn_session", target_id=sesion.id,
                 detail={"servidor": servidor.id, "proposito": body.proposito}, commit=False)
    db.commit()
    return _a_salida(sesion, servidor)


class EstadoTunelIn(BaseModel):
    sesion_id: str
    estado: str = Field(pattern="^(conectada|error|cerrada)$")
    ip_salida: str | None = Field(None, max_length=45)
    ip_previa: str | None = Field(None, max_length=45)   # se acepta por compatibilidad, NUNCA se guarda
    ip_cambio: bool | None = None                          # lo que envían las apps nuevas: solo si cambió
    latencia_ms: int = Field(0, ge=0, le=60000)
    motivo: str | None = Field(None, max_length=60)


@router.post("/tunel", response_model=SesionOut)
def confirmar_tunel(body: EstadoTunelIn, p: CurrentUser, db: DB):
    """El agente informa el resultado del túnel, con la IP pública antes y después.

    Regla dura: «conectada» exige que la IP haya cambiado de verdad. Si alguien reporta conexión sin
    demostrarlo, la sesión queda «sin_verificar» y la interfaz lo dice. Un panel de seguridad que
    afirma que su tráfico va cifrado cuando no lo está es peor que no tener panel.
    """
    sesion = db.get(VpnSession, body.sesion_id)
    if sesion is None or sesion.user_id != p.user.id:
        raise not_found("sesión")
    if body.latencia_ms:
        sesion.latencia_ms = body.latencia_ms
    sesion.ip_salida = body.ip_salida
    sesion.ip_previa = None                                # política sin registros

    if body.estado == "conectada":
        cambio = body.ip_cambio if body.ip_cambio is not None else bool(
            body.ip_salida and body.ip_previa and body.ip_salida != body.ip_previa)
        sesion.verificada = cambio
        sesion.estado = "conectada" if cambio else "sin_verificar"
        if not cambio:
            sesion.motivo_cierre = "la IP pública no cambió"
    else:
        sesion.estado = body.estado
        sesion.cerrada_at = utcnow()
        sesion.motivo_cierre = body.motivo or body.estado
    db.commit()
    return _a_salida(sesion, db.get(VpnServer, sesion.server_id))


@router.post("/desconectar", response_model=SesionOut)
def desconectar(request: Request, p: CurrentUser, db: DB):
    sesion = db.execute(select(VpnSession).where(VpnSession.user_id == p.user.id,
                                                 VpnSession.estado.in_(ACTIVAS))
                        .order_by(VpnSession.iniciada_at.desc())).scalar()
    if sesion is None:
        raise ApiError(409, "sin_sesion", "No hay ninguna conexión de VPN activa")
    sesion.estado = "cerrada"
    sesion.cerrada_at = utcnow()
    sesion.motivo_cierre = "usuario"
    audit.record(db, "vpn.desconectar", actor_id=p.user.id, target_type="vpn_session", target_id=sesion.id,
                 detail={"segundos": _duracion_s(sesion.iniciada_at, sesion.cerrada_at)},
                 commit=False)
    db.commit()
    return _a_salida(sesion, db.get(VpnServer, sesion.server_id))


@router.get("/sesion")
def sesion_actual(p: CurrentUser, db: DB):
    """Sesión en curso, si la hay. La interfaz lo consulta para pintar el botón y el cronómetro."""
    sesion = db.execute(select(VpnSession).where(VpnSession.user_id == p.user.id,
                                                 VpnSession.estado.in_(ACTIVAS))
                        .order_by(VpnSession.iniciada_at.desc())).scalar()
    return None if sesion is None else _a_salida(sesion, db.get(VpnServer, sesion.server_id))


@router.get("/sesiones", response_model=list[SesionOut])
def historial_sesiones(p: CurrentUser, db: DB, limit: int = Query(15, ge=1, le=50)):
    filas = db.execute(select(VpnSession).where(VpnSession.user_id == p.user.id)
                       .order_by(VpnSession.iniciada_at.desc()).limit(limit)).scalars().all()
    return [_a_salida(f, db.get(VpnServer, f.server_id)) for f in filas]


@router.get("/uso")
def uso(p: CurrentUser, db: DB):
    """Cuánto ha usado la VPN: sirve para el resumen y para justificar el plan."""
    desde = utcnow() - timedelta(days=30)
    filas = db.execute(select(VpnSession).where(VpnSession.user_id == p.user.id,
                                                VpnSession.iniciada_at >= desde)).scalars().all()
    total = sum(_duracion_s(f.iniciada_at, f.cerrada_at) for f in filas)
    por_pais: dict[str, int] = {}
    for f in filas:
        servidor = db.get(VpnServer, f.server_id)
        if servidor:
            por_pais[servidor.country] = por_pais.get(servidor.country, 0) + 1
    return {"sesiones_30d": len(filas), "segundos_30d": total,
            "horas_30d": round(total / 3600, 1), "por_pais": por_pais}


# ═════════════════════════════════════ túnel real (WireGuard)
# El servidor entrega la configuración; el túnel lo levanta el agente con privilegios. La clave
# privada se genera en el equipo y nunca viaja: aquí solo se conoce la pública. Así, ni una fuga de
# esta base permite suplantar un dispositivo o descifrar tráfico.
RED_TUNEL = "10.66.0."
PRIMERA_IP = 2
ULTIMA_IP = 250


class PeerIn(BaseModel):
    server_id: str = Field(max_length=40)
    device_id: str = Field(max_length=36)
    public_key: str = Field(min_length=40, max_length=64,
                            description="Clave pública WireGuard del dispositivo (base64)")


class ConfigOut(Out):
    sesion_id: str | None
    interfaz: dict
    par: dict
    archivo: str
    servidor: str
    aviso: str


def _asignar_ip(db, servidor: VpnServer, user_id: str, device_id: str, public_key: str) -> VpnPeer:
    """Da al dispositivo una IP fija dentro del túnel, o reutiliza la suya si ya la tenía."""
    peer = db.execute(select(VpnPeer).where(VpnPeer.server_id == servidor.id,
                                            VpnPeer.device_id == device_id)).scalar()
    if peer:
        peer.public_key = public_key      # el equipo rotó sus claves: se acepta la nueva
        peer.activo = True
        return peer
    usadas = {p.ip_tunel for p in db.execute(select(VpnPeer).where(VpnPeer.server_id == servidor.id)).scalars()}
    for n in range(PRIMERA_IP, ULTIMA_IP + 1):
        candidata = f"{RED_TUNEL}{n}"
        if candidata not in usadas:
            peer = VpnPeer(user_id=user_id, device_id=device_id, server_id=servidor.id,
                           public_key=public_key, ip_tunel=candidata)
            db.add(peer)
            db.flush()
            return peer
    raise ApiError(507, "sin_ips", "El servidor no tiene direcciones libres en el túnel")


@router.post("/peer", response_model=ConfigOut, status_code=201)
def registrar_peer(body: PeerIn, p: CurrentUser, db: DB):
    """Registra la clave pública del dispositivo y devuelve su configuración de WireGuard."""
    _require_vpn(p.user.plan)
    servidor = db.get(VpnServer, body.server_id)
    if servidor is None or not servidor.active:
        raise not_found("servidor")
    if servidor.is_premium and not _premium_allowed(p.user.plan):
        raise ApiError(402, "plan_required", "Ese servidor requiere plan Enterprise")
    if not servidor.public_key or not servidor.endpoint:
        # Es el caso de los servidores de ejemplo: se dice con claridad en vez de entregar una
        # configuración que nunca va a levantar.
        raise ApiError(409, "servidor_sin_tunel",
                       f"«{servidor.city}» es un servidor de ejemplo: no tiene un WireGuard real detrás. "
                       "Registre uno propio con: python -m app.cli vpn-servidor")

    peer = _asignar_ip(db, servidor, p.user.id, body.device_id, body.public_key)
    sesion = db.execute(select(VpnSession).where(VpnSession.user_id == p.user.id,
                                                 VpnSession.estado.in_(("conectando", "conectada")))
                        .order_by(VpnSession.iniciada_at.desc())).scalar()
    db.commit()

    interfaz = {"Address": f"{peer.ip_tunel}/32", "DNS": servidor.dns}
    par = {"PublicKey": servidor.public_key, "Endpoint": servidor.endpoint,
           # 0.0.0.0/0 = todo el tráfico por el túnel. Es lo que hace que la IP pública cambie;
           # con una ruta parcial, el navegador seguiría saliendo por la conexión normal.
           "AllowedIPs": "0.0.0.0/0, ::/0", "PersistentKeepalive": "25"}
    archivo = ("[Interface]\n"
               f"PrivateKey = <la genera su equipo, no sale de él>\n"
               f"Address = {interfaz['Address']}\n"
               f"DNS = {interfaz['DNS']}\n\n"
               "[Peer]\n"
               f"PublicKey = {par['PublicKey']}\n"
               f"Endpoint = {par['Endpoint']}\n"
               f"AllowedIPs = {par['AllowedIPs']}\n"
               f"PersistentKeepalive = {par['PersistentKeepalive']}\n")
    return ConfigOut(sesion_id=sesion.id if sesion else None, interfaz=interfaz, par=par, archivo=archivo,
                     servidor=f"{servidor.city}, {servidor.country}",
                     aviso="La clave privada se genera en su equipo y nunca se envía al servidor.")


class VerificarIn(BaseModel):
    sesion_id: str
    ip_observada: str = Field(max_length=45, description="IP pública vista desde el equipo con el túnel arriba")


@router.post("/verificar")
def verificar_tunel(body: VerificarIn, p: CurrentUser, db: DB):
    """Comprueba de verdad que el tráfico sale por el servidor.

    Es la única prueba que vale: si la IP pública del equipo, con el túnel arriba, coincide con la
    del servidor, el tráfico va por ahí. Si no coincide, la sesión se marca como NO verificada,
    aunque el cliente crea lo contrario. Un botón verde que miente es peor que no tener botón.
    """
    sesion = db.get(VpnSession, body.sesion_id)
    if sesion is None or sesion.user_id != p.user.id:
        raise not_found("sesión")
    servidor = db.get(VpnServer, sesion.server_id)
    esperada = (servidor.ip_salida if servidor else None)
    coincide = bool(esperada) and body.ip_observada.strip() == esperada
    sesion.ip_salida = body.ip_observada.strip()
    sesion.verificada = coincide
    # Mismo criterio que /tunel: sin prueba, la sesión queda «sin_verificar» y la interfaz lo dice.
    sesion.estado = "conectada" if coincide else "sin_verificar"
    if not coincide:
        sesion.motivo_cierre = "la IP pública no coincide con la del servidor"
    db.commit()
    return {
        "verificada": coincide,
        "ip_observada": sesion.ip_salida,
        "ip_esperada": esperada,
        "mensaje": ("Tráfico saliendo por el servidor: túnel confirmado." if coincide
                    else "La IP pública de su equipo no es la del servidor: el tráfico NO va por el túnel."
                         + ("" if esperada else " Además, este servidor no tiene IP de salida registrada.")),
    }
