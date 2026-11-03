"""Agente local: el Ãºnico componente que puede tocar el disco del equipo.

Arquitectura, y por quÃ© es asÃ­:

    agente con privilegios  â†â†’  este backend  â†â†’  consola web
      (escanea, aÃ­sla)          (decide, registra)   (usted ordena)

El navegador no puede ni debe escanear discos: su sandbox lo impide, y un sitio web capaz de leer y
borrar archivos serÃ­a exactamente el problema que decimos resolver. Por eso hay un agente que corre
como servicio del sistema (SYSTEM en Windows, root en Linux) y habla con esta API.

Principios de seguridad del canal, que es donde un antivirus mal diseÃ±ado se vuelve el arma:

1. **El servidor nunca ordena ejecutar nada.** Las tareas posibles son un conjunto cerrado:
   escanear una ruta, aislar un archivo por su hash, restaurar o eliminar algo que ya estÃ¡ en
   cuarentena. No existe Â«ejecuta este comandoÂ», y el agente rechaza lo que no estÃ© en esa lista.
2. **Nada se borra desde el servidor.** Eliminar es siempre una decisiÃ³n de la persona, tomada en la
   consola sobre un archivo que ya estÃ¡ aislado; el agente solo la ejecuta.
3. **El agente se autentica con el token del dispositivo**, no con la sesiÃ³n del usuario: un servicio
   del sistema no puede depender de que alguien tenga la sesiÃ³n abierta.
4. **Los archivos no se suben.** El agente manda huellas y rasgos; el binario sospechoso se queda
   cifrado en la cuarentena local del propio equipo.
"""
from __future__ import annotations

from datetime import UTC, timedelta

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.ai import antivirus as av
from app.api.deps import DB, CurrentUser, client_ip
from app.core import audit
from app.core.errors import ApiError, conflict, not_found
from app.core.ratelimit import limiter
from app.core.security import token_hash, utcnow
from app.db.models import Agent, Device, QuarantineItem, ScanRun, VpnPeer, VpnServer, VpnSession
from app.schemas.common import Msg, Out
from app.schemas.security import FileScanIn
from app.services.alerts import notify, raise_alert

router = APIRouter(tags=["Agente de protecciÃ³n"])

VERSION_AGENTE = "1.0.0"
MAX_LOTE = 200
LATIDO_SEGUNDOS = 60


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ autenticaciÃ³n
class AgenteAuth(BaseModel):
    device_token: str = Field(min_length=20)


def _agente(db, token: str) -> tuple[Agent, Device]:
    """Resuelve el agente por el token de su dispositivo. Nunca por id: serÃ­a suplantable."""
    device = db.execute(select(Device).where(Device.device_token_hash == token_hash(token))).scalar()
    if device is None or device.status == "wiped":
        raise ApiError(401, "invalid_device_token", "Dispositivo no reconocido")
    agente = db.execute(select(Agent).where(Agent.device_id == device.id)).scalar()
    if agente is None:
        raise ApiError(409, "agente_no_registrado", "Registre el agente primero con /v1/agente/registrar")
    return agente, device


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ registro
class RegistroIn(AgenteAuth):
    hostname: str = Field(max_length=120)
    so: str = Field(max_length=60)
    version: str = Field(max_length=20)
    privilegios: bool = False


@router.post("/agente/registrar", status_code=201)
def registrar(body: RegistroIn, request: Request, db: DB):
    device = db.execute(select(Device).where(Device.device_token_hash == token_hash(body.device_token))).scalar()
    if device is None or device.status == "wiped":
        raise ApiError(401, "invalid_device_token", "Dispositivo no reconocido")
    agente = db.execute(select(Agent).where(Agent.device_id == device.id)).scalar()
    if agente is None:
        agente = Agent(user_id=device.user_id, device_id=device.id)
        db.add(agente)
    agente.hostname, agente.so, agente.version = body.hostname, body.so, body.version
    agente.ultimo_latido = utcnow()
    db.flush()
    audit.record(db, "agente.registrado", actor_id=device.user_id, target_type="agent", target_id=agente.id,
                 ip=client_ip(request), detail={"so": body.so, "version": body.version,
                                                "privilegios": body.privilegios}, commit=False)
    if not body.privilegios:
        notify(db, device.user_id, "El agente corre sin privilegios",
               f"En {body.hostname} el agente no se ejecuta como administrador: podrÃ¡ revisar sus carpetas "
               "personales, pero no todo el disco ni poner archivos del sistema en cuarentena.",
               kind="agente.privilegios", severity="medium")
    db.commit()
    return {"agente_id": agente.id, "intervalo_latido_s": LATIDO_SEGUNDOS,
            "politica": _politica(agente), "version_servidor": VERSION_AGENTE}


def _politica(a: Agent) -> dict:
    return {"tiempo_real": a.tiempo_real, "cuarentena_automatica": a.cuarentena_automatica,
            # El agente decide solo cuÃ¡ndo tocan los anÃ¡lisis: nadie tiene que ejecutar nada.
            "auto_rapido_horas": a.auto_rapido_horas, "auto_completo_dias": a.auto_completo_dias,
            "extensiones_vigiladas": [".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                                      ".jar", ".apk", ".docm", ".xlsm", ".zip", ".rar", ".iso", ".lnk"],
            "rutas_excluidas": ["/proc", "/sys", "/dev", "C:\\\\Windows\\\\WinSxS", "C:\\\\Windows\\\\servicing"],
            "max_bytes_por_archivo": 256 * 1024 * 1024}


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ latido
class LatidoIn(AgenteAuth):
    cpu_percent: float = Field(0, ge=0, le=100)
    archivos_protegidos: int = Field(0, ge=0)
    tiempo_real_activo: bool = True
    # Progreso del anÃ¡lisis en curso, para que la web lo muestre sin preguntarle al usuario.
    progreso: dict | None = None


@router.post("/agente/latido")
def latido(body: LatidoIn, db: DB):
    """El agente dice que sigue vivo y recoge las tareas pendientes.

    Las tareas son un conjunto cerrado. Si algÃºn dÃ­a alguien compromete este servidor, lo mÃ¡s que
    puede hacer contra un equipo es pedirle que escanee: no hay forma de decirle Â«ejecuta estoÂ».
    """
    agente, device = _agente(db, body.device_token)
    limiter.hit(f"latido:{agente.id}", 6)
    agente.ultimo_latido = utcnow()
    agente.cpu_percent = body.cpu_percent
    if body.progreso is not None:
        agente.progreso = {k: v for k, v in body.progreso.items()
                           if k in ("modo", "revisados", "total", "actual", "estado", "iniciado")}
    if body.archivos_protegidos:
        agente.archivos_protegidos = body.archivos_protegidos

    tareas: list[dict] = []
    # Tarea de VPN: si hay una sesiÃ³n pidiendo tÃºnel para este equipo, se manda la configuraciÃ³n.
    sesion = db.execute(select(VpnSession).where(
        VpnSession.user_id == device.user_id, VpnSession.estado == "conectando",
        VpnSession.device_id.in_((device.id, None)))
        .order_by(VpnSession.iniciada_at.desc())).scalar()
    if sesion:
        servidor = db.get(VpnServer, sesion.server_id)
        peer = db.execute(select(VpnPeer).where(VpnPeer.server_id == sesion.server_id,
                                                VpnPeer.device_id == device.id)).scalar()
        if servidor and servidor.public_key and servidor.endpoint and not peer:
            # El agente aÃºn no tiene clave registrada: se le pide que la genere y la registre Ã©l mismo.
            tareas.append({"tipo": "vpn_conectar", "sesion_id": sesion.id, "registrar_en": servidor.id})
        elif servidor and servidor.public_key and servidor.endpoint and peer:
            tareas.append({"tipo": "vpn_conectar", "sesion_id": sesion.id, "config": {
                "interfaz": {"Address": f"{peer.ip_tunel}/32", "DNS": servidor.dns},
                "par": {"PublicKey": servidor.public_key, "Endpoint": servidor.endpoint,
                        "AllowedIPs": "0.0.0.0/0, ::/0", "PersistentKeepalive": "25"}}})
    cerradas = db.execute(select(VpnSession).where(
        VpnSession.user_id == device.user_id, VpnSession.estado == "cerrada",
        VpnSession.cerrada_at.is_not(None), VpnSession.device_id == device.id)
        .order_by(VpnSession.cerrada_at.desc()).limit(1)).scalar()
    if cerradas and agente.ultimo_latido and cerradas.cerrada_at > agente.ultimo_latido:
        tareas.append({"tipo": "vpn_desconectar", "sesion_id": cerradas.id})
    if agente.escaneo_pedido:
        tareas.append({"tipo": "escanear", "modo": agente.escaneo_pedido, "ruta": agente.ruta_pedida})
        agente.escaneo_pedido = agente.ruta_pedida = None
    for item in db.execute(select(QuarantineItem).where(
            QuarantineItem.device_id == device.id,
            QuarantineItem.estado.in_(("pendiente_restaurar", "pendiente_eliminar")))).scalars():
        tareas.append({"tipo": "restaurar" if item.estado == "pendiente_restaurar" else "eliminar",
                       "cuarentena_id": item.id, "sha256": item.sha256})
    db.commit()
    return {"tareas": tareas, "politica": _politica(agente), "intervalo_latido_s": LATIDO_SEGUNDOS}


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ escaneo
class HallazgoAgente(BaseModel):
    archivo: FileScanIn
    ruta: str = Field(max_length=400)


class ReporteIn(AgenteAuth):
    tipo: str = Field("completo", pattern="^(rapido|completo|personalizado|tiempo_real)$")
    final: bool = True
    ruta: str | None = Field(None, max_length=400)
    archivos_revisados: int = Field(0, ge=0)
    archivos_omitidos: int = Field(0, ge=0)
    duracion_ms: int = Field(0, ge=0)
    candidatos: list[HallazgoAgente] = Field(default_factory=list, max_length=MAX_LOTE)


class VeredictoOut(Out):
    sha256: str
    nivel: str
    probabilidad: float
    familia: str | None
    motivos: list[str]
    accion: str          # ninguna | aislar


@router.post("/agente/escaneo")
def reportar_escaneo(body: ReporteIn, db: DB):
    """El agente envÃ­a los candidatos y el servidor decide el veredicto y la acciÃ³n.

    La decisiÃ³n se toma aquÃ­ a propÃ³sito: asÃ­ la polÃ­tica y el motor se actualizan en un solo lugar
    y no hay que redistribuir el agente cada vez que cambia una regla.
    """
    agente, device = _agente(db, body.device_token)
    limiter.hit(f"agente-escaneo:{agente.id}", 300, 600)

    veredictos: list[VeredictoOut] = []
    maliciosos = sospechosos = 0
    for candidato in body.candidatos:
        a = candidato.archivo
        resultado = av.scan_file(av.FileSample(
            name=a.name, size=a.size, sha256=a.sha256.lower(), kind=a.kind, header_hex=a.header_hex,
            strings=a.strings, entropy=a.entropy, imports=a.imports, yara_hits=a.yara_hits,
            is_signed=a.is_signed, signer=a.signer))
        if resultado.level == "limpio":
            continue
        if resultado.level == "malicioso":
            maliciosos += 1
        else:
            sospechosos += 1
        # Solo se aÃ­sla lo malicioso, y solo si la persona dejÃ³ activa la cuarentena automÃ¡tica.
        # Un sospechoso no se toca: el falso positivo que borra el trabajo de alguien hace mÃ¡s daÃ±o
        # que el archivo dudoso que se queda quieto.
        aislar = resultado.level == "malicioso" and agente.cuarentena_automatica
        veredictos.append(VeredictoOut(
            sha256=a.sha256.lower(), nivel=resultado.level,
            probabilidad=round(resultado.malicious_probability, 3), familia=resultado.family_guess,
            motivos=[d.reason for d in resultado.detections][:4],
            accion="aislar" if aislar else "ninguna"))

    limpios = max(0, body.archivos_revisados - maliciosos - sospechosos)
    corrida = ScanRun(user_id=device.user_id, origen="agente", device_id=device.id, tipo=body.tipo,
                      total=body.archivos_revisados, limpios=limpios, sospechosos=sospechosos,
                      maliciosos=maliciosos, omitidos=body.archivos_omitidos, duracion_ms=body.duracion_ms,
                      hallazgos=[{"nombre": v.sha256[:12], "nivel": v.nivel, "probabilidad": v.probabilidad,
                                  "familia": v.familia, "motivos": v.motivos, "sha256": v.sha256}
                                 for v in veredictos[:20]])
    db.add(corrida)
    agente.ultimo_escaneo = utcnow()
    agente.amenazas_totales += maliciosos
    if body.final:
        agente.progreso = {}
        if body.tipo == "rapido":
            agente.ultimo_rapido = utcnow()
        elif body.tipo == "completo":
            agente.ultimo_completo = utcnow()
    if maliciosos:
        raise_alert(db, user_id=device.user_id, category="device", severity="high",
                    title=f"{maliciosos} amenaza(s) en {agente.hostname or 'su equipo'}",
                    description=f"El anÃ¡lisis {body.tipo} encontrÃ³ {maliciosos} archivo(s) malicioso(s)"
                                + (" y se aislaron automÃ¡ticamente." if agente.cuarentena_automatica
                                   else ". La cuarentena automÃ¡tica estÃ¡ desactivada: revÃ­selos en ProtecciÃ³n."),
                    data={"device_id": device.id, "scan_run": corrida.id}, engine=av.ENGINE_VERSION)
    db.commit()
    return {"veredictos": veredictos, "scan_run": corrida.id}


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ tÃºnel VPN
class PeerAgenteIn(AgenteAuth):
    server_id: str = Field(max_length=40)
    public_key: str = Field(min_length=40, max_length=64)


@router.post("/agente/vpn/peer", status_code=201)
def peer_del_agente(body: PeerAgenteIn, db: DB):
    """El agente registra su propia clave pÃºblica y recibe la configuraciÃ³n del tÃºnel.

    Se hace con el token del dispositivo y no con la sesiÃ³n del usuario: el agente debe poder
    reconectar el tÃºnel tras un reinicio, aunque nadie haya abierto la web.
    """
    from app.api.v1.vpn import _asignar_ip
    agente, device = _agente(db, body.device_token)
    servidor = db.get(VpnServer, body.server_id)
    if servidor is None or not servidor.active:
        raise not_found("servidor")
    if not servidor.public_key or not servidor.endpoint:
        raise conflict("servidor_sin_tunel", f"Â«{servidor.city}Â» es un servidor de ejemplo, sin WireGuard detrÃ¡s")
    peer = _asignar_ip(db, servidor, device.user_id, device.id, body.public_key)
    db.commit()
    return {"interfaz": {"Address": f"{peer.ip_tunel}/32", "DNS": servidor.dns},
            "par": {"PublicKey": servidor.public_key, "Endpoint": servidor.endpoint,
                    "AllowedIPs": "0.0.0.0/0, ::/0", "PersistentKeepalive": "25"},
            "ip_salida_esperada": servidor.ip_salida}


class EstadoTunelAgenteIn(AgenteAuth):
    sesion_id: str
    estado: str = Field(pattern="^(conectada|error|cerrada)$")
    ip_salida: str | None = Field(None, max_length=45)
    ip_previa: str | None = Field(None, max_length=45)
    motivo: str | None = Field(None, max_length=60)


@router.post("/agente/vpn/estado")
def estado_tunel_agente(body: EstadoTunelAgenteIn, db: DB):
    """El agente informa si el tÃºnel quedÃ³ arriba, probÃ¡ndolo con el cambio de IP pÃºblica."""
    from app.db.models import VpnSession as _Sesion
    _agente_, device = _agente(db, body.device_token)
    sesion = db.get(_Sesion, body.sesion_id)
    if sesion is None or sesion.user_id != device.user_id:
        raise not_found("sesiÃ³n")
    sesion.ip_salida, sesion.ip_previa = body.ip_salida, body.ip_previa
    cambio = bool(body.ip_salida and body.ip_previa and body.ip_salida != body.ip_previa)
    sesion.verificada = cambio and body.estado == "conectada"
    if body.estado == "conectada":
        # Sin cambio de IP no hay tÃºnel, diga lo que diga el cliente.
        sesion.estado = "conectada" if cambio else "sin_verificar"
        if not cambio:
            sesion.motivo_cierre = "la IP pÃºblica no cambiÃ³"
    else:
        sesion.estado = "cerrada" if body.estado == "cerrada" else "error"
        sesion.cerrada_at = utcnow()
        sesion.motivo_cierre = body.motivo or body.estado
    db.commit()
    return {"estado": sesion.estado, "verificada": sesion.verificada}


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ cuarentena
class ItemCuarentena(BaseModel):
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    filename: str = Field(max_length=200)
    ruta_original: str = Field("", max_length=400)
    size_bytes: int = Field(0, ge=0)
    nivel: str = Field("malicioso", pattern="^(sospechoso|malicioso)$")
    familia: str | None = Field(None, max_length=60)
    motivos: list[str] = Field(default_factory=list, max_length=6)


class CuarentenaIn(AgenteAuth):
    items: list[ItemCuarentena] = Field(min_length=1, max_length=50)


@router.post("/agente/cuarentena", status_code=201)
def registrar_cuarentena(body: CuarentenaIn, db: DB):
    """El agente informa lo que ya aislÃ³ en el propio equipo."""
    agente, device = _agente(db, body.device_token)
    creados = []
    for item in body.items:
        fila = QuarantineItem(user_id=device.user_id, device_id=device.id, sha256=item.sha256.lower(),
                              filename=item.filename, ruta_original=item.ruta_original,
                              size_bytes=item.size_bytes, nivel=item.nivel, familia=item.familia,
                              motivos=item.motivos[:6])
        db.add(fila)
        db.flush()
        creados.append(fila.id)
    audit.record(db, "agente.cuarentena", actor_id=device.user_id, target_type="device", target_id=device.id,
                 level="warning", detail={"archivos": len(creados)}, commit=False)
    notify(db, device.user_id, f"{len(creados)} archivo(s) puestos en cuarentena",
           f"En {agente.hostname or 'su equipo'}. Los archivos quedaron cifrados y sin poder ejecutarse. "
           "Puede restaurarlos o eliminarlos definitivamente desde ProtecciÃ³n.",
           kind="cuarentena", severity="high", data={"device_id": device.id})
    db.commit()
    return {"ids": creados}


class ResultadoTareaIn(AgenteAuth):
    cuarentena_id: str
    estado: str = Field(pattern="^(restaurado|eliminado|error)$")
    detalle: str | None = Field(None, max_length=200)


@router.post("/agente/cuarentena/resultado", response_model=Msg)
def resultado_tarea(body: ResultadoTareaIn, db: DB):
    _agente_, device = _agente(db, body.device_token)
    item = db.get(QuarantineItem, body.cuarentena_id)
    if item is None or item.device_id != device.id:
        raise not_found("elemento en cuarentena")
    item.estado = body.estado
    item.detalle_error = body.detalle
    item.resuelto_at = utcnow()
    db.commit()
    return Msg(mensaje="Resultado registrado")


@router.get("/agente/firmas")
def firmas(device_token: str, db: DB):
    """Hashes que este servidor ya sabe maliciosos, para que el agente decida sin preguntar.

    Sirve para dos cosas: rapidez (no hay que consultar por cada archivo) y trabajo sin conexiÃ³n.
    """
    _agente(db, device_token)
    filas = db.execute(select(QuarantineItem.sha256).where(QuarantineItem.nivel == "malicioso")
                       .distinct().limit(5000)).scalars().all()
    return {"version": utcnow().strftime("%Y%m%d%H"), "hashes": list(filas),
            "reglas_motor": av.ENGINE_VERSION}


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ lado de la persona (web)
@router.get("/proteccion/agentes")
def listar_agentes(p: CurrentUser, db: DB):
    filas = db.execute(select(Agent, Device).join(Device, Agent.device_id == Device.id)
                       .where(Agent.user_id == p.user.id)).all()
    ahora = utcnow()
    salida = []
    for agente, device in filas:
        # SQLite devuelve fechas sin zona: restarlas contra una con zona revienta.
        latido = agente.ultimo_latido
        if latido is not None and latido.tzinfo is None:
            latido = latido.replace(tzinfo=UTC)
        en_linea = latido is not None and (ahora - latido) < timedelta(minutes=5)
        salida.append({
            "id": agente.id, "device_id": device.id, "equipo": agente.hostname or device.name,
            "so": agente.so, "version": agente.version, "en_linea": en_linea,
            "ultimo_latido": agente.ultimo_latido, "ultimo_escaneo": agente.ultimo_escaneo,
            "tiempo_real": agente.tiempo_real, "cuarentena_automatica": agente.cuarentena_automatica,
            "archivos_protegidos": agente.archivos_protegidos, "amenazas_totales": agente.amenazas_totales,
            "cpu_percent": agente.cpu_percent,
            "escaneo_pendiente": agente.escaneo_pedido,
            "progreso": agente.progreso or None,
            "auto_rapido_horas": agente.auto_rapido_horas,
            "auto_completo_dias": agente.auto_completo_dias,
            "ultimo_rapido": agente.ultimo_rapido, "ultimo_completo": agente.ultimo_completo,
            "en_cuarentena": db.execute(select(func.count()).select_from(QuarantineItem).where(
                QuarantineItem.device_id == device.id, QuarantineItem.estado == "en_cuarentena")).scalar_one(),
        })
    return salida


class OrdenEscaneoIn(BaseModel):
    modo: str = Field("rapido", pattern="^(rapido|completo|personalizado)$")
    ruta: str | None = Field(None, max_length=400)


@router.post("/proteccion/agentes/{agente_id}/escanear", response_model=Msg, status_code=202)
def ordenar_escaneo(agente_id: str, body: OrdenEscaneoIn, request: Request, p: CurrentUser, db: DB):
    agente = db.get(Agent, agente_id)
    if agente is None or agente.user_id != p.user.id:
        raise not_found("agente")
    if body.modo == "personalizado" and not body.ruta:
        raise ApiError(422, "ruta_requerida", "Indique la carpeta que quiere analizar")
    agente.escaneo_pedido = body.modo
    agente.ruta_pedida = body.ruta
    audit.record(db, "proteccion.escaneo_ordenado", actor_id=p.user.id, target_type="agent",
                 target_id=agente.id, ip=client_ip(request), detail={"modo": body.modo}, commit=False)
    db.commit()
    return Msg(mensaje=f"AnÃ¡lisis {body.modo} solicitado. El agente lo iniciarÃ¡ en menos de un minuto.")


class PoliticaIn(BaseModel):
    tiempo_real: bool | None = None
    cuarentena_automatica: bool | None = None
    auto_rapido_horas: int | None = Field(None, ge=0, le=168)     # 0 = desactivado
    auto_completo_dias: int | None = Field(None, ge=0, le=60)


@router.put("/proteccion/agentes/{agente_id}/politica", response_model=Msg)
def cambiar_politica(agente_id: str, body: PoliticaIn, request: Request, p: CurrentUser, db: DB):
    agente = db.get(Agent, agente_id)
    if agente is None or agente.user_id != p.user.id:
        raise not_found("agente")
    if body.tiempo_real is not None:
        agente.tiempo_real = body.tiempo_real
    if body.cuarentena_automatica is not None:
        agente.cuarentena_automatica = body.cuarentena_automatica
    if body.auto_rapido_horas is not None:
        agente.auto_rapido_horas = body.auto_rapido_horas
    if body.auto_completo_dias is not None:
        agente.auto_completo_dias = body.auto_completo_dias
    audit.record(db, "proteccion.politica", actor_id=p.user.id, target_type="agent", target_id=agente.id,
                 ip=client_ip(request), level="warning",
                 detail={"tiempo_real": agente.tiempo_real,
                         "cuarentena_automatica": agente.cuarentena_automatica}, commit=False)
    db.commit()
    return Msg(mensaje="ConfiguraciÃ³n actualizada. El agente la aplicarÃ¡ en el prÃ³ximo latido.")


@router.get("/proteccion/cuarentena")
def listar_cuarentena(p: CurrentUser, db: DB, limit: int = 100):
    filas = db.execute(select(QuarantineItem).where(QuarantineItem.user_id == p.user.id)
                       .order_by(QuarantineItem.created_at.desc()).limit(min(limit, 200))).scalars().all()
    return [{"id": f.id, "archivo": f.filename, "ruta": f.ruta_original, "sha256": f.sha256,
             "bytes": f.size_bytes, "nivel": f.nivel, "familia": f.familia, "motivos": f.motivos,
             "estado": f.estado, "creado": f.created_at, "resuelto": f.resuelto_at,
             "error": f.detalle_error} for f in filas]


class DecisionIn(BaseModel):
    accion: str = Field(pattern="^(restaurar|eliminar)$")


@router.post("/proteccion/cuarentena/{item_id}/decidir", response_model=Msg, status_code=202)
def decidir_cuarentena(item_id: str, body: DecisionIn, request: Request, p: CurrentUser, db: DB):
    """Restaurar o eliminar definitivamente. Lo ejecuta el agente, no el servidor."""
    item = db.get(QuarantineItem, item_id)
    if item is None or item.user_id != p.user.id:
        raise not_found("elemento en cuarentena")
    if item.estado != "en_cuarentena":
        raise ApiError(409, "ya_resuelto", f"Este archivo ya estÃ¡ en estado Â«{item.estado}Â»")
    item.estado = "pendiente_restaurar" if body.accion == "restaurar" else "pendiente_eliminar"
    audit.record(db, f"cuarentena.{body.accion}", actor_id=p.user.id, target_type="quarantine",
                 target_id=item.id, ip=client_ip(request), level="security",
                 detail={"archivo": item.filename, "sha256": item.sha256, "nivel": item.nivel}, commit=False)
    db.commit()
    mensaje = ("Se restaurarÃ¡ en el equipo cuando el agente reciba la orden."
               if body.accion == "restaurar"
               else "Se eliminarÃ¡ definitivamente del equipo cuando el agente reciba la orden.")
    return Msg(mensaje=mensaje)

