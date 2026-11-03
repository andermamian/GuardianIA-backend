"""Protección de ESTE equipo: antivirus, tiempo real, cuarentena y VPN, sin agente ni PowerShell.

El servidor de GuardianIA corre en el mismo computador que se quiere proteger, así que puede leer el
disco directamente. Antes eso se delegaba a un agente aparte que había que vincular con un código y
arrancar desde PowerShell como administrador; ahora basta con abrir la app.

**Regla de seguridad que no se negocia:** estas rutas solo responden a peticiones que nacen en el
propio equipo (127.0.0.1 / ::1). Si algún día expone el servidor en la red para usar la app desde el
celular, nadie en esa red podrá ordenar analizar, aislar o borrar archivos de este computador, ni
aunque tenga una cuenta válida. Se usa la IP de la conexión, no cabeceras como X-Forwarded-For, que
cualquiera puede falsificar.
"""
from __future__ import annotations

import threading
import time

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.core import audit
from app.core.config import get_settings
from app.core.errors import ApiError, not_found
from app.core.plans import features_for
from app.core.ratelimit import limiter
from app.core.security import utcnow
from app.db.models import QuarantineItem, VpnServer, VpnSession
from app.local import ajustes, cuarentena, ia, kernel, red, sistema
from app.local import vpn as tunel
from app.local.escaner import escaner
from app.local.firmas import base as firmas_base
from app.local.motor import MOTOR_LOCAL
from app.local.tiempo_real import vigilante

LOCALES = {"127.0.0.1", "::1", "localhost"}


def solo_este_equipo(request: Request) -> None:
    host = request.client.host if request.client else ""
    if host in LOCALES or (host == "testclient" and get_settings().env == "test"):
        return
    raise ApiError(403, "solo_local", "La protección del equipo solo se controla desde el propio equipo "
                                      "(https://127.0.0.1:8443). Desde otro dispositivo no está permitido.")


router = APIRouter(prefix="/local", tags=["Protección de este equipo"], dependencies=[Depends(solo_este_equipo)])


# ═══════════════════════════════════════════════════════════ estado
@router.get("/estado")
def estado(p: CurrentUser, db: DB):
    conf = ajustes.leer()
    analisis = escaner.instantanea()
    return {
        "equipo": {"sistema": "Windows" if sistema.ES_WINDOWS else "otro", "administrador": sistema.es_admin(),
                   "nucleos": sistema.nucleos(), "cpu": sistema.cpu_percent(),
                   "unidades": [str(u) for u in sistema.unidades()]},
        "motor": MOTOR_LOCAL, "firmas": firmas_base().estado(),
        "defender": bool(sistema.defender_disponible()),
        "tiempo_real": vigilante.estado(),
        "ajustes": {k: conf[k] for k in ("tiempo_real", "cuarentena_automatica", "segunda_opinion_defender",
                                         "auto_rapido_horas", "auto_completo_dias", "rendimiento")},
        "ultimo_rapido": conf["ultimo_rapido"] or None, "ultimo_completo": conf["ultimo_completo"] or None,
        "es_propietario": conf.get("propietario") == p.user.id,
        "analisis": None if analisis is None else {k: analisis[k] for k in
                                                   ("id", "estado", "modo", "porcentaje", "maliciosos", "terminado")},
        "en_cuarentena": sum(1 for i in cuarentena.listar(db, p.user.id, 500) if i.estado == "en_cuarentena"),
    }


class AjustesIn(BaseModel):
    tiempo_real: bool | None = None
    cuarentena_automatica: bool | None = None
    segunda_opinion_defender: bool | None = None
    auto_rapido_horas: int | None = Field(None, ge=0, le=168)
    auto_completo_dias: int | None = Field(None, ge=0, le=90)
    rendimiento: str | None = Field(None, pattern="^(auto|turbo|silencioso)$")


@router.put("/ajustes")
def cambiar_ajustes(body: AjustesIn, request: Request, p: CurrentUser, db: DB):
    cambios = body.model_dump(exclude_none=True)
    # Quien configura la protección del equipo recibe sus alertas y los análisis automáticos.
    cambios["propietario"] = p.user.id
    conf = ajustes.guardar(cambios)
    if "tiempo_real" in cambios:
        (vigilante.iniciar(p.user.id) if conf["tiempo_real"] else vigilante.detener())
    elif conf["tiempo_real"]:
        vigilante.iniciar(p.user.id)
    escaner.iniciar_programador()
    audit.record(db, "proteccion.ajustes_locales", actor_id=p.user.id, detail=body.model_dump(exclude_none=True))
    return {"mensaje": "Ajustes guardados", "ajustes": {k: conf[k] for k in AjustesIn.model_fields}}


# ═════════════════════════════════════════════════════════ análisis
class EscaneoIn(BaseModel):
    modo: str = Field("rapido", pattern="^(rapido|completo|personalizado)$")
    ruta: str | None = Field(None, max_length=400)
    rendimiento: str | None = Field(None, pattern="^(auto|turbo|silencioso)$")


@router.post("/escaneo", status_code=202)
def iniciar_escaneo(body: EscaneoIn, request: Request, p: CurrentUser, db: DB):
    limiter.hit(f"local-escaneo:{p.user.id}", 20, 600)
    if not ajustes.leer().get("propietario"):
        ajustes.guardar({"propietario": p.user.id})
    try:
        snap = escaner.iniciar(p.user.id, body.modo, body.ruta, body.rendimiento)
    except RuntimeError as e:
        raise ApiError(409, "escaneo_en_curso", str(e)) from e
    except ValueError as e:
        raise ApiError(422, "ruta_invalida", str(e)) from e
    escaner.iniciar_programador()
    audit.record(db, "proteccion.escaneo_local_inicio", actor_id=p.user.id, detail={"modo": body.modo})
    return snap


@router.get("/escaneo")
def progreso(p: CurrentUser):
    """Lo consulta la barra de progreso varias veces por segundo: es solo lectura de memoria."""
    return escaner.instantanea()


def _control(accion) -> dict:
    try:
        return accion()
    except LookupError as e:
        raise ApiError(409, "sin_escaneo", str(e)) from e


@router.post("/escaneo/pausar")
def pausar(p: CurrentUser):
    return _control(escaner.pausar)


@router.post("/escaneo/reanudar")
def reanudar(p: CurrentUser):
    return _control(escaner.reanudar)


@router.post("/escaneo/cancelar")
def cancelar(p: CurrentUser):
    return _control(escaner.cancelar)


@router.get("/eventos")
def eventos(p: CurrentUser):
    return {"tiempo_real": vigilante.estado(), "eventos": list(vigilante.eventos)[:50]}


@router.get("/kernel")
def revisar_kernel(p: CurrentUser):
    """Estado profundo del sistema: drivers sin firma, procesos suplantados y cambios en el arranque.

    No es un análisis de kernel «desde dentro» (eso exige un driver firmado por Microsoft, que este
    proyecto no tiene). Es vigilancia desde afuera con las herramientas nativas de Windows: ver, no
    intervenir. Detecta lo que un rootkit deja a la vista.
    """
    return kernel.revisar_todo()


@router.get("/red")
def revisar_red(p: CurrentUser):
    """Conexiones activas, servidores DNS y estado real de la VPN (incluida detección de fugas)."""
    return red.revisar_todo()


@router.get("/revision-profunda")
def revision_profunda(p: CurrentUser):
    """Kernel + red en una sola llamada, con un veredicto conjunto en lenguaje claro."""
    k = kernel.revisar_todo()
    n = red.revisar_todo()
    peligrosos = k["peligrosos"] + n["peligrosos"]
    sospechosos = k["sospechosos"] + n["sospechosos"]
    if peligrosos:
        estado = "peligro"
        resumen = f"Se encontraron {peligrosos} señal(es) de alto riesgo entre el sistema y la red. Revíselas."
    elif sospechosos:
        estado = "revisar"
        resumen = f"{sospechosos} elemento(s) merecen su revisión, sin ser amenazas confirmadas."
    else:
        estado = "limpio"
        resumen = "El núcleo del sistema y la red se ven limpios."
    return {"estado": estado, "resumen": resumen, "peligrosos": peligrosos, "sospechosos": sospechosos,
            "kernel": k, "red": n}


@router.post("/firmas/actualizar")
def actualizar_firmas(p: CurrentUser, db: DB):
    limiter.hit(f"firmas:{p.user.id}", 6, 3600)
    try:
        r = firmas_base().actualizar()
    except RuntimeError as e:
        raise ApiError(502, "firmas_no_disponibles", str(e)) from e
    audit.record(db, "proteccion.firmas", actor_id=p.user.id, detail=r)
    return {"mensaje": f"Base actualizada: {r['nuevas']} firmas nuevas, {r['total']} en total", **r}


# ═══════════════════════════════════════════════════════ cuarentena
def _item_salida(i: QuarantineItem) -> dict:
    return {"id": i.id, "archivo": i.filename, "ruta": i.ruta_original, "sha256": i.sha256, "bytes": i.size_bytes,
            "nivel": i.nivel, "familia": i.familia, "motivos": i.motivos, "estado": i.estado,
            "error": i.detalle_error, "creado": i.created_at, "resuelto": i.resuelto_at}


@router.get("/analisis/resumen")
def resumen_analisis(p: CurrentUser):
    """Resumen en lenguaje claro del último análisis (con IA si hay modelo; si no, frases locales)."""
    final = escaner.instantanea()
    if not final:
        return {"texto": "Todavía no ha corrido ningún análisis en este equipo.", "por_modelo": False, "hay": False}
    return {**ia.resumen_analisis(final), "hay": True, "estado": final.get("estado")}


class ExplicarIn(BaseModel):
    sha256: str = Field(min_length=64, max_length=64)


@router.post("/analisis/explicar")
def explicar_amenaza(body: ExplicarIn, p: CurrentUser):
    """Explica una amenaza concreta en palabras sencillas."""
    candidatos = []
    snap = escaner.instantanea()
    if snap and isinstance(snap.get("amenazas"), list):
        candidatos += snap["amenazas"]
    candidatos += [e for e in vigilante.eventos if e.get("sha256")]
    a = next((h for h in candidatos if h.get("sha256") == body.sha256), None)
    if a is None:
        raise not_found("amenaza")
    return ia.explicar_amenaza(a)


@router.get("/cuarentena")
def listar_cuarentena(p: CurrentUser, db: DB):
    return [_item_salida(i) for i in cuarentena.listar(db, p.user.id)]


class AislarIn(BaseModel):
    sha256: str = Field(min_length=64, max_length=64)


@router.post("/cuarentena/aislar")
def aislar(body: AislarIn, request: Request, p: CurrentUser, db: DB):
    """Aísla una amenaza que quedó «para su decisión».

    Se recibe la huella, no una ruta: así esta ruta no sirve para mover archivos arbitrarios; solo
    los que el propio motor reportó como amenaza en el análisis o en el tiempo real.
    """
    candidatos = []
    snap = escaner.instantanea()
    if snap and isinstance(snap.get("amenazas"), list):
        candidatos += snap["amenazas"]
    candidatos += [e for e in vigilante.eventos if e.get("sha256")]
    hallazgo = next((h for h in candidatos if h.get("sha256") == body.sha256 and h.get("ruta")), None)
    if hallazgo is None:
        raise not_found("amenaza reportada")
    datos = {"ruta": hallazgo["ruta"], "sha256": body.sha256, "nivel": hallazgo.get("nivel", "sospechoso"),
             "familia": hallazgo.get("familia"), "motivos": hallazgo.get("motivos", [])}
    r = escaner.aislar(p.user.id, datos)
    if r["estado"] != "aislado":
        raise ApiError(409, "no_aislado", r.get("detalle", "No se pudo aislar"))
    hallazgo["estado"] = "aislado"
    audit.record(db, "proteccion.aislar_local", actor_id=p.user.id, detail={"sha256": body.sha256})
    return {"mensaje": "Archivo aislado en cuarentena", **r}


def _item(db, p, item_id: str) -> QuarantineItem:
    i = db.get(QuarantineItem, item_id)
    if i is None or i.user_id != p.user.id or i.device_id != cuarentena.EQUIPO:
        raise not_found("archivo en cuarentena")
    if i.estado != "en_cuarentena":
        raise ApiError(409, "ya_resuelto", "Ese archivo ya fue restaurado o eliminado")
    return i


@router.post("/cuarentena/{item_id}/restaurar")
def restaurar(item_id: str, p: CurrentUser, db: DB):
    i = _item(db, p, item_id)
    try:
        destino = cuarentena.restaurar(db, i)
    except (OSError, ValueError) as e:
        i.detalle_error = str(e)[:200]
        db.commit()
        raise ApiError(409, "no_restaurado", f"No se pudo restaurar: {e}") from e
    audit.record(db, "proteccion.restaurar_local", actor_id=p.user.id, target_id=i.id, level="warning")
    return {"mensaje": f"Restaurado en {destino}. No se volverá a marcar ese archivo.", "ruta": destino}


@router.post("/cuarentena/{item_id}/eliminar")
def eliminar(item_id: str, p: CurrentUser, db: DB):
    i = _item(db, p, item_id)
    try:
        cuarentena.eliminar(db, i)
    except OSError as e:
        raise ApiError(409, "no_eliminado", f"No se pudo eliminar: {e}") from e
    audit.record(db, "proteccion.eliminar_local", actor_id=p.user.id, target_id=i.id)
    return {"mensaje": "Eliminado definitivamente"}


# ════════════════════════════════════════════════════════════ VPN
def _requiere_vpn(p) -> None:
    if "basic_vpn" not in features_for(p.user.plan):
        raise ApiError(402, "plan_required", "La VPN requiere plan Premium o Enterprise")


def _vpn_error(e: Exception) -> ApiError:
    return ApiError(409, "vpn_error", str(e))


@router.get("/vpn")
def vpn_estado(p: CurrentUser):
    return tunel.estado()


@router.get("/vpn/estadisticas")
def vpn_estadisticas(p: CurrentUser):
    """Cifras en vivo del túnel para el tablero: tiempo, datos, latencia y apretón de manos.

    La barra de estadísticas la consulta cada pocos segundos: es solo lectura, sin efectos.
    """
    return tunel.estadisticas()


_conexion = threading.Lock()


# ─────────────────────────── modo cebolla (Tor), gratis
@router.get("/tor")
def tor_estado(p: CurrentUser, verificar: bool = False):
    """Estado del modo cebolla. Con verificar=true le pregunta al Tor Project si la salida es Tor."""
    from app.ai import anonimato
    from app.local import tor
    e = tor.estado(verificar_salida=verificar)
    if verificar and e.get("listo"):
        # SOCKS5h: los nombres se resuelven dentro de Tor (sin fuga de DNS); IPv6 no aplica al proxy.
        e["anonimato"] = anonimato.evaluar(ip_oculta=bool(e.get("is_tor")), ipv6_fuga=None, dns_fuga=False,
                                           kill_switch=None, proveedor="tor", nombre="Tor", pais_salida=None)
    return e


@router.post("/tor/iniciar")
def tor_iniciar(p: CurrentUser):
    from app.local import tor
    limiter.hit(f"tor-iniciar:{p.user.id}", 6, 300)   # nadie lanza procesos en bucle
    try:
        return tor.iniciar()
    except tor.ErrorTor as e:
        raise ApiError(409, "tor_no_instalado", str(e))


# ─────────────────────────── pasarela de privacidad: VPN + Tor con un solo control
class PrivacidadIn(BaseModel):
    # «proton»/«proton_tor» se aceptan por compatibilidad y significan su servidor (+ Tor).
    modo: str = Field(pattern="^(apagado|auto|servidor|tor|servidor_tor|proton|proton_tor)$")
    objetivo: str = Field("equilibrio", pattern="^(equilibrio|velocidad|anonimato)$")
    pais: str | None = Field(None, pattern="^[A-Z]{2}$")        # país de salida de Tor (opcional)


@router.get("/privacidad")
def privacidad_estado(p: CurrentUser):
    """Estado en vivo: modo, ubicación, bytes, circuito Tor (3 relevos), red y nivel de anonimato."""
    from app.local import privacidad
    return privacidad.estado()


@router.put("/privacidad")
def privacidad_activar(body: PrivacidadIn, p: CurrentUser, db: DB):
    """UN botón: apaga lo que sobra y conecta su servidor y/o Tor. En «auto» decide la IA."""
    from app.local import privacidad
    limiter.hit(f"privacidad:{p.user.id}", 20, 300)
    try:
        r = privacidad.activar(body.modo, body.objetivo, body.pais)
    except privacidad.ErrorPrivacidad as e:
        raise ApiError(409, "privacidad", str(e))
    except tunel.ErrorVpn as e:
        raise _vpn_error(e) from e
    audit.record(db, "privacidad.modo", actor_id=p.user.id, detail={"modo": body.modo, "objetivo": body.objetivo})
    return r


@router.post("/privacidad/nueva-identidad")
def privacidad_nueva_identidad(p: CurrentUser):
    from app.local import privacidad
    limiter.hit(f"newnym:{p.user.id}", 6, 60)
    try:
        return privacidad.nueva_identidad()
    except privacidad.ErrorPrivacidad as e:
        raise ApiError(409, "tor_inactivo", str(e))


# ─────────────────────────── servidor VPN propio (se configura solo desde este PC)
class PropioIn(BaseModel):
    url: str = Field(min_length=12, max_length=120)
    huella: str = Field(min_length=64, max_length=110)
    ficha: str = Field(min_length=20, max_length=200)


@router.get("/vpn/propio")
def vpn_propio_estado(p: CurrentUser):
    from app.local import vpn_propio
    return vpn_propio.estado()


@router.put("/vpn/propio")
def vpn_propio_configurar(body: PropioIn, p: CurrentUser, db: DB):
    """Conecta el servidor GuardianIA VPN con los 3 datos del instalador y da de alta este PC."""
    from app.local import vpn_propio
    limiter.hit(f"vpn-propio:{p.user.id}", 10, 600)
    try:
        r = vpn_propio.configurar(body.url, body.huella, body.ficha, p.user.id)
    except vpn_propio.ErrorPropio as e:
        raise ApiError(409, "servidor_propio", str(e))
    audit.record(db, "vpn.propio.configurado", actor_id=p.user.id, detail={"region": r.get("region")})
    return r


@router.delete("/vpn/propio")
def vpn_propio_quitar(p: CurrentUser, db: DB):
    from app.local import vpn_propio
    audit.record(db, "vpn.propio.quitado", actor_id=p.user.id)
    return vpn_propio.quitar()


# ─────────────────────────── Cloudflare WARP (gratis, sin cuenta, reemplaza al servidor propio)
@router.get("/vpn/warp")
def vpn_warp_estado(p: CurrentUser):
    from app.local import warp
    perf = tunel.perfil() or {}
    return {"activo": perf.get("proveedor") == "warp", "registrado": warp.registrado()}


@router.post("/vpn/warp")
def vpn_warp_activar(p: CurrentUser, db: DB):
    """Registra este equipo en Cloudflare WARP (gratis) y deja el túnel listo para conectar."""
    from app.local import warp
    limiter.hit(f"vpn-warp:{p.user.id}", 10, 600)
    try:
        r = tunel.configurar_warp()
    except warp.ErrorWarp as e:
        raise ApiError(502, "warp", str(e))
    audit.record(db, "vpn.warp.activado", actor_id=p.user.id)
    return r


@router.delete("/vpn/warp")
def vpn_warp_quitar(p: CurrentUser, db: DB):
    audit.record(db, "vpn.warp.quitado", actor_id=p.user.id)
    return tunel.quitar_warp()



class PaisTorIn(BaseModel):
    pais: str | None = Field(None, pattern="^[A-Za-z]{2}$")


@router.put("/tor/pais")
def tor_pais(body: PaisTorIn, p: CurrentUser):
    """País por el que Tor sale a internet (lista cerrada) o null para el más rápido."""
    from app.local import tor
    try:
        return tor.fijar_pais(body.pais)
    except tor.ErrorTor as e:
        raise ApiError(422, "pais_no_disponible", str(e))


class RedTorIn(BaseModel):
    modo: str = Field(pattern="^(apagado|preferir|estricto)$")


@router.get("/tor/red")
def tor_red(p: CurrentUser):
    """Cómo salen a internet los módulos de GuardianIA: directo, preferir Tor o solo Tor (estricto)."""
    from app.core import red
    return red.estado()


@router.put("/tor/red")
def tor_red_fijar(body: RedTorIn, p: CurrentUser):
    from app.core import red
    red.fijar_modo(body.modo)
    return red.estado()


@router.post("/tor/detener")
def tor_detener(p: CurrentUser):
    from app.local import tor
    return tor.detener()


@router.get("/vpn/anonimato")
def vpn_anonimato(p: CurrentUser, repetir: bool = False):
    """Nivel de anonimato del túnel de este equipo (IP, IPv6, DNS, kill switch, jurisdicción, operador)."""
    _requiere_vpn(p)
    return tunel.anonimato(repetir=repetir)


@router.post("/vpn/conectar")
def vpn_conectar(request: Request, p: CurrentUser, db: DB):
    """Levanta el túnel y lo verifica. Windows mostrará una ventana pidiendo permiso de administrador."""
    _requiere_vpn(p)
    limiter.hit(f"vpn-local:{p.user.id}", 20, 600)
    if not _conexion.acquire(blocking=False):
        raise ApiError(409, "vpn_ocupada", "Ya se está conectando: espere unos segundos")
    try:
        try:
            r = tunel.conectar()
        except tunel.ErrorVpn as e:
            raise _vpn_error(e) from e
        perfil = tunel.perfil() or {}
        servidor_id = perfil.get("servidor_id") or f"local-{perfil.get('proveedor', 'vpn')}"
        _asegurar_servidor(db, servidor_id, perfil, r)
        for vieja in db.execute(select(VpnSession).where(VpnSession.user_id == p.user.id, VpnSession.estado.in_(
                ("conectando", "conectada", "sin_verificar")))).scalars():
            vieja.estado, vieja.cerrada_at, vieja.motivo_cierre = "cerrada", utcnow(), "reemplazada"
        from app.api.v1.vpn import purgar_registros
        purgar_registros(db, p.user.id)
        # La IP real se queda en este equipo (estado local del túnel); la base de datos no la guarda.
        sesion = VpnSession(user_id=p.user.id, server_id=servidor_id, device_id=cuarentena.EQUIPO,
                            proposito="general", estado="conectada" if r["verificado"] else "sin_verificar",
                            ip_previa=None, ip_salida=r["ip_salida"], verificada=r["verificado"])
        db.add(sesion)
        db.flush()
        tunel.anotar_sesion(sesion.id)
        audit.record(db, "vpn.conectar_local", actor_id=p.user.id, target_type="vpn_session", target_id=sesion.id,
                     detail={"verificada": r["verificado"], "proveedor": perfil.get("proveedor")}, commit=False)
        db.commit()
    finally:
        _conexion.release()
    estado_ = tunel.estado()
    estado_["mensaje"] = (f"VPN conectada y verificada: su IP pública ahora es {r['ip_salida']}"
                          if r["verificado"] else
                          (r.get("motivo") or "El túnel se instaló pero la IP no cambió todavía.")
                          + " Presione «Verificar» en unos segundos; si sigue igual, revise la app WireGuard.")
    return estado_


def _asegurar_servidor(db, servidor_id: str, perfil: dict, r: dict) -> None:
    """Deja un registro del túnel local para que el historial muestre ciudad y país."""
    if db.get(VpnServer, servidor_id) is not None:
        return
    host, _, puerto = (perfil.get("peer", {}).get("Endpoint") or "").rpartition(":")
    db.add(VpnServer(id=servidor_id[:40], country=(r.get("pais") or "--")[:2], city=perfil.get("nombre", "VPN")[:60],
                     host=host[:120] or "-", port=int(puerto) if puerto.isdigit() else 51820, protocol="wireguard",
                     is_premium=False, load=0.0, latency_ms=0, active=False))
    db.flush()


@router.post("/vpn/desconectar")
def vpn_desconectar(p: CurrentUser, db: DB):
    try:
        r = tunel.desconectar()
    except tunel.ErrorVpn as e:
        raise _vpn_error(e) from e
    if r.get("sesion_id"):
        s = db.get(VpnSession, r["sesion_id"])
        if s and s.user_id == p.user.id and s.cerrada_at is None:
            s.estado, s.cerrada_at, s.motivo_cierre = "cerrada", utcnow(), "usuario"
    db.commit()
    return {"mensaje": "VPN desconectada" if r["cerrado"] else "WireGuard no confirmó el cierre", **tunel.estado()}


@router.post("/vpn/verificar")
def vpn_verificar(p: CurrentUser, db: DB):
    r = tunel.verificar()
    tunel.estadisticas(leer_bytes=True)   # de paso lee Descargado/Subido (una sola ventana de permiso)
    e = tunel.estado()
    if e.get("sesion_id"):
        s = db.get(VpnSession, e["sesion_id"])
        if s and s.user_id == p.user.id:
            s.verificada, s.ip_salida = r["verificado"], r["ip"]
            s.estado = "conectada" if r["verificado"] else "sin_verificar"
            db.commit()
    return {**e, **r, "comprobado": time.time()}
