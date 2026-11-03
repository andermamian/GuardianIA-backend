"""Pasarela de privacidad del PC: SOLO su servidor GuardianIA VPN (Google Cloud) y Tor, con UN botón.

Modos (excluyentes: cada cambio apaga primero lo que sobra, así nunca hay dos cosas en conflicto):
    apagado
    auto          — la IA decide entre las tres vías de abajo y cambia sola si algo empeora.
    servidor      — túnel WireGuard a su servidor: cifra todo el equipo.
    tor           — 3 relevos Tor (proxy 127.0.0.1:9150 / 9050).
    servidor_tor  — Tor dentro del túnel: el operador solo ve su servidor; el sitio solo ve un relevo.
Objetivo: equilibrio · velocidad · anonimato (lo usa la IA para puntuar; en anonimato Tor aísla cada
sitio en un circuito y la salida a internet de GuardianIA va SOLO por Tor).

Nunca se deja un túnel encendido que no cambió la IP, y nunca se deja a la persona desprotegida por
una caída: si su servidor no responde, se pasa a Tor y se vuelve al servidor cuando responde.
El cerebro está en app/ai/cerebro_vpn.py (explicable, aprende de este equipo, igual que en Android).
"""
from __future__ import annotations

import atexit
import json
import logging
import threading
import time

from app.ai import anonimato, cerebro_vpn as cerebro
from app.core import red
from app.local import ajustes, sistema, tor, vpn

log = logging.getLogger("guardian.privacidad")

MODOS = ("apagado", "auto", "servidor", "tor", "servidor_tor")
LEGADO = {"proton": "servidor", "proton_tor": "servidor_tor"}     # nombres de v3.5–3.7
OBJETIVOS = cerebro.OBJETIVOS
_lock = threading.RLock()
_vigilante: threading.Thread | None = None
_ultimo = {"evento": "", "cuando": 0.0, "razon": ""}
_decision: dict = {}
_senales_cache: dict = {"cuando": 0.0, "senales": None, "detalle": {}}
_tor_pendiente: dict = {}          # {"modo":…, "desde":…}: para aprender cuánto tarda Tor en quedar listo

usa_servidor = cerebro.usa_servidor
usa_tor = cerebro.usa_tor


class ErrorPrivacidad(Exception):
    pass


def config() -> dict:
    a = ajustes.leer()
    modo = LEGADO.get(a.get("privacidad_modo"), a.get("privacidad_modo"))
    efectivo = LEGADO.get(a.get("privacidad_efectivo"), a.get("privacidad_efectivo"))
    objetivo = a.get("privacidad_objetivo")
    return {"modo": modo if modo in MODOS else "apagado",
            "objetivo": objetivo if objetivo in OBJETIVOS else "equilibrio",
            "pais": a.get("privacidad_pais") if a.get("privacidad_pais") in tor.PAISES else None,
            "efectivo": efectivo if efectivo in MODOS else (modo if modo in cerebro.CANDIDATOS else "apagado"),
            "respaldo": bool(a.get("privacidad_respaldo")),
            "ultimo_cambio": float(a.get("privacidad_cambio") or 0.0)}


# ─────────────────────────── memoria del cerebro (lo aprendido en este equipo)
def _ruta_memoria():
    return vpn._dir() / "cerebro.json"


def memoria() -> dict:
    try:
        m = json.loads(_ruta_memoria().read_text("utf-8"))
        return {k: m.get(k) or v for k, v in cerebro.memoria_vacia().items()}
    except (OSError, ValueError):
        return cerebro.memoria_vacia()


def _aprender(modo: str, exito: bool, segundos: float | None = None) -> None:
    m = cerebro.aprender(memoria(), modo, exito, segundos)
    try:
        vpn._escribir_privado(_ruta_memoria(), json.dumps(m))
    except OSError:
        pass


# ─────────────────────────── señales del entorno
def senales(forzar: bool = False) -> cerebro.Senales:
    """Lo que la IA mira: su servidor (en línea, latencia, cupo del mes), Tor y el tipo de red.
    Se consulta como mucho cada 60 s (el servidor no se martilla)."""
    if not forzar and _senales_cache["senales"] and time.time() - _senales_cache["cuando"] < 60:
        return _senales_cache["senales"]
    # Cloudflare WARP se registra SOLO la primera vez que se necesita (ver _conectar_servidor): la
    # persona no configura nada. Antes se exigía haber pulsado «Activar WARP» a mano; sin eso el modo
    # automático descartaba siempre la VPN y dejaba solo Tor.
    configurado = True
    en_linea = latencia = fraccion = None
    detalle: dict = {}
    ubic = vpn.ubicaciones()
    # WARP es la red global de Cloudflare: se asume disponible (no tiene un "/salud" propio que
    # consultar, ni cupo mensual que vigilar, a diferencia de un servidor propio).
    en_linea = True
    detalle = {"region": None, "pais": ubic[0].get("pais") if ubic else None, "consumo": None,
               "dispositivos": None, "error": None}
    t = tor.estado()
    s = cerebro.Senales(servidor_configurado=configurado, servidor_en_linea=en_linea,
                        latencia_servidor_ms=latencia, consumo_fraccion=fraccion,
                        tor_disponible=bool(t.get("instalado")), red_insegura=sistema.red_publica(),
                        tunel_disponible=bool(vpn.wireguard()))
    _senales_cache.update(cuando=time.time(), senales=s, detalle=detalle)
    return s


def _senales_publicas() -> dict:
    s = _senales_cache["senales"]
    if not s:
        return {}
    return {"servidor_configurado": s.servidor_configurado, "servidor_en_linea": s.servidor_en_linea,
            "latencia_servidor_ms": s.latencia_servidor_ms,
            "consumo_pct": None if s.consumo_fraccion is None else round(s.consumo_fraccion * 100),
            "tor_disponible": s.tor_disponible, "red_insegura": s.red_insegura,
            "servidor": _senales_cache["detalle"], "hace_s": round(time.time() - _senales_cache["cuando"])}


def resumen_para_celular() -> dict:
    """Lo que el celular necesita para que su IA decida igual que el PC (sin datos sensibles)."""
    s = senales()
    return {"en_linea": s.servidor_en_linea, "latencia_ms": s.latencia_servidor_ms,
            "consumo_fraccion": s.consumo_fraccion}


# ─────────────────────────── aplicar un modo concreto
def _asegurar_ubicacion() -> dict:
    """Hay siempre una ubicación lista: si no existe, se registra WARP gratis (sin que la persona haga nada)."""
    propias = vpn.ubicaciones()
    if propias:
        return propias[0]
    from app.local import warp
    try:
        vpn.configurar_warp()
    except warp.ErrorWarp as e:
        raise ErrorPrivacidad(str(e)) from e
    except (OSError, ValueError, KeyError) as e:
        raise ErrorPrivacidad(f"No pude preparar la VPN gratuita de Cloudflare WARP ({type(e).__name__}).") from e
    propias = vpn.ubicaciones()
    if not propias:
        raise ErrorPrivacidad("No pude preparar la VPN gratuita de Cloudflare WARP. Intente de nuevo en un momento.")
    return propias[0]


def _conectar_servidor() -> dict:
    ubicacion = _asegurar_ubicacion()
    vpn.usar_ubicacion(ubicacion["id"])
    e = vpn.conectar()
    if not e.get("verificado"):
        try:
            vpn.desconectar()                       # nunca un túnel encendido que no protege
        except vpn.ErrorVpn:
            pass
        raise ErrorPrivacidad(e.get("motivo") or "El túnel VPN subió pero la IP no cambió.")
    return e


def _proxy_tor(poner: bool) -> None:
    """Hace que el navegador (Opera, Chrome, Edge) salga de verdad por Tor.

    Tor solo abre un proxy SOCKS local; sin esto el navegador seguía saliendo por la IP real y los DNS
    del operador aunque el panel dijera «Protegido · Tor». Se usa el proxy del sistema de Windows (sin
    administrador) y se devuelve a como estaba al apagar. SOCKS5: los nombres se resuelven dentro de Tor."""
    try:
        if poner and ajustes.leer().get("tor_proxy_sistema", True):
            puerto = tor.PUERTO_TOR_BROWSER if tor.puerto_activo() == tor.PUERTO_TOR_BROWSER else tor.PUERTO_PROPIO
            if sistema.proxy_sistema_poner(f"socks=127.0.0.1:{puerto}"):
                atexit.register(_proxy_tor, False)
        elif not poner:
            sistema.proxy_sistema_quitar()
    except Exception:  # noqa: BLE001 - no poder tocar el proxy nunca debe romper la protección
        log.exception("proxy del sistema para Tor")


def _proxy_huerfano() -> None:
    """Si el proxy apunta a un Tor que ya no corre (el servidor se cerró mal), internet quedaría
    cortado: se devuelve a como estaba."""
    puesto = sistema.proxy_sistema_puesto()
    if puesto and time.time() - puesto > 60 and not tor.puerto_activo():
        _proxy_tor(False)


def _aplicar(modo: str, objetivo: str, pais: str | None) -> dict:
    """Deja el equipo EXACTAMENTE en `modo`. Lanza ErrorPrivacidad si no pudo."""
    resultado: dict = {}
    if not usa_tor(modo):
        _proxy_tor(False)
        tor.detener()
        red.fijar_modo("apagado")
    if not usa_servidor(modo):
        try:
            if vpn.wireguard() and vpn.activo():
                vpn.desconectar()
        except vpn.ErrorVpn:
            pass
    if usa_servidor(modo) and not (vpn.wireguard() and vpn.activo()):
        t0 = time.monotonic()
        try:
            resultado["vpn"] = _conectar_servidor()
        except (ErrorPrivacidad, vpn.ErrorVpn) as e:
            _aprender(modo, False)
            raise ErrorPrivacidad(str(e)) from e
        _aprender(modo, True, time.monotonic() - t0)
    if usa_tor(modo):
        # El aislamiento por sitio y el país de salida se aplican al arrancar: Tor se reinicia.
        ajustes.guardar({"tor_aislamiento": objetivo == "anonimato", "tor_pais": pais})
        tor.detener()
        try:
            tor.iniciar()
        except tor.ErrorTor as e:
            _aprender(modo, False)
            if usa_servidor(modo):
                try:
                    vpn.desconectar()
                except vpn.ErrorVpn:
                    pass
            raise ErrorPrivacidad(str(e)) from e
        _tor_pendiente.update(modo=modo, desde=time.time())
        _proxy_tor(True)
        red.fijar_modo("estricto" if objetivo == "anonimato" else "preferir")
    ajustes.guardar({"privacidad_efectivo": modo, "privacidad_cambio": time.time()})
    return resultado


# ─────────────────────────── el botón
def activar(modo: str, objetivo: str = "equilibrio", pais: str | None = None) -> dict:
    modo = LEGADO.get(modo, modo)
    if modo not in MODOS or objetivo not in OBJETIVOS:
        raise ErrorPrivacidad("Modo u objetivo inválido")
    if pais is not None and pais not in tor.PAISES:
        raise ErrorPrivacidad(f"País de salida de Tor no disponible: {pais}")
    purga = vpn.purgar_terceros()                   # ProtonVPN, WARP y .conf ajenos: fuera
    with _lock:
        ajustes.guardar({"privacidad_modo": modo, "privacidad_objetivo": objetivo, "privacidad_pais": pais,
                         "privacidad_respaldo": False})
        if modo == "apagado":
            _aplicar("apagado", objetivo, pais)
            _decision.clear()
            _anotar("apagado", "Protección apagada.")
            return {**estado(), "razon": "Protección apagada."}
        aviso = ""
        if modo == "auto":
            usado, razon_ = _activar_auto(objetivo, pais)
        else:
            usado = modo
            modo_real = modo   # Tor solo = solo Tor, sin tunel
            try:
                _aplicar(modo_real, objetivo, pais)
                razon_ = _razon_manual(modo)
            except ErrorPrivacidad as e:
                if not (usa_servidor(modo) and senales().tor_disponible):
                    raise
                # Nunca desprotegido: Tor mientras su servidor vuelve.
                _aplicar("tor", objetivo, pais)
                usado = "tor"
                ajustes.guardar({"privacidad_respaldo": True})
                aviso = (f"Su servidor no conectó ({e}). Le dejé protegido con Tor y volveré a su servidor "
                         "en cuanto responda.")
                razon_ = aviso
        if purga["ubicaciones_borradas"] or purga["perfil_quitado"]:
            aviso = (aviso + " " if aviso else "") + "Se retiraron las VPN de terceros que quedaban (ProtonVPN/WARP)."
        if modo != "auto":                          # la IA opina aunque la persona eligiera a mano
            d = cerebro.decidir(senales(), objetivo, memoria())
            _decision.clear()
            _decision.update(d.a_dict(), cuando=time.time())
        _anotar("activado", razon_)
        _asegurar_vigilante()
        return {**estado(), "razon": razon_, "aviso": aviso, "efectivo": usado}


def _razon_manual(modo: str) -> str:
    return {"servidor": "Conectado a su servidor GuardianIA VPN: todo el equipo va cifrado.",
            "tor": "Tor activo, con todo el equipo tambien cifrado por su servidor/WARP: nadie ve a la vez quien es usted y que visita.",
            "servidor_tor": "Tor dentro de su servidor: maxima privacidad."}[modo]


def _activar_auto(objetivo: str, pais: str | None) -> tuple[str, str]:
    """La IA elige; si su elección falla, aprende del fallo y prueba la siguiente (hasta 3)."""
    probados: list[str] = []
    ultimo_error = ""
    for _ in range(3):
        d = cerebro.decidir(senales(forzar=not probados), objetivo, memoria(), excluir=tuple(probados))
        _decision.clear()
        _decision.update(d.a_dict(), cuando=time.time())
        if d.modo is None:
            break
        try:
            _aplicar(d.modo, objetivo, pais)
            return d.modo, " ".join(d.razones[:2])
        except ErrorPrivacidad as e:
            probados.append(d.modo)
            ultimo_error = str(e)
    motivo = ultimo_error or "; ".join(_decision.get("razones") or []) or "sin opciones"
    raise ErrorPrivacidad(f"No pude protegerle con ninguna vía: {motivo}")


def nueva_identidad() -> dict:
    """Circuitos Tor nuevos: los sitios verán otra IP (Tor limita esto a una vez cada ~10 s)."""
    from app.local import tor_control
    try:
        c = tor_control.ControlTor(tor.cookie_control())
    except (OSError, tor_control.ErrorControl) as e:
        raise ErrorPrivacidad("Tor no está activo (o no lo lanzó GuardianIA).") from e
    try:
        c.nueva_identidad()
    finally:
        c.cerrar()
    _anotar("nueva_identidad", "Circuitos Tor renovados")
    return estado()


# ─────────────────────────── estado en vivo
def _circuito() -> dict:
    from app.local import tor_control
    try:
        c = tor_control.ControlTor(tor.cookie_control(), timeout=2.0)
    except (OSError, tor_control.ErrorControl):
        return {}
    try:
        return {"arranque": c.arranque(), "relevos": c.circuito_actual()}
    except (OSError, tor_control.ErrorControl):
        return {}
    finally:
        c.cerrar()


def estado() -> dict:
    from app.local import warp
    _proxy_huerfano()
    cfg = config()
    efectivo = cfg["efectivo"] if cfg["modo"] != "apagado" else "apagado"
    t = tor.estado()
    vpn_arriba = vpn.activo() if vpn.wireguard() else False
    est_vpn = vpn.estadisticas(medir_latencia=False, leer_bytes=False) if vpn_arriba else {}
    circuito = _circuito() if t.get("activo") else {}
    relevos = circuito.get("relevos") or []
    salida_tor = relevos[-1] if relevos else {}
    protegido = (efectivo != "apagado" and (not usa_servidor(efectivo) or vpn_arriba)
                 and (not usa_tor(efectivo) or bool(t.get("listo"))))
    if usa_tor(efectivo):
        cal = anonimato.evaluar(ip_oculta=bool(t.get("listo")), ipv6_fuga=None, dns_fuga=False, kill_switch=None,
                                proveedor="tor", nombre="Tor", pais_salida=salida_tor.get("pais"))
    elif usa_servidor(efectivo):
        cal = vpn.anonimato()
    else:
        cal = None
    mem = memoria()
    return {**cfg, "efectivo": efectivo, "protegido": protegido, "vpn_activa": vpn_arriba,
            "servidor": {"configurado": warp.registrado(),
                        "pais": (vpn.ubicaciones()[0].get("pais") if vpn.ubicaciones() else None)},
            "vpn": est_vpn,
            "tor": {"activo": t.get("activo"), "listo": t.get("listo"), "progreso": t.get("progreso"),
                    "resumen": t.get("resumen"), "error": t.get("error"), "circuito": relevos,
                    "instalado": t.get("instalado"), "aislamiento": tor.aislamiento(),
                    "pais": (t.get("pais") or {}).get("elegido")},
            "red": red.estado(), "anonimato": cal, "ultimo": dict(_ultimo),
            "ia": {"decision": dict(_decision), "senales": _senales_publicas(),
                   "aprendizaje": {m: {"fiabilidad": round(float(v.get("fiabilidad", 0.8)) * 100),
                                       "intentos": v.get("intentos", 0),
                                       "segundos": None if v.get("segundos") is None else round(v["segundos"])}
                                   for m, v in mem.items()}}}


# ─────────────────────────── vigilante (cada 30 s)
def _anotar(evento: str, razon_: str) -> None:
    _ultimo.update(evento=evento, cuando=time.time(), razon=razon_)


def _sano(efectivo: str) -> bool:
    arriba = (not usa_servidor(efectivo)) or (bool(vpn.wireguard()) and vpn.activo())
    t = tor.estado() if usa_tor(efectivo) else {}
    return arriba and ((not usa_tor(efectivo)) or bool(t.get("activo")))


def _aprender_tor() -> None:
    """Cuando el Tor recién lanzado queda listo (o se atasca), la IA lo anota."""
    if not _tor_pendiente:
        return
    t = tor.estado()
    if t.get("listo"):
        _aprender(_tor_pendiente["modo"], True, time.time() - _tor_pendiente["desde"])
        _tor_pendiente.clear()
    elif t.get("error"):
        _aprender(_tor_pendiente["modo"], False)
        _tor_pendiente.clear()


def revisar_una_vez() -> str | None:
    """Revisa y repara. Devuelve qué hizo (para el registro y las pruebas) o None si todo estaba bien."""
    cfg = config()
    if cfg["modo"] == "apagado":
        return None
    with _lock:
        _aprender_tor()
        efectivo, objetivo, pais = cfg["efectivo"], cfg["objetivo"], cfg["pais"]
        sano = _sano(efectivo)
        if cfg["modo"] == "auto":
            d = cerebro.decidir(senales(), objetivo, memoria())
            _decision.clear()
            _decision.update(d.a_dict(), cuando=time.time())
            if cerebro.conviene_cambiar(efectivo, d, cfg["ultimo_cambio"], sano):
                try:
                    _aplicar(d.modo, objetivo, pais)
                    _anotar("cambio_ia", f"Pasé de {cerebro.nombre(efectivo)} a {cerebro.nombre(d.modo)}: "
                                         + d.razones[0])
                    return "cambio_ia"
                except ErrorPrivacidad as e:
                    _anotar("fallo", str(e))
                    return "fallo"
            if sano:
                return None
            return _reparar(efectivo, objetivo, pais)
        # Modo elegido a mano.
        if cfg["respaldo"]:
            if senales().servidor_en_linea:
                try:
                    _aplicar(cfg["modo"], objetivo, pais)
                    ajustes.guardar({"privacidad_respaldo": False})
                    _anotar("restaurado", "Su servidor volvió a responder: regresé a él.")
                    return "restaurado"
                except ErrorPrivacidad:
                    pass
            return None if sano else _reparar(efectivo, objetivo, pais)
        if sano:
            return None
        hecho = _reparar(efectivo, objetivo, pais)
        if hecho == "fallo" and usa_servidor(efectivo) and senales(forzar=True).tor_disponible:
            try:
                _aplicar("tor", objetivo, pais)
                ajustes.guardar({"privacidad_respaldo": True})
                _anotar("respaldo_tor", "Su servidor no responde: le protegí con Tor mientras vuelve.")
                return "respaldo_tor"
            except ErrorPrivacidad as e:
                _anotar("fallo", str(e))
        return hecho


_ESPERA_TRAS_FALLO = 300.0       # s: tras un fallo no se reintenta enseguida (cada intento puede pedir permiso UAC)
_ultimo_fallo = 0.0


def _reparar(efectivo: str, objetivo: str, pais: str | None) -> str:
    global _ultimo_fallo
    if time.monotonic() - _ultimo_fallo < _ESPERA_TRAS_FALLO and _ultimo_fallo:
        return "fallo"
    tunel_caido = usa_servidor(efectivo) and not (vpn.wireguard() and vpn.activo())
    try:
        _aplicar(efectivo, objetivo, pais)
    except ErrorPrivacidad as e:
        _ultimo_fallo = time.monotonic()
        _anotar("fallo", str(e))
        return "fallo"
    evento = "reconectado" if tunel_caido else "tor_reiniciado"
    _anotar(evento, "Algo se había caído: lo reconecté.")
    return evento


def _asegurar_vigilante() -> None:
    global _vigilante
    if _vigilante and _vigilante.is_alive():
        return

    def bucle():
        while config()["modo"] != "apagado":
            time.sleep(30)
            try:
                hecho = revisar_una_vez()
                if hecho:
                    log.info("privacidad: %s", hecho)
            except Exception:  # noqa: BLE001 - el vigilante nunca debe morir por un error puntual
                log.exception("vigilante de privacidad")

    if config()["modo"] != "apagado":
        _vigilante = threading.Thread(target=bucle, name="vigilante-privacidad", daemon=True)
        _vigilante.start()
