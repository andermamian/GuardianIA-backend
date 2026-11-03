"""La VPN de este equipo: SOLO su servidor GuardianIA VPN (Google Cloud), levantado con WireGuard.

Desde v3.8 GuardianIA usa dos vías y nada más: su propio servidor y Tor (app/local/tor.py). Se retiraron
Cloudflare WARP, ProtonVPN y los .conf de terceros: varias VPN a la vez generaban conflictos, y un
proveedor ajeno es un tercero que ve su tráfico. `purgar_terceros()` borra lo que quedara de antes.

El túnel lo instala wireguard.exe como servicio de Windows. Eso requiere administrador, así que se
pide con UNA ventana de control de cuentas en el momento de conectar (no hace falta correr el
servidor como administrador, que sería mucho más riesgoso).

**Nada se marca como conectado sin prueba**: se consulta la IP pública antes y después. Conectado =
la IP pública cambió.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import stat
import threading
import time
import socket
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from app.local import ajustes, sistema

NOMBRE = "guardiania"
SERVICIO = f"WireGuardTunnel${NOMBRE}"
TRACE = "https://www.cloudflare.com/cdn-cgi/trace"
_lock = threading.Lock()


class ErrorVpn(Exception):
    pass


def _dir() -> Path:
    return ajustes.sub("vpn")


def _escribir_privado(ruta: Path, texto: str) -> None:
    tmp = ruta.with_suffix(ruta.suffix + ".tmp")
    tmp.write_text(texto, "utf-8")
    try:
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    os.replace(tmp, ruta)


# ════════════════════════════════════════════════════════════ claves
def claves() -> tuple[str, str]:
    """(privada, pública) de ESTE equipo. La privada nunca sale de aquí."""
    archivo = _dir() / "claves.json"
    if archivo.exists():
        datos = json.loads(archivo.read_text("utf-8"))
        return datos["privada"], datos["publica"]
    priv = X25519PrivateKey.generate()
    privada = base64.b64encode(priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    publica = base64.b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    _escribir_privado(archivo, json.dumps({"privada": privada, "publica": publica}))
    return privada, publica


# ══════════════════════════════════════════════════════ perfil (qué túnel)
def perfil() -> dict | None:
    try:
        return json.loads((_dir() / "perfil.json").read_text("utf-8"))
    except (OSError, ValueError):
        return None


def _guardar_perfil(p: dict) -> dict:
    _escribir_privado(_dir() / "perfil.json", json.dumps(p, ensure_ascii=False, indent=1))
    return p


def _publico(p: dict | None) -> dict | None:
    """Lo que se puede mostrar en pantalla: nunca claves privadas."""
    if not p:
        return None
    return {"proveedor": p["proveedor"], "nombre": p["nombre"], "endpoint": p["peer"].get("Endpoint"),
            "direccion": p["interfaz"].get("Address"), "dns": p["interfaz"].get("DNS"),
            "creado": p.get("creado"), "clave_publica_equipo": p.get("clave_publica_equipo")}


# ════════════════════════════════════ ubicación: su servidor GuardianIA VPN
# Países con nombre en español (para mostrar el país de salida de su servidor).
PAISES_VPN = {
    "US": "Estados Unidos", "CA": "Canadá", "MX": "México", "BR": "Brasil", "AR": "Argentina", "CL": "Chile",
    "CO": "Colombia", "PE": "Perú", "ES": "España", "GB": "Reino Unido", "UK": "Reino Unido", "FR": "Francia",
    "DE": "Alemania", "NL": "Países Bajos", "BE": "Bélgica", "CH": "Suiza", "SE": "Suecia", "NO": "Noruega",
    "FI": "Finlandia", "DK": "Dinamarca", "IT": "Italia", "PL": "Polonia", "RO": "Rumania", "AT": "Austria",
    "IE": "Irlanda", "PT": "Portugal", "CZ": "Chequia", "IS": "Islandia", "JP": "Japón", "KR": "Corea del Sur",
    "SG": "Singapur", "HK": "Hong Kong", "TW": "Taiwán", "IN": "India", "AU": "Australia", "NZ": "Nueva Zelanda",
    "ZA": "Sudáfrica", "IL": "Israel", "TR": "Turquía", "AE": "Emiratos Árabes",
}
_ID_UBICACION = re.compile(r"^[0-9a-f]{8}$")      # evita rutas como «../../» en las operaciones de archivo


def _dir_ubicaciones() -> Path:
    d = _dir() / "ubicaciones"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _guardar_ubicacion(p: dict, privada: str) -> None:
    carpeta = _dir_ubicaciones() / p["id"]
    carpeta.mkdir(parents=True, exist_ok=True)
    _escribir_privado(carpeta / "perfil.json", json.dumps(p, ensure_ascii=False, indent=1))
    _escribir_privado(carpeta / "privada.key", privada)


def _ubicacion(id_: str) -> tuple[dict, str]:
    if not _ID_UBICACION.fullmatch(id_ or ""):
        raise ErrorVpn("Ubicación no válida")
    carpeta = _dir_ubicaciones() / id_
    try:
        return (json.loads((carpeta / "perfil.json").read_text("utf-8")),
                (carpeta / "privada.key").read_text("utf-8").strip())
    except (OSError, ValueError):
        raise ErrorVpn("Esa ubicación ya no existe")


def ubicaciones() -> list[dict]:
    """Ubicaciones guardadas (sin claves privadas), con cuál está en uso."""
    actual = (perfil() or {}).get("id")
    salida = []
    for carpeta in sorted(_dir_ubicaciones().iterdir()) if _dir_ubicaciones().exists() else []:
        if not _ID_UBICACION.fullmatch(carpeta.name):
            continue
        try:
            p = json.loads((carpeta / "perfil.json").read_text("utf-8"))
        except (OSError, ValueError):
            continue
        pais = p.get("pais_verificado") or p.get("pais")
        salida.append({"id": carpeta.name, "nombre": p.get("nombre"), "pais": pais,
                       "pais_nombre": PAISES_VPN.get(pais or "", "País desconocido"),
                       "verificado": bool(p.get("pais_verificado")), "endpoint": p["peer"].get("Endpoint"),
                       "en_uso": carpeta.name == actual, "propio": bool(p.get("propio"))})
    return [u for u in salida if u["propio"]]          # solo su servidor GuardianIA VPN


def purgar_terceros() -> dict:
    """Borra lo que quedara de VPN de terceros (ProtonVPN, WARP, .conf importados).

    Si el túnel activo era de un tercero, se baja primero: nunca se deja un túnel ajeno encendido.
    Devuelve cuántas ubicaciones se borraron y si se quitó el perfil activo."""
    borradas = 0
    if _dir_ubicaciones().exists():
        for carpeta in _dir_ubicaciones().iterdir():
            if not _ID_UBICACION.fullmatch(carpeta.name):
                continue
            try:
                propio = json.loads((carpeta / "perfil.json").read_text("utf-8")).get("propio")
            except (OSError, ValueError):
                propio = False
            if not propio:
                shutil.rmtree(carpeta, ignore_errors=True)
                borradas += 1
    p = perfil()
    perfil_quitado = False
    if p and p.get("proveedor") not in ("servidor", "warp"):
        try:
            if wireguard() and activo():
                desconectar()
        except ErrorVpn:
            pass
        for nombre in ("perfil.json", "importada.key", f"{NOMBRE}.conf"):
            try:
                (_dir() / nombre).unlink()
            except OSError:
                pass
        perfil_quitado = True
    return {"ubicaciones_borradas": borradas, "perfil_quitado": perfil_quitado}


def usar_ubicacion(id_: str) -> dict:
    """Deja esa ubicación como túnel activo. Si la VPN está conectada, reconecta desde ahí."""
    p, privada = _ubicacion(id_)
    _escribir_privado(_dir() / "importada.key", privada)
    _guardar_perfil(p)
    return conectar() if (wireguard() and activo()) else {"perfil": _publico(p), "reconectar": False}


def eliminar_ubicacion(id_: str) -> None:
    _ubicacion(id_)                                   # valida el id y que exista
    shutil.rmtree(_dir_ubicaciones() / id_, ignore_errors=True)


def _confirmar_pais_ubicacion(pais_real: str | None) -> None:
    """Tras conectar, guarda el país que de verdad ven los sitios (puede diferir del nombre del archivo)."""
    p = perfil() or {}
    if not pais_real or not p.get("id") or not _ID_UBICACION.fullmatch(p["id"]):
        return
    try:
        guardada, privada = _ubicacion(p["id"])
    except ErrorVpn:
        return
    guardada["pais_verificado"] = pais_real.upper()
    _guardar_ubicacion(guardada, privada)


def configurar_servidor(servidor, direccion_tunel: str) -> dict:
    """Perfil para un servidor propio registrado en la base (VpnServer con clave y endpoint)."""
    _, publica = claves()
    return _guardar_perfil({
        "proveedor": "servidor", "nombre": f"{servidor.city}, {servidor.country}", "servidor_id": servidor.id,
        "creado": time.time(), "clave_publica_equipo": publica, "privada_propia": True,
        "interfaz": {"Address": direccion_tunel, "DNS": servidor.dns},
        "peer": {"PublicKey": servidor.public_key, "Endpoint": servidor.endpoint,
                 "AllowedIPs": "0.0.0.0/0, ::/0", "PersistentKeepalive": "25"},
    })


def configurar_warp() -> dict:
    """Se registra gratis con Cloudflare WARP (si no lo estaba ya) y lo deja como su ubicación activa,
    igual que un servidor propio: así "Automático (IA)" y "Servidor + Tor" lo reconocen."""
    from app.local import warp
    cfg = warp._cfg() or warp.registrar()
    if not _ID_UBICACION.fullmatch(cfg.get("ubicacion_id") or ""):
        cfg = warp.registrar()   # registro viejo sin id: se renueva
    p = warp.perfil_wireguard(cfg)
    p["id"], p["propio"] = cfg["ubicacion_id"], True
    _guardar_ubicacion(p, cfg["clave_privada"])
    return usar_ubicacion(p["id"])


def quitar_warp() -> dict:
    """Olvida el registro de WARP en este equipo (no hay nada que avisarle a Cloudflare).
    Limpia también un perfil viejo que quedó de una versión anterior sin pasar por "ubicaciones"."""
    from app.local import warp
    cfg = warp._cfg()
    if cfg and cfg.get("ubicacion_id"):
        try:
            eliminar_ubicacion(cfg["ubicacion_id"])
        except ErrorVpn:
            pass
    p = perfil()
    if p and p.get("proveedor") == "warp":
        try:
            if wireguard() and activo():
                desconectar()
        except ErrorVpn:
            pass
        for nombre in ("perfil.json", "importada.key", f"{NOMBRE}.conf"):
            try:
                (_dir() / nombre).unlink()
            except OSError:
                pass
    warp.olvidar()
    return {"quitado": True}



def _redes_publicas_v4() -> str:
    """Todo IPv4 menos redes locales, loopback y multicast (igual que la app Android)."""
    import ipaddress
    todo = [ipaddress.ip_network("0.0.0.0/0")]
    for ex in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "224.0.0.0/4",
               "255.255.255.255/32"):
        e = ipaddress.ip_network(ex)
        nuevo = []
        for n in todo:
            if e.subnet_of(n):
                nuevo += list(n.address_exclude(e))
            elif not n.subnet_of(e):
                nuevo.append(n)
        todo = nuevo
    return ", ".join(str(n) for n in ipaddress.collapse_addresses(todo))


def permitir_lan() -> bool:
    """¿La VPN deja pasar la red de la casa? (por defecto sí: el celular necesita llegar a este PC)."""
    return bool(ajustes.leer().get("vpn_permitir_lan", True))


def rutas_para(allowed: str, lan: bool) -> str:
    """Con la red local permitida, 0.0.0.0/0 → IPv4 públicas y ::/0 → IPv6 pública (2000::/3).

    Sin ninguna ruta «/0», WireGuard para Windows NO activa su bloqueo de tráfico fuera del túnel,
    que también cortaba la red local: el celular dejaba de ver el PC con la VPN encendida.
    La IP pública sigue oculta y el IPv6 público sigue por el túnel (sin fugas)."""
    if not lan:
        return allowed
    rutas = [r.strip() for r in allowed.split(",") if r.strip()]
    salida = []
    for r in rutas:
        if r == "0.0.0.0/0":
            salida.append(_redes_publicas_v4())
        elif r == "::/0":
            salida.append("2000::/3")
        else:
            salida.append(r)
    return ", ".join(salida)


def _texto_conf(p: dict) -> str:
    privada = claves()[0] if p.get("privada_propia", True) else (_dir() / "importada.key").read_text("utf-8").strip()
    interfaz = dict(p["interfaz"])
    if p.get("proveedor") == "warp" and not any(k.lower() == "mtu" for k in interfaz):
        interfaz["MTU"] = "1280"          # perfiles guardados antes de v4.1: sin esto muchas páginas no cargan
    lineas = ["[Interface]", f"PrivateKey = {privada}"]
    lineas += [f"{k} = {v}" for k, v in interfaz.items() if k.lower() != "privatekey"]
    lan = permitir_lan()
    lineas += ["", "[Peer]"] + [f"{k} = {rutas_para(v, lan) if k.lower() == 'allowedips' else v}"
                                for k, v in p["peer"].items()]
    return "\n".join(lineas) + "\n"


# ═══════════════════════════════════════════════════════════ DNS sin fugas (Windows)
COMENTARIO_NRPT = "GuardianIA-VPN"


def _dns_del_tunel(p: dict) -> str | None:
    """Primer DNS IPv4 del perfil (el del túnel, p. ej. 1.1.1.1)."""
    import ipaddress
    for d in str(p.get("interfaz", {}).get("DNS", "")).replace(";", ",").split(","):
        try:
            if ipaddress.ip_address(d.strip()).version == 4:
                return d.strip()
        except ValueError:
            continue
    return None


def _ps_nrpt_poner(dns: str) -> str:
    """Regla NRPT «.» → todo nombre se resuelve SOLO por el DNS del túnel. Sin ella, Windows pregunta
    también a los DNS del operador (multi-homed): la prueba de fugas mostraba Telmex junto a Cloudflare."""
    return (f"powershell -NoProfile -NonInteractive -Command \"Get-DnsClientNrptRule | Where-Object "
            f"{{$_.Comment -eq '{COMENTARIO_NRPT}'}} | Remove-DnsClientNrptRule -Force; "
            f"Add-DnsClientNrptRule -Namespace '.' -NameServers '{dns}' -Comment '{COMENTARIO_NRPT}'; "
            f"Clear-DnsClientCache\"\r\n")


def _ps_nrpt_quitar() -> str:
    return (f"powershell -NoProfile -NonInteractive -Command \"Get-DnsClientNrptRule | Where-Object "
            f"{{$_.Comment -eq '{COMENTARIO_NRPT}'}} | Remove-DnsClientNrptRule -Force; Clear-DnsClientCache\"\r\n")


# ═══════════════════════════════════════════════════════════ túnel
def wireguard() -> str | None:
    """wireguard.exe en Windows (no agrega su carpeta al PATH), wg-quick en Linux/macOS."""
    if sistema.ES_WINDOWS:
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"), r"C:\Program Files (x86)"):
            candidato = Path(base) / "WireGuard" / "wireguard.exe"
            if candidato.is_file():
                return str(candidato)
        return shutil.which("wireguard")
    return shutil.which("wg-quick")


def activo() -> bool:
    """¿Hay un túnel de GuardianIA arriba? En Windows se comprueba de dos formas por robustez."""
    if sistema.ES_WINDOWS:
        if sistema.estado_servicio(SERVICIO) == "RUNNING":
            return True
        # Respaldo: `wg show` lista las interfaces activas; si aparece la nuestra, está arriba.
        return NOMBRE in _wg_interfaces()
    return Path(f"/sys/class/net/{NOMBRE}").exists()


def tunel_instalado() -> bool:
    """¿Existe el servicio del túnel (corriendo o detenido)? En Windows, sc.exe no lo encuentra si no existe."""
    if not sistema.ES_WINDOWS:
        return activo()
    return sistema.estado_servicio(SERVICIO) is not None or NOMBRE in _wg_interfaces()


def _wg_interfaces() -> set[str]:
    import shutil as _sh
    import subprocess
    wg = _sh.which("wg")
    if not wg and sistema.ES_WINDOWS:
        cand = Path(r"C:\Program Files\WireGuard\wg.exe")
        wg = str(cand) if cand.exists() else None
    if not wg:
        return set()
    try:
        r = subprocess.run([wg, "show", "interfaces"], capture_output=True, text=True, timeout=6,
                           creationflags=sistema.CREATE_NO_WINDOW if sistema.ES_WINDOWS else 0)
        return set((r.stdout or "").split())
    except (OSError, subprocess.SubprocessError):
        return set()


def trace(timeout: float = 6.0) -> dict:
    """IP pública y país vistos desde internet. Cloudflare además dice si el tráfico va por WARP."""
    try:
        r = httpx.get(TRACE, timeout=timeout, headers={"Cache-Control": "no-cache"})
        datos = dict(linea.split("=", 1) for linea in r.text.splitlines() if "=" in linea)
        return {"ip": datos.get("ip"), "pais": datos.get("loc"), "warp": datos.get("warp"),
                "colo": datos.get("colo")}
    except (httpx.HTTPError, ValueError):
        pass
    try:
        ip = httpx.get("https://api.ipify.org", timeout=timeout).text.strip()
        return {"ip": ip, "pais": None, "warp": None, "colo": None}
    except httpx.HTTPError:
        return {"ip": None, "pais": None, "warp": None, "colo": None}


def ipv6_publica(timeout: float = 4.0) -> str | None:
    """IPv6 pública vista desde internet, o None si no hay salida IPv6 (lo normal con el túnel endurecido)."""
    try:
        ip = httpx.get("https://api6.ipify.org", timeout=timeout).text.strip()
        return ip if ":" in ip else None
    except httpx.HTTPError:
        return None


def resolutor_dns() -> str | None:
    """IP del resolutor DNS que atiende a este equipo (whoami.akamai.net responde con esa IP).

    Si después de conectar sigue siendo el mismo que sin VPN, las consultas no van por el túnel.
    """
    try:
        return socket.gethostbyname("whoami.akamai.net")
    except OSError:
        return None


def sondas() -> dict:
    """Lo que ve internet de este equipo: IPv4, IPv6 y resolutor DNS."""
    t = trace()
    return {"ip": t.get("ip"), "pais": t.get("pais"), "warp": t.get("warp"), "colo": t.get("colo"),
            "ip6": ipv6_publica(), "dns": resolutor_dns()}


def fugas(antes: dict, despues: dict) -> dict:
    """Compara antes y después de conectar. None = no se pudo comprobar."""
    ip6_fuga = None
    if despues.get("ip6") and antes.get("ip6"):
        ip6_fuga = despues["ip6"] == antes["ip6"]
    elif despues.get("ip6") is None:
        ip6_fuga = None                      # sin salida IPv6: no hay por dónde fugarse
    dns_fuga = None
    if despues.get("dns") and antes.get("dns"):
        dns_fuga = despues["dns"] == antes["dns"]
    return {"ipv6_fuga": ip6_fuga, "dns_fuga": dns_fuga}


def _estado_archivo() -> dict:
    try:
        return json.loads((_dir() / "estado.json").read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def _guardar_estado(e: dict) -> dict:
    _escribir_privado(_dir() / "estado.json", json.dumps(e))
    return e


def estado() -> dict:
    wg = wireguard()
    arriba = activo() if wg else False
    e = _estado_archivo()
    return {"wireguard": wg, "wireguard_instalado": bool(wg), "sistema": "windows" if sistema.ES_WINDOWS else "otro",
            "administrador": sistema.es_admin(), "perfil": _publico(perfil()), "activo": arriba,
            "conectado_desde": e.get("desde") if arriba else None, "ip_previa": e.get("ip_previa"),
            "ip_salida": e.get("ip_salida") if arriba else None, "pais_salida": e.get("pais") if arriba else None,
            "verificado": bool(e.get("verificado")) if arriba else False, "warp": e.get("warp") if arriba else None,
            "sesion_id": e.get("sesion_id") if arriba else None}


def conectar() -> dict:
    with _lock:
        p = perfil()
        if not p or p.get("proveedor") not in ("servidor", "warp"):
            raise ErrorVpn("Primero active WARP (Protección → VPN → «Activar WARP») o use el botón de privacidad, que lo hace solo. También puede usar Tor.")
        wg = wireguard()
        if not wg:
            raise ErrorVpn("WireGuard no está instalado. Descárguelo gratis de https://www.wireguard.com/install/ "
                           "(es un instalador normal, sin comandos) y vuelva a intentar.")
        antes = sondas()
        conf = _dir() / f"{NOMBRE}.conf"
        _escribir_privado(conf, _texto_conf(p))
        try:
            if sistema.ES_WINDOWS:
                # Un solo script elevado (un solo permiso): reinstala SOLO si ya existe un túnel
                # (desinstalar uno inexistente hacía fallar el primer intento) y fuerza el DNS por el túnel.
                dns = _dns_del_tunel(p)
                lineas = ["@echo off\r\n"]
                if tunel_instalado():
                    lineas += [f'"{wg}" /uninstalltunnelservice {NOMBRE}\r\n', "timeout /t 2 /nobreak >nul\r\n"]
                lineas.append(f'"{wg}" /installtunnelservice "{conf}"\r\n')
                lineas.append("set RC=%ERRORLEVEL%\r\n")
                if dns:
                    lineas.append(_ps_nrpt_poner(dns))
                lineas.append("exit /b %RC%\r\n")
                script = _dir() / f"{NOMBRE}_instalar.cmd"
                _escribir_privado(script, "".join(lineas))
                codigo = sistema.ejecutar_elevado("cmd.exe", ["/c", str(script)])
                if codigo != 0 and activo():
                    # Quedó corriendo pese al código: es el mismo túnel. Se acepta y se verifica.
                    codigo = 0
            else:
                codigo = sistema.ejecutar_elevado("sudo", ["-n", wg, "up", str(conf)])
        except sistema.ElevacionCancelada as e:
            raise ErrorVpn("Canceló el permiso de administrador: sin él Windows no deja crear el túnel") from e
        except (OSError, Exception) as e:  # noqa: BLE001
            if "already" in str(e).lower() and activo():
                codigo = 0   # el túnel ya estaba arriba: no es un error
            else:
                raise ErrorVpn(f"WireGuard no pudo iniciar el túnel: {e}") from e
        if codigo != 0:
            raise ErrorVpn(f"WireGuard terminó con el código {codigo}. Abra la app WireGuard para ver el detalle.")

        # Verificación: hasta 30 s para el primer apretón de manos y el cambio de IP. Con WARP, además
        # de que cambie la IP, Cloudflare confirma el túnel con «warp=on|plus» en su propia página
        # de diagnóstico; eso también vale (la IP de salida de WARP puede coincidir con la anterior
        # en redes IPv6 o con NAT64, y antes eso se marcaba como "no conectó" aunque sí lo hizo).
        despues, verificado = {}, False
        for _ in range(15):
            time.sleep(2)
            despues = trace(timeout=5)
            cambio_ip = bool(despues.get("ip") and despues["ip"] != antes.get("ip"))
            por_warp = p.get("proveedor") == "warp" and despues.get("warp") in ("on", "plus")
            if cambio_ip or por_warp:
                verificado = True
                break
        motivo = ""
        if not verificado:
            motivo = _diagnostico_sin_verificar(despues)
        # Pruebas de anonimato con el túnel ya arriba: IPv6 y DNS.
        despues_full = {**despues, "ip6": ipv6_publica(), "dns": resolutor_dns()} if verificado else despues
        f = fugas(antes, despues_full) if verificado else {"ipv6_fuga": None, "dns_fuga": None}
        if verificado:
            _confirmar_pais_ubicacion(despues.get("pais"))   # el país que de verdad ven los sitios
        # La IP real solo se guarda en ESTE equipo (para verificar el cambio); nunca se envía al servidor.
        return _guardar_estado({"desde": time.time(), "ip_previa": antes.get("ip"), "ip_salida": despues.get("ip"),
                                "pais": despues.get("pais"), "warp": despues.get("warp"), "colo": despues.get("colo"),
                                "verificado": verificado, "proveedor": p["proveedor"], "motivo": motivo,
                                "ip6_previa": antes.get("ip6"), "dns_previo": antes.get("dns"),
                                "pais_previo": antes.get("pais"), **f})


def _diagnostico_sin_verificar(despues: dict) -> str:
    """Dice POR QUÉ no se pudo verificar el túnel, en vez de un genérico «la IP no cambió»."""
    if not activo():
        return "El túnel no quedó activo: Windows pudo haber bloqueado el servicio de WireGuard."
    wg = _wg_show()
    ahora = time.time()
    hs = wg.get("ultimo_handshake")
    if wg and not hs:
        return ("WireGuard está arriba pero no hubo apretón de manos con el servidor: su red o su operador "
                "probablemente bloquean el puerto UDP 2408. Pruebe con otra red (datos móviles) o use Tor.")
    if hs and ahora - hs < 180 and not despues.get("ip"):
        return ("Hay conexión con el servidor pero no sale tráfico a internet: reinicie el túnel; si sigue "
                "igual, desactive otras VPN o antivirus con filtro de red.")
    if not despues.get("ip"):
        return "El túnel está arriba pero no se pudo consultar la IP pública (sin internet por el túnel)."
    return "El túnel subió pero la IP pública no cambió todavía."


def desconectar() -> dict:
    with _lock:
        wg = wireguard()
        if not wg:
            raise ErrorVpn("WireGuard no está instalado")
        try:
            if sistema.ES_WINDOWS:
                # Si no hay túnel instalado no hay nada que desinstalar (evita el error de WireGuard).
                # Un solo permiso: quita el túnel y la regla de DNS (sin ella no habría DNS al cortar la VPN).
                script = _dir() / f"{NOMBRE}_quitar.cmd"
                _escribir_privado(script, "@echo off\r\n"
                                  + (f'"{wg}" /uninstalltunnelservice {NOMBRE}\r\nset RC=%ERRORLEVEL%\r\n'
                                     if tunel_instalado() else "set RC=0\r\n")
                                  + _ps_nrpt_quitar() + "exit /b %RC%\r\n")
                codigo = sistema.ejecutar_elevado("cmd.exe", ["/c", str(script)])
            else:
                codigo = sistema.ejecutar_elevado("sudo", ["-n", wg, "down", str(_dir() / f"{NOMBRE}.conf")])
        except sistema.ElevacionCancelada as e:
            raise ErrorVpn("Canceló el permiso de administrador: el túnel sigue activo") from e
        previo = _estado_archivo()
        _guardar_estado({})
        return {"cerrado": codigo == 0, "codigo": codigo, "sesion_id": previo.get("sesion_id"),
                "desde": previo.get("desde")}


def verificar() -> dict:
    e = _estado_archivo()
    ahora = trace()
    arriba = activo()
    verificado = bool(arriba and ahora.get("ip") and (ahora["ip"] != e.get("ip_previa")
                                                       or ahora.get("warp") in ("on", "plus")))
    if arriba:
        _guardar_estado({**e, "ip_salida": ahora.get("ip"), "pais": ahora.get("pais"), "warp": ahora.get("warp"),
                         "colo": ahora.get("colo"), "verificado": verificado})
    return {"activo": arriba, "verificado": verificado, "ip": ahora.get("ip"), "pais": ahora.get("pais"),
            "warp": ahora.get("warp"), "ip_previa": e.get("ip_previa")}


def anonimato(repetir: bool = False) -> dict:
    """Nivel de anonimato del túnel actual. Con repetir=True vuelve a medir IPv6 y DNS."""
    from app.ai import anonimato as an
    e = _estado_archivo()
    p = perfil() or {}
    arriba = activo() if wireguard() else False
    if arriba and repetir:
        ahora = sondas()
        f = fugas({"ip6": e.get("ip6_previa"), "dns": e.get("dns_previo")}, ahora)
        e = _guardar_estado({**e, **f, "ip_salida": ahora.get("ip"), "pais": ahora.get("pais"),
                             "verificado": bool(ahora.get("ip") and ahora.get("ip") != e.get("ip_previa"))})
    rutas = (p.get("peer") or {}).get("AllowedIPs", "")
    # En Windows, WireGuard bloquea el tráfico fuera del túnel cuando el único par enruta 0.0.0.0/0 y ::/0.
    # Con la red local permitida (para que el celular llegue al PC) ese bloqueo no se activa.
    kill = (sistema.ES_WINDOWS and not permitir_lan() and "0.0.0.0/0" in rutas and "::/0" in rutas) if p else None
    r = an.evaluar(ip_oculta=bool(arriba and e.get("verificado")), ipv6_fuga=e.get("ipv6_fuga") if arriba else None,
                   dns_fuga=e.get("dns_fuga") if arriba else None, kill_switch=kill if kill else None,
                   proveedor=p.get("proveedor"), nombre=p.get("nombre"), pais_salida=e.get("pais") if arriba else None)
    return {**r, "activo": arriba, "endurecido": p.get("endurecido", [])}


# ═══════════════════════════════════════════ estadísticas en vivo del túnel
def _ruta_wg() -> str | None:
    wg = shutil.which("wg")
    if not wg and sistema.ES_WINDOWS:
        candidato = Path(r"C:\Program Files\WireGuard\wg.exe")
        wg = str(candidato) if candidato.exists() else None
    return wg


def _parse_dump(texto: str) -> dict:
    lineas = [l.split("\t") for l in (texto or "").strip().splitlines()]
    if len(lineas) < 2:
        return {}
    peer = lineas[1]   # la primera línea es la interfaz; la segunda, el peer
    try:
        return {"ultimo_handshake": int(peer[4]), "recibidos": int(peer[5]), "enviados": int(peer[6]),
                "endpoint": peer[2]}
    except (IndexError, ValueError):
        return {}


_ultima_elevacion_wg = 0.0


def _wg_show(permitir_elevacion: bool = False) -> dict:
    """Lee el estado real del túnel con `wg show` (no PowerShell): apretón de manos y bytes.

    Cuando WireGuard corre como servicio de Windows, `wg show … dump` necesita privilegios para leer
    los contadores. Si la salida directa viene vacía (sin admin), se reintenta de forma elevada
    escribiendo el volcado a un archivo temporal que luego se lee. Así los datos de Descargado/Subido
    aparecen aunque el servidor no corra como administrador.
    """
    import subprocess
    import tempfile
    wg = _ruta_wg()
    if not wg:
        return {}
    try:
        r = subprocess.run([wg, "show", NOMBRE, "dump"], capture_output=True, text=True, timeout=6,
                           creationflags=sistema.CREATE_NO_WINDOW if sistema.ES_WINDOWS else 0)
        datos = _parse_dump(r.stdout)
    except (OSError, subprocess.SubprocessError):
        datos = {}
    if datos or not sistema.ES_WINDOWS or not permitir_elevacion:
        return datos
    # Reintento elevado (solo bajo petición, no en cada refresco): wg.exe escribe el volcado a un
    # archivo que este proceso sí puede leer. Como mucho una vez cada 10 minutos: cada intento abre
    # la ventana de permisos de Windows, y repetirla cada pocos segundos es inaceptable.
    global _ultima_elevacion_wg
    ahora = time.monotonic()
    if _ultima_elevacion_wg and ahora - _ultima_elevacion_wg < 600:
        return datos
    _ultima_elevacion_wg = ahora
    try:
        salida = Path(tempfile.gettempdir()) / f"gia_wg_{NOMBRE}.txt"
        cmd = f'"{wg}" show {NOMBRE} dump > "{salida}"'
        codigo = sistema.ejecutar_elevado("cmd.exe", ["/c", cmd], timeout=8)
        if codigo == 0 and salida.exists():
            datos = _parse_dump(salida.read_text("utf-8", "ignore"))
            salida.unlink(missing_ok=True)
    except (OSError, sistema.ElevacionCancelada, Exception):  # noqa: BLE001
        pass
    return datos


def estadisticas(medir_latencia: bool = True, leer_bytes: bool = False) -> dict:
    """Cifras en vivo para la pantalla: tiempo conectado, datos, latencia y último apretón de manos.

    `leer_bytes=True` (al pulsar «Verificar») autoriza leer los contadores de forma elevada una vez;
    el refresco automático no lo hace, para no lanzar una ventana de permiso cada pocos segundos.
    """
    import time as _t
    e = _estado_archivo()
    arriba = activo()
    wg = _wg_show(permitir_elevacion=leer_bytes) if arriba else {}
    # Los bytes leídos se guardan para que el refresco automático los siga mostrando.
    if wg.get("recibidos") is not None:
        e["recibidos_bytes"], e["enviados_bytes"] = wg["recibidos"], wg["enviados"]
        _guardar_estado(e)
    elif arriba:
        wg.setdefault("recibidos", e.get("recibidos_bytes"))
        wg.setdefault("enviados", e.get("enviados_bytes"))
    latencia = None
    if arriba and medir_latencia:
        latencia = _latencia()
        if latencia is not None:
            e["latencia_ms"] = latencia
            _guardar_estado(e)
    ahora = _t.time()
    hs = wg.get("ultimo_handshake")
    return {
        "activo": arriba, "verificado": bool(e.get("verificado")) and arriba,
        "segundos_conectado": round(ahora - e["desde"]) if arriba and e.get("desde") else 0,
        "ip_salida": e.get("ip_salida"), "pais_salida": e.get("pais"), "warp": e.get("warp"),
        "colo": e.get("colo"), "ip_previa": e.get("ip_previa"),
        "recibidos_bytes": wg.get("recibidos"), "enviados_bytes": wg.get("enviados"),
        "latencia_ms": latencia if latencia is not None else e.get("latencia_ms"),
        "ultimo_handshake_hace_s": (round(ahora - hs) if hs else None),
        "handshake_ok": bool(hs and ahora - hs < 180),
        "proveedor": (perfil() or {}).get("proveedor"), "medido": ahora,
    }


def _latencia() -> int | None:
    """Latencia hasta Cloudflare a través del túnel (una petición HTTPS corta)."""
    import time as _t
    try:
        t0 = _t.perf_counter()
        httpx.head(TRACE, timeout=4)
        return round((_t.perf_counter() - t0) * 1000)
    except httpx.HTTPError:
        return None


def anotar_sesion(sesion_id: str) -> None:
    e = _estado_archivo()
    if e:
        _guardar_estado({**e, "sesion_id": sesion_id})
