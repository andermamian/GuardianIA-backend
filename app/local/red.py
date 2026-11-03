"""Análisis de la red del equipo: conexiones activas, DNS y estado de la VPN.

Qué vigila y por qué importa:

* **Conexiones activas.** A qué direcciones está hablando el equipo ahora mismo, y qué programa las
  abrió. El malware se delata aquí: un proceso desconocido conectado a un servidor remoto por un
  puerto raro, o una conexión a una IP con mala reputación.
* **DNS.** Qué servidores DNS usa el sistema. Un DNS cambiado sin permiso es una técnica de secuestro
  (redirige su banco a una página falsa). Con la VPN activa, el DNS debe ser el del túnel.
* **WARP / VPN.** Si la protección de red que ya tiene está de verdad activa y sin fugas.

Todo se lee con la API nativa de Windows y utilidades del sistema (ipconfig, getUdpTable), nunca con
PowerShell. En Linux/macOS degrada con elegancia.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass, field

from app.local import sistema

try:
    import psutil
except Exception:  # noqa: BLE001
    psutil = None

# Puertos que un programa normal de usuario rara vez abre hacia afuera; su uso pide una mirada.
PUERTOS_LLAMATIVOS = {23: "Telnet", 445: "SMB", 1080: "SOCKS proxy", 3389: "Escritorio remoto",
                      4444: "Metasploit (típico de malware)", 5555: "ADB/puerta trasera",
                      6667: "IRC (botnets)", 31337: "puerta trasera clásica"}
# DNS legítimos y conocidos: si el sistema usa uno fuera de esta idea, se avisa (no se bloquea).
DNS_CONOCIDOS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "8.8.8.8": "Google", "8.8.4.4": "Google",
    "9.9.9.9": "Quad9", "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "94.140.14.14": "AdGuard", "185.228.168.9": "CleanBrowsing",
}


@dataclass
class Hallazgo:
    nivel: str
    titulo: str
    detalle: str
    categoria: str      # conexion | dns | vpn
    datos: dict = field(default_factory=dict)


def _privada(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved
    except ValueError:
        return True


# ═══════════════════════════════════════════════════ conexiones activas
def conexiones() -> list[dict]:
    """(proceso, pid, ip remota, puerto) de cada conexión establecida hacia afuera."""
    salida: list[dict] = []
    if psutil is not None:
        nombres = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status != "ESTABLISHED" or not c.raddr:
                    continue
                ip, puerto = c.raddr.ip, c.raddr.port
                if _privada(ip):
                    continue
                if c.pid and c.pid not in nombres:
                    try:
                        nombres[c.pid] = psutil.Process(c.pid).name()
                    except Exception:  # noqa: BLE001
                        nombres[c.pid] = "?"
                salida.append({"proceso": nombres.get(c.pid, "?"), "pid": c.pid or 0, "ip": ip, "puerto": puerto})
        except Exception:  # noqa: BLE001 - net_connections puede requerir permisos
            pass
        return salida
    # Sin psutil: netstat, que viene en Windows.
    if not sistema.ES_WINDOWS:
        return salida
    try:
        r = subprocess.run(["netstat.exe", "-no"], capture_output=True, text=True, timeout=15,
                           creationflags=sistema.CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return salida
    for linea in (r.stdout or "").splitlines():
        m = re.search(r"TCP\s+\S+\s+([\d.]+):(\d+)\s+ESTABLISHED\s+(\d+)", linea)
        if m and not _privada(m.group(1)):
            salida.append({"proceso": "?", "pid": int(m.group(3)), "ip": m.group(1), "puerto": int(m.group(2))})
    return salida


def revisar_conexiones() -> list[Hallazgo]:
    hallazgos: list[Hallazgo] = []
    vistas = set()
    for c in conexiones():
        etiqueta = PUERTOS_LLAMATIVOS.get(c["puerto"])
        clave = (c["ip"], c["puerto"])
        if etiqueta and clave not in vistas:
            vistas.add(clave)
            nivel = "peligroso" if c["puerto"] in (4444, 5555, 31337, 6667) else "sospechoso"
            hallazgos.append(Hallazgo(nivel, f"Conexión por puerto {c['puerto']} ({etiqueta})",
                                      f"«{c['proceso']}» está conectado a {c['ip']} por un puerto asociado a {etiqueta}. "
                                      "Si no reconoce ese programa, revíselo.", "conexion", c))
    return hallazgos


# ═══════════════════════════════════════════════════ DNS
def servidores_dns() -> list[str]:
    """Los servidores DNS que usa el equipo, leídos de ipconfig (nativo)."""
    if not sistema.ES_WINDOWS:
        try:
            with open("/etc/resolv.conf", encoding="ascii", errors="ignore") as fh:
                return re.findall(r"nameserver\s+([\d.]+)", fh.read())
        except OSError:
            return []
    try:
        r = subprocess.run(["ipconfig.exe", "/all"], capture_output=True, text=True, timeout=15,
                           creationflags=sistema.CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return []
    # ipconfig lista los DNS en líneas, la primera con etiqueta y las siguientes solo con la IP.
    servidores, capturando = [], False
    for linea in (r.stdout or "").splitlines():
        if re.search(r"(DNS Servers|Servidores DNS)", linea, re.I):
            capturando = True
        if capturando:
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", linea)
            if m:
                servidores.append(m.group(1))
            elif ":" in linea and not re.search(r"\d{1,3}\.\d", linea):
                capturando = False
    return list(dict.fromkeys(servidores))


def revisar_dns(vpn_activa: bool, dns_vpn: str | None = None) -> list[Hallazgo]:
    hallazgos: list[Hallazgo] = []
    lista = servidores_dns()
    publicos = [d for d in lista if not _privada(d)]
    for d in publicos:
        if d in DNS_CONOCIDOS or (dns_vpn and d in dns_vpn):
            continue
        # Un DNS público que no es de un proveedor conocido merece una mirada (no es prueba de ataque).
        hallazgos.append(Hallazgo("sospechoso", f"Servidor DNS no reconocido: {d}",
                                  f"El equipo resuelve nombres con {d}, que no es un DNS público conocido. Si usted no "
                                  "lo configuró, un cambio de DNS puede redirigir sus sitios a páginas falsas.",
                                  "dns", {"servidor": d}))
    if vpn_activa and dns_vpn:
        fuga = [d for d in publicos if d not in dns_vpn and d not in DNS_CONOCIDOS]
        if fuga:
            hallazgos.append(Hallazgo("sospechoso", "Posible fuga de DNS con la VPN activa",
                                      f"La VPN está conectada, pero el equipo también usa DNS fuera del túnel ({', '.join(fuga)}). "
                                      "Eso puede revelar qué sitios visita.", "dns", {"fuera_del_tunel": fuga}))
    return hallazgos


# ═══════════════════════════════════════════════════ resumen
def revisar_todo() -> dict:
    """Foto del estado de la red, incluyendo si la VPN protege de verdad."""
    from app.local import vpn as tunel
    try:
        est_vpn = tunel.estado()
    except Exception:  # noqa: BLE001
        est_vpn = {"activo": False}
    dns_vpn = None
    perfil = tunel.perfil() if hasattr(tunel, "perfil") else None
    if perfil:
        dns_vpn = (perfil.get("interfaz") or {}).get("DNS")

    hallazgos: list[Hallazgo] = []
    for revision in (revisar_conexiones, lambda: revisar_dns(est_vpn.get("activo", False), dns_vpn)):
        try:
            hallazgos.extend(revision())
        except Exception:  # noqa: BLE001
            continue

    peligrosos = [h for h in hallazgos if h.nivel == "peligroso"]
    sospechosos = [h for h in hallazgos if h.nivel == "sospechoso"]
    dns = servidores_dns()
    return {
        "vpn_activa": bool(est_vpn.get("activo")),
        "vpn_verificada": bool(est_vpn.get("verificado")),
        "dns": dns, "dns_conocidos": [DNS_CONOCIDOS.get(d, "privado" if _privada(d) else "desconocido") for d in dns],
        "conexiones_externas": len(conexiones()),
        "peligrosos": len(peligrosos), "sospechosos": len(sospechosos),
        "hallazgos": [{"nivel": h.nivel, "titulo": h.titulo, "detalle": h.detalle, "categoria": h.categoria,
                       "datos": h.datos} for h in (peligrosos + sospechosos)][:50],
        "resumen": _frase(est_vpn, peligrosos, sospechosos),
    }


def _frase(est_vpn: dict, peligrosos: list, sospechosos: list) -> str:
    partes = []
    if est_vpn.get("activo"):
        partes.append("La VPN está protegiendo su conexión." if est_vpn.get("verificado")
                      else "La VPN está activa pero sin verificar.")
    else:
        partes.append("La VPN está apagada: su tráfico sale sin cifrar por su proveedor.")
    if peligrosos:
        partes.append(f"Hay {len(peligrosos)} conexión(es) de alto riesgo.")
    elif sospechosos:
        partes.append(f"{len(sospechosos)} elemento(s) de red merecen su revisión.")
    else:
        partes.append("No veo conexiones ni DNS sospechosos.")
    return " ".join(partes)
