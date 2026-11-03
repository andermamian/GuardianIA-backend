"""Anonimato de la VPN: qué tan anónimo queda el usuario y cómo cerrar las fugas.

Una VPN cambia la IP, pero eso no basta para el anonimato. Este motor revisa lo que de verdad
delata a una persona y lo explica sin exagerar:

* **IP**: que la IP pública haya cambiado (sin eso no hay nada).
* **Fuga de IPv6**: si el túnel solo lleva IPv4, el tráfico IPv6 sale con la IP real.
* **Fuga de DNS**: si las consultas de nombres siguen yendo al resolutor del operador, este ve cada
  sitio visitado aunque el tráfico vaya cifrado.
* **Kill switch**: si el túnel se cae, ¿sale tráfico sin cifrar?
* **Jurisdicción** del país de salida (alianzas de vigilancia 5/9/14 Ojos) y **quién opera** la VPN.
* **Registros**: el propio servidor de GuardianIA no guarda la IP real (política sin registros).

Es lógica pura (sin red): las sondas de red están en app/local/vpn.py y en la app Android, que usa
una copia idéntica de estas reglas (probada contra este archivo).
"""
from __future__ import annotations

MOTOR = "anonimato-1.0.0"

# Alianzas de intercambio de inteligencia (lo que se conoce públicamente como 5, 9 y 14 Ojos).
CINCO_OJOS = {"US", "GB", "CA", "AU", "NZ"}
NUEVE_OJOS = CINCO_OJOS | {"DK", "FR", "NL", "NO"}
CATORCE_OJOS = NUEVE_OJOS | {"DE", "BE", "IT", "SE", "ES"}

# DNS privado por defecto cuando un .conf no trae DNS: Quad9 (fundación suiza sin fines de lucro, sin
# registro de IPs, bloquea dominios maliciosos).
DNS_PRIVADO = "9.9.9.9, 149.112.112.112, 2620:fe::fe"

LIMITES = [
    "Si inicia sesión en Google, Facebook, su banco u otra cuenta, ese sitio sabe quién es, con o sin VPN.",
    "El navegador puede identificarle por su «huella» (tamaño de pantalla, fuentes, extensiones). "
    "Use el modo privado y pocos complementos.",
    "Algunos navegadores filtran la IP real por WebRTC: desactívelo o use Firefox con "
    "media.peerconnection.enabled=false.",
    "Para anonimato fuerte (periodismo, activismo) use Tor Browser: una VPN confía en un solo operador; "
    "Tor reparte la confianza entre varios.",
]


def jurisdiccion(pais: str | None) -> dict:
    """Clasifica el país de salida según las alianzas de vigilancia."""
    p = (pais or "").upper()
    if not p:
        return {"pais": None, "alianza": "desconocida", "puntaje": 0.5,
                "texto": "País de salida desconocido"}
    if p in CINCO_OJOS:
        return {"pais": p, "alianza": "5 Ojos", "puntaje": 0.1,
                "texto": f"{p} pertenece a los 5 Ojos: sus agencias comparten datos de vigilancia"}
    if p in NUEVE_OJOS:
        return {"pais": p, "alianza": "9 Ojos", "puntaje": 0.3,
                "texto": f"{p} pertenece a los 9 Ojos (intercambio de inteligencia)"}
    if p in CATORCE_OJOS:
        return {"pais": p, "alianza": "14 Ojos", "puntaje": 0.5,
                "texto": f"{p} pertenece a los 14 Ojos (intercambio de inteligencia)"}
    return {"pais": p, "alianza": "ninguna", "puntaje": 1.0,
            "texto": f"{p} no pertenece a las alianzas 5/9/14 Ojos"}


def operador(proveedor: str | None, nombre: str | None = None) -> dict:
    """Quién opera el túnel y qué sabe de usted."""
    n = (nombre or "").lower()
    if proveedor == "tor":
        return {"puntaje": 1.0, "texto": "Tor: su tráfico pasa por 3 relevos y ninguno conoce a la vez quién es usted "
                "y qué visita."}
    if proveedor == "warp":
        return {"puntaje": 0.35, "texto": "Cloudflare WARP cifra su tráfico, pero Cloudflare conoce su IP real y "
                "la salida suele quedar en su mismo país: protege su privacidad en la red, no le hace anónimo."}
    if proveedor == "importado" and ("proton" in n or "mullvad" in n or "ivpn" in n):
        return {"puntaje": 1.0, "texto": "Proveedor con política de no registros auditada públicamente."}
    if proveedor == "importado":
        return {"puntaje": 0.7, "texto": "Proveedor importado: revise que tenga política de no registros auditada."}
    if proveedor == "servidor":
        return {"puntaje": 0.6, "texto": "Servidor propio: usted controla los registros, pero si lo contrató a su "
                "nombre, la IP de salida puede rastrearse hasta usted."}
    return {"puntaje": 0.0, "texto": "Sin túnel configurado."}


def endurecer(interfaz: dict, peer: dict) -> list[str]:
    """Cierra las fugas en la configuración. Modifica los diccionarios y devuelve qué cambió.

    * Sin DNS en el archivo → se usa un DNS privado dentro del túnel (si no, el sistema pregunta al
      operador por cada sitio).
    * AllowedIPs sin ::/0 → se agrega: el IPv6 también entra al túnel (o se descarta si el túnel no
      tiene IPv6), así la IPv6 real no se filtra. En Windows, 0.0.0.0/0 + ::/0 activa además el
      «kill switch» de WireGuard (bloquea el tráfico fuera del túnel).
    """
    cambios: list[str] = []
    if not interfaz.get("DNS"):
        interfaz["DNS"] = DNS_PRIVADO
        cambios.append("dns_privado")
    rutas = [r.strip() for r in peer.get("AllowedIPs", "").split(",") if r.strip()]
    if "::/0" not in rutas:
        rutas.append("::/0")
        peer["AllowedIPs"] = ", ".join(rutas)
        cambios.append("ipv6_por_tunel")
    return cambios


def evaluar(*, ip_oculta: bool, ipv6_fuga: bool | None, dns_fuga: bool | None, kill_switch: bool | None,
            proveedor: str | None, nombre: str | None = None, pais_salida: str | None = None,
            servidor_sin_registros: bool = True) -> dict:
    """Nivel de anonimato 0-100 con cada revisión explicada. None = no se pudo comprobar."""
    revisiones: list[dict] = []

    def rev(clave: str, estado: str, texto: str, peso: int, logro: float) -> None:
        revisiones.append({"clave": clave, "estado": estado, "texto": texto, "peso": peso,
                           "puntos": round(peso * logro, 1)})

    rev("ip", "ok" if ip_oculta else "falla",
        "Su IP real está oculta" if ip_oculta else "Su IP real sigue visible: el túnel no está funcionando", 20,
        1.0 if ip_oculta else 0.0)
    if ipv6_fuga is None:
        rev("ipv6", "ok", "Sin fuga de IPv6 (su conexión no usa IPv6 o va por el túnel)", 15, 1.0)
    else:
        rev("ipv6", "falla" if ipv6_fuga else "ok",
            "Fuga de IPv6: su IPv6 real sale fuera del túnel" if ipv6_fuga else "Su IPv6 va por el túnel", 15,
            0.0 if ipv6_fuga else 1.0)
    if dns_fuga is None:
        rev("dns", "aviso", "No se pudo comprobar el DNS", 15, 0.5)
    else:
        rev("dns", "falla" if dns_fuga else "ok",
            "Posible fuga de DNS: sus consultas siguen yendo al mismo resolutor que sin VPN" if dns_fuga
            else "Sus consultas de DNS van por el túnel", 15, 0.0 if dns_fuga else 1.0)
    if kill_switch is None:
        rev("kill_switch", "aviso", "Active el bloqueo de tráfico sin VPN (kill switch) en los ajustes del sistema", 10, 0.3)
    else:
        rev("kill_switch", "ok" if kill_switch else "falla",
            "Si el túnel se cae, el tráfico se bloquea (kill switch)" if kill_switch
            else "Si el túnel se cae, el tráfico saldría sin cifrar", 10, 1.0 if kill_switch else 0.0)
    j = jurisdiccion(pais_salida)
    rev("jurisdiccion", "ok" if j["puntaje"] >= 0.99 else "aviso" if j["puntaje"] >= 0.3 else "falla",
        j["texto"], 10, j["puntaje"])
    o = operador(proveedor, nombre)
    rev("operador", "ok" if o["puntaje"] >= 0.99 else "aviso" if o["puntaje"] >= 0.3 else "falla",
        o["texto"], 25, o["puntaje"])
    rev("registros", "ok" if servidor_sin_registros else "falla",
        "GuardianIA no guarda su IP real ni el historial de la VPN" if servidor_sin_registros
        else "El servidor guarda su IP real", 5, 1.0 if servidor_sin_registros else 0.0)

    total = round(sum(r["puntos"] for r in revisiones))
    if not ip_oculta:
        total = min(total, 10)       # sin IP oculta no hay anonimato, aunque lo demás esté bien
    if o["puntaje"] < 0.7:
        # Si el operador conoce su IP real (WARP) o el servidor puede rastrearse hasta usted (servidor
        # propio contratado a su nombre), el anonimato no puede ser «alto».
        total = min(total, 79)
    nivel = "alto" if total >= 80 else "medio" if total >= 55 else "bajo"
    consejos = [r["texto"] for r in revisiones if r["estado"] != "ok"]
    return {"motor": MOTOR, "puntaje": total, "nivel": nivel, "revisiones": revisiones,
            "consejos": consejos, "limites": LIMITES}
