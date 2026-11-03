"""Salida a internet de GuardianIA, con la opción de ir por Tor (anonimato de las peticiones del servidor).

Tres modos (ajuste «red_por_tor»):

* ``apagado``   (por defecto) — conexión directa, como siempre.
* ``preferir``  — si Tor está activo, las peticiones a internet van por Tor; si no, salen directo.
* ``estricto``  — SOLO por Tor. Si Tor no está activo, la petición NO sale (se lanza ``SinTor``): la IP
  real nunca se filtra por un fallo de Tor.

Qué va por aquí: lo que sale a INTERNET (búsqueda web del asistente, revisión de filtraciones de
correo y contraseñas, actualización de firmas). Qué NO va por aquí: el modelo de IA local (127.0.0.1)
ni la conexión con el celular (red de la casa): los relevos de salida de Tor no alcanzan direcciones
privadas y además es su propio servidor.

DNS: se usa ``socks5h`` — el nombre del sitio lo resuelve el relevo de salida de Tor, que no sabe quién
es usted. NO se usa DoH de Cloudflare en este camino: fuera de Tor le mostraría a Cloudflare su IP real
junto a cada dominio (fuga de DNS); dentro de Tor, una sola empresa vería todas sus consultas y podría
correlacionarlas. Es la recomendación del propio Tor Project.
"""
from __future__ import annotations

import httpx

from app.local import ajustes

MODOS = ("apagado", "preferir", "estricto")


class SinTor(Exception):
    """Modo estricto: Tor no está activo, así que la petición no sale (sin filtrar la IP real)."""


def modo() -> str:
    m = ajustes.leer().get("red_por_tor", "apagado")
    return m if m in MODOS else "apagado"


def fijar_modo(m: str) -> str:
    if m not in MODOS:
        raise ValueError(f"Modo inválido: {m}")
    ajustes.guardar({"red_por_tor": m})
    return m


def proxy_tor() -> str | None:
    """socks5h://127.0.0.1:PUERTO del Tor activo (el de GuardianIA o el de Tor Browser), o None."""
    from app.local import tor
    puerto = tor.puerto_activo()
    return f"socks5h://127.0.0.1:{puerto}" if puerto else None


def _proxy_para_salir() -> str | None:
    m = modo()
    if m == "apagado":
        return None
    p = proxy_tor()
    if p:
        return p
    if m == "estricto":
        raise SinTor("El modo estricto exige Tor y Tor no está activo: la petición no salió (su IP no se "
                     "expuso). Active Tor en Protección → VPN → Modo cebolla.")
    return None


def cliente_internet(timeout: float = 15.0, **kwargs) -> httpx.Client:
    """Cliente httpx para salir a internet según el modo. El que lo crea debe cerrarlo (``with``)."""
    proxy = _proxy_para_salir()
    return httpx.Client(proxy=proxy, timeout=timeout, **kwargs) if proxy else httpx.Client(timeout=timeout, **kwargs)


def get(url: str, *, timeout: float = 15.0, follow_redirects: bool = False, **kwargs) -> httpx.Response:
    """GET a internet según el modo (reemplaza a httpx.get en los módulos que salen a internet).
    Sin Tor, es exactamente httpx.get: el comportamiento directo no cambia en nada."""
    proxy = _proxy_para_salir()
    if not proxy:
        return httpx.get(url, timeout=timeout, follow_redirects=follow_redirects, **kwargs)
    with httpx.Client(proxy=proxy, timeout=timeout, follow_redirects=follow_redirects) as c:
        return c.get(url, **kwargs)


def estado() -> dict:
    p = proxy_tor()
    m = modo()
    return {"modo": m, "tor_activo": bool(p),
            "saliendo_por_tor": bool(p) and m != "apagado",
            "bloqueado": m == "estricto" and not p}
