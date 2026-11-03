"""Navegador web para el asistente de IA — con defensa contra SSRF.

El asistente puede buscar en internet y leer páginas para responder. El riesgo grande de
"dar a una IA un navegador" es la falsificación de solicitud del lado del servidor (SSRF):
que alguien la induzca a pedir `http://169.254.169.254/` (metadatos de la nube) o a la red
interna. Aquí eso se bloquea en varias capas:

* Solo http/https, sin credenciales en la URL, sin puertos raros.
* Se resuelve el DNS y se rechaza cualquier IP privada, de loopback, enlace-local o reservada
  (cubre el rebinding: se comprueba la IP real, no solo el nombre).
* Se sigue un número limitado de redirecciones y CADA salto se vuelve a validar.
* Límite de tamaño, tiempo y solo `text/html`/`text/plain` (nada de descargar binarios).
* Se extrae solo texto legible; se ignoran scripts y estilos.

La búsqueda usa la API pública de DuckDuckGo (HTML), sin claves. Es reemplazable por Brave/Bing
detrás de la interfaz `search()`.
"""
from __future__ import annotations

import html
import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

USER_AGENT = "GuardianIA-Assistant/1.0 (+https://guardianai.dev/bot)"
MAX_BYTES = 2_000_000
ALLOWED_CONTENT = ("text/html", "text/plain", "application/xhtml+xml")
BLOCKED_PORTS = {22, 23, 25, 445, 3306, 3389, 5432, 6379, 9200, 11211, 27017}


class UnsafeUrl(ValueError):
    pass


@dataclass
class Page:
    url: str
    title: str
    text: str
    truncated: bool


@dataclass
class SearchHit:
    title: str
    url: str
    snippet: str


def _ip_is_public(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified)


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeUrl("Solo se permiten enlaces http o https")
    if parsed.username or parsed.password:
        raise UnsafeUrl("La URL no puede contener credenciales")
    host = parsed.hostname
    if not host:
        raise UnsafeUrl("URL sin dominio")
    if parsed.port and parsed.port in BLOCKED_PORTS:
        raise UnsafeUrl("Puerto no permitido")
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise UnsafeUrl("No se pudo resolver el dominio")
    for *_, sockaddr in infos:
        if not _ip_is_public(sockaddr[0]):
            raise UnsafeUrl("El dominio apunta a una dirección de red interna")
    return url


def _extract(html_text: str) -> tuple[str, str]:
    title_m = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.I | re.S)
    title = html.unescape(re.sub(r"\s+", " ", title_m.group(1)).strip())[:200] if title_m else ""
    body = re.sub(r"(?is)<(script|style|noscript|template|svg|head)[^>]*>.*?</\1>", " ", html_text)
    body = re.sub(r"(?is)<(nav|footer|header|form|aside)[^>]*>.*?</\1>", " ", body)
    body = re.sub(r"(?s)<[^>]+>", " ", body)
    body = html.unescape(body)
    body = re.sub(r"[ \t\r\f]+", " ", body)
    body = re.sub(r"\n\s*\n\s*\n+", "\n\n", body)
    return title, body.strip()


def fetch(url: str, *, client: httpx.Client, max_chars: int = 6000, max_redirects: int = 3) -> Page:
    """Descarga una página segura y devuelve su texto. Valida cada redirección."""
    current = validate_url(url)
    truncated = False
    for _ in range(max_redirects + 1):
        with client.stream("GET", current, headers={"User-Agent": USER_AGENT,
                                                     "Accept": "text/html,text/plain"},
                           follow_redirects=False) as resp:
            if resp.is_redirect:
                nxt = resp.headers.get("location", "")
                current = validate_url(urljoin(current, nxt))
                continue
            ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            if ctype and not any(ctype.startswith(a) for a in ALLOWED_CONTENT):
                raise UnsafeUrl(f"El contenido no es una página de texto ({ctype})")
            chunks, size = [], 0
            for chunk in resp.iter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BYTES:
                    truncated = True
                    break
            raw = b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")
        title, text = _extract(raw)
        if len(text) > max_chars:
            text, truncated = text[:max_chars].rsplit(" ", 1)[0] + " …", True
        return Page(url=current, title=title, text=text, truncated=truncated)
    raise UnsafeUrl("Demasiadas redirecciones")


def search(query: str, *, client: httpx.Client, limit: int = 5) -> list[SearchHit]:
    """Busca en la web (DuckDuckGo HTML, sin API key)."""
    resp = client.post("https://html.duckduckgo.com/html/", data={"q": query[:300]},
                       headers={"User-Agent": USER_AGENT}, follow_redirects=True)
    resp.raise_for_status()
    hits: list[SearchHit] = []
    for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', resp.text, re.S):
        raw_url, raw_title = m.group(1), re.sub(r"<[^>]+>", "", m.group(2))
        real = re.search(r"uddg=([^&]+)", raw_url)
        from urllib.parse import unquote
        target = unquote(real.group(1)) if real else raw_url
        try:
            validate_url(target)
        except UnsafeUrl:
            continue
        hits.append(SearchHit(title=html.unescape(raw_title).strip()[:200], url=target, snippet=""))
        if len(hits) >= limit:
            break
    # Fragmentos por separado (el HTML de DDG los pone en otro nodo).
    snippets = [html.unescape(re.sub(r"<[^>]+>", "", s)).strip()
                for s in re.findall(r'result__snippet[^>]*>(.*?)</a>', resp.text, re.S)]
    for hit, snip in zip(hits, snippets):
        hit.snippet = snip[:300]
    return hits
