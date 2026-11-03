"""Detección de phishing por características léxicas (pantalla Escudo Web y Red).

Funciona sin enviar la navegación a terceros. Señales usadas por los modelos académicos de
detección de phishing (Sahingoz et al., 2019) y ajustadas a fraudes frecuentes en Colombia
(suplantación de bancos, DIAN, SIMIT, empresas de mensajería):

* Host como IP, punycode (homógrafos), exceso de subdominios, TLD abusados.
* Marca conocida fuera de su dominio registrado («bancolombia.seguro-login.xyz»).
* Palabras de urgencia/credenciales en la ruta.
* Símbolo @ (engaña al leer la URL), longitud y entropía anómalas, HTTP sin TLS.

El dominio registrable se calcula con una lista corta de sufijos compuestos; para producción
se recomienda la Public Suffix List completa (paquete `tldextract`).
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlsplit

ENGINE_VERSION = "urlrisk-1.2.0"

BRANDS = {
    "bancolombia": "bancolombia.com", "davivienda": "davivienda.com", "bbva": "bbva.com.co",
    "nequi": "nequi.com.co", "daviplata": "daviplata.com", "bancodebogota": "bancodebogota.com",
    "dian": "dian.gov.co", "simit": "fcm.org.co", "servientrega": "servientrega.com",
    "interrapidisimo": "interrapidisimo.com", "paypal": "paypal.com", "google": "google.com",
    "microsoft": "microsoft.com", "apple": "apple.com", "whatsapp": "whatsapp.com", "netflix": "netflix.com",
    "mercadolibre": "mercadolibre.com.co", "facebook": "facebook.com", "instagram": "instagram.com",
}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "zip", "mov", "icu", "buzz", "rest", "cfd", "sbs", "live", "shop",
                   "support", "online", "site", "fun", "gq", "tk", "ml"}
COMPOUND_SUFFIXES = {"com.co", "gov.co", "edu.co", "org.co", "net.co", "com.mx", "com.br", "co.uk", "com.ar"}
LURE_WORDS = {"login", "verify", "verificar", "seguro", "secure", "update", "actualizar", "cuenta", "account",
              "banking", "confirm", "confirmar", "password", "clave", "desbloquear", "suspendida", "premio",
              "multa", "pago", "wallet", "otp", "token"}
CATEGORY_HINTS = {
    "adultos": {"porn", "xxx", "sex", "adult"},
    "apuestas": {"bet", "casino", "apuesta", "poker", "slots"},
    "juegos": {"game", "juego", "roblox", "steam", "epicgames"},
    "redes_sociales": {"facebook", "instagram", "tiktok", "twitter", "x.com", "snapchat"},
}


@dataclass
class UrlVerdict:
    host: str
    registrable_domain: str
    score: int
    verdict: str  # permitir|advertir|bloquear
    category: str | None
    reasons: list[dict] = field(default_factory=list)
    engine_version: str = ENGINE_VERSION


def registrable_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in COMPOUND_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if "://" not in value:
        value = "http://" + value
    host = urlsplit(value).hostname or ""
    if not host or len(host) > 253 or not re.fullmatch(r"[a-z0-9.\-]+", host):
        raise ValueError("Dominio inválido")
    return host.removeprefix("www.")


def categorize(host: str) -> str | None:
    for cat, hints in CATEGORY_HINTS.items():
        if any(h in host for h in hints):
            return cat
    return None


def assess_url(url: str, allow: set[str] | None = None, block: set[str] | None = None) -> UrlVerdict:
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("URL inválida")
    domain = registrable_domain(host)
    allow, block = allow or set(), block or set()

    def listed(domains: set[str]) -> bool:
        return any(host == d or host.endswith("." + d) for d in domains)

    category = categorize(host)
    if listed(block):
        return UrlVerdict(host, domain, 100, "bloquear", category, [{"puntos": 100, "motivo": "En su lista negra"}])
    if listed(allow):
        return UrlVerdict(host, domain, 0, "permitir", category, [{"puntos": 0, "motivo": "En su lista blanca"}])

    reasons: list[dict] = []

    def add(points: int, why: str):
        reasons.append({"puntos": points, "motivo": why})

    try:
        ipaddress.ip_address(host)
        add(30, "Usa una dirección IP en lugar de un nombre de dominio")
    except ValueError:
        pass
    if "xn--" in host:
        add(30, "Dominio con caracteres internacionales que pueden imitar otra marca")
    if "@" in parts.netloc:
        add(25, "Contiene «@», un truco para ocultar el destino real")
    if parts.scheme == "http":
        add(10, "Conexión sin cifrar (HTTP)")
    labels = host.split(".")
    if len(labels) - len(domain.split(".")) >= 3:
        add(12, "Demasiados subdominios")
    tld = labels[-1]
    if tld in SUSPICIOUS_TLDS:
        add(12, f"Extensión .{tld} muy usada en fraudes")
    tokens = set(re.split(r"[.\-]", host))
    for brand, official in BRANDS.items():
        # Marcas cortas: token exacto (evita «pineapple»); largas: subcadena («bancolombiasegura»).
        mentioned = brand in tokens or (len(brand) >= 8 and brand in host.replace("-", ""))
        if mentioned and not (host == official or host.endswith("." + official)):
            add(40, f"Menciona «{brand}» pero no es el sitio oficial ({official})")
            break
    path = (parts.path + "?" + parts.query).lower()
    lures = sorted({w for w in LURE_WORDS if w in path or w in host})
    if lures:
        add(min(20, 7 * len(lures)), "Palabras típicas de robo de credenciales: " + ", ".join(lures[:4]))
    if host.count("-") >= 3:
        add(8, "Muchos guiones en el dominio")
    if len(raw) > 120:
        add(6, "URL inusualmente larga")
    first = labels[0] if len(labels) > 2 else domain.split(".")[0]
    if len(first) >= 12 and _entropy(first) > 3.6:
        add(10, "Nombre de dominio con apariencia aleatoria")

    score = min(100, sum(r["puntos"] for r in reasons))
    verdict = "bloquear" if score >= 50 else "advertir" if score >= 25 else "permitir"
    reasons.sort(key=lambda r: -r["puntos"])
    return UrlVerdict(host, domain, score, verdict, category, reasons)
