"""La capa de IA de la protección: convierte números en explicaciones y elige el mejor servidor.

Dos cosas, ambas con un principio: **si hay un modelo de lenguaje configurado, se usa; si no, hay un
respaldo local que responde igual de claro, solo que con frases fijas.** Nunca se queda callada por
falta de LLM, y nunca inventa datos: el modelo solo redacta a partir de las cifras que ya calculó el
motor. Así funciona en su equipo con o sin internet, con o sin clave de API.

1. **Resumen del análisis.** Tras un escaneo, resume en dos o tres frases qué se encontró, qué es
   más urgente y qué conviene hacer. Sobre una amenaza concreta, explica en palabras sencillas por
   qué es peligrosa.
2. **Asesor de VPN.** Ordena los servidores disponibles según lo que la persona quiere hacer
   (navegar, privacidad, velocidad) y explica por qué recomienda ese. Reutiliza el optimizador
   explicable que ya existía (app.ai.vpn_ai), así que la recomendación siempre tiene un porqué
   medible detrás, no una corazonada del modelo.
"""
from __future__ import annotations

import json
import logging

import httpx

from app.ai import vpn_ai
from app.core.config import get_settings

log = logging.getLogger("guardian.local.ia")


# ═══════════════════════════════════════════════ ¿hay modelo disponible?
def hay_modelo() -> bool:
    try:
        return get_settings().llm_kind != "ninguno"
    except Exception:  # noqa: BLE001
        return False


def _preguntar(system: str, usuario: str, *, max_tokens: int = 320) -> str | None:
    """Una consulta breve al modelo configurado. Devuelve None si no hay modelo o si falla."""
    s = get_settings()
    if s.llm_kind == "ninguno":
        return None
    try:
        with httpx.Client(timeout=min(s.llm_timeout_seconds, 20.0)) as c:
            if s.llm_kind == "anthropic":
                r = c.post("https://api.anthropic.com/v1/messages",
                           headers={"x-api-key": s.anthropic_api_key, "anthropic-version": "2023-06-01",
                                    "content-type": "application/json"},
                           json={"model": s.anthropic_model, "max_tokens": max_tokens, "system": system,
                                 "messages": [{"role": "user", "content": usuario}]})
                r.raise_for_status()
                return "".join(b.get("text", "") for b in r.json().get("content", [])
                               if b.get("type") == "text").strip() or None
            headers = {"content-type": "application/json"}
            if s.llm_api_key:
                headers["Authorization"] = f"Bearer {s.llm_api_key}"
            r = c.post(f"{s.llm_base_url.rstrip('/')}/chat/completions", headers=headers,
                       json={"model": s.llm_model or "gpt-4o-mini", "max_tokens": max_tokens,
                             "messages": [{"role": "system", "content": system},
                                          {"role": "user", "content": usuario}]})
            r.raise_for_status()
            return (r.json()["choices"][0]["message"].get("content") or "").strip() or None
    except (httpx.HTTPError, ValueError, KeyError, IndexError) as e:
        log.info("El modelo no respondió (%s); se usa el resumen local", type(e).__name__)
        return None


SISTEMA_ANTIVIRUS = (
    "Eres el asistente de seguridad de GuardianIA, un antivirus. Hablas español claro y cercano, sin "
    "tecnicismos innecesarios, tuteando con respeto (usa «usted»). Resume SOLO con los datos que te "
    "doy; no inventes nombres de virus ni cifras. Máximo 3 frases. Si hay amenazas maliciosas, di "
    "primero lo más urgente y qué hacer. Si no hay ninguna, tranquiliza sin exagerar. No uses viñetas."
)


# ═══════════════════════════════════════════════════ resumen del análisis
def resumen_analisis(final: dict) -> dict:
    """Explica el resultado de un escaneo. Con modelo, en prosa; sin él, con frases armadas."""
    datos = {"modo": final.get("modo"), "archivos": final.get("analizados"),
             "limpios": final.get("limpios"), "sospechosos": final.get("sospechosos"),
             "maliciosos": final.get("maliciosos"), "aislados": final.get("aislados"),
             "amenazas": [{"nombre": a["nombre"], "nivel": a["nivel"], "familia": a.get("familia"),
                           "motivo": (a.get("motivos") or [""])[0], "estado": a.get("estado")}
                          for a in (final.get("amenazas") or [])[:6] if isinstance(a, dict)]}
    local = _resumen_local(datos)
    if not hay_modelo():
        return {"texto": local, "por_modelo": False}
    prompt = ("Resultado de un análisis antivirus (JSON). Redáctame un resumen para la persona dueña del "
              f"equipo:\n{json.dumps(datos, ensure_ascii=False)}")
    texto = _preguntar(SISTEMA_ANTIVIRUS, prompt)
    return {"texto": texto or local, "por_modelo": bool(texto)}


def _resumen_local(d: dict) -> str:
    mal, sos, ais = d["maliciosos"] or 0, d["sospechosos"] or 0, d["aislados"] or 0
    n = d["archivos"] or 0
    if not mal and not sos:
        return (f"Revisé {n:,} archivos y no encontré amenazas. Su equipo se ve limpio. "
                "Mantenga la protección en tiempo real activada.").replace(",", ".")
    partes = []
    if mal:
        nombres = ", ".join(a["nombre"] for a in d["amenazas"] if a["nivel"] == "malicioso")[:120]
        partes.append(f"Encontré {mal} amenaza(s) maliciosa(s)" + (f" ({nombres})" if nombres else "") + ".")
        partes.append(f"{ais} ya está(n) en cuarentena y no puede(n) hacer daño." if ais
                      else "Póngala(s) en cuarentena desde la lista de amenazas.")
    if sos:
        partes.append(f"Además hay {sos} archivo(s) sospechoso(s) que conviene que usted revise: si no los "
                      "reconoce, aíslelos.")
    return " ".join(partes)


def explicar_amenaza(a: dict) -> dict:
    """Explica una amenaza concreta en lenguaje sencillo (qué es, por qué importa, qué hacer)."""
    base = a.get("motivos") or ["Señales de comportamiento peligroso"]
    local = (f"«{a.get('nombre')}» se marcó como {a.get('nivel')}. " + base[0]
             + (". Está en cuarentena: ya no puede ejecutarse." if a.get("estado") == "aislado"
                else ". Si no lo reconoce, póngalo en cuarentena."))
    if not hay_modelo():
        return {"texto": local, "por_modelo": False}
    prompt = ("Explica a una persona sin conocimientos técnicos, en 2 frases, por qué este archivo es "
              f"peligroso y qué hacer:\n{json.dumps({k: a.get(k) for k in ('nombre', 'nivel', 'familia', 'motivos', 'estado')}, ensure_ascii=False)}")
    texto = _preguntar(SISTEMA_ANTIVIRUS, prompt)
    return {"texto": texto or local, "por_modelo": bool(texto)}


# ═══════════════════════════════════════════════════════ asesor de VPN
PROPOSITOS = {
    "general": "Navegar tranquilo",
    "anonimato": "Anonimato (ocultar quién soy)",
    "privacy": "Máxima privacidad",
    "streaming": "Ver contenido de otro país",
    "gaming": "Juegos en línea",
    "download": "Descargas grandes",
}


def _a_server(cat: dict) -> vpn_ai.Server:
    return vpn_ai.Server(id=cat["id"], country=cat["country"], city=cat["city"], host=cat.get("host", ""),
                         port=cat.get("port", 51820), protocol="wireguard", is_premium=cat.get("premium", False),
                         load=cat.get("load", 0.3), latency_ms=cat.get("latency_ms", 0), active=cat.get("conectable", True))


def asesorar_vpn(catalogo: list[dict], *, proposito: str = "general", pais_usuario: str | None = "CO",
                 observada: dict[str, float] | None = None) -> dict:
    """Ordena los servidores y recomienda uno, con explicación. La parte medible es determinista;
    solo el texto final lo pule el modelo si está disponible."""
    servidores = [_a_server(c) for c in catalogo if c.get("conectable", True)]
    if not servidores:
        return {"recomendado": None, "ranking": [], "texto": "Aún no hay servidores conectables. Registre "
                "Cloudflare WARP o importe un archivo .conf.", "proposito": proposito, "por_modelo": False}
    rec = vpn_ai.recommend(servidores, purpose=proposito, user_country=pais_usuario, observed_latency=observada or {})
    ranking = vpn_ai.rank(servidores, purpose=proposito, user_country=pais_usuario,
                          observed_latency=observada or {}, limit=8)
    por_id = {c["id"]: c for c in catalogo}
    salida_ranking = [{"id": r.server.id, "nombre": por_id.get(r.server.id, {}).get("nombre", r.server.city),
                       "pais": r.server.country, "puntaje": r.score,
                       "latencia_ms": r.breakdown["latencia_estimada_ms"], "carga": round(r.server.load, 2)}
                      for r in ranking]
    local = (f"Le recomiendo {por_id.get(rec.server.id, {}).get('nombre', rec.server.city)}: "
             + "; ".join(rec.reasons).lower() + ".") if rec else ""
    resultado = {"recomendado": rec.server.id if rec else None,
                 "recomendado_nombre": por_id.get(rec.server.id, {}).get("nombre", rec.server.city) if rec else None,
                 "razones": rec.reasons if rec else [], "ranking": salida_ranking, "proposito": proposito,
                 "texto": local, "por_modelo": False}
    if hay_modelo() and rec:
        prompt = ("Un asesor de VPN recomendó un servidor. Explícalo a la persona en 1-2 frases, cálido y "
                  f"claro, sin repetir cifras exactas:\n{json.dumps({'objetivo': PROPOSITOS.get(proposito), 'servidor': resultado['recomendado_nombre'], 'razones': rec.reasons}, ensure_ascii=False)}")
        texto = _preguntar("Eres el asesor de VPN de GuardianIA. Español claro, usando «usted». Sin viñetas, "
                           "máximo 2 frases.", prompt)
        if texto:
            resultado["texto"], resultado["por_modelo"] = texto, True
    return resultado
