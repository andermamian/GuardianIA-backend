"""Cerebro de la VPN: decide cómo proteger la conexión con solo dos vías — su servidor GuardianIA VPN
(Google Cloud) y Tor — y aprende de lo que funciona en SU equipo.

Por qué un motor propio y no un modelo de lenguaje: la decisión se toma cada 30 s, tiene que ser
instantánea, funcionar sin internet y poder explicarse. Es un modelo de puntuación con rasgos
explicables + aprendizaje en línea (promedios móviles exponenciales de éxito y tiempo de conexión por
modo) + histéresis para no saltar de un modo a otro por una medición aislada.

Los mismos pesos están en Android (vpn/CerebroVpn.java); tests/test_cerebro_vpn.py y
CerebroVpnTest.java comprueban los mismos casos para que el PC y el celular decidan igual.

Modos candidatos:
    servidor      — WireGuard a su servidor: cifra TODO el equipo, rápido, pero el servidor está a su nombre.
    tor           — 3 relevos: nadie une quién es usted con qué visita; más lento; en el PC solo cubre
                    el tráfico que usa el proxy (GuardianIA, navegador configurado).
    servidor_tor  — Tor dentro del túnel: el operador solo ve su servidor, el servidor solo ve Tor
                    cifrado, el sitio solo ve un relevo Tor. Máxima privacidad, más lento.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field

CANDIDATOS = ("servidor", "tor", "servidor_tor")
OBJETIVOS = ("equilibrio", "velocidad", "anonimato")

# Afinidad de cada modo con cada objetivo (0..1). Fuente: modelo de amenazas, no gustos.
BASE = {
    "equilibrio": {"servidor": 0.78, "tor": 0.52, "servidor_tor": 0.70},
    "velocidad": {"servidor": 0.92, "tor": 0.30, "servidor_tor": 0.35},
    "anonimato": {"servidor": 0.42, "tor": 0.80, "servidor_tor": 0.95},
}
LATENCIA_ALTA_MS = 250          # un servidor más lento que esto pierde puntos
CONSUMO_ALERTA = 0.85           # fracción del límite mensual desde la que se ahorra servidor
CONSUMO_CORTE = 0.97            # por encima, el servidor frena solo: no se elige
MARGEN_CAMBIO = 0.12            # histéresis: el nuevo modo debe ganar por esto para cambiar
MIN_ENTRE_CAMBIOS_S = 600       # y no más de un cambio automático cada 10 min (salvo caída)
ALFA = 0.3                      # peso de la última experiencia en el aprendizaje
RECIENTE_S = 300                # un fallo «reciente» pesa durante 5 minutos


@dataclass
class Senales:
    servidor_configurado: bool = False
    servidor_en_linea: bool | None = None      # None = no se pudo consultar (se intenta igual)
    latencia_servidor_ms: int | None = None
    consumo_fraccion: float | None = None      # usado / límite del mes
    tor_disponible: bool = True
    red_insegura: bool | None = None           # WiFi pública o desconocida
    tunel_disponible: bool = True              # PC: ¿está instalado WireGuard? (Android lo trae)


@dataclass
class Decision:
    modo: str | None
    puntajes: dict[str, float]
    razones: list[str]
    confianza: float
    descartados: dict[str, str] = field(default_factory=dict)

    def a_dict(self) -> dict:
        return {"modo": self.modo, "puntajes": {k: round(v, 3) for k, v in self.puntajes.items()},
                "razones": self.razones, "confianza": round(self.confianza, 2), "descartados": self.descartados}


def usa_servidor(m: str | None) -> bool:
    return m in ("servidor", "servidor_tor")


def usa_tor(m: str | None) -> bool:
    return m in ("tor", "servidor_tor")


def comparten(a: str, b: str) -> bool:
    """¿Los dos modos dependen de alguna pieza común (servidor o Tor)?"""
    return (usa_servidor(a) and usa_servidor(b)) or (usa_tor(a) and usa_tor(b))


# ─────────────────────────── memoria (aprendizaje en línea)
def memoria_vacia() -> dict:
    return {m: {"intentos": 0, "fiabilidad": 0.8, "segundos": None, "ultimo_fallo": 0.0} for m in CANDIDATOS}


def aprender(memoria: dict, modo: str, exito: bool, segundos: float | None = None,
             ahora: float | None = None) -> dict:
    """Actualiza la memoria con el resultado de una conexión real (verificada o fallida)."""
    if modo not in CANDIDATOS:
        return memoria
    m = memoria.setdefault(modo, memoria_vacia()[modo])
    m["intentos"] = int(m.get("intentos", 0)) + 1
    m["fiabilidad"] = (1 - ALFA) * float(m.get("fiabilidad", 0.8)) + ALFA * (1.0 if exito else 0.0)
    if exito and segundos is not None:
        prev = m.get("segundos")
        m["segundos"] = segundos if prev is None else (1 - ALFA) * prev + ALFA * segundos
    if not exito:
        m["ultimo_fallo"] = ahora if ahora is not None else time.time()
    return memoria


# ─────────────────────────── decisión
def decidir(s: Senales, objetivo: str = "equilibrio", memoria: dict | None = None,
            ahora: float | None = None, excluir: tuple[str, ...] = ()) -> Decision:
    objetivo = objetivo if objetivo in OBJETIVOS else "equilibrio"
    memoria = memoria or memoria_vacia()
    ahora = ahora if ahora is not None else time.time()
    puntajes: dict[str, float] = {}
    descartados: dict[str, str] = {}
    notas: dict[str, list[str]] = {m: [] for m in CANDIDATOS}

    # Fallos recientes: un fallo marca a TODOS los modos que comparten la pieza que falló (si el
    # servidor no conectó, «servidor + Tor» tampoco conviene durante unos minutos).
    recientes = [m for m in CANDIDATOS
                 if ahora - float((memoria.get(m) or {}).get("ultimo_fallo", 0.0)) < RECIENTE_S]

    for modo in CANDIDATOS:
        if modo in excluir:
            descartados[modo] = "acaba de fallar"
            continue
        # 1) Factibilidad: lo que no puede funcionar no se elige.
        if usa_servidor(modo):
            if not s.servidor_configurado:
                descartados[modo] = "su servidor GuardianIA VPN no está conectado a la app"
                continue
            if not s.tunel_disponible:
                descartados[modo] = "falta WireGuard, el programa que crea el túnel"
                continue
            if s.servidor_en_linea is False:
                descartados[modo] = "su servidor no responde (¿máquina apagada o firewall?)"
                continue
            if s.consumo_fraccion is not None and s.consumo_fraccion >= CONSUMO_CORTE:
                descartados[modo] = "su servidor llegó al límite gratis del mes"
                continue
        if usa_tor(modo) and not s.tor_disponible:
            descartados[modo] = "Tor no está disponible en este equipo"
            continue

        p = BASE[objetivo][modo]
        # 2) Rasgos del entorno.
        if usa_servidor(modo):
            if s.latencia_servidor_ms is not None and s.latencia_servidor_ms > LATENCIA_ALTA_MS:
                p -= 0.12 if modo == "servidor" else 0.06
                notas[modo].append(f"su servidor responde lento ({s.latencia_servidor_ms} ms)")
            if s.consumo_fraccion is not None and s.consumo_fraccion >= CONSUMO_ALERTA:
                p -= 0.30
                notas[modo].append(f"ya usó el {round(s.consumo_fraccion * 100)} % del cupo gratis del mes")
            if s.servidor_en_linea is None:
                p -= 0.05                               # no se pudo comprobar: algo menos de confianza
            if s.red_insegura:
                p += 0.10                               # el túnel cifra TODO el equipo, Tor solo el proxy
                notas[modo].append("red WiFi pública: conviene cifrar todo el equipo")
        elif s.red_insegura:
            p -= 0.08
        # 3) Lo aprendido en este equipo.
        mem = memoria.get(modo) or {}
        if int(mem.get("intentos", 0)) >= 2:
            p += 0.25 * (float(mem.get("fiabilidad", 0.8)) - 0.8)
            seg = mem.get("segundos")
            if seg is not None and seg > 60 and usa_tor(modo):
                p -= 0.05
        if any(comparten(modo, m) for m in recientes):
            p -= 0.30
            notas[modo].append("hubo un fallo con esta vía hace menos de 5 minutos")
        puntajes[modo] = p

    if not puntajes:
        return Decision(None, {}, ["Ningún modo es posible ahora: " + "; ".join(descartados.values())], 0.0,
                        descartados)

    orden = sorted(puntajes, key=puntajes.get, reverse=True)
    mejor = orden[0]
    segundo = puntajes[orden[1]] if len(orden) > 1 else puntajes[mejor] - 0.5
    confianza = 1 / (1 + math.exp(-8 * (puntajes[mejor] - segundo)))   # margen → 0.5..1
    return Decision(mejor, puntajes, _explicar(mejor, objetivo, notas[mejor], descartados), confianza, descartados)


def _explicar(modo: str, objetivo: str, notas: list[str], descartados: dict[str, str]) -> list[str]:
    que = {"servidor": "Su servidor GuardianIA VPN: rápido y cifra todo el equipo.",
           "tor": "Tor: tres relevos; nadie puede unir quién es usted con lo que visita.",
           "servidor_tor": "Servidor + Tor: su operador solo ve su servidor y el sitio solo ve un relevo Tor."}[modo]
    por = {"equilibrio": "Buen equilibrio entre privacidad y velocidad.",
           "velocidad": "Prioriza la velocidad.", "anonimato": "Prioriza el anonimato."}[objetivo]
    r = [que, por, *notas[:2]]
    for m, motivo in list(descartados.items())[:1]:
        r.append(f"Descarté {nombre(m)}: {motivo}.")
    return r


def nombre(modo: str | None) -> str:
    return {"servidor": "su servidor", "tor": "Tor", "servidor_tor": "servidor + Tor",
            "apagado": "apagado", "auto": "automático (IA)"}.get(modo or "", modo or "—")


def conviene_cambiar(actual: str | None, d: Decision, ultimo_cambio: float, actual_sano: bool,
                     ahora: float | None = None) -> bool:
    """Histéresis: si el modo actual está caído se cambia YA; si funciona, solo si el nuevo gana con
    margen y pasó el tiempo mínimo (evita saltos por una medición aislada)."""
    if d.modo is None or d.modo == actual:
        return False
    if not actual_sano or actual not in d.puntajes:
        return True
    ahora = ahora if ahora is not None else time.time()
    return (d.puntajes[d.modo] - d.puntajes[actual] >= MARGEN_CAMBIO
            and ahora - ultimo_cambio >= MIN_ENTRE_CAMBIOS_S)
