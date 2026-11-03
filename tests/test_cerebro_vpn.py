"""Cerebro de la VPN: mismos casos que Android (CerebroVpnTest.java lee el mismo JSON)."""
import json
from pathlib import Path

import pytest

from app.ai import cerebro_vpn as c

CASOS = json.loads((Path(__file__).parent / "fixtures" / "cerebro_vpn_casos.json").read_text("utf-8"))


@pytest.mark.parametrize("caso", CASOS, ids=[k["nombre"] for k in CASOS])
def test_casos_compartidos_con_android(caso):
    d = c.decidir(c.Senales(**caso["senales"]), caso["objetivo"], caso["memoria"], ahora=caso["ahora"],
                  excluir=tuple(caso.get("excluir") or ()))
    assert d.modo == caso["esperado"]
    assert {k: round(v, 4) for k, v in d.puntajes.items()} == caso["puntajes"]


def test_explica_y_dice_que_descarto():
    d = c.decidir(c.Senales(servidor_configurado=True, servidor_en_linea=False), "anonimato")
    assert d.modo == "tor" and d.razones[0].startswith("Tor")
    assert "servidor" in d.descartados and any("Descarté" in r for r in d.razones)
    assert 0.5 <= d.confianza <= 1


def test_aprende_de_exitos_y_fallos():
    m = c.memoria_vacia()
    for _ in range(4):
        c.aprender(m, "servidor", False, ahora=10)
    assert m["servidor"]["fiabilidad"] < 0.25 and m["servidor"]["intentos"] == 4
    c.aprender(m, "tor", True, segundos=40)
    c.aprender(m, "tor", True, segundos=20)
    assert 30 < m["tor"]["segundos"] < 40                      # promedio móvil, no el último valor
    assert c.aprender(m, "inventado", True) is m                # modos desconocidos no ensucian la memoria


def test_histeresis_evita_saltos():
    s = c.Senales(servidor_configurado=True, servidor_en_linea=True, tor_disponible=True)
    d = c.decidir(s, "equilibrio", ahora=10_000)                # gana el servidor (0.78 vs Tor 0.52)
    # Funcionando en Tor: solo cambia si pasó el tiempo mínimo.
    assert c.conviene_cambiar("tor", d, ultimo_cambio=9_900, actual_sano=True, ahora=10_000) is False
    assert c.conviene_cambiar("tor", d, ultimo_cambio=0, actual_sano=True, ahora=10_000) is True
    # Si el modo actual está caído, se cambia YA.
    assert c.conviene_cambiar("tor", d, ultimo_cambio=9_990, actual_sano=False, ahora=10_000) is True
    # Una diferencia pequeña no justifica cortar la conexión.
    d2 = c.decidir(s, "anonimato", ahora=10_000)               # servidor_tor 0.95 vs tor 0.80 → 0.15
    assert c.conviene_cambiar("tor", d2, 0, True, 10_000) is True
    d2.puntajes["servidor_tor"] = 0.85
    assert c.conviene_cambiar("tor", d2, 0, True, 10_000) is False
    assert c.conviene_cambiar("servidor_tor", d2, 0, True, 10_000) is False   # ya está ahí


def test_objetivo_desconocido_cae_en_equilibrio():
    d = c.decidir(c.Senales(servidor_configurado=True, servidor_en_linea=True), "cualquiera")
    assert d.modo == "servidor"
