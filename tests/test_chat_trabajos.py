"""Respuestas del asistente que siguen aunque el cliente se desconecte (cambiar de app, girar, cambiar de chat)."""
import json
import time


def _eventos(texto: str) -> list[dict]:
    return [json.loads(l[6:]) for l in texto.splitlines() if l.startswith("data: ")]


def _esperar(client, auth, trabajo_id, max_s=20):
    for _ in range(int(max_s * 10)):
        lista = client.get("/v1/assistant/chat/trabajos", headers=auth).json()
        t = next((x for x in lista if x["trabajo_id"] == trabajo_id), None)
        if t and t["terminado"]:
            return t
        time.sleep(0.1)
    raise AssertionError("el trabajo no terminó")


def test_la_respuesta_sigue_aunque_el_cliente_se_desconecte(client, auth):
    # El cliente lee SOLO el primer evento y se va (como cuando el celular cambia de app).
    with client.stream("POST", "/v1/assistant/chat/stream", headers=auth,
                       json={"message": "¿Cómo creo una contraseña segura?"}) as r:
        assert r.status_code == 200
        primera = next(l for l in r.iter_lines() if l.startswith("data: "))
    inicio = json.loads(primera[6:])
    assert inicio["tipo"] == "trabajo" and inicio["trabajo_id"] and inicio["conversation_id"]
    fin = _esperar(client, auth, inicio["trabajo_id"])
    assert fin["terminado"] and not fin["cancelado"]
    # La respuesta completa quedó guardada en la conversación.
    msgs = client.get(f"/v1/assistant/conversations/{inicio['conversation_id']}", headers=auth).json()
    assert [m["role"] for m in msgs][-2:] == ["user", "assistant"] and msgs[-1]["content"].strip()


def test_retomar_desde_donde_quedo(client, auth):
    r = client.post("/v1/assistant/chat/stream", headers=auth, json={"message": "Hola, ¿qué puedes hacer?"})
    evs = _eventos(r.text)
    tid = evs[0]["trabajo_id"]
    _esperar(client, auth, tid)
    todos = _eventos(client.get(f"/v1/assistant/chat/trabajos/{tid}/stream", headers=auth).text)
    assert todos[-1]["tipo"] == "fin" and [e["i"] for e in todos] == list(range(len(todos)))
    # Reconectar desde el evento 2 entrega exactamente el resto.
    resto = _eventos(client.get(f"/v1/assistant/chat/trabajos/{tid}/stream?desde=2", headers=auth).text)
    assert [e["i"] for e in resto] == [e["i"] for e in todos[2:]]


def test_solo_el_dueno_ve_su_respuesta(client, auth):
    otro = client.post("/v1/auth/register", json={
        "email": "luis@example.com", "full_name": "Luis Gómez", "password": "OtraClaveSegura2026!",
        "accept_terms": True})
    other_auth = {"Authorization": f"Bearer {otro.json()['access_token']}"}
    r = client.post("/v1/assistant/chat/stream", headers=auth, json={"message": "hola"})
    tid = _eventos(r.text)[0]["trabajo_id"]
    assert client.get(f"/v1/assistant/chat/trabajos/{tid}/stream", headers=other_auth).status_code == 404
    assert client.post(f"/v1/assistant/chat/trabajos/{tid}/detener", headers=other_auth).status_code == 404
    assert all(t["trabajo_id"] != tid for t in client.get("/v1/assistant/chat/trabajos", headers=other_auth).json())


def test_detener_a_mitad_de_respuesta(client, auth, monkeypatch):
    """Cerrar la conexión ya no detiene la IA; «Detener» sí, y se guarda lo que alcanzó a escribir."""
    import threading
    from app.ai import assistant
    from app.services import chat_trabajos

    def lenta(*a, **k):
        for n in range(200):
            time.sleep(0.02)
            yield {"tipo": "texto", "texto": f"trozo{n} "}
    monkeypatch.setattr(assistant, "stream", lenta)

    respuestas_detener = []

    def pulsar_detener():               # como la persona tocando «Detener» mientras la IA escribe
        for t in list(chat_trabajos._trabajos.values()):
            if not t.terminado:
                respuestas_detener.append(client.post(f"/v1/assistant/chat/trabajos/{t.id}/detener", headers=auth))
    temporizador = threading.Timer(0.4, pulsar_detener)
    temporizador.start()
    todos = _eventos(client.post("/v1/assistant/chat/stream", headers=auth,
                                 json={"message": "cuéntame algo largo"}).text)
    inicio = todos[0]
    temporizador.join()
    # Se comprueba aquí, en el hilo de la prueba: un assert dentro del temporizador no la haría fallar.
    assert respuestas_detener and respuestas_detener[0].status_code == 200, respuestas_detener
    assert respuestas_detener[0].json()["mensaje"] == "Deteniendo la respuesta"
    fin = _esperar(client, auth, inicio["trabajo_id"])
    assert fin["cancelado"] and fin["terminado"]
    assert todos[-1]["tipo"] == "cancelado"
    textos = [e for e in todos if e["tipo"] == "texto"]
    assert 0 < len(textos) < 200                     # se detuvo a mitad de camino
    msgs = client.get(f"/v1/assistant/conversations/{inicio['conversation_id']}", headers=auth).json()
    assert msgs[-1]["role"] == "assistant" and msgs[-1]["content"].startswith("trozo0")
    # Un trabajo ya terminado no se puede detener.
    assert client.post(f"/v1/assistant/chat/trabajos/{inicio['trabajo_id']}/detener", headers=auth).status_code == 404


def test_limites_contra_abuso(monkeypatch):
    """Un atacante no puede agotar la memoria: tope por persona, tope global y tope de eventos."""
    from app.services import chat_trabajos as ct
    import threading
    bloqueo = threading.Event()
    monkeypatch.setattr(ct, "_trabajos", {})
    lentos = [ct.iniciar("u1", "c", lambda t: bloqueo.wait(5)) for _ in range(ct.MAX_POR_USUARIO)]
    try:
        ct.iniciar("u1", "c", lambda t: None)
        raise AssertionError("debió rechazar el cuarto trabajo de la misma persona")
    except ct.Ocupado:
        pass
    monkeypatch.setattr(ct, "MAX_GLOBAL", len(lentos))
    try:
        ct.iniciar("otra", "c", lambda t: None)
        raise AssertionError("debió respetar el tope global")
    except ct.Ocupado:
        pass
    bloqueo.set()
    monkeypatch.setattr(ct, "MAX_EVENTOS", 5)
    t = ct.Trabajo(id="x", user_id="u", conversation_id="c")
    for n in range(50):
        t.agregar({"tipo": "texto", "texto": str(n)})
    assert len(t.eventos) == 5 and t.cancelado
