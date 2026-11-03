// Canal WebSocket con reconexión exponencial y jitter.
// El token viaja en el primer mensaje (no en la URL, que queda en logs de proxies).

export function connectRealtime({ path, getToken, onEvent, onStatus }) {
  let ws = null;
  let attempt = 0;
  let stopped = false;
  let timer = null;

  function schedule() {
    if (stopped) return;
    const base = Math.min(30000, 1000 * 2 ** attempt);
    const delay = base / 2 + Math.random() * (base / 2); // evita que mil clientes reconecten al mismo tiempo
    attempt++;
    timer = setTimeout(open, delay);
  }

  function open() {
    const token = getToken();
    if (!token || stopped) return schedule();
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(`${proto}//${location.host}${path}`);
    ws.addEventListener("open", () => ws.send(JSON.stringify({ token })));
    ws.addEventListener("message", (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      if (msg.tipo === "conectado") { attempt = 0; onStatus?.("online"); return; }
      if (msg.tipo === "ping") return;
      onEvent(msg);
    });
    ws.addEventListener("close", (e) => {
      onStatus?.("offline");
      if (e.code === 4401) attempt = Math.max(attempt, 3); // token vencido: se espera la renovación
      schedule();
    });
    ws.addEventListener("error", () => ws.close());
  }

  open();
  return {
    reconnect() { attempt = 0; clearTimeout(timer); ws?.close(); },
    stop() { stopped = true; clearTimeout(timer); ws?.close(); },
  };
}
