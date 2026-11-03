// Componentes de la app con lógica de seguridad: SOS y aviso de incidente con cuenta regresiva.
import { busy, confirmDialog, dialog, fmt, h, toast, toastError } from "../shared/dom.js";

const HOLD_MS = 2000;

export function currentPosition(timeout = 4000) {
  // La ubicación ayuda, pero nunca bloquea el SOS: si tarda o se niega, la alerta sale igual.
  return new Promise((resolve) => {
    if (!("geolocation" in navigator)) return resolve({});
    const timer = setTimeout(() => resolve({}), timeout + 500);
    navigator.geolocation.getCurrentPosition(
      (p) => { clearTimeout(timer); resolve({ lat: p.coords.latitude, lon: p.coords.longitude }); },
      () => { clearTimeout(timer); resolve({}); },
      { enableHighAccuracy: true, timeout, maximumAge: 60000 });
  });
}

// Botón de pánico: mantener presionado 2 s evita activaciones en el bolsillo.
// Con teclado o lector de pantalla, Enter abre una confirmación (mantener presionado no es accesible).
export function sosButton({ api, onIncident }) {
  const NS = "http://www.w3.org/2000/svg";
  const ring = document.createElementNS(NS, "svg");
  ring.setAttribute("viewBox", "0 0 100 100");
  ring.classList.add("sos-ring");
  ring.setAttribute("aria-hidden", "true");
  const circle = document.createElementNS(NS, "circle");
  const C = 2 * Math.PI * 46;
  Object.entries({ cx: 50, cy: 50, r: 46, "stroke-dasharray": C, "stroke-dashoffset": C }).forEach(([k, v]) => circle.setAttribute(k, v));
  ring.append(circle);

  const btn = h("button", { class: "sos", type: "button", "aria-label": "SOS: mantenga presionado dos segundos para pedir ayuda" },
    ring, "SOS", h("small", {}, "Mantener 2 s"));
  let start = 0, raf = 0, fired = false;

  const reset = () => { cancelAnimationFrame(raf); circle.setAttribute("stroke-dashoffset", C); start = 0; };
  const tick = (now) => {
    const p = Math.min(1, (now - start) / HOLD_MS);
    circle.setAttribute("stroke-dashoffset", C * (1 - p));
    if (p >= 1) { fired = true; reset(); navigator.vibrate?.(200); trigger(); return; }
    raf = requestAnimationFrame(tick);
  };

  async function trigger() {
    await busy(btn, async () => {
      const pos = await currentPosition();
      try {
        const inc = await api.post("emergency/sos", { kind: "sos", ...pos });
        onIncident?.(inc);
        showIncidentDialog(api, inc, pos);
      } catch (e) {
        toastError(e);
        dialog({ title: "No se pudo enviar la alerta", body: h("p", {}, "Llame ya a la línea 123. GuardianIA no logró comunicarse con el servidor."),
          actions: [{ label: "Entendido", kind: "primary" }] });
      }
    });
  }

  btn.addEventListener("pointerdown", (e) => {
    if (e.button !== 0 || btn.disabled) return;
    btn.setPointerCapture(e.pointerId);
    fired = false;
    start = performance.now();
    raf = requestAnimationFrame(tick);
  });
  ["pointerup", "pointercancel", "pointerleave"].forEach((ev) => btn.addEventListener(ev, () => { if (!fired) reset(); }));
  btn.addEventListener("contextmenu", (e) => e.preventDefault());
  btn.addEventListener("keydown", async (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();
    if (await confirmDialog({ title: "¿Enviar alerta SOS?", message: "Se avisará de inmediato a sus contactos de emergencia con su ubicación.", confirmLabel: "Enviar SOS", danger: true })) trigger();
  });
  return btn;
}

const ACTION = { sms: "Mensaje a", llamada: "Llamada a", linea_123: "Línea 123" };
export const planText = (step) =>
  `${step.min === 0 ? "Ahora" : `Minuto ${step.min}`}: ${ACTION[step.accion] || step.accion}${step.nombre ? ` ${step.nombre}` : ""}${step.nota ? ` (${step.nota.toLowerCase()})` : ""}`;

function showIncidentDialog(api, inc, pos) {
  const body = h("div", { class: "stack" },
    h("p", {}, "Estamos avisando a sus contactos en orden de prioridad."),
    pos.lat ? h("p", { class: "muted" }, "Se compartió su ubicación actual.") : h("p", { class: "notice notice-warn" }, "No fue posible obtener su ubicación. Si puede, dígasela a quien lo llame."),
    (inc.plan || []).length
      ? h("ol", {}, inc.plan.slice(0, 6).map((step) => h("li", {}, planText(step))))
      : h("p", { class: "notice notice-warn" }, "No tiene contactos de emergencia registrados. Agréguelos en la sección Emergencia."),
    h("p", { class: "notice notice-danger" }, "Si está en peligro inmediato, llame al 123."));
  dialog({
    title: "Alerta enviada",
    body,
    actions: [
      { label: "Estoy bien, cancelar", onClick: async () => cancelIncident(api, inc) },
      { label: "Cerrar", kind: "primary" },
    ],
  });
}

export async function cancelIncident(api, inc) {
  try {
    await api.post(`emergency/incidents/${inc.id}/cancel`);
    toast("Alerta cancelada. Avisamos a quienes ya habían sido contactados.", "ok");
    return true;
  } catch (e) {
    toastError(e);
    return false;
  }
}

const KIND = { sos: "Botón SOS", fall: "Posible caída", vitals: "Signos vitales", theft: "Robo" };

// Incidente automático (caída o signos críticos del reloj): ventana para decir "estoy bien"
// antes de que se escale a los contactos. Evita alarmas falsas sin demorar las reales.
export function incidentBanner(api, inc, onDone) {
  const remaining = h("span", { class: "countdown", "aria-live": "off" });
  const status = h("p", { class: "muted", "aria-live": "polite" });
  const cancel = h("button", { class: "btn btn-primary", onClick: () => busy(cancel, async () => { if (await cancelIncident(api, inc)) { clearInterval(timer); onDone?.(); } }) }, "Estoy bien");
  const el = h("section", { class: "panel notice-danger stack", role: "alert" },
    h("div", { class: "row row-between" },
      h("div", {}, h("h2", {}, KIND[inc.kind] || "Emergencia"), h("p", {}, inc.summary)),
      inc.status === "pending_cancel" ? remaining : null),
    status, h("div", { class: "row" }, cancel));
  let announced = false;
  const timer = setInterval(update, 1000);
  function update() {
    if (inc.status !== "pending_cancel" || !inc.cancel_deadline) {
      status.textContent = `Avisando a sus contactos desde las ${fmt.time(inc.created_at)}`;
      return;
    }
    const secs = Math.max(0, Math.round((new Date(inc.cancel_deadline) - Date.now()) / 1000));
    remaining.textContent = `${secs}s`;
    status.textContent = secs > 0 ? `Si no responde en ${secs} segundos, avisaremos a sus contactos.` : "Avisando a sus contactos.";
    if (!announced && secs <= 10) { announced = true; navigator.vibrate?.([300, 150, 300]); }
    if (secs === 0) { clearInterval(timer); remaining.remove(); }
  }
  update();
  el.stop = () => clearInterval(timer);
  return el;
}
