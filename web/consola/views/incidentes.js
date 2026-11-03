import { badge, busy, dialog, emptyState, field, fmt, h, mount, promptDialog, toast, toastError } from "../../shared/dom.js";

const KIND = { sos: "SOS", fall: "Caída", vitals: "Signos vitales", theft: "Robo" };
const STATUS = { pending_cancel: ["Esperando al usuario", "warn"], escalating: ["Escalando", "danger"], cancelled: ["Cancelado", "neutral"], resolved: ["Resuelto", "ok"] };
const mapUrl = (lat, lon) => `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`;

export default async function incidentes(ctx) {
  let activeOnly = true;
  const listEl = h("div", {});
  async function load() {
    const rows = await ctx.api.get("admin/incidents", { query: { active_only: activeOnly, limit: 100 } });
    mount(listEl, rows.length ? h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", {}, h("tr", {}, ["Abierto", "Tipo", "Resumen", "Estado", "Ubicación", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, rows.map((i) => {
        const [label, tone] = STATUS[i.status] || [i.status, "neutral"];
        const open = ["pending_cancel", "escalating"].includes(i.status);
        const assign = h("button", { class: "btn btn-sm" }, "Asignarme");
        assign.addEventListener("click", () => busy(assign, async () => { try { await ctx.api.post(`admin/incidents/${i.id}/assign`); toast("Asignado", "ok"); load(); } catch (e) { toastError(e); } }));
        const resolve = h("button", { class: "btn btn-sm btn-primary" }, "Resolver");
        resolve.addEventListener("click", async () => {
          const note = await promptDialog({ title: "Resolver incidente", label: "Qué pasó y cómo se cerró (queda en la bitácora)", confirmLabel: "Resolver" });
          if (!note) return;
          try { await ctx.api.post(`admin/incidents/${i.id}/resolve`, undefined, { query: { note } }); toast("Incidente resuelto", "ok"); load(); } catch (e) { toastError(e); }
        });
        const detail = h("button", { class: "btn btn-sm btn-ghost", onClick: () => dialog({ title: i.summary, wide: true,
          body: h("ol", {}, i.timeline.map((t) => h("li", {}, `${fmt.time(t.t)}: ${String(t.evento).replaceAll("_", " ")}${t.contacto ? `, ${t.contacto}` : ""}${t.nota ? `. ${t.nota}` : ""}`))),
          actions: [{ label: "Cerrar", kind: "primary" }] }) }, "Línea de tiempo");
        return h("tr", {},
          h("td", {}, fmt.date(i.created_at)), h("td", {}, KIND[i.kind] || i.kind), h("td", {}, i.summary),
          h("td", {}, badge(label, tone)),
          h("td", {}, i.lat != null ? h("a", { href: mapUrl(i.lat, i.lon), target: "_blank", rel: "noopener noreferrer" }, "Mapa") : "—"),
          h("td", {}, h("div", { class: "row" }, detail, open && ctx.can("incidents:manage") ? [assign, resolve] : null)));
      })))) : emptyState(activeOnly ? "Sin incidentes activos" : "Sin incidentes", "Los SOS y las alertas automáticas del reloj aparecen aquí en tiempo real."));
  }
  const onEvent = (e) => { if (e.detail.tipo === "alerta" && ["vitals", "device"].includes(e.detail.categoria)) load().catch(() => {}); };
  ctx.events.addEventListener("realtime", onEvent);
  ctx.onCleanup(() => ctx.events.removeEventListener("realtime", onEvent));
  await load();

  const toggle = h("div", { class: "segmented", role: "group" },
    [[true, "Activos"], [false, "Todos"]].map(([v, l]) => h("button", { type: "button", "aria-pressed": String(activeOnly === v), onClick: (e) => {
      activeOnly = v; e.currentTarget.parentElement.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b === e.currentTarget))); load();
    } }, l)));

  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, "Centro de comando"),
      h("p", {}, "Incidentes de emergencia de los usuarios. Los contactos se avisan automáticamente; aquí se hace seguimiento y cierre.")), toggle),
    h("section", { class: "panel" }, listEl),
    ctx.can("incidents:broadcast") ? broadcastPanel(ctx) : null);
}

function broadcastPanel(ctx) {
  const title = h("input", { class: "input", minlength: 5, maxlength: 120, required: true });
  const body = h("textarea", { class: "input", minlength: 10, maxlength: 500, required: true });
  const reason = h("input", { class: "input", minlength: 5, maxlength: 200, required: true });
  const severity = h("select", { class: "input" }, [["high", "Alta"], ["critical", "Crítica"], ["medium", "Media"], ["info", "Informativa"]].map(([v, l]) => h("option", { value: v }, l)));
  const send = h("button", { class: "btn btn-danger", type: "submit" }, "Enviar a todos los usuarios");
  const form = h("form", { class: "form" },
    h("div", {}, h("h2", {}, "Alerta masiva"), h("p", { class: "muted" }, "Para emergencias que afectan a muchos usuarios (desastre natural, falla del servicio). Máximo 3 por hora.")),
    h("div", { class: "form-row" }, field("Título", title), field("Severidad", severity)),
    field("Mensaje", body), field("Motivo interno", reason, "Queda en la bitácora; no lo ven los usuarios."),
    h("div", { class: "row" }, send));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    dialog({ title: "Confirmar alerta masiva", body: h("p", {}, `Se enviará «${title.value}» a todos los usuarios activos. No se puede retirar.`),
      actions: [{ label: "Cancelar" }, { label: "Enviar", kind: "danger", onClick: () => {
        busy(send, async () => {
          try {
            const r = await ctx.api.post("admin/broadcast", undefined, { query: { title: title.value, body: body.value, severity: severity.value, reason: reason.value } });
            toast(r.mensaje, "ok"); form.reset();
          } catch (e2) { toastError(e2); }
        });
      } }] });
  });
  return h("section", { class: "panel" }, form);
}
