import { badge, busy, confirmDialog, dialog, emptyState, field, fmt, formData, h, icon, mount, toast, toastError } from "../../shared/dom.js";
import { cancelIncident, planText, sosButton } from "../components.js";

const REL = { family: "Familia", friends: "Amigos", work: "Trabajo", other: "Otro" };
const STATUS = { pending_cancel: ["Esperando respuesta", "warn"], escalating: ["Avisando contactos", "danger"], cancelled: ["Cancelado", "neutral"], resolved: ["Resuelto", "ok"] };

export default async function emergencia(ctx) {
  const { api } = ctx;
  let filter = null;
  const [summary, settings, incidents] = await Promise.all([
    api.get("emergency/contacts"), api.get("emergency/settings"), api.get("emergency/incidents", { query: { limit: 10 } })]);

  const contactsPanel = h("section", { class: "panel" });
  const page = h("div", { class: "stack" },
    h("header", { class: "page-head" },
      h("div", {}, h("h1", {}, "Emergencia"), h("p", {}, "Quién recibe el aviso, en qué orden y cómo. Pruébelo antes de necesitarlo."))),
    h("div", { class: "grid grid-2" },
      h("section", { class: "panel row sos-panel" }, sosButton({ api, onIncident: () => ctx.refresh() }),
        h("div", { class: "stack" }, h("h2", {}, "Botón de pánico"),
          h("p", { class: "muted" }, `Mantenga presionado dos segundos. Avisa de inmediato, sin ventana de cancelación. Tiempo total de escalamiento: ${summary.tiempo_total_escalamiento_min} min.`))),
      settingsPanel(ctx, settings)),
    contactsPanel,
    incidentsPanel(ctx, incidents));

  async function reload() {
    try { draw(await api.get("emergency/contacts", { query: { relation: filter } })); } catch (e) { toastError(e); }
  }

  function draw(data) {
    const add = h("button", { class: "btn btn-primary" }, icon("mas_simbolo"), "Agregar contacto");
    add.addEventListener("click", () => contactDialog(ctx, null, reload));
    const test = h("button", { class: "btn" }, "Enviar mensaje de prueba");
    test.addEventListener("click", async () => {
      if (!(await confirmDialog({ title: "Probar contactos", message: `Se enviará un SMS marcado como PRUEBA a ${data.total} contactos. Máximo 3 pruebas por hora.`, confirmLabel: "Enviar prueba" }))) return;
      busy(test, async () => { try { toast((await api.post("emergency/contacts/test")).mensaje, "ok"); reload(); } catch (e) { toastError(e); } });
    });
    const chips = h("div", { class: "segmented", role: "group", "aria-label": "Filtrar por relación" },
      [[null, `Todos (${summary.total})`], ...Object.entries(REL).map(([k, v]) => [k, `${v} (${summary.por_relacion[k] || 0})`])]
        .map(([k, label]) => h("button", { type: "button", "aria-pressed": String(filter === k), onClick: () => { filter = k; reload(); } }, label)));
    mount(contactsPanel,
      h("div", { class: "panel-head" },
        h("div", {}, h("h2", {}, "Contactos de emergencia"),
          h("p", {}, data.ultima_prueba ? `Última prueba ${fmt.ago(data.ultima_prueba)}` : "Nunca se han probado. Hágalo hoy.")),
        h("div", { class: "row" }, data.total ? test : null, add)),
      data.total ? chips : null,
      data.contactos.length
        ? h("ul", { class: "list" }, data.contactos.map((c) => contactRow(ctx, c, reload)))
        : emptyState("Sin contactos", "Agregue al menos dos personas que puedan responder a cualquier hora.", null));
  }
  draw(summary);
  return page;
}

function contactRow(ctx, c, reload) {
  const edit = h("button", { class: "btn btn-sm" }, "Editar");
  edit.addEventListener("click", () => contactDialog(ctx, c, reload));
  const del = h("button", { class: "icon-btn", "aria-label": `Eliminar a ${c.name}` }, icon("papelera"));
  del.addEventListener("click", async () => {
    if (!(await confirmDialog({ title: "Eliminar contacto", message: `${c.name} dejará de recibir alertas.`, confirmLabel: "Eliminar", danger: true }))) return;
    try { await ctx.api.del(`emergency/contacts/${c.id}`); toast("Contacto eliminado", "ok"); reload(); } catch (e) { toastError(e); }
  });
  const channels = [c.notify_sms && "SMS", c.notify_call && "llamada"].filter(Boolean).join(" y ") || "sin canal";
  return h("li", {},
    h("span", { class: "badge badge-blue", "aria-label": `Prioridad ${c.priority}` }, c.priority),
    h("div", { class: "list-main" },
      h("p", { class: "list-title" }, c.name),
      h("p", { class: "list-sub" }, `${REL[c.relation]}. ${c.phone_e164}. Por ${channels}.`)),
    c.last_test_status ? badge(`Prueba ${fmt.ago(c.last_test_at)}`, "ok") : null, edit, del);
}

function contactDialog(ctx, c, reload) {
  const form = h("form", { class: "form", id: "contact-form" },
    field("Nombre", h("input", { class: "input", name: "name", required: true, minlength: 2, value: c?.name || "" })),
    field("Celular", h("input", { class: "input", name: "phone", type: "tel", required: true, value: c?.phone_e164 || "", placeholder: "+57 300 123 4567" }),
      "Los números de 10 dígitos se toman como colombianos."),
    h("div", { class: "form-row" },
      field("Relación", h("select", { class: "input", name: "relation" },
        Object.entries(REL).map(([k, v]) => h("option", { value: k, selected: (c?.relation || "family") === k }, v)))),
      field("Prioridad", h("input", { class: "input", name: "priority", type: "number", min: 1, max: 20, value: c?.priority || 1 }), "1 se avisa primero.")),
    h("label", { class: "check" }, h("input", { type: "checkbox", name: "notify_sms", checked: c ? c.notify_sms : true }), h("span", {}, "Enviar SMS con mi ubicación")),
    h("label", { class: "check" }, h("input", { type: "checkbox", name: "notify_call", checked: c ? c.notify_call : true }), h("span", {}, "Llamar si no confirma")));
  dialog({
    title: c ? "Editar contacto" : "Nuevo contacto",
    body: form,
    actions: [{ label: "Cancelar" }, { label: c ? "Guardar cambios" : "Agregar contacto", kind: "primary", onClick: async (close) => {
      if (!form.reportValidity()) return false;
      try {
        const body = formData(form);
        c ? await ctx.api.patch(`emergency/contacts/${c.id}`, body) : await ctx.api.post("emergency/contacts", body);
        toast(c ? "Contacto actualizado" : "Contacto agregado", "ok");
        close();
        reload();
      } catch (e) { toastError(e); }
      return false;
    } }],
  });
  form.elements.namedItem("name").focus();
}

function settingsPanel(ctx, s) {
  const save = h("button", { class: "btn btn-primary", type: "submit" }, "Guardar ajustes");
  const form = h("form", { class: "form" },
    h("div", { class: "panel-head" }, h("h2", {}, "Cómo se escala")),
    h("div", { class: "form-row" },
      field("Minutos entre contactos", h("input", { class: "input", type: "number", name: "wait_minutes", min: 1, max: 10, value: s.wait_minutes })),
      field("Segundos para cancelar", h("input", { class: "input", type: "number", name: "cancel_window_seconds", min: 10, max: 120, value: s.cancel_window_seconds }),
        "Solo en alertas automáticas del reloj.")),
    h("label", { class: "check" }, h("input", { type: "checkbox", name: "auto_call", checked: s.auto_call }), h("span", {}, "Llamar además de enviar SMS")),
    h("label", { class: "check" }, h("input", { type: "checkbox", name: "live_location", checked: s.live_location }), h("span", {}, "Compartir ubicación en tiempo real durante la emergencia")),
    h("label", { class: "check" }, h("input", { type: "checkbox", name: "auto_police", checked: s.auto_police }), h("span", {}, "Avisar a la línea 123 si ningún contacto confirma")),
    field("Mensaje", h("textarea", { class: "input", name: "message_template", maxlength: 300 }, s.message_template), "Use {nombre} y {mapa}. {mapa} es obligatorio."),
    h("div", { class: "row" }, save));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    busy(save, async () => { try { await ctx.api.put("emergency/settings", formData(form)); toast("Ajustes guardados", "ok"); } catch (e2) { toastError(e2); } });
  });
  return h("section", { class: "panel" }, form);
}

function incidentsPanel(ctx, incidents) {
  return h("section", { class: "panel" },
    h("div", { class: "panel-head" }, h("h2", {}, "Historial de alertas")),
    incidents.length ? h("ul", { class: "list" }, incidents.map((i) => {
      const [label, tone] = STATUS[i.status] || [i.status, "neutral"];
      const active = ["pending_cancel", "escalating"].includes(i.status);
      const cancel = active ? h("button", { class: "btn btn-sm", onClick: async () => { if (await cancelIncident(ctx.api, i)) ctx.refresh(); } }, "Estoy bien") : null;
      const details = h("button", { class: "btn btn-sm btn-ghost", onClick: () => dialog({ title: i.summary, body: h("ol", {},
        i.timeline.map((t) => h("li", {}, `${fmt.time(t.t)}: ${String(t.evento).replaceAll("_", " ")}${t.contacto ? `, ${t.contacto}` : ""}`)),
        ...(i.plan || []).map((p) => h("li", { class: "muted" }, `Plan: ${planText(p)}`))), actions: [{ label: "Cerrar", kind: "primary" }] }) }, "Detalle");
      return h("li", {}, h("div", { class: "list-main" }, h("p", { class: "list-title" }, i.summary), h("p", { class: "list-sub" }, fmt.date(i.created_at))),
        badge(label, tone), cancel, details);
    })) : emptyState("Sin alertas", "Aquí quedarán registradas las alertas enviadas y canceladas."));
}
