import { badge, dialog, emptyState, field, fmt, h, mount, toast, toastError } from "../../shared/dom.js";

const AREA = { medical: "Médica", security: "Seguridad", system: "Sistema" };
const ST = { pending: "Pendientes", approved: "Aprobadas", modified: "Modificadas", rejected: "Rechazadas" };
const pretty = (v) => JSON.stringify(v, null, 2);

export default async function recomendaciones(ctx) {
  let status = "pending";
  const listEl = h("div", {});
  async function load() {
    const rows = await ctx.api.get("admin/recommendations", { query: { status } });
    mount(listEl, rows.length ? h("div", { class: "stack" }, rows.map((r) => card(ctx, r, load)))
      : emptyState(status === "pending" ? "Nada por decidir" : `Sin recomendaciones ${ST[status].toLowerCase()}`,
        "Los motores proponen ajustes cuando detectan patrones (por ejemplo, demasiados falsos positivos)."));
  }
  const seg = h("div", { class: "segmented", role: "group" }, Object.entries(ST).map(([k, l]) =>
    h("button", { type: "button", "aria-pressed": String(k === status), onClick: (e) => {
      status = k; e.currentTarget.parentElement.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b === e.currentTarget))); load();
    } }, l)));
  await load();
  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, "Recomendaciones de la IA"),
      h("p", {}, "La IA propone; una persona decide. Los cambios médicos exigen además la revisión registrada de un profesional de la salud.")), seg),
    listEl);
}

function card(ctx, r, reload) {
  const pending = r.status === "pending";
  const blocked = r.area === "medical" && !r.expert_review;
  const decide = (decision) => decisionDialog(ctx, r, decision, reload);
  return h("article", { class: "panel stack" },
    h("div", { class: "panel-head" },
      h("div", {}, h("h2", {}, r.setting_key), h("p", {}, fmt.date(r.created_at))),
      h("div", { class: "row" }, badge(AREA[r.area] || r.area, r.area === "medical" ? "danger" : "blue"), pending ? null : badge(r.status))),
    h("p", {}, r.rationale),
    h("div", { class: "grid grid-2" },
      h("div", {}, h("h3", {}, "Valor actual"), h("pre", { class: "mono panel" }, pretty(r.current_value))),
      h("div", {}, h("h3", {}, "Propuesto"), h("pre", { class: "mono panel" }, pretty(r.proposed_value)))),
    Object.keys(r.evidence || {}).length ? h("details", {}, h("summary", {}, "Evidencia"), h("pre", { class: "mono" }, pretty(r.evidence))) : null,
    r.area === "medical" ? (r.expert_review
      ? h("div", { class: "finding" }, h("div", {}, h("strong", {}, "Revisión profesional: "), r.expert_review))
      : h("p", { class: "notice notice-warn" }, "Falta la revisión de un profesional de la salud. Solo puede rechazarse hasta que se registre.")) : null,
    pending && ctx.can("config:decide") ? h("div", { class: "row" },
      h("button", { class: "btn", onClick: () => decide("reject") }, "Rechazar"),
      h("button", { class: "btn", disabled: blocked, onClick: () => decide("modify") }, "Modificar y aprobar"),
      h("button", { class: "btn btn-primary", disabled: blocked, onClick: () => decide("approve") }, "Aprobar")) : null);
}

function decisionDialog(ctx, r, decision, reload) {
  const note = h("textarea", { class: "input", maxlength: 300, required: decision !== "approve" });
  const value = h("textarea", { class: "input mono", rows: 6 }, pretty(r.proposed_value));
  const titles = { approve: "Aprobar recomendación", modify: "Modificar y aprobar", reject: "Rechazar recomendación" };
  dialog({ title: titles[decision], body: h("div", { class: "stack" },
    decision === "modify" ? field("Valor final (JSON)", value) : null,
    field(decision === "approve" ? "Nota (opcional)" : "Motivo", note),
    h("p", { class: "muted" }, "La decisión, el valor anterior y el nuevo quedan en la bitácora con su nombre.")),
  actions: [{ label: "Cancelar" }, { label: titles[decision].split(" ")[0], kind: decision === "reject" ? "danger" : "primary", onClick: async (close) => {
    const body = { decision, note: note.value.trim() || null };
    if (decision !== "approve" && !body.note) { note.focus(); return false; }
    if (decision === "modify") {
      try { body.modified_value = JSON.parse(value.value); } catch { toast("El valor no es JSON válido", "error"); value.focus(); return false; }
      if (typeof body.modified_value !== "object" || Array.isArray(body.modified_value) || body.modified_value === null) { toast("El valor debe ser un objeto JSON", "error"); return false; }
    }
    try { await ctx.api.post(`admin/recommendations/${r.id}/decision`, body); toast("Decisión registrada", "ok"); close(); reload(); } catch (e) { toastError(e); }
    return false;
  } }] });
}
