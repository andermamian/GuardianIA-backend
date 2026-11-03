import { badge, busy, dialog, emptyState, field, fmt, h, mount, SEVERITY_LABEL, SEVERITY_TONE, toast, toastError } from "../../shared/dom.js";

const CAT = { auth: "Acceso", device: "Dispositivo", app: "Aplicación", web: "Web", vitals: "Signos vitales", system: "Sistema" };
const ST = { open: ["Abierta", "danger"], acknowledged: ["En revisión", "warn"], resolved: ["Resuelta", "ok"] };
const PAGE = 50;

export default async function alertas(ctx) {
  const q = { status: "open", severity: "", category: "", offset: 0 };
  const tableEl = h("div", {});
  const sel = (name, opts) => {
    const s = h("select", { class: "input" }, opts.map(([v, l]) => h("option", { value: v, selected: q[name] === v }, l)));
    s.addEventListener("change", () => { q[name] = s.value; q.offset = 0; load(); });
    return s;
  };
  async function load() {
    const page = await ctx.api.get("admin/alerts", { query: { ...q, limit: PAGE } });
    mount(tableEl, page.items.length ? [h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", {}, h("tr", {}, ["Fecha", "Severidad", "Categoría", "Alerta", "Estado"].map((t) => h("th", {}, t)))),
      h("tbody", {}, page.items.map((a) => {
        const tr = h("tr", { dataset: { clickable: "" }, tabindex: 0 },
          h("td", {}, fmt.date(a.created_at)), h("td", {}, badge(SEVERITY_LABEL[a.severity], SEVERITY_TONE[a.severity])),
          h("td", {}, CAT[a.category] || a.category), h("td", {}, h("strong", {}, a.title), h("br"), h("span", { class: "muted" }, a.engine ? `Motor ${a.engine}` : "")),
          h("td", {}, badge(...(ST[a.status] || [a.status, "neutral"]))));
        const open = () => alertDialog(ctx, a, load);
        tr.addEventListener("click", open);
        tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
        return tr;
      })))), pager(page, (off) => { q.offset = off; load(); })]
      : emptyState("Sin alertas con estos filtros", q.status === "open" ? "Buen momento para revisar las que están en revisión." : null));
  }
  await load();
  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, "Alertas de seguridad"),
      h("p", {}, "Marque cada alerta como verdadero o falso positivo: esa etiqueta mide la precisión real y reentrena los motores."))),
    h("section", { class: "panel" },
      h("div", { class: "toolbar" },
        field("Estado", sel("status", [["open", "Abiertas"], ["acknowledged", "En revisión"], ["resolved", "Resueltas"], ["", "Todas"]])),
        field("Severidad", sel("severity", [["", "Todas"], ["critical", "Crítica"], ["high", "Alta"], ["medium", "Media"], ["low", "Baja"], ["info", "Informativa"]])),
        field("Categoría", sel("category", [["", "Todas"], ...Object.entries(CAT)]))),
      tableEl));
}

export function pager(page, go) {
  const from = page.total ? page.offset + 1 : 0;
  const to = Math.min(page.offset + page.limit, page.total);
  return h("div", { class: "pager" }, h("span", {}, `${from} a ${to} de ${page.total}`),
    h("div", { class: "row" },
      h("button", { class: "btn btn-sm", disabled: page.offset === 0, onClick: () => go(Math.max(0, page.offset - page.limit)) }, "Anterior"),
      h("button", { class: "btn btn-sm", disabled: to >= page.total, onClick: () => go(page.offset + page.limit) }, "Siguiente")));
}

function alertDialog(ctx, a, reload) {
  const note = h("textarea", { class: "input", maxlength: 300, placeholder: "Qué se verificó" });
  const actions = [{ label: "Cerrar" }];
  if (a.status === "open") actions.push({ label: "Tomar para revisión", onClick: async (close) => {
    try { await ctx.api.post(`admin/alerts/${a.id}/acknowledge`); close(); reload(); } catch (e) { toastError(e); }
    return false;
  } });
  if (a.status !== "resolved" && ctx.can("security:respond")) {
    for (const [fb, label, kind] of [["false_positive", "Falso positivo", null], ["true_positive", "Amenaza real", "primary"]]) {
      actions.push({ label, kind, onClick: async (close) => {
        try { await ctx.api.post(`admin/alerts/${a.id}/resolve`, { feedback: fb, note: note.value.trim() || null }); toast("Alerta resuelta", "ok"); close(); reload(); } catch (e) { toastError(e); }
        return false;
      } });
    }
  }
  dialog({ title: a.title, wide: true, actions, body: h("div", { class: "stack" },
    h("div", { class: "row" }, badge(SEVERITY_LABEL[a.severity], SEVERITY_TONE[a.severity]), badge(CAT[a.category] || a.category), badge(...(ST[a.status] || [a.status, "neutral"]))),
    h("p", {}, a.description),
    h("dl", { class: "kv" }, h("dt", {}, "Fecha"), h("dd", {}, fmt.date(a.created_at)), h("dt", {}, "Usuario"), h("dd", { class: "mono" }, a.user_id || "Sistema"),
      h("dt", {}, "Motor"), h("dd", {}, a.engine || "—"), h("dt", {}, "Id"), h("dd", { class: "mono" }, a.id)),
    a.status !== "resolved" && ctx.can("security:respond") ? field("Nota de resolución", note) : null) });
}
