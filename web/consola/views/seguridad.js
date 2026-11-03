import { badge, busy, confirmDialog, emptyState, field, fmt, h, mount, toast, toastError } from "../../shared/dom.js";
import { pager } from "./alertas.js";

const LEVEL_TONE = { info: "neutral", warning: "warn", error: "danger", security: "blue" };

export default async function seguridad(ctx) {
  const auditPanel = h("section", { class: "panel" });
  const ipPanel = h("section", { class: "panel" });
  await Promise.all([drawAudit(ctx, auditPanel), drawIps(ctx, ipPanel)]);
  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, "Bitácora e IP"),
      h("p", {}, "Registro encadenado con hashes: si alguien edita o borra una fila directamente en la base de datos, la verificación lo detecta."))),
    auditPanel, ipPanel);
}

async function drawAudit(ctx, panel) {
  const q = { level: "", action: "", offset: 0 };
  const tableEl = h("div", {});
  const verifyOut = h("span", { "aria-live": "polite" });
  const verify = h("button", { class: "btn" }, "Verificar integridad");
  verify.addEventListener("click", () => busy(verify, async () => {
    try {
      const r = await ctx.api.get("admin/audit/verify");
      mount(verifyOut, r.integra ? badge(`Íntegra: ${fmt.num(r.registros_verificados)} registros`, "ok")
        : badge(`Alterada desde el registro ${r.primer_registro_alterado}`, "critical"));
      if (!r.integra) toast("La bitácora fue manipulada. Trate esto como un incidente de seguridad.", "error", { timeout: 20000 });
    } catch (e) { toastError(e); }
  }));
  const level = h("select", { class: "input" }, [["", "Todos"], ["security", "Seguridad"], ["warning", "Advertencia"], ["error", "Error"], ["info", "Informativo"]].map(([v, l]) => h("option", { value: v }, l)));
  level.addEventListener("change", () => { q.level = level.value; q.offset = 0; load(); });
  const action = h("input", { class: "input", type: "search", placeholder: "admin.user, device.command" });
  let t;
  action.addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => { q.action = action.value.trim(); q.offset = 0; load(); }, 300); });

  async function load() {
    const page = await ctx.api.get("admin/audit", { query: { ...q, limit: 50 } });
    mount(tableEl, page.items.length ? [h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", {}, h("tr", {}, ["#", "Fecha", "Nivel", "Acción", "Actor", "Objetivo", "IP", "Detalle"].map((x) => h("th", {}, x)))),
      h("tbody", {}, page.items.map((r) => h("tr", {},
        h("td", { class: "mono" }, r.id), h("td", {}, fmt.date(r.ts)), h("td", {}, badge(r.level, LEVEL_TONE[r.level])),
        h("td", { class: "mono" }, r.action), h("td", { class: "mono" }, r.actor_id ? r.actor_id.slice(0, 8) : "sistema"),
        h("td", { class: "mono" }, r.target_type ? `${r.target_type}:${(r.target_id || "").slice(0, 12)}` : "—"),
        h("td", { class: "mono" }, r.ip || "—"),
        h("td", {}, Object.keys(r.detail || {}).length ? h("details", {}, h("summary", {}, "Ver"), h("pre", { class: "mono" }, JSON.stringify(r.detail, null, 2))) : "—")))))),
      pager(page, (off) => { q.offset = off; load(); })] : emptyState("Sin registros"));
  }
  await load();
  mount(panel, h("div", { class: "panel-head" }, h("h2", {}, "Bitácora de auditoría"), h("div", { class: "row" }, verifyOut, verify)),
    h("div", { class: "toolbar" }, field("Nivel", level), field("Acción que empieza por", action)), tableEl);
}

async function drawIps(ctx, panel) {
  const rows = await ctx.api.get("admin/blocked-ips");
  const canRespond = ctx.can("security:respond");
  const ip = h("input", { class: "input", required: true, placeholder: "185.220.101.4" });
  const reason = h("input", { class: "input", required: true, minlength: 3, placeholder: "Fuerza bruta contra /login" });
  const hours = h("select", { class: "input" }, [["24", "24 horas"], ["168", "7 días"], ["720", "30 días"], ["", "Indefinido"]].map(([v, l]) => h("option", { value: v }, l)));
  const add = h("button", { class: "btn btn-danger", type: "submit" }, "Bloquear IP");
  const form = h("form", { class: "toolbar" }, field("IP", ip), field("Motivo", reason), field("Duración", hours), add);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    busy(add, async () => {
      try {
        const r = await ctx.api.post("admin/blocked-ips", { ip: ip.value.trim(), reason: reason.value.trim(), hours: hours.value ? Number(hours.value) : null });
        toast(r.mensaje, "ok"); drawIps(ctx, panel);
      } catch (e2) { toastError(e2); }
    });
  });
  mount(panel,
    h("div", { class: "panel-head" }, h("div", {}, h("h2", {}, "IP bloqueadas"),
      h("p", {}, "Prefiera bloqueos temporales: las IP de operadores móviles se reasignan y un bloqueo indefinido termina afectando a clientes legítimos."))),
    canRespond ? form : null,
    rows.length ? h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", {}, h("tr", {}, ["IP", "Motivo", "Vence", "Creado", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.map((r) => {
        const del = canRespond ? h("button", { class: "btn btn-sm" }, "Desbloquear") : null;
        del?.addEventListener("click", async () => {
          if (!(await confirmDialog({ title: "Desbloquear IP", message: `${r.ip} podrá volver a conectarse.`, confirmLabel: "Desbloquear" }))) return;
          try { await ctx.api.del(`admin/blocked-ips/${encodeURIComponent(r.ip)}`); toast("IP desbloqueada", "ok"); drawIps(ctx, panel); } catch (e) { toastError(e); }
        });
        return h("tr", {}, h("td", { class: "mono" }, r.ip), h("td", {}, r.motivo), h("td", {}, r.expira ? fmt.date(r.expira) : "Indefinido"), h("td", {}, fmt.date(r.creado)), h("td", {}, del));
      })))) : emptyState("Ninguna IP bloqueada"));
}
