import { badge, busy, confirmDialog, dialog, emptyState, field, fmt, h, mount, promptDialog, toast, toastError } from "../../shared/dom.js";
import { pager } from "./alertas.js";

const ROLE = { user: "Usuario", supervisor: "Supervisor", admin: "Administrador", super_admin: "Super administrador" };
const LEVEL = { user: 0, supervisor: 1, admin: 2, super_admin: 3 };

export default async function usuarios(ctx) {
  const q = { q: "", role: "", status: "", offset: 0 };
  const tableEl = h("div", {});
  const search = h("input", { class: "input", type: "search", placeholder: "Nombre o correo" });
  let debounce;
  search.addEventListener("input", () => { clearTimeout(debounce); debounce = setTimeout(() => { q.q = search.value.trim(); q.offset = 0; load(); }, 300); });
  const sel = (name, opts) => {
    const s = h("select", { class: "input" }, opts.map(([v, l]) => h("option", { value: v }, l)));
    s.addEventListener("change", () => { q[name] = s.value; q.offset = 0; load(); });
    return s;
  };

  async function load() {
    const page = await ctx.api.get("admin/users", { query: { ...q, limit: 50 } });
    mount(tableEl, page.items.length ? [h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", {}, h("tr", {}, ["Nombre", "Correo", "Rol", "Plan", "Estado", "2FA", "Último acceso"].map((t) => h("th", {}, t)))),
      h("tbody", {}, page.items.map((u) => {
        const tr = h("tr", { dataset: { clickable: "" }, tabindex: 0 },
          h("td", {}, u.full_name), h("td", {}, u.email), h("td", {}, ROLE[u.role]), h("td", {}, u.plan),
          h("td", {}, u.status === "active" ? badge("Activo", "ok") : badge("Suspendido", "danger")),
          h("td", {}, u.totp_enabled ? "Sí" : u.role !== "user" ? badge("Falta", "danger") : "No"),
          h("td", {}, fmt.ago(u.last_login_at)));
        const open = () => userDialog(ctx, u, load);
        tr.addEventListener("click", open);
        tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
        return tr;
      })))), pager(page, (off) => { q.offset = off; load(); })] : emptyState("Sin resultados"));
  }
  await load();
  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, "Usuarios"),
      h("p", {}, "Solo puede gestionar cuentas de un nivel inferior al suyo. Cada cambio pide un motivo y queda en la bitácora."))),
    h("section", { class: "panel" },
      h("div", { class: "toolbar" }, field("Buscar", search),
        field("Rol", sel("role", [["", "Todos"], ...Object.entries(ROLE)])),
        field("Estado", sel("status", [["", "Todos"], ["active", "Activos"], ["suspended", "Suspendidos"]]))),
      tableEl));
}

function userDialog(ctx, u, reload) {
  const me = ctx.user;
  const manageable = me.id !== u.id && (me.role === "super_admin" || LEVEL[me.role] > LEVEL[u.role]);
  const actions = h("div", { class: "stack" });
  const run = async (btn, fn, ok) => busy(btn, async () => { try { await fn(); toast(ok, "ok"); dlg.close(); reload(); } catch (e) { toastError(e); } });

  if (!manageable) actions.append(h("p", { class: "notice" }, me.id === u.id ? "No puede gestionar su propia cuenta." : "Esta cuenta es de su mismo nivel o superior."));
  if (manageable && ctx.can("users:write")) {
    const suspend = h("button", { class: `btn ${u.status === "active" ? "btn-danger" : "btn-primary"}` }, u.status === "active" ? "Suspender cuenta" : "Reactivar cuenta");
    suspend.addEventListener("click", async () => {
      const reason = await promptDialog({ title: suspend.textContent, label: "Motivo", confirmLabel: suspend.textContent });
      if (reason) run(suspend, () => ctx.api.put(`admin/users/${u.id}/status`, { status: u.status === "active" ? "suspended" : "active", reason }),
        u.status === "active" ? "Cuenta suspendida y sesiones cerradas" : "Cuenta reactivada");
    });
    actions.append(h("div", { class: "row" }, suspend));
  }
  if (manageable && ctx.can("security:respond")) {
    const revoke = h("button", { class: "btn" }, "Cerrar todas sus sesiones");
    revoke.addEventListener("click", async () => {
      if (await confirmDialog({ title: "Cerrar sesiones", message: `${u.full_name} tendrá que volver a ingresar en todos sus dispositivos.`, confirmLabel: "Cerrar sesiones" }))
        run(revoke, () => ctx.api.del(`admin/users/${u.id}/sessions`), "Sesiones cerradas");
    });
    actions.append(h("div", { class: "row" }, revoke));
  }
  if (manageable && ctx.can("users:roles")) {
    const role = h("select", { class: "input" }, Object.entries(ROLE).map(([v, l]) => h("option", { value: v, selected: v === u.role }, l)));
    const apply = h("button", { class: "btn" }, "Cambiar rol");
    apply.addEventListener("click", async () => {
      if (role.value === u.role) return;
      const reason = await promptDialog({ title: `Cambiar rol a ${ROLE[role.value]}`, label: "Motivo (p. ej. número de solicitud aprobada)", confirmLabel: "Cambiar rol" });
      if (reason) run(apply, () => ctx.api.put(`admin/users/${u.id}/role`, { role: role.value, reason }), "Rol actualizado");
    });
    actions.append(h("div", { class: "row" }, field("Rol", role), apply));
  }
  if (u.role === "user" && ctx.can("health:thresholds")) actions.append(thresholdsForm(ctx, u));

  const dlg = dialog({ title: u.full_name, wide: true, actions: [{ label: "Cerrar", kind: "primary" }], body: h("div", { class: "stack" },
    h("dl", { class: "kv" },
      h("dt", {}, "Correo"), h("dd", {}, u.email), h("dt", {}, "Rol"), h("dd", {}, ROLE[u.role]), h("dt", {}, "Plan"), h("dd", {}, u.plan),
      h("dt", {}, "Estado"), h("dd", {}, u.status === "active" ? "Activo" : "Suspendido"),
      h("dt", {}, "2FA"), h("dd", {}, u.totp_enabled ? "Activa" : "No configurada"),
      h("dt", {}, "Registro"), h("dd", {}, fmt.date(u.created_at)), h("dt", {}, "Último acceso"), h("dd", {}, fmt.date(u.last_login_at)),
      h("dt", {}, "Id"), h("dd", { class: "mono" }, u.id)),
    h("hr", { class: "divider" }), actions) });
}

function thresholdsForm(ctx, u) {
  const num = (name, min, max) => h("input", { class: "input", type: "number", name, min, max, placeholder: "Sin cambio" });
  const hrMin = num("hr_min", 20, 100), hrMax = num("hr_max", 60, 250), spo2 = num("spo2_min", 70, 100);
  const reason = h("textarea", { class: "input", minlength: 3, required: true, placeholder: "Profesional que lo indicó y justificación clínica" });
  const save = h("button", { class: "btn", type: "submit" }, "Aplicar umbrales");
  const form = h("form", { class: "form" },
    h("details", {}, h("summary", {}, "Umbrales clínicos personalizados"),
      h("div", { class: "stack" },
        h("p", { class: "notice notice-warn" }, "Solo con indicación de un profesional de la salud. El usuario recibe una notificación del cambio."),
        h("div", { class: "form-row" }, field("Pulso mínimo", hrMin), field("Pulso máximo en reposo", hrMax), field("SpO₂ de atención", spo2)),
        field("Justificación", reason), h("div", { class: "row" }, save))));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const body = { reason: reason.value.trim() };
    [hrMin, hrMax, spo2].forEach((i) => { if (i.value) body[i.name] = Number(i.value); });
    busy(save, async () => { try { toast((await ctx.api.put(`admin/users/${u.id}/health-thresholds`, body)).mensaje, "ok"); form.reset(); } catch (e2) { toastError(e2); } });
  });
  return form;
}
