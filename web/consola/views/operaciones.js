import { badge, busy, confirmDialog, emptyState, fmt, h, mount, toast, toastError } from "../../shared/dom.js";

const CHECK = { base_de_datos: "Base de datos", cifrado: "Cifrado y claves", boveda: "Almacenamiento de la bóveda", asistente_llm: "Asistente de IA", cadena_auditoria: "Cadena de auditoría", configuracion_produccion: "Configuración de producción" };

export default async function operaciones(ctx) {
  const diagPanel = h("section", { class: "panel" });
  const backupPanel = h("section", { class: "panel" });
  const keysPanel = h("section", { class: "panel" });
  const tasks = [drawDiagnostics(ctx, diagPanel)];
  if (ctx.can("ops:backups")) tasks.push(drawBackups(ctx, backupPanel));
  await Promise.all(tasks);
  if (ctx.can("ops:keys")) drawKeys(ctx, keysPanel);
  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, "Operaciones"), h("p", {}, "Estado del sistema, copias de seguridad y rotación de claves de cifrado."))),
    diagPanel, ctx.can("ops:backups") ? backupPanel : null, ctx.can("ops:keys") ? keysPanel : null);
}

async function drawDiagnostics(ctx, panel) {
  const run = h("button", { class: "btn" }, "Ejecutar de nuevo");
  run.addEventListener("click", () => busy(run, () => drawDiagnostics(ctx, panel)));
  try {
    const d = await ctx.api.get("admin/diagnostics");
    mount(panel,
      h("div", { class: "panel-head" }, h("h2", {}, "Diagnóstico"), h("div", { class: "row" }, d.ok ? badge("Todo en orden", "ok") : badge("Hay fallas", "danger"), run)),
      h("ul", { class: "list" }, Object.entries(d.comprobaciones).map(([k, c]) => {
        const ok = c.ok ?? c.integra;
        const detail = Object.entries(c).filter(([key]) => !["ok", "integra"].includes(key)).map(([key, v]) => `${key.replaceAll("_", " ")}: ${Array.isArray(v) ? v.join(", ") : v}`).join(". ");
        return h("li", {}, h("div", { class: "list-main" }, h("p", { class: "list-title" }, CHECK[k] || k), h("p", { class: "list-sub" }, detail)), badge(ok ? "Correcto" : "Falla", ok ? "ok" : "danger"));
      })));
  } catch (e) { mount(panel, h("h2", {}, "Diagnóstico"), h("p", {}, e.message)); }
}

async function drawBackups(ctx, panel) {
  const create = h("button", { class: "btn btn-primary" }, "Crear copia ahora");
  create.addEventListener("click", () => busy(create, async () => {
    try {
      const b = await ctx.api.post("admin/backups", undefined, { timeout: 120000 });
      toast(b.estado === "completed" ? `Copia creada (${fmt.bytes(b.bytes)})` : "La copia falló; revise el registro del servidor", b.estado === "completed" ? "ok" : "error");
      drawBackups(ctx, panel);
    } catch (e) { toastError(e); }
  }));
  let rows = [];
  let note = null;
  try { rows = await ctx.api.get("admin/backups"); } catch (e) { note = e.message; }
  mount(panel,
    h("div", { class: "panel-head" }, h("div", {}, h("h2", {}, "Copias de seguridad"), h("p", {}, "Una copia que nunca se verificó no es una copia. Verifique después de crearla.")), create),
    note ? h("p", { class: "notice notice-warn" }, note) : null,
    rows.length ? h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", {}, h("tr", {}, ["Archivo", "Tamaño", "Creada", "Estado", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.map((b) => {
        const verify = h("button", { class: "btn btn-sm" }, "Verificar");
        verify.addEventListener("click", () => busy(verify, async () => {
          try {
            const r = await ctx.api.post(`admin/backups/${b.id}/verify`);
            toast(r.verificado ? `Verificada: ${r.usuarios_en_respaldo} usuarios, integridad ${r.integridad_sqlite}` : "La verificación falló: no confíe en esta copia", r.verificado ? "ok" : "error");
            drawBackups(ctx, panel);
          } catch (e) { toastError(e); }
        }));
        const tone = { verified: "ok", completed: "blue", failed: "danger", running: "warn" }[b.estado];
        const label = { verified: "Verificada", completed: "Sin verificar", failed: "Falló", running: "En curso" }[b.estado] || b.estado;
        return h("tr", {}, h("td", { class: "mono" }, b.archivo), h("td", {}, fmt.bytes(b.bytes)), h("td", {}, fmt.date(b.creado)),
          h("td", {}, badge(label, tone)), h("td", {}, ["completed", "verified"].includes(b.estado) ? verify : null));
      })))) : note ? null : emptyState("Sin copias todavía", "Programe copias automáticas en el servidor y use esta sección para las manuales."));
}

function drawKeys(ctx, panel) {
  const out = h("div", { "aria-live": "polite" });
  const rotate = h("button", { class: "btn" }, "Re-envolver claves con la versión activa");
  rotate.addEventListener("click", async () => {
    if (!(await confirmDialog({ title: "Rotar claves", message: "Solo tiene efecto si ya configuró una nueva versión activa en GUARDIAN_KEYRING y reinició el servidor.", confirmLabel: "Rotar" }))) return;
    busy(rotate, async () => {
      try {
        const r = await ctx.api.post("admin/keys/rotate", undefined, { timeout: 120000 });
        mount(out, h("p", {}, `Versión activa ${r.version_activa}. Rotados: ${r.rotados}. Pendientes: ${r.pendientes}.`),
          r.pendientes ? h("p", { class: "notice notice-warn" }, "Quedan archivos por rotar: ejecute de nuevo.") : h("p", { class: "notice" }, "Listo. Ya puede retirar la versión anterior del anillo de claves."));
      } catch (e) { toastError(e); }
    });
  });
  mount(panel, h("div", { class: "panel-head" }, h("div", {}, h("h2", {}, "Rotación de claves"),
    h("p", {}, "Solo re-cifra las claves de cada archivo, no los archivos: tarda segundos aunque la bóveda pese gigabytes."))), h("div", { class: "row" }, rotate), out);
}
