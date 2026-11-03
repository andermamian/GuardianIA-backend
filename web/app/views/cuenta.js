import { badge, busy, confirmDialog, dialog, field, fmt, h, icon, mount, toast, toastError } from "../../shared/dom.js";

export default async function cuenta(ctx) {
  const { api } = ctx;
  const [me, sessions] = await Promise.all([api.get("auth/me"), api.get("auth/sessions")]);
  ctx.setUser(me);

  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, "Cuenta"), h("p", {}, me.email))),
    h("div", { class: "grid grid-2" },
      h("section", { class: "panel stack" },
        h("div", { class: "panel-head" }, h("h2", {}, "Datos"), badge(`Plan ${me.plan}`, "blue")),
        h("dl", { class: "kv" }, h("dt", {}, "Nombre"), h("dd", {}, me.full_name), h("dt", {}, "Correo"), h("dd", {}, me.email),
          h("dt", {}, "Zona horaria"), h("dd", {}, me.timezone), h("dt", {}, "Miembro desde"), h("dd", {}, fmt.date(me.created_at)))),
      mfaPanel(ctx, me)),
    passwordPanel(ctx),
    sessionsPanel(ctx, sessions));
}

function mfaPanel(ctx, me) {
  const panel = h("section", { class: "panel stack" });
  if (me.totp_enabled) {
    mount(panel, h("div", { class: "panel-head" }, h("h2", {}, "Verificación en dos pasos"), badge("Activa", "ok")),
      h("p", {}, "Si alguien obtiene su contraseña, igual necesitará el código de su celular."));
    return panel;
  }
  const start = h("button", { class: "btn btn-primary" }, "Activar verificación en dos pasos");
  start.addEventListener("click", () => busy(start, async () => {
    try { setup(await ctx.api.post("auth/2fa/setup")); } catch (e) { toastError(e); }
  }));
  function setup(data) {
    const code = h("input", { class: "input", inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code", required: true });
    const confirm = h("button", { class: "btn btn-primary", type: "submit" }, "Confirmar");
    const form = h("form", { class: "form" },
      h("ol", { class: "stack" },
        h("li", {}, "Instale una app autenticadora (Aegis, Google Authenticator, Microsoft Authenticator o 1Password)."),
        h("li", {}, "En el celular, toque ", h("a", { href: data.otpauth_uri }, "este enlace"), ". En computador, agregue la cuenta manualmente con esta clave:",
          h("p", { class: "mono panel" }, data.secret.match(/.{1,4}/g).join(" "))),
        h("li", {}, "Escriba el código de 6 dígitos que muestra la app.")),
      field("Código", code), h("div", { class: "row" }, confirm));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      busy(confirm, async () => {
        try {
          const r = await ctx.api.post("auth/2fa/enable", { code: code.value.trim() });
          showRecovery(r.recovery_codes);
          ctx.refresh();
        } catch (e2) { toastError(e2); code.select(); }
      });
    });
    mount(panel, h("h2", {}, "Configurar verificación en dos pasos"), form);
    code.focus();
  }
  mount(panel, h("div", { class: "panel-head" }, h("h2", {}, "Verificación en dos pasos"), badge("Desactivada", "warn")),
    h("p", {}, "Es la medida que más protege su cuenta. Tarda un minuto."), h("div", { class: "row" }, start));
  return panel;
}

function showRecovery(codes) {
  const text = codes.join("\n");
  dialog({
    title: "Guarde sus códigos de recuperación",
    body: h("div", { class: "stack" },
      h("p", { class: "notice notice-warn" }, "Úselos si pierde el celular. Cada uno sirve una sola vez y no se volverán a mostrar."),
      h("pre", { class: "mono panel" }, text),
      h("button", { class: "btn", onClick: async () => { await navigator.clipboard.writeText(text); toast("Copiados", "ok"); } }, icon("copiar"), "Copiar")),
    actions: [{ label: "Ya los guardé", kind: "primary" }],
  });
}

function passwordPanel(ctx) {
  const current = h("input", { class: "input", type: "password", autocomplete: "current-password", required: true });
  const next = h("input", { class: "input", type: "password", autocomplete: "new-password", required: true, minlength: 12 });
  const save = h("button", { class: "btn btn-primary", type: "submit" }, "Cambiar contraseña");
  const form = h("form", { class: "form" }, h("h2", {}, "Contraseña"),
    h("div", { class: "form-row" }, field("Actual", current), field("Nueva", next, "Mínimo 12 caracteres. Se cerrarán sus otras sesiones.")),
    h("div", { class: "row" }, save));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    busy(save, async () => {
      try {
        const r = await ctx.api.post("auth/password/change", { current_password: current.value, new_password: next.value });
        // El servidor invalida los tokens emitidos antes del cambio; esta sesión sigue viva, así que se renueva ya.
        await ctx.api.refresh();
        toast(r.mensaje, "ok");
        form.reset();
      } catch (e2) { toastError(e2); }
    });
  });
  return h("section", { class: "panel" }, form);
}

const whereFrom = (s) => [s.device_label || "Dispositivo desconocido", s.country, s.ip].filter(Boolean).join(". ");

function sessionsPanel(ctx, sessions) {
  return h("section", { class: "panel" },
    h("div", { class: "panel-head" }, h("div", {}, h("h2", {}, "Sesiones activas"), h("p", {}, "Si no reconoce alguna, ciérrela y cambie su contraseña."))),
    h("ul", { class: "list" }, sessions.map((s) => {
      const close = s.actual ? badge("Esta sesión", "blue") : h("button", { class: "btn btn-sm" }, "Cerrar sesión");
      if (!s.actual) close.addEventListener("click", async () => {
        if (!(await confirmDialog({ title: "Cerrar sesión", message: `Se cerrará la sesión de ${s.device_label || "ese dispositivo"}.`, confirmLabel: "Cerrar" }))) return;
        try { await ctx.api.del(`auth/sessions/${s.id}`); toast("Sesión cerrada", "ok"); ctx.refresh(); } catch (e) { toastError(e); }
      });
      return h("li", {}, h("div", { class: "list-main" }, h("p", { class: "list-title" }, whereFrom(s)),
        h("p", { class: "list-sub" }, `Activa ${fmt.ago(s.last_seen_at)}. Inició ${fmt.date(s.created_at)}.`)), close);
    })));
}
