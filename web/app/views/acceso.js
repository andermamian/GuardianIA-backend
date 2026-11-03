import { authScreen } from "../../shared/auth-screen.js";
import { busy, field, formData, h, mount, toast, errorText } from "../../shared/dom.js";

const deviceLabel = () => {
  const ua = navigator.userAgent;
  const os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Windows/.test(ua) ? "Windows" : /Mac/.test(ua) ? "macOS" : "Linux";
  const br = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Navegador";
  return `${br} en ${os}`;
};

function errorBox() {
  return h("p", { class: "notice notice-danger", role: "alert", hidden: true });
}
function showError(box, err) {
  box.hidden = false;
  box.textContent = errorText(err);
}

export function renderAuth({ api, onAuthenticated }) {
  const card = h("div", { class: "stack" });

  function loginForm() {
    const err = errorBox();
    const form = h("form", { class: "form", novalidate: true },
      h("div", {}, h("h2", {}, "Ingresar"), h("p", { class: "muted" }, "Use el mismo correo de la app Android.")),
      err,
      field("Correo", h("input", { class: "input", name: "email", type: "email", autocomplete: "username", required: true })),
      field("Contraseña", h("input", { class: "input", name: "password", type: "password", autocomplete: "current-password", required: true })),
      h("button", { class: "btn btn-primary btn-block", type: "submit" }, "Ingresar"),
      h("div", { class: "row row-between" },
        h("button", { class: "btn btn-ghost btn-sm", type: "button", onClick: () => show(recoveryForm()) }, "Olvidé mi contraseña"),
        h("button", { class: "btn btn-ghost btn-sm", type: "button", onClick: () => show(registerForm()) }, "Crear cuenta")));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const btn = form.querySelector("[type=submit]");
      busy(btn, async () => {
        err.hidden = true;
        try {
          const data = await api.webAuth("login", { ...formData(form), device_label: deviceLabel() });
          if (data.mfa_required) return show(mfaForm(data));
          api.setToken(data.access_token);
          onAuthenticated(data.user);
        } catch (e2) {
          if (e2.code === "rate_limited" && e2.extra?.retry_after) e2.message += ` (espere ${e2.extra.retry_after} s)`;
          showError(err, e2);
          form.password.value = "";
          form.password.focus();
        }
      });
    });
    return form;
  }

  function mfaForm(challenge) {
    const err = errorBox();
    const form = h("form", { class: "form" },
      h("div", {}, h("h2", {}, "Confirme que es usted"),
        h("p", { class: "muted" }, `Detectamos algo inusual en este acceso (${challenge.motivo}). Escriba el código de su app autenticadora o un código de recuperación.`)),
      err,
      field("Código", h("input", { class: "input", name: "code", inputmode: "numeric", autocomplete: "one-time-code", required: true, maxlength: 13 })),
      h("button", { class: "btn btn-primary btn-block", type: "submit" }, "Verificar"),
      h("button", { class: "btn btn-ghost", type: "button", onClick: () => show(loginForm()) }, "Volver"));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      busy(form.querySelector("[type=submit]"), async () => {
        try {
          const data = await api.webAuth("login/mfa", { challenge_id: challenge.challenge_id, code: form.code.value.trim() });
          api.setToken(data.access_token);
          onAuthenticated(data.user);
        } catch (e2) {
          showError(err, e2);
          if (e2.code === "challenge_invalid") setTimeout(() => show(loginForm()), 2500);
        }
      });
    });
    return form;
  }

  function registerForm() {
    const err = errorBox();
    const pw = h("input", { class: "input", name: "password", type: "password", autocomplete: "new-password", required: true, minlength: 12 });
    const form = h("form", { class: "form" },
      h("div", {}, h("h2", {}, "Crear cuenta"), h("p", { class: "muted" }, "Mínimo 12 caracteres. Una frase de varias palabras es más segura y fácil de recordar.")),
      err,
      field("Nombre completo", h("input", { class: "input", name: "full_name", autocomplete: "name", required: true })),
      field("Correo", h("input", { class: "input", name: "email", type: "email", autocomplete: "email", required: true })),
      field("Celular", h("input", { class: "input", name: "phone", type: "tel", autocomplete: "tel", placeholder: "+57 300 123 4567" }), "Opcional. Se usa para avisarle si un contacto lo necesita."),
      field("Contraseña", pw),
      h("label", { class: "check" }, h("input", { type: "checkbox", name: "accept_terms", required: true }),
        h("span", {}, "Acepto los términos y la política de tratamiento de datos (Ley 1581 de 2012).")),
      h("button", { class: "btn btn-primary btn-block", type: "submit" }, "Crear cuenta"),
      h("button", { class: "btn btn-ghost", type: "button", onClick: () => show(loginForm()) }, "Ya tengo cuenta"));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      busy(form.querySelector("[type=submit]"), async () => {
        err.hidden = true;
        const body = { ...formData(form), device_label: deviceLabel() };
        if (!body.accept_terms) return showError(err, { message: "Debe aceptar los términos para continuar" });
        try {
          const data = await api.webAuth("register", body);
          api.setToken(data.access_token);
          onAuthenticated(data.user);
        } catch (e2) { showError(err, e2); }
      });
    });
    return form;
  }

  function recoveryForm() {
    const form = h("form", { class: "form" },
      h("div", {}, h("h2", {}, "Recuperar acceso"), h("p", { class: "muted" }, "Le enviaremos un enlace si el correo tiene una cuenta. Por seguridad, la respuesta es la misma en ambos casos.")),
      field("Correo", h("input", { class: "input", name: "email", type: "email", required: true, autocomplete: "email" })),
      h("button", { class: "btn btn-primary btn-block", type: "submit" }, "Enviar enlace"),
      h("button", { class: "btn btn-ghost", type: "button", onClick: () => show(loginForm()) }, "Volver"));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      busy(form.querySelector("[type=submit]"), async () => {
        try {
          const r = await api.post("auth/password/recovery", { email: form.email.value.trim() }, { auth: false });
          toast(r.mensaje, "ok");
          show(loginForm());
        } catch (e2) { toast(errorText(e2), "error"); }
      });
    });
    return form;
  }

  function show(form) {
    mount(card, form);
    form.querySelector("input")?.focus();
  }

  show(loginForm());
  return authScreen({
    title: "Sus equipos y su seguridad, protegidos en un solo lugar.",
    lead: "Proteja sus equipos, navegue con privacidad y deje listos a sus contactos de emergencia. GuardianIA avisa cuando algo no está bien.",
    footer: "Ante una emergencia médica o de seguridad, llame al 123.",
    form: card,
  });
}
