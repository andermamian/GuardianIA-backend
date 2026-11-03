import { createClient } from "../shared/api.js";
import { authScreen, disposeAuth } from "../shared/auth-screen.js";
import { busy, errorText, field, h, icon, mount, toast } from "../shared/dom.js";
import { connectRealtime } from "../shared/realtime.js";
import { createRouter } from "../shared/router.js";

const root = document.getElementById("root");
const state = { user: null, perms: new Set(), realtime: null };
const api = createClient({
  webAuthBase: "/v1/web/admin/auth",
  onSessionEnd: () => endSession("La sesión administrativa terminó. Por seguridad dura poco; ingrese de nuevo."),
});

// [ruta, etiqueta, ícono, permiso requerido]
const NAV = [
  ["resumen", "Resumen", "inicio", "dashboard:read"],
  ["incidentes", "Centro de comando", "emergencia", "incidents:read"],
  ["alertas", "Alertas", "campana", "security:read"],
  ["usuarios", "Usuarios", "usuarios", "users:read"],
  ["recomendaciones", "Recomendaciones IA", "ajustes", "config:read"],
  ["seguridad", "Bitácora e IP", "bitacora", "security:read"],
  ["operaciones", "Operaciones", "servidor", "dashboard:read"],
  ["modelos", "Redes neuronales", "ajustes", "ai:read"],
];
const TITLES = Object.fromEntries(NAV.map((n) => [n[0], n[1]]));
const lazy = (name) => ({ title: TITLES[name], render: async (ctx) => (await import(`./views/${name}.js`)).default(ctx) });
const ROLE = { supervisor: "Supervisor", admin: "Administrador", super_admin: "Super administrador" };

function renderError(outlet, err) {
  mount(outlet, h("div", { class: "panel empty" }, h("p", { class: "empty-title" }, err.status === 403 ? "Su rol no tiene acceso a esta sección" : "No se pudo cargar"),
    h("p", {}, errorText(err)), err.requestId ? h("p", { class: "mono muted" }, `Referencia: ${err.requestId}`) : null));
}

async function start(user) {
  state.user = user;
  const perms = await api.get("admin/permissions");
  state.perms = new Set(perms.permisos);
  disposeAuth(root);
  const allowed = NAV.filter((n) => state.perms.has(n[3]));
  const routes = Object.fromEntries(allowed.map((n) => [n[0], lazy(n[0])]));
  const outlet = h("main", { class: "main", id: "contenido" });
  const conn = h("span", { class: "conn" }, "Eventos en vivo");
  mount(root, h("div", { class: "shell" },
    h("nav", { class: "rail", "aria-label": "Consola" },
      h("a", { class: "brand", href: "#/resumen" }, h("span", { class: "brand-mark", "aria-hidden": "true" }, icon("proteccion", { size: 18 })), "Consola"),
      h("div", { class: "nav" }, allowed.map(([id, label, ic]) => h("a", { href: `#/${id}`, dataset: { route: id } }, icon(ic), h("span", {}, label)))),
      h("div", { class: "nav-foot nav" }, conn,
        h("div", { class: "rail-user" }, h("strong", {}, user.full_name), ROLE[user.role] || user.role),
        h("a", { href: "#", onClick: (e) => { e.preventDefault(); logout(); } }, icon("salir"), h("span", {}, "Cerrar sesión")))),
    outlet,
    h("nav", { class: "tabbar", "aria-label": "Consola móvil" }, allowed.slice(0, 5).map(([id, label, ic]) =>
      h("a", { href: `#/${id}`, dataset: { route: id } }, icon(ic, { size: 22 }), h("span", {}, label.split(" ")[0]))))));

  const events = new EventTarget();
  const ctx = { api, appName: "Consola GuardianIA", renderError, events, can: (p) => state.perms.has(p), get user() { return state.user; } };
  const router = createRouter({ routes, outlet, ctx, fallback: allowed[0]?.[0] || "resumen",
    onChange: (name) => document.querySelectorAll("[data-route]").forEach((a) => a.dataset.route === name ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")) });
  ctx.navigate = router.go;
  ctx.refresh = () => router.render();
  await router.render();

  state.realtime?.stop();
  state.realtime = connectRealtime({
    path: "/v1/admin/ws", getToken: () => api.token,
    onStatus: (s) => { conn.dataset.state = s; },
    onEvent: (evt) => {
      events.dispatchEvent(new CustomEvent("realtime", { detail: evt }));
      if (evt.severidad === "critical") toast(`Crítica: ${evt.titulo}`, "error", { timeout: 15000 });
    },
  });
}
api.onToken((t) => { if (t) state.realtime?.reconnect(); });

async function logout() {
  try { await api.webAuth("logout"); } catch { /* expira sola */ }
  endSession("Sesión cerrada.");
}

function endSession(message) {
  state.realtime?.stop();
  state.realtime = null;
  api.setToken(null);
  history.replaceState(null, "", location.pathname);
  showLogin();
  if (message) toast(message);
}

// ------------------------------------------------------------- acceso en dos pasos
function showLogin() {
  const card = h("div", { class: "stack" });
  const err = h("p", { class: "notice notice-danger", role: "alert", hidden: true });
  const fail = (e) => { err.hidden = false; err.textContent = errorText(e); };

  function step1() {
    const levels = h("div", { class: "segmented", role: "radiogroup", "aria-label": "Nivel de autorización" },
      Object.entries(ROLE).map(([v, l], i) => h("label", {}, h("input", { type: "radio", name: "authorization_level", value: v, checked: i === 1 }), h("span", {}, l))));
    const submit = h("button", { class: "btn btn-primary btn-block", type: "submit" }, "Continuar");
    const form = h("form", { class: "form" },
      h("div", {}, h("h2", {}, "Acceso administrativo"), h("p", { class: "muted" }, "Todas las acciones quedan registradas en la bitácora con su nombre.")),
      err,
      h("div", { class: "field" }, h("span", { class: "field-label" }, "Nivel de autorización"), levels),
      field("Correo institucional", h("input", { class: "input", name: "email", type: "email", autocomplete: "username", required: true })),
      field("Contraseña", h("input", { class: "input", name: "password", type: "password", autocomplete: "current-password", required: true })),
      h("label", { class: "check" }, h("input", { type: "checkbox", name: "remember_session" }), h("span", {}, "Mantener la sesión 12 horas en este equipo")),
      submit);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      busy(submit, async () => {
        err.hidden = true;
        try {
          const ch = await api.webAuth("login", {
            email: form.email.value.trim(), password: form.password.value,
            authorization_level: form.querySelector("[name=authorization_level]:checked").value,
            remember_session: form.remember_session.checked,
          });
          step2(ch);
        } catch (e2) { fail(e2); form.password.value = ""; }
      });
    });
    mount(card, form);
    form.email.focus();
  }

  function step2(ch) {
    const remaining = h("span", { class: "muted", "aria-live": "off" });
    const deadline = Date.now() + ch.expires_in * 1000;
    const timer = setInterval(() => {
      const s = Math.max(0, Math.round((deadline - Date.now()) / 1000));
      remaining.textContent = `El reto vence en ${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
      if (!s) { clearInterval(timer); step1(); toast("El código venció. Inicie de nuevo."); }
    }, 1000);
    const code = h("input", { class: "input", name: "code", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 13, required: true });
    const submit = h("button", { class: "btn btn-primary btn-block", type: "submit" }, "Verificar e ingresar");
    const form = h("form", { class: "form" },
      h("div", {}, h("h2", {}, "Código de verificación"), h("p", { class: "muted" }, ch.motivo)), err,
      field("Código de 6 dígitos o código de recuperación", code), remaining, submit,
      h("button", { class: "btn btn-ghost", type: "button", onClick: () => { clearInterval(timer); step1(); } }, "Volver"));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      busy(submit, async () => {
        err.hidden = true;
        try {
          const data = await api.webAuth("mfa", { challenge_id: ch.challenge_id, code: code.value.trim() });
          clearInterval(timer);
          api.setToken(data.access_token);
          await start(data.user);
        } catch (e2) {
          fail(e2);
          code.select();
          if (e2.code === "challenge_invalid") { clearInterval(timer); setTimeout(step1, 2000); }
        }
      });
    });
    mount(card, form);
    code.focus();
  }

  step1();
  mount(root, authScreen({
    title: "Consola de operación GuardianIA",
    lead: "Monitoreo de incidentes, alertas de seguridad y decisiones sobre recomendaciones de la IA. Solo personal autorizado.",
    footer: "El acceso indebido a sistemas informáticos es delito en Colombia (Ley 1273 de 2009).",
    form: card,
  }));
}

const hasSessionHint = () => document.cookie.split("; ").includes("gi_admin_s=1");

(async () => {
  if (!hasSessionHint()) return showLogin();
  try {
    const data = await api.refresh();
    await start(data.user);
  } catch {
    showLogin();
  }
})();
