import { createClient } from "../shared/api.js";
import { disposeAuth } from "../shared/auth-screen.js";
import { h, icon, mount, toast, toastError, errorText } from "../shared/dom.js";
import { connectRealtime } from "../shared/realtime.js";
import { createRouter } from "../shared/router.js";
import { renderAuth } from "./views/acceso.js";

// Estilos de la v3 (animaciones, chat, Tor, privacidad) en su propio archivo: no pisan base.css.
if (!document.querySelector('link[href$="guardian-v3.css"]')) {
  document.head.append(h("link", { rel: "stylesheet", href: new URL("../shared/guardian-v3.css", import.meta.url).href }));
}

const root = document.getElementById("root");
const state = { user: null, unread: 0, realtime: null, conn: "offline" };

const api = createClient({
  webAuthBase: "/v1/web/auth",
  onSessionEnd: (reason) => endSession(reason === "session_revoked" ? "Su sesión fue cerrada desde otro dispositivo." : "Su sesión expiró. Ingrese de nuevo."),
});

const NAV = [
  ["inicio", "Inicio", "inicio"],
  ["emergencia", "Emergencia", "emergencia"],
  ["dispositivos", "Dispositivos", "dispositivos"],
  ["boveda", "Bóveda", "boveda"],
  ["proteccion", "Protección", "proteccion"],
  ["asistente", "Asistente", "asistente"],
  ["notificaciones", "Notificaciones", "campana"],
  ["cuenta", "Cuenta", "cuenta"],
];
const TABS = ["inicio", "emergencia", "dispositivos", "proteccion", "mas"];

const lazy = (file, title) => ({ title, render: async (ctx) => (await import(`./views/${file}.js`)).default(ctx) });
const routes = {
  inicio: lazy("inicio", "Inicio"),
  emergencia: lazy("emergencia", "Emergencia"),
  dispositivos: lazy("dispositivos", "Dispositivos"),
  boveda: lazy("boveda", "Bóveda"),
  proteccion: lazy("proteccion", "Protección"),
  asistente: lazy("asistente", "Asistente"),
  notificaciones: lazy("notificaciones", "Notificaciones"),
  cuenta: lazy("cuenta", "Cuenta"),
  mas: lazy("mas", "Más"),
};

function shell() {
  const outlet = h("main", { class: "main", id: "contenido" });
  const navLinks = NAV.map(([id, label, ic]) => h("a", { href: `#/${id}`, dataset: { route: id } }, icon(ic), h("span", {}, label),
    id === "notificaciones" ? h("span", { class: "count", hidden: true, "aria-label": "sin leer" }) : null));
  const tabLinks = TABS.map((id) => {
    const item = NAV.find((n) => n[0] === id) || ["mas", "Más", "mas"];
    return h("a", { href: `#/${id}`, dataset: { route: id } }, icon(item[2], { size: 22 }), h("span", {}, item[1]));
  });
  const conn = h("span", { class: "conn", dataset: { state: state.conn } }, "Alertas en vivo");
  const el = h("div", { class: "shell" },
    h("a", { href: "#contenido", class: "sr-only" }, "Saltar al contenido"),
    h("nav", { class: "rail", "aria-label": "Principal" },
      h("a", { class: "brand", href: "#/inicio" }, h("span", { class: "brand-mark", "aria-hidden": "true" }, icon("proteccion", { size: 18 })), "GuardianIA"),
      h("div", { class: "nav" }, navLinks),
      h("div", { class: "nav-foot nav" }, conn,
        h("a", { href: "#", onClick: (e) => { e.preventDefault(); logout(); } }, icon("salir"), h("span", {}, "Cerrar sesión")))),
    outlet,
    h("nav", { class: "tabbar", "aria-label": "Principal móvil" }, tabLinks));
  return { el, outlet, conn };
}

function setActive(name) {
  document.querySelectorAll("[data-route]").forEach((a) => {
    const active = a.dataset.route === name || (a.dataset.route === "mas" && !TABS.includes(name));
    active ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current");
  });
}

function setUnread(n) {
  state.unread = n;
  document.querySelectorAll(".count").forEach((c) => { c.hidden = !n; c.textContent = n > 99 ? "99+" : n; });
}

function renderError(outlet, err) {
  mount(outlet, h("div", { class: "panel empty" },
    h("p", { class: "empty-title" }, "No se pudo cargar esta sección"),
    h("p", {}, errorText(err)),
    err?.requestId ? h("p", { class: "mono muted" }, `Referencia: ${err.requestId}`) : null,
    h("button", { class: "btn", onClick: () => router.render() }, "Reintentar")));
}

let router;

async function startApp(user) {
  state.user = user;
  disposeAuth(root);
  const { el, outlet, conn } = shell();
  mount(root, el);
  const ctx = {
    api, appName: "GuardianIA", renderError,
    get user() { return state.user; },
    setUser: (u) => { state.user = u; },
    setUnread,
    events: new EventTarget(),
  };
  router = createRouter({ routes, outlet, ctx, fallback: "inicio", onChange: setActive });
  ctx.navigate = router.go;
  ctx.refresh = () => router.render();
  await router.render();

  api.get("notifications", { query: { limit: 1 } }).then((r) => setUnread(r.sin_leer)).catch(() => {});
  state.realtime?.stop();
  state.realtime = connectRealtime({
    path: "/v1/ws",
    getToken: () => api.token,
    onStatus: (s) => { state.conn = s; conn.dataset.state = s; },
    onEvent: (evt) => {
      ctx.events.dispatchEvent(new CustomEvent("realtime", { detail: evt }));
      if (evt.tipo === "alerta" || evt.tipo === "notificacion") {
        setUnread(state.unread + 1);
        const tone = ["high", "critical"].includes(evt.severidad) ? "error" : "info";
        toast(evt.titulo, tone, { timeout: tone === "error" ? 12000 : 6000 });
      }
    },
  });
}

// Un token nuevo (renovación) reabre el WebSocket con credenciales vigentes.
api.onToken((t) => { if (t) state.realtime?.reconnect(); });

async function logout() {
  try { await api.webAuth("logout"); } catch { /* la cookie se limpia igual al expirar */ }
  endSession("Sesión cerrada.");
}

function endSession(message) {
  state.realtime?.stop();
  state.realtime = null;
  api.setToken(null);
  state.user = null;
  history.replaceState(null, "", location.pathname);
  showAuth(message);
}

function showAuth(message) {
  mount(root, renderAuth({ api, onAuthenticated: startApp }));
  if (message) toast(message);
}

// Arranque: si la cookie de sesión sigue viva, se entra directo sin pedir contraseña.
const hasSessionHint = () => document.cookie.split("; ").includes("gi_app_s=1");

(async () => {
  if (!hasSessionHint()) return showAuth();
  try {
    const data = await api.refresh();
    await startApp(data.user);
  } catch (e) {
    if (e.status && e.status !== 401) toastError(e);
    showAuth();
  }
})();
