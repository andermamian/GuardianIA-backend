// Pantalla de acceso compartida por la app y la consola: panel de identidad con el monitor
// + formulario. El contenido del formulario lo decide cada cliente.
import { h } from "./dom.js";
import { pulseTrace } from "./pulse.js";

export function authScreen({ title, lead, footer, form }) {
  const canvas = h("canvas", { "aria-hidden": "true" });
  const root = h("div", { class: "auth" },
    h("aside", { class: "auth-aside" },
      h("a", { class: "brand", href: "#" }, h("span", { class: "brand-mark", "aria-hidden": "true" }, "G"), h("span", {}, "GuardianIA")),
      h("div", {}, h("h1", {}, title), h("p", {}, lead)),
      canvas,
      h("p", { class: "auth-foot" }, footer)),
    h("main", { class: "auth-main" }, h("div", { class: "auth-card" }, form)));
  requestAnimationFrame(() => {
    const trace = pulseTrace(canvas);
    trace.setBpm(64);
    root.addEventListener("remove-auth", () => trace.stop(), { once: true });
  });
  return root;
}

export function disposeAuth(root) {
  root?.querySelector?.(".auth")?.dispatchEvent(new Event("remove-auth"));
}
