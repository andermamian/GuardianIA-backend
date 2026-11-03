import { h, icon } from "../../shared/dom.js";

const ITEMS = [
  ["boveda", "Bóveda", "Documentos y contraseñas cifrados", "boveda"],
  ["proteccion", "Protección", "Analizar archivos sospechosos", "proteccion"],
  ["asistente", "Asistente", "Pregunte sobre seguridad y bienestar", "asistente"],
  ["notificaciones", "Notificaciones", "Alertas y avisos", "campana"],
  ["cuenta", "Cuenta", "Verificación en dos pasos y sesiones", "cuenta"],
];

export default async function mas() {
  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("h1", {}, "Más")),
    h("nav", { class: "panel", "aria-label": "Más secciones" }, h("ul", { class: "list" },
      ITEMS.map(([route, title, sub, ic]) => h("li", {}, icon(ic),
        h("a", { class: "list-main", href: `#/${route}` }, h("p", { class: "list-title" }, title), h("p", { class: "list-sub" }, sub)))))));
}
