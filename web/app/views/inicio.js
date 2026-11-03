import { badge, fmt, h, icon, SEVERITY_TONE } from "../../shared/dom.js";
import { incidentBanner, sosButton } from "../components.js";

const settle = (p) => p.then((v) => ({ ok: true, v }), (e) => ({ ok: false, e }));

export default async function inicio(ctx) {
  const { api, user } = ctx;
  const [devices, contacts, notes, incidents] = await Promise.all([
    settle(api.get("devices/overview")),
    settle(api.get("emergency/contacts")),
    settle(api.get("notifications", { query: { limit: 5 } })),
    settle(api.get("emergency/incidents", { query: { limit: 5 } })),
  ]);

  const firstName = user.full_name.split(" ")[0];

  // --------------------------------------------------------- incidentes activos
  const activeWrap = h("div", { class: "stack" });
  const drawIncidents = (list) => {
    activeWrap.querySelectorAll("section").forEach((s) => s.stop?.());
    activeWrap.replaceChildren(...list.filter((i) => ["pending_cancel", "escalating"].includes(i.status))
      .map((i) => incidentBanner(api, i, () => ctx.navigate("inicio"))));
  };
  if (incidents.ok) drawIncidents(incidents.v);
  ctx.onCleanup(() => activeWrap.querySelectorAll("section").forEach((s) => s.stop?.()));
  const onRealtime = async (e) => {
    if (e.detail.tipo === "alerta" && e.detail.categoria === "device") {
      try { drawIncidents(await api.get("emergency/incidents", { query: { limit: 5 } })); } catch { /* se reintenta con el próximo evento */ }
    }
  };
  ctx.events.addEventListener("realtime", onRealtime);
  ctx.onCleanup(() => ctx.events.removeEventListener("realtime", onRealtime));

  // --------------------------------------------------------- resumen
  const c = contacts.ok ? contacts.v : null;
  const d = devices.ok ? devices.v : null;
  const sos = h("section", { class: "panel row sos-panel", "aria-labelledby": "sos-t" },
    sosButton({ api, onIncident: (inc) => drawIncidents([inc]) }),
    h("div", { class: "stack" },
      h("h2", { id: "sos-t" }, "Pedir ayuda"),
      h("p", { class: "muted" }, c?.total
        ? `Avisará a ${c.total} ${c.total === 1 ? "contacto" : "contactos"} con su ubicación, en orden de prioridad.`
        : "Todavía no tiene contactos de emergencia. Sin ellos, el SOS no puede avisar a nadie."),
      h("a", { class: "btn btn-sm", href: "#/emergencia" }, c?.total ? "Revisar contactos" : "Agregar contactos")));

  const summary = h("section", { class: "grid grid-3" },
    tile("Contactos de emergencia", c ? c.total : "—",
      c?.ultima_prueba ? `Última prueba ${fmt.ago(c.ultima_prueba)}` : "Nunca se han probado", "#/emergencia"),
    tile("Dispositivos protegidos", d ? `${d.protegidos} de ${d.total}` : "—",
      d?.perdidos_o_robados ? `${d.perdidos_o_robados} reportado(s) como perdido o robado` : d?.sin_reporte_24h ? `${d.sin_reporte_24h} sin reportar en 24 h` : d?.total ? "Todos reportando" : "Ninguno registrado", "#/dispositivos",
      d?.perdidos_o_robados ? "danger" : null),
    tile("Notificaciones sin leer", notes.ok ? notes.v.sin_leer : "—", "Alertas de seguridad", "#/notificaciones"));

  const recent = h("section", { class: "panel" },
    h("div", { class: "panel-head" }, h("h2", {}, "Actividad reciente"), h("a", { href: "#/notificaciones" }, "Ver todo")),
    notes.ok && notes.v.items.length
      ? h("ul", { class: "list" }, notes.v.items.map((n) => h("li", {},
        h("div", { class: "list-main" }, h("p", { class: "list-title" }, n.title), h("p", { class: "list-sub" }, fmt.ago(n.created_at))),
        badge(n.severity === "info" ? "Aviso" : n.severity === "critical" ? "Crítica" : n.severity === "high" ? "Alta" : "Media", SEVERITY_TONE[n.severity]))))
      : h("p", { class: "muted" }, "Sin actividad. Aquí verá alertas de sus equipos y su cuenta."));

  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, `Hola, ${firstName}`),
      h("p", {}, "Así están sus equipos y su protección en este momento."))),
    activeWrap, h("div", { class: "grid grid-2" }, sos, recent), summary);
}

function tile(label, value, sub, href, tone) {
  return h("a", { class: "panel stat", href },
    h("span", { class: "stat-label" }, label),
    h("span", { class: "stat-value" }, value),
    h("span", { class: tone === "danger" ? "badge badge-danger" : "muted" }, sub));
}
