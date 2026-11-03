import { badge, fmt, h, mount, SEVERITY_LABEL, SEVERITY_TONE } from "../../shared/dom.js";

const stat = (label, value, sub, tone) => h("div", { class: "panel stat" }, h("span", { class: "stat-label" }, label),
  h("span", { class: "stat-value" }, value), sub ? h("span", { class: tone ? `badge badge-${tone}` : "muted" }, sub) : null);

export default async function resumen(ctx) {
  const body = h("div", { class: "stack" });
  const feed = h("ul", { class: "feed", "aria-live": "polite" });
  const updated = h("span", { class: "muted" });

  async function load() {
    const d = await ctx.api.get("admin/dashboard");
    const alerts = d.seguridad.alertas_abiertas;
    const criticalOpen = (alerts.critical || 0) + (alerts.high || 0);
    const p = d.seguridad.precision_alertas_7d;
    mount(body,
      h("section", { class: "grid grid-3" },
        stat("Incidentes activos", d.salud_sistema.incidentes_activos, d.salud_sistema.incidentes_activos ? "Requieren seguimiento" : "Ninguno en curso", d.salud_sistema.incidentes_activos ? "danger" : null),
        stat("Alertas altas o críticas abiertas", criticalOpen, `${Object.values(alerts).reduce((a, b) => a + b, 0)} abiertas en total`, criticalOpen ? "warn" : null),
        stat("Precisión de alertas (7 días)", p == null ? "Sin datos" : `${Math.round(p * 100)} %`, `Según ${d.seguridad.alertas_revisadas_7d} alertas revisadas por analistas`)),
      h("div", { class: "grid grid-2" },
        h("section", { class: "panel" }, h("div", { class: "panel-head" }, h("h2", {}, "Usuarios")),
          h("dl", { class: "kv" },
            h("dt", {}, "Total"), h("dd", {}, fmt.num(d.usuarios.total)),
            h("dt", {}, "Nuevos en 7 días"), h("dd", {}, fmt.num(d.usuarios.nuevos_7d)),
            h("dt", {}, "Suspendidos"), h("dd", {}, fmt.num(d.usuarios.por_estado.suspended || 0)),
            h("dt", {}, "Por plan"), h("dd", {}, Object.entries(d.usuarios.por_plan).map(([k, v]) => `${k} ${v}`).join(", ") || "—"))),
        h("section", { class: "panel" }, h("div", { class: "panel-head" }, h("h2", {}, "Accesos en 24 h")),
          h("dl", { class: "kv" },
            h("dt", {}, "Exitosos"), h("dd", {}, fmt.num(d.seguridad.logins_24h.exitosos)),
            h("dt", {}, "Fallidos"), h("dd", {}, fmt.num(d.seguridad.logins_24h.fallidos),
              d.seguridad.logins_24h.fallidos > d.seguridad.logins_24h.exitosos && d.seguridad.logins_24h.fallidos > 20 ? badge("Posible ataque de fuerza bruta", "danger") : null),
            h("dt", {}, "IP bloqueadas"), h("dd", {}, d.seguridad.ips_bloqueadas),
            h("dt", {}, "Equipos reportados"), h("dd", {}, d.salud_sistema.dispositivos_reportados)))),
      h("div", { class: "grid grid-2" },
        h("section", { class: "panel" }, h("div", { class: "panel-head" }, h("h2", {}, "Motores de IA (24 h)")),
          Object.keys(d.motores_ia).length ? h("div", { class: "table-wrap" }, h("table", { class: "table" },
            h("thead", {}, h("tr", {}, h("th", {}, "Motor"), h("th", {}, "Llamadas"), h("th", {}, "Latencia media"), h("th", {}, "Errores"))),
            h("tbody", {}, Object.entries(d.motores_ia).map(([k, m]) => h("tr", {}, h("td", {}, k), h("td", {}, fmt.num(m.llamadas_24h)),
              h("td", {}, `${m.latencia_media_ms} ms`), h("td", {}, m.tasa_error > 0.05 ? badge(`${Math.round(m.tasa_error * 100)} %`, "danger") : `${Math.round(m.tasa_error * 100)} %`))))))
            : h("p", { class: "muted" }, "Sin actividad de los motores en las últimas 24 horas.")),
        h("section", { class: "panel" }, h("div", { class: "panel-head" }, h("h2", {}, "Eventos en vivo"), h("span", { class: "muted" }, "Altas y críticas")),
          feed.childElementCount ? feed : (feed.append(h("li", { class: "muted" }, "Esperando eventos. Se mostrarán apenas ocurran.")), feed))));
    updated.textContent = `Actualizado ${fmt.time(new Date())}`;
  }

  const onEvent = (e) => {
    const ev = e.detail;
    if (ev.tipo !== "alerta") return;
    feed.querySelector(".muted:only-child")?.remove();
    feed.prepend(h("li", {}, h("time", {}, fmt.time(new Date())), badge(SEVERITY_LABEL[ev.severidad] || ev.severidad, SEVERITY_TONE[ev.severidad]), h("span", {}, ev.titulo)));
    while (feed.childElementCount > 50) feed.lastChild.remove();
  };
  ctx.events.addEventListener("realtime", onEvent);
  ctx.onCleanup(() => ctx.events.removeEventListener("realtime", onEvent));
  const timer = setInterval(() => load().catch(() => {}), 60000);
  ctx.onCleanup(() => clearInterval(timer));
  await load();
  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, "Resumen"), h("p", {}, "Cifras medidas en el sistema, no estimaciones.")), updated),
    body);
}
