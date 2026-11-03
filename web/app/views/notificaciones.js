import { badge, busy, emptyState, fmt, h, SEVERITY_LABEL, SEVERITY_TONE, toastError } from "../../shared/dom.js";

export default async function notificaciones(ctx) {
  const data = await ctx.api.get("notifications", { query: { limit: 100 } });
  ctx.setUnread(data.sin_leer);
  const all = h("button", { class: "btn" }, "Marcar todas como leídas");
  all.addEventListener("click", () => busy(all, async () => { try { await ctx.api.post("notifications/read-all"); ctx.refresh(); } catch (e) { toastError(e); } }));

  const link = (n) => {
    if (n.data?.device_id) return "#/dispositivos";
    if (n.kind?.startsWith("alert.auth")) return "#/cuenta";
    return null;
  };

  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, "Notificaciones"), h("p", {}, `${data.sin_leer} sin leer`)), data.sin_leer ? all : null),
    h("section", { class: "panel" }, data.items.length ? h("ul", { class: "list" }, data.items.map((n) => {
      const href = link(n);
      const read = h("button", { class: "btn btn-sm btn-ghost" }, "Marcar leída");
      read.addEventListener("click", () => busy(read, async () => {
        try { await ctx.api.post(`notifications/${n.id}/read`); read.replaceWith(badge("Leída")); ctx.setUnread(Math.max(0, data.sin_leer -= 1)); } catch (e) { toastError(e); }
      }));
      return h("li", {},
        h("div", { class: "list-main" },
          h("p", { class: "list-title" }, n.read_at ? n.title : h("strong", {}, n.title)),
          h("p", {}, n.body),
          h("p", { class: "list-sub" }, fmt.date(n.created_at))),
        n.severity !== "info" ? badge(SEVERITY_LABEL[n.severity], SEVERITY_TONE[n.severity]) : null,
        href ? h("a", { class: "btn btn-sm", href }, "Ver") : null,
        n.read_at ? null : read);
    })) : emptyState("Todo en orden", "Cuando algo requiera su atención lo verá aquí y en una alerta en pantalla.")));
}
