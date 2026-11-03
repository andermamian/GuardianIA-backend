// Gráfico de serie temporal en SVG: línea del promedio, banda mínimo-máximo y umbrales.
// Incluye una tabla equivalente para lectores de pantalla.
import { fmt, h } from "./dom.js";

const NS = "http://www.w3.org/2000/svg";
const s = (tag, attrs = {}) => {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
};

export function timeSeries({ points, unit = "", thresholds = [], height = 220, label }) {
  const wrap = h("figure", { class: "chart" });
  if (!points.length) {
    wrap.append(h("p", { class: "muted chart-empty" }, "Todavía no hay lecturas en este período."));
    return wrap;
  }
  const W = 640, H = height, P = { t: 12, r: 12, b: 26, l: 40 };
  const xs = points.map((p) => new Date(p.t).getTime());
  const vals = points.flatMap((p) => [p.minimo, p.maximo, p.promedio]).concat(thresholds.map((t) => t.value)).filter((v) => v != null);
  let lo = Math.min(...vals), hi = Math.max(...vals);
  const pad = Math.max(2, (hi - lo) * 0.12);
  lo = Math.floor(lo - pad); hi = Math.ceil(hi + pad);
  const x0 = Math.min(...xs), x1 = Math.max(...xs) || x0 + 1;
  const X = (t) => P.l + ((t - x0) / Math.max(1, x1 - x0)) * (W - P.l - P.r);
  const Y = (v) => P.t + (1 - (v - lo) / Math.max(1, hi - lo)) * (H - P.t - P.b);

  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": label, class: "chart-svg" });
  for (let i = 0; i <= 4; i++) {
    const v = lo + ((hi - lo) * i) / 4, y = Y(v);
    svg.append(s("line", { x1: P.l, x2: W - P.r, y1: y, y2: y, class: "chart-grid" }));
    const t = s("text", { x: P.l - 6, y: y + 4, class: "chart-tick", "text-anchor": "end" });
    t.textContent = Math.round(v);
    svg.append(t);
  }
  for (const th of thresholds) {
    const y = Y(th.value);
    svg.append(s("line", { x1: P.l, x2: W - P.r, y1: y, y2: y, class: `chart-threshold chart-threshold-${th.tone || "warn"}` }));
    const t = s("text", { x: W - P.r, y: y - 4, class: "chart-tick", "text-anchor": "end" });
    t.textContent = th.label;
    svg.append(t);
  }
  const band = points.filter((p) => p.minimo != null && p.maximo != null);
  if (band.length > 1) {
    const d = band.map((p, i) => `${i ? "L" : "M"}${X(new Date(p.t))},${Y(p.maximo)}`).join("") +
      band.slice().reverse().map((p) => `L${X(new Date(p.t))},${Y(p.minimo)}`).join("") + "Z";
    svg.append(s("path", { d, class: "chart-band" }));
  }
  const line = points.filter((p) => p.promedio != null)
    .map((p, i) => `${i ? "L" : "M"}${X(new Date(p.t))},${Y(p.promedio)}`).join("");
  svg.append(s("path", { d: line, class: "chart-line" }));
  const ticks = Math.min(6, points.length);
  for (let i = 0; i < ticks; i++) {
    const p = points[Math.round((i * (points.length - 1)) / Math.max(1, ticks - 1))];
    const t = s("text", { x: X(new Date(p.t)), y: H - 6, class: "chart-tick", "text-anchor": "middle" });
    t.textContent = fmt.time(p.t);
    svg.append(t);
  }
  const dot = s("circle", { r: 4, class: "chart-dot", visibility: "hidden" });
  svg.append(dot);
  const tip = h("div", { class: "chart-tip", hidden: true });
  svg.addEventListener("pointermove", (e) => {
    const rect = svg.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * W;
    let best = points[0];
    for (const p of points) if (Math.abs(X(new Date(p.t)) - px) < Math.abs(X(new Date(best.t)) - px)) best = p;
    if (best.promedio == null) return;
    dot.setAttribute("cx", X(new Date(best.t)));
    dot.setAttribute("cy", Y(best.promedio));
    dot.setAttribute("visibility", "visible");
    tip.hidden = false;
    tip.textContent = `${fmt.time(best.t)}: ${best.promedio} ${unit} (mín. ${best.minimo}, máx. ${best.maximo})`;
  });
  svg.addEventListener("pointerleave", () => { dot.setAttribute("visibility", "hidden"); tip.hidden = true; });

  const table = h("details", { class: "chart-data" }, h("summary", {}, "Ver datos en tabla"),
    h("table", { class: "table" },
      h("thead", {}, h("tr", {}, h("th", {}, "Hora"), h("th", {}, "Promedio"), h("th", {}, "Mínimo"), h("th", {}, "Máximo"))),
      h("tbody", {}, points.map((p) => h("tr", {}, h("td", {}, fmt.time(p.t)), h("td", {}, p.promedio), h("td", {}, p.minimo), h("td", {}, p.maximo))))));
  wrap.append(svg, tip, table);
  return wrap;
}
