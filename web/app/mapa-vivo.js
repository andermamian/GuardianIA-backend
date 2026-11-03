// Mapa en vivo de un dispositivo: posición, círculo de precisión, recorrido y seguimiento automático.
// Se alimenta de los mismos eventos del WebSocket que la tarjeta, así que se mueve sin recargar.
// Leaflet se sirve desde este servidor (/static/shared/vendor/leaflet): la CSP no permite scripts externos.
import { badge, dialog, fmt, h, toast, toastError } from "../shared/dom.js";

let cargaLeaflet = null;
function cargarLeaflet() {
  if (window.L) return Promise.resolve(window.L);
  if (cargaLeaflet) return cargaLeaflet;
  cargaLeaflet = new Promise((ok, mal) => {
    const css = document.createElement("link");
    css.rel = "stylesheet"; css.href = "/static/shared/vendor/leaflet/leaflet.css";
    document.head.append(css);
    const js = document.createElement("script");
    js.src = "/static/shared/vendor/leaflet/leaflet.js";
    js.onload = () => ok(window.L);
    js.onerror = () => { cargaLeaflet = null; mal(new Error("No se pudo cargar el mapa")); };
    document.head.append(js);
  });
  return cargaLeaflet;
}

const gmaps = (lat, lon) => `https://www.google.com/maps?q=${lat},${lon}`;
const dist = (a, b) => {                     // metros entre dos puntos (haversine)
  const r = 6371000, rad = Math.PI / 180;
  const dLat = (b[0] - a[0]) * rad, dLon = (b[1] - a[1]) * rad;
  const x = Math.sin(dLat / 2) ** 2 + Math.cos(a[0] * rad) * Math.cos(b[0] * rad) * Math.sin(dLon / 2) ** 2;
  return 2 * r * Math.asin(Math.sqrt(x));
};

export async function abrirMapaVivo(ctx, equipo) {
  let d = { ...equipo };
  const lienzo = h("div", { class: "mapa-vivo", role: "application", "aria-label": `Mapa de ${d.name}` });
  const estado = h("div", { class: "mapa-estado" });
  const seguir = h("input", { type: "checkbox", checked: true });
  const localizar = h("button", { class: "btn btn-sm" }, "Localizar ahora");
  const abrirG = h("a", { class: "btn btn-sm", target: "_blank", rel: "noopener noreferrer", href: "#" }, "Abrir en Google Maps");
  const cuerpo = h("div", { class: "stack" },
    estado, lienzo,
    h("div", { class: "row row-between" },
      h("label", { class: "check" }, seguir, h("span", {}, "Seguir al teléfono")),
      h("div", { class: "row" }, localizar, abrirG)),
    h("p", { class: "muted" }, "Posición del GPS del propio teléfono. El círculo azul es el margen de error: el teléfono "
      + "está en algún punto dentro de él. La línea es su recorrido de las últimas 24 horas."));

  let limpiar = () => {}, cerrado = false;
  dialog({ title: `${d.name} · en vivo`, body: cuerpo, wide: true, onClose: () => { cerrado = true; limpiar(); },
    actions: [{ label: "Cerrar", kind: "primary" }] });

  let L;
  try { L = await cargarLeaflet(); } catch (e) { estado.replaceChildren(h("p", { class: "notice notice-warn" }, e.message)); return; }
  if (cerrado) return;                        // lo cerraron mientras cargaba

  const inicio = d.last_lat != null ? [d.last_lat, d.last_lon] : [4.6, -74.08];   // sin datos: Colombia
  const mapa = L.map(lienzo, { zoomControl: true, attributionControl: true }).setView(inicio, d.last_lat != null ? 17 : 5);
  L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 19, attribution: "© colaboradores de OpenStreetMap",
    // El servidor usa «no-referrer» en todo, pero la política de OpenStreetMap exige saber qué sitio pide
    // el mapa (si no, responde 403). Solo para los mosaicos se envía el origen (ej. https://127.0.0.1:8443),
    // nunca la ruta ni datos del usuario.
    referrerPolicy: "strict-origin-when-cross-origin",
  }).addTo(mapa);
  const trazo = L.polyline([], { color: "#38bdf8", weight: 4, opacity: 0.8 }).addTo(mapa);
  const margen = L.circle(inicio, { radius: 0, color: "#2563eb", weight: 1, fillOpacity: 0.12 }).addTo(mapa);
  const punto = L.circleMarker(inicio, { radius: 9, color: "#fff", weight: 3, fillColor: "#2563eb", fillOpacity: 1 }).addTo(mapa);
  if (d.last_lat == null) { punto.remove(); margen.remove(); }
  // El diálogo termina de dibujarse después: sin esto Leaflet calcula mal el tamaño y quedan mosaicos grises.
  setTimeout(() => mapa.invalidateSize(), 60);

  try {
    const hist = await ctx.api.get(`devices/${d.id}/locations`, { query: { hours: 24 } });
    const pts = hist.puntos.map((p) => [p.lat, p.lon]);
    if (d.last_lat != null) pts.push([d.last_lat, d.last_lon]);
    trazo.setLatLngs(pts);
    if (pts.length > 1 && d.last_lat == null) mapa.fitBounds(trazo.getBounds(), { padding: [30, 30] });
  } catch { /* el recorrido es un extra: el mapa sirve sin él */ }

  // Movimiento suave entre dos posiciones (en vez de saltar), sin bloquear la pantalla.
  let anim = null;
  function moverA(destino) {
    const origen = punto.getLatLng();
    cancelAnimationFrame(anim);
    const t0 = performance.now(), dur = 900;
    const paso = (t) => {
      const k = Math.min(1, (t - t0) / dur), e = 1 - (1 - k) ** 3;
      const p = [origen.lat + (destino[0] - origen.lat) * e, origen.lng + (destino[1] - origen.lng) * e];
      punto.setLatLng(p); margen.setLatLng(p);
      if (seguir.checked) mapa.panTo(p, { animate: false });
      if (k < 1) anim = requestAnimationFrame(paso);
    };
    anim = requestAnimationFrame(paso);
  }

  function pintarEstado() {
    const vivo = d.last_seen_at && Date.now() - new Date(d.last_seen_at).getTime() < Math.max(45, 2.5 * (d.report_interval_s || 30)) * 1000;
    const partes = [badge(vivo ? "En línea" : "Desconectado", vivo ? "ok" : "neutral")];
    if (d.last_lat == null) partes.push(h("span", { class: "muted" }, d.gps_status === "https_required"
      ? "Sin GPS: el teléfono abrió la página con http://. Hace falta HTTPS." : "Aún no hay posición GPS."));
    else partes.push(h("span", {}, `±${Math.round(d.last_accuracy_m ?? 0)} m · ${fmt.ago(d.last_fix_at || d.last_seen_at)}`),
      d.battery != null ? h("span", { class: "muted" }, `Batería ${d.battery} %${d.charging ? " (cargando)" : ""}`) : null);
    estado.replaceChildren(h("div", { class: "row" }, partes));
    if (d.last_lat != null) abrirG.href = gmaps(d.last_lat, d.last_lon);
  }
  pintarEstado();

  const onRealtime = (ev) => {
    const e = ev.detail || {};
    if (e.tipo !== "dispositivo" || e.dispositivo?.id !== d.id) return;
    const antes = d.last_lat != null ? [d.last_lat, d.last_lon] : null;
    d = { ...d, ...e.dispositivo };
    if (d.last_lat != null) {
      const ahora = [d.last_lat, d.last_lon];
      if (!mapa.hasLayer(punto)) { punto.setLatLng(ahora).addTo(mapa); margen.setLatLng(ahora).addTo(mapa); mapa.setView(ahora, 17); }
      else if (!antes || dist(antes, ahora) > 0.5) moverA(ahora);
      margen.setRadius(d.last_accuracy_m || 0);
      // Solo se alarga el recorrido si se movió más que el margen de error (el GPS «tiembla» quieto).
      const ult = trazo.getLatLngs().at(-1);
      if (!ult || dist([ult.lat, ult.lng], ahora) > Math.max(10, (d.last_accuracy_m || 0) / 2)) trazo.addLatLng(ahora);
    }
    pintarEstado();
  };
  ctx.events.addEventListener("realtime", onRealtime);
  const reloj = setInterval(pintarEstado, 5000);
  margen.setRadius(d.last_accuracy_m || 0);

  localizar.addEventListener("click", async () => {
    localizar.disabled = true;
    try { await ctx.api.post(`devices/${d.id}/commands`, { kind: "locate" }); toast("Pidiendo posición fresca al teléfono…", "info"); }
    catch (e) { toastError(e); }
    finally { setTimeout(() => { localizar.disabled = false; }, 3000); }
  });

  limpiar = () => { ctx.events.removeEventListener("realtime", onRealtime); clearInterval(reloj); cancelAnimationFrame(anim); mapa.remove(); };
}
