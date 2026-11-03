import { abrirMapaVivo } from "../mapa-vivo.js";
import { badge, busy, confirmDialog, dialog, emptyState, errorText, field, fmt, h, icon, mount, promptDialog, toast, toastError } from "../../shared/dom.js";

// Pantalla Dispositivos EN VIVO: cada latido del teléfono llega por WebSocket (evento «dispositivo»)
// y la tarjeta se repinta sola. Todo lo que se muestra sale de datos reales que reporta el equipo.

const STATUS = { ok: ["Protegido", "ok"], lost: ["Perdido", "warn"], stolen: ["Robado", "danger"], wiped: ["Borrado", "neutral"] };
const CMD = { ring: "Sonar alarma", locate: "Localizar", lock: "Bloquear", message: "Mensaje en pantalla", photo: "Foto del intruso", wipe: "Borrar todo", sos: "Enviar SOS desde el teléfono" };
const CMD_STATUS = { pending: "En cola", delivered: "Entregado", completed: "Ejecutado", failed: "Falló", expired: "Venció" };
const GPS = {
  ok: "Activo",
  waiting: "Buscando señal…",
  https_required: "Bloqueado: el teléfono abrió la página con http://. Arranque con INICIAR_GUARDIANIA.bat (usa HTTPS) y vuelva a vincular.",
  denied: "Permiso de ubicación negado en el teléfono.",
  unavailable: "El teléfono no logra leer el GPS (¿ubicación apagada?).",
  paused: "Pausado desde este PC.",
};
const RIESGO = { bajo: ["Riesgo bajo", "ok"], medio: ["Riesgo medio", "warn"], alto: ["Riesgo alto", "danger"] };
const mapUrl = (lat, lon) => `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=17/${lat}/${lon}`;
const ANALISIS_CADA_MS = 20000;   // el análisis no necesita recalcularse con cada latido

// En línea si reportó dentro de 2,5 intervalos (igual que el servidor, pero calculado aquí para que
// pase a «Desconectado» aunque no llegue ningún evento: justamente cuando el teléfono se apaga).
function enLinea(d) {
  if (!d.last_seen_at) return false;
  // El canal en vivo se cerró después del último reporte: pestaña cerrada, teléfono apagado o sin señal.
  if (d._canal === false && d._canalT >= new Date(d.last_seen_at).getTime()) return false;
  const limite = Math.max(45, 2.5 * (d.report_interval_s || 30)) * 1000;
  return Date.now() - new Date(d.last_seen_at).getTime() <= limite;
}
const porNavegador = (d) => !!(d.device_info && d.device_info.navegador);

export default async function dispositivos(ctx) {
  const { api } = ctx;
  const lista = await api.get("devices");
  const equipos = new Map(lista.map((d) => [d.id, { ...d, _canal: d.canal_en_vivo, _canalT: Date.now() }]));
  const analisis = new Map();       // id → { datos, pedido }
  const tarjetas = new Map();       // id → elemento

  const stat = (label) => { const v = h("span", { class: "stat-value" }, "—"); return [h("div", { class: "panel stat" }, h("span", { class: "stat-label" }, label), v), v]; };
  const [pVivo, vVivo] = stat("En línea ahora");
  const [pPerd, vPerd] = stat("Perdidos o robados");
  const [pSin, vSin] = stat("Sin reportar en 24 h");
  const grid = h("div", { class: "grid grid-2" });
  const vacio = h("section", { class: "panel" }, emptyState("Sin dispositivos",
    "Vincule su computador o su celular para poder localizarlos, bloquearlos o borrarlos a distancia.",
    h("button", { class: "btn btn-primary", onClick: () => vincularDialog(ctx) }, "Vincular equipo nuevo")));

  function contadores() {
    const ds = [...equipos.values()];
    const hace24 = Date.now() - 864e5;
    vVivo.textContent = `${ds.filter(enLinea).length} de ${ds.length}`;
    vPerd.textContent = ds.filter((d) => ["lost", "stolen"].includes(d.status)).length;
    vSin.textContent = ds.filter((d) => !d.last_seen_at || new Date(d.last_seen_at).getTime() < hace24).length;
    grid.hidden = !ds.length; vacio.hidden = !!ds.length;
  }

  function pintar(id) {
    const d = equipos.get(id);
    if (!d) return;
    const nueva = deviceCard(vivo, d, analisis.get(id)?.datos);
    const vieja = tarjetas.get(id);
    vieja ? vieja.replaceWith(nueva) : grid.append(nueva);
    tarjetas.set(id, nueva);
  }

  async function pedirAnalisis(id, forzar = false) {
    const a = analisis.get(id) || {};
    analisis.set(id, a);
    const falta = ANALISIS_CADA_MS - (Date.now() - (a.pedido || 0));
    if (!forzar && falta > 0) {
      // Llegaron datos nuevos antes de tiempo: se agenda UNA actualización al cumplirse el plazo,
      // así el análisis nunca se queda con datos viejos ni se recalcula en cada latido.
      if (!a.agenda) a.agenda = setTimeout(() => { a.agenda = null; pedirAnalisis(id, true); }, falta);
      return;
    }
    a.pedido = Date.now();
    try { a.datos = await api.get(`devices/${id}/analisis`); pintar(id); } catch { /* se reintenta con el próximo latido */ }
  }

  const vivo = {
    ctx,
    upsert(d, { analizar = true } = {}) {
      const previo = equipos.get(d.id) || {};
      // Un reporte nuevo del teléfono prueba que está vivo, aunque el canal WebSocket esté caído.
      const canal = d.canal_en_vivo ?? previo._canal;
      equipos.set(d.id, { ...previo, ...d, _canal: canal, _canalT: canal !== previo._canal ? Date.now() : previo._canalT });
      pintar(d.id); contadores();
      if (analizar) pedirAnalisis(d.id);
    },
    quitar(id) { equipos.delete(id); tarjetas.get(id)?.remove(); tarjetas.delete(id); contadores(); },
    analizar: (id) => pedirAnalisis(id, true),
  };
  ctx.vivo = vivo;

  const onRealtime = (ev) => {
    const e = ev.detail || {};
    if (e.tipo === "dispositivo" && e.dispositivo) {
      const nuevo = !equipos.has(e.dispositivo.id);
      vivo.upsert(e.dispositivo);
      if (e.evento === "vinculado" && nuevo) toast(`«${e.dispositivo.name}» quedó vinculado`, "ok");
    } else if (e.tipo === "dispositivo_conexion" && equipos.has(e.device_id)) {
      const d = equipos.get(e.device_id);
      d._canal = e.conectado; d._canalT = Date.now();
      if (e.conectado) d.last_seen_at = new Date().toISOString();
      pintar(e.device_id); contadores();
      if (!e.conectado) pedirAnalisis(e.device_id);
    } else if (e.tipo === "dispositivo_comando" && e.comando) {
      avisoComando(e);
      if (["completed", "failed"].includes(e.comando.status)) pedirAnalisis(e.device_id, true);
    }
  };
  ctx.events.addEventListener("realtime", onRealtime);
  // Reloj de la pantalla: «hace X» y En línea/Desconectado cambian aunque no llegue ningún evento.
  const reloj = setInterval(() => { tarjetas.forEach((_, id) => pintar(id)); contadores(); }, 10000);
  // Respaldo si el WebSocket se cae (proxy, antivirus, red): se relee la lista cada 20 s.
  const respaldo = setInterval(async () => {
    try { (await api.get("devices")).forEach((d) => vivo.upsert(d, { analizar: false })); } catch { /* sin red */ }
  }, 20000);
  ctx.onCleanup(() => {
    ctx.events.removeEventListener("realtime", onRealtime); clearInterval(reloj); clearInterval(respaldo);
    analisis.forEach((a) => clearTimeout(a.agenda));
  });

  lista.forEach((d) => pintar(d.id));
  contadores();
  lista.forEach((d) => pedirAnalisis(d.id, true));

  const vincular = h("button", { class: "btn btn-primary" }, icon("mas_simbolo"), "Vincular equipo nuevo");
  vincular.addEventListener("click", () => vincularDialog(ctx));
  const add = h("button", { class: "btn" }, "Registro manual");
  add.addEventListener("click", () => registerDialog(ctx));

  return h("div", { class: "stack" },
    h("header", { class: "page-head" },
      h("div", {}, h("h1", {}, "Dispositivos"), h("p", {}, "Estado en vivo de sus equipos. Ubique, bloquee o borre si se pierden; localizar y bloquear son gratis.")),
      h("div", { class: "row" }, vincular, add)),
    h("section", { class: "grid grid-3" }, pVivo, pPerd, pSin),
    grid, vacio,
    guiaLocalizacion());
}

function avisoComando(e) {
  const c = e.comando, r = c.result || {};
  const nombre = `${CMD[c.kind] || c.kind} en «${e.nombre}»`;
  if (c.status === "delivered") return toast(`${nombre}: el teléfono lo recibió`, "info");
  if (c.status === "failed") return toast(`${nombre}: falló${r.motivo ? ` (${r.motivo})` : ""}`, "error", { timeout: 10000 });
  if (c.status !== "completed") return;
  let extra = "";
  if (c.kind === "ring") extra = r.sonido ? "" : ` (sin sonido: ${r.motivo || "el navegador lo bloqueó"}; se mostró la alerta en pantalla)`;
  if (c.kind === "locate" && r.lat != null) extra = ` (±${r.precision_m} m)`;
  if (r.nota) extra = ` — ${r.nota}`;
  toast(`${nombre}: ejecutado${extra}`, "ok", { timeout: 9000 });
}

function datoRed(i) {
  const partes = [i.red, i.red_calidad && i.red_calidad.toUpperCase(), i.red_mbps != null ? `${i.red_mbps} Mbps` : null].filter(Boolean);
  return partes.length ? partes.join(" · ") : null;
}

function deviceCard(vivo, d, a) {
  const { ctx } = vivo;
  const [label, tone] = STATUS[d.status] || [d.status, "neutral"];
  const reported = ["lost", "stolen"].includes(d.status);
  const online = enLinea(d);
  const i = d.device_info || {};
  const kv = [];
  const par = (k, v) => { if (v !== null && v !== undefined && v !== "") kv.push(h("dt", {}, k), h("dd", {}, v)); };

  par("Conexión", online
    ? `En línea · ${d._canal ? "canal en vivo (órdenes al instante)" : `reporta cada ${d.report_interval_s || 30} s`}`
    : d.last_seen_at ? `Desconectado · última señal ${fmt.ago(d.last_seen_at)}` : "Nunca se ha conectado");
  par("Último reporte", d.last_seen_at ? `${fmt.ago(d.last_seen_at)} (${fmt.time(d.last_seen_at)})` : "nunca");
  par("Batería", d.battery != null ? `${d.battery} %${d.charging ? " · cargando" : ""}`
    : d.gps_status === "https_required" ? "No disponible sin HTTPS (Chrome la bloquea igual que el GPS)" : "—");
  par("GPS", d.tracking_enabled ? (GPS[d.gps_status] || (d.last_seen_at ? "Sin datos" : "—")) : GPS.paused);
  par("Ubicación", d.last_lat != null
    ? h("span", {}, h("a", { href: mapUrl(d.last_lat, d.last_lon), target: "_blank", rel: "noopener noreferrer" },
        `${d.last_lat.toFixed(5)}, ${d.last_lon.toFixed(5)}`),
      d.last_accuracy_m != null ? ` · ±${Math.round(d.last_accuracy_m)} m` : "",
      d.last_fix_at ? ` · ${fmt.ago(d.last_fix_at)}` : "")
    : "Sin ubicación todavía");
  par("Red", datoRed(i));
  if (porNavegador(d)) par("Pestaña", i.pestana_visible === false ? "En segundo plano (puede reportar más lento)"
    : i.pantalla_activa ? "Abierta, con pantalla encendida" : "Abierta");
  par("Equipo", [d.model, i.sistema && `${i.sistema} ${d.os_version || i.version_sistema || ""}`.trim(), i.navegador].filter(Boolean).join(" · ") || null);
  par("Hardware", [i.pantalla && `Pantalla ${i.pantalla}`, i.memoria_gb && `${i.memoria_gb} GB RAM`, i.nucleos && `${i.nucleos} núcleos`].filter(Boolean).join(" · ") || null);
  par("Idioma / zona", [i.idioma, i.zona_horaria].filter(Boolean).join(" · ") || null);
  par("Vinculado", d.created_at ? fmt.date(d.created_at) : null);
  par("IMEI y línea", d.tiene_identificacion ? "Registrados (cifrados)" : "Sin registrar: los necesitará para denunciar y bloquear el equipo");

  const badges = h("div", { class: "row" },
    badge(label, tone),
    d.status !== "wiped" ? badge(online ? "En línea" : "Desconectado", online ? "ok" : "neutral") : null,
    d.status !== "wiped" && !d.tracking_enabled ? badge("Seguimiento pausado", "warn") : null);

  const card = h("article", { class: "panel stack" },
    h("div", { class: "panel-head" },
      h("div", {}, h("h2", {}, d.name), h("p", {}, [d.model, d.platform].filter(Boolean).join(", "))), badges),
    h("dl", { class: "kv" }, kv));
  if (d.status === "wiped") return card;

  if (d.status === "stolen") card.append(h("p", { class: "notice notice-danger" },
    "No intente recuperarlo por su cuenta. Denuncie en adenunciar.policia.gov.co o en la línea 123 y entregue a la Policía la ubicación del historial."));
  if (a) card.append(bloqueAnalisis(a));

  const conectar = d.tracking_enabled
    ? h("button", { class: "btn", disabled: reported, title: reported ? "Un equipo reportado no se puede desconectar" : "",
        onClick: (e) => seguimiento(vivo, d, false, e.currentTarget) }, "Desconectar")
    : h("button", { class: "btn btn-primary", onClick: (e) => seguimiento(vivo, d, true, e.currentTarget) }, "Conectar");
  // «Conectar ahora»: pide al teléfono que reporte ya y reabra su canal en vivo.
  const reconectar = !online || !d._canal
    ? h("button", { class: online ? "btn" : "btn btn-primary", onClick: (e) => reconectarEquipo(ctx, d, e.currentTarget) },
        online ? "Activar canal en vivo" : "Conectar ahora")
    : null;
  const statusBtns = h("div", { class: "row" }, reconectar, conectar,
    reported
      ? h("button", { class: "btn", onClick: (e) => setStatus(vivo, d, "ok", e.currentTarget) }, "Lo recuperé")
      : [h("button", { class: "btn", onClick: (e) => setStatus(vivo, d, "lost", e.currentTarget) }, "Lo perdí"),
         h("button", { class: "btn btn-danger", onClick: (e) => setStatus(vivo, d, "stolen", e.currentTarget) }, "Me lo robaron")]);
  const cmds = h("div", { class: "row" }, ["locate", "ring", "lock", "message", ...(d.status === "lost" || d.status === "stolen" ? ["photo"] : []), "wipe"].map((k) =>
    h("button", { class: `btn btn-sm ${k === "wipe" ? "btn-ghost" : ""}`, onClick: (e) => command(ctx, d, k, e.currentTarget) }, CMD[k])));
  // SOS remoto: el teléfono avisa a los contactos de emergencia por SMS con SU SIM y su ubicación.
  if (!porNavegador(d)) cmds.prepend(h("button", { class: "btn btn-sm btn-danger", onClick: (e) => command(ctx, d, "sos", e.currentTarget) }, CMD.sos));
  const history = h("button", { class: "btn btn-sm btn-ghost", onClick: () => historyDialog(ctx, d) }, "Historial");
  const remove = h("button", { class: "icon-btn", "aria-label": `Eliminar ${d.name}`, onClick: () => removeDevice(ctx, d) }, icon("papelera"));
  const herramientas = h("div", { class: "row" },
    h("button", { class: "btn btn-primary", onClick: () => abrirMapaVivo(ctx, d) }, "Mapa en vivo"),
    h("button", { class: reported ? "btn btn-danger" : "btn", onClick: () => denunciaDialog(ctx, d) },
      reported ? "Preparar denuncia" : "Datos para denuncia"),
    h("button", { class: "btn", onClick: () => identificacionDialog(vivo, d) },
      d.tiene_identificacion ? "Editar IMEI y número" : "Registrar IMEI y número"));
  if (!d.tiene_identificacion) card.append(h("p", { class: "notice notice-warn" },
    "Registre ya el IMEI (marque *#06# en el teléfono) y el número: si se lo roban, ya no podrá consultarlos."));
  card.append(herramientas, statusBtns, h("hr", { class: "divider" }), h("h3", {}, "Acciones remotas"), cmds,
    porNavegador(d) ? h("p", { class: "muted" }, "Vinculado por navegador: las acciones se ejecutan mientras la pestaña de GuardianIA esté abierta en el teléfono. "
      + "«Bloquear» y «Borrar todo» actúan sobre GuardianIA en ese navegador; una página web no puede bloquear ni borrar el sistema del teléfono.") : null,
    h("div", { class: "row row-between" }, history, remove));
  return card;
}

function bloqueAnalisis(a) {
  const [txt, tono] = RIESGO[a.riesgo.nivel] || ["Riesgo", "neutral"];
  const lineas = [a.movimiento?.texto, a.bateria?.texto, a.zona_habitual?.texto,
    a.recorrido_24h_km != null ? `Recorrido en 24 h: ${a.recorrido_24h_km} km (${a.posiciones_24h} posiciones).` : null,
    a.gps?.texto].filter(Boolean);
  return h("section", { class: "resumen-ia stack-sm" },
    h("div", { class: "row row-between" }, h("strong", {}, "Análisis automático"), badge(`${txt} · ${a.riesgo.puntaje}/100`, tono)),
    h("ul", { class: "list" }, lineas.map((t) => h("li", {}, t))),
    a.recomendaciones.length ? h("div", { class: "notice notice-warn" }, h("div", { class: "stack-sm" },
      a.recomendaciones.map((r) => h("span", {}, r)))) : null);
}

async function seguimiento(vivo, d, activo, btn) {
  if (!activo && !(await confirmDialog({ title: `Desconectar ${d.name}`, confirmLabel: "Desconectar",
    message: "El teléfono dejará de enviar su ubicación. Seguirá avisando que está conectado para que pueda reconectarlo desde aquí." }))) return;
  busy(btn, async () => {
    try {
      const r = await vivo.ctx.api.put(`devices/${d.id}/seguimiento`, { activo });
      vivo.upsert(r);
      toast(activo ? "Seguimiento reanudado: el teléfono lo aplicará en su próximo reporte" : "Seguimiento pausado", "ok");
    } catch (e) { toastError(e); }
  });
}

async function setStatus(vivo, d, status, btn) {
  let message = null;
  if (status !== "ok") {
    const ok = await confirmDialog({
      title: status === "stolen" ? "Reportar robo" : "Activar modo perdido",
      message: "El equipo mostrará un aviso de bloqueo, reportará su ubicación cada 15 segundos y no podrá desconectarse.",
      confirmLabel: "Activar", danger: status === "stolen" });
    if (!ok) return;
    message = status === "lost" ? "Este celular está perdido. Si lo encontró, llame al número de contacto." : null;
  }
  busy(btn, async () => {
    try {
      const r = await vivo.ctx.api.put(`devices/${d.id}/status`, { status, message });
      vivo.upsert(r); vivo.analizar(d.id);
      toast(status === "ok" ? "Equipo marcado como recuperado" : "Modo de protección activado", "ok");
    } catch (e) { toastError(e); }
  });
}

async function command(ctx, d, kind, btn) {
  const body = { kind };
  if (kind === "message") {
    const text = await promptDialog({ title: "Mensaje en pantalla", label: "Se mostrará a pantalla completa en el teléfono", minLength: 3, confirmLabel: "Enviar mensaje" });
    if (!text) return;
    body.message = text.slice(0, 200);
  }
  if (kind === "sos") {
    const ok = await confirmDialog({ title: `Enviar SOS desde ${d.name}`, danger: true, confirmLabel: "Enviar SOS ahora",
      message: "El teléfono enviará un SMS de emergencia, con su SIM y su ubicación actual, a todos los contactos de emergencia. "
        + "Úselo si cree que la persona que lo lleva necesita ayuda y no responde. En el teléfono aparecerá un aviso con «Estoy bien» para cancelarlo." });
    if (!ok) return;
    body.confirm_sos = true;
  }
  if (kind === "wipe") {
    const ok = await confirmDialog({ title: `Borrar ${d.name}`, danger: true, confirmLabel: "Borrar definitivamente", typeToConfirm: "BORRAR",
      message: porNavegador(d)
        ? "Se borrarán los datos de GuardianIA en el navegador del teléfono y dejará de poder localizarlo. No se puede deshacer."
        : "Se eliminarán todos los datos del equipo y dejará de poder localizarlo. Úselo solo si no espera recuperarlo. No se puede deshacer." });
    if (!ok) return;
    body.confirm_wipe = true;
  }
  busy(btn, async () => {
    try {
      await ctx.api.post(`devices/${d.id}/commands`, body);
      toast(enLinea(d) ? (d._canal ? `${CMD[kind]}: enviado al teléfono.`
          : `${CMD[kind]}: enviado. Llegará al teléfono en su próximo reporte (≤ ${d.report_interval_s || 30} s).`)
        : `${CMD[kind]}: en cola. El teléfono está desconectado; se ejecutará cuando vuelva a conectarse.`, "ok");
    } catch (e) { toastError(e); }
  });
}

async function reconectarEquipo(ctx, d, btn) {
  busy(btn, async () => {
    try {
      const r = await ctx.api.post(`devices/${d.id}/conectar`, {});
      toast(r.mensaje, r.en_vivo ? "ok" : "info", { timeout: 9000 });
    } catch (e) { toastError(e); }
  });
}

// Todas las formas reales de ubicar un teléfono, sin vender humo: qué puede la app y qué es del operador.
function guiaLocalizacion() {
  const fila = (metodo, puede, nota) => h("tr", {},
    h("td", {}, h("strong", {}, metodo)),
    h("td", {}, badge(puede ? "Sí" : "No", puede ? "ok" : "neutral")),
    h("td", { class: "muted" }, nota));
  return h("details", { class: "panel" },
    h("summary", {}, h("strong", {}, "Cómo ubicar un teléfono (y qué es cierto de cada método)")),
    h("p", { class: "muted" },
      "Hay muchas ideas falsas sobre «rastrear un celular». Esto es lo que de verdad se puede:"),
    h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", {}, h("tr", {}, ["Método", "¿La app?", "Realidad"].map((t) => h("th", {}, t)))),
      h("tbody", {},
        fila("GPS por navegador", true, "Lo que usa GuardianIA. Preciso y en vivo mientras el teléfono tenga internet y la pestaña abierta."),
        fila("GPS en segundo plano", false, "Necesita una app nativa instalada con permiso «siempre»."),
        fila("Por número de teléfono", false, "Nadie ubica un celular «con solo el número», salvo el operador con orden judicial."),
        fila("Por IMEI", false, "Sirve para que el operador o la policía bloqueen el equipo. Puede denunciar el IMEI, no rastrearlo usted."),
        fila("Por antenas de red", false, "Solo el operador sabe a qué antena está conectado. Se pide con denuncia formal.")))),
    h("div", { class: "notice notice-info" },
      h("strong", {}, "Si se lo roban: "),
      "Marque el teléfono como perdido y vea su última ubicación aquí. Denuncie en el 123 o en "
      + "adenunciar.policia.gov.co con la ubicación del historial, y bloquee el IMEI ante su operador "
      + "(lo ve marcando *#06#; anótelo mientras tenga el teléfono). No intente recuperarlo por su cuenta."));
}

async function historyDialog(ctx, d) {
  const body = h("div", { class: "stack" }, h("div", { class: "skeleton" }, h("span", {}), h("span", {})));
  dialog({ title: `Historial de ${d.name}`, body, wide: true, actions: [{ label: "Cerrar", kind: "primary" }] });
  try {
    const [cmds, locs] = await Promise.all([ctx.api.get(`devices/${d.id}/commands`), ctx.api.get(`devices/${d.id}/locations`, { query: { hours: 72 } })]);
    mount(body,
      h("h3", {}, "Ubicaciones (72 h)"),
      locs.puntos.length ? h("div", { class: "table-wrap" }, h("table", { class: "table" },
        h("thead", {}, h("tr", {}, h("th", {}, "Hora"), h("th", {}, "Precisión"), h("th", {}, ""))),
        h("tbody", {}, locs.puntos.slice(-30).reverse().map((p) => h("tr", {}, h("td", {}, fmt.date(p.t)),
          h("td", {}, p.precision_m != null ? `${Math.round(p.precision_m)} m` : "—"),
          h("td", {}, h("a", { href: mapUrl(p.lat, p.lon), target: "_blank", rel: "noopener noreferrer" }, "Mapa"))))))) : h("p", { class: "muted" }, "Sin ubicaciones en este período."),
      h("p", { class: "muted" }, `Las ubicaciones se borran automáticamente a los ${locs.retencion_dias} días.`),
      h("h3", {}, "Fotos del intruso"),
      galeriaFotos(ctx, d),
      h("h3", {}, "Acciones enviadas"),
      cmds.length ? h("ul", { class: "list" }, cmds.map((c) => h("li", {}, h("div", { class: "list-main" }, h("p", { class: "list-title" }, CMD[c.kind]), h("p", { class: "list-sub" }, fmt.date(c.created_at))),
        badge(CMD_STATUS[c.status] || c.status, c.status === "completed" ? "ok" : c.status === "failed" ? "danger" : "neutral")))) : h("p", { class: "muted" }, "Sin acciones."));
  } catch (e) { mount(body, h("p", {}, e.message)); }
}

// Fotos de la cámara frontal (app Android, solo con el equipo reportado). Se piden con la sesión y se
// muestran desde un blob: la URL nunca lleva el token y el navegador no las guarda en caché.
function galeriaFotos(ctx, d) {
  const cont = h("div", { class: "row" }, h("p", { class: "muted" }, "Cargando…"));
  ctx.api.get(`devices/${d.id}/fotos`).then(async (fotos) => {
    if (!fotos.length) {
      mount(cont, h("p", { class: "muted" }, "Sin fotos. Con el equipo reportado, use «Foto del intruso»."));
      return;
    }
    const figuras = [];
    for (const f of fotos.slice(0, 12)) {
      try {
        const res = await ctx.api.get(f.url, { rawResponse: true });
        if (!res.ok) continue;
        const img = h("img", { src: URL.createObjectURL(await res.blob()), alt: `Foto del ${fmt.date(f.creada)}`, class: "foto-intruso" });
        figuras.push(h("figure", {}, img, h("figcaption", { class: "muted" }, fmt.date(f.creada))));
      } catch { /* una foto dañada no impide ver las demás */ }
    }
    mount(cont, figuras.length ? figuras : h("p", { class: "muted" }, "No se pudieron cargar las fotos."));
  }).catch((e) => mount(cont, h("p", { class: "muted" }, errorText(e))));
  return cont;
}

async function removeDevice(ctx, d) {
  if (!(await confirmDialog({ title: `Eliminar ${d.name}`, message: "Dejará de estar protegido y se borrará su historial.", confirmLabel: "Eliminar", danger: true }))) return;
  try { await ctx.api.del(`devices/${d.id}`); toast("Dispositivo eliminado", "ok"); ctx.vivo?.quitar(d.id); } catch (e) { toastError(e); }
}

function registerDialog(ctx) {
  const form = h("form", { class: "form" },
    field("Nombre", h("input", { class: "input", name: "name", required: true, placeholder: "Celular de mamá" })),
    h("div", { class: "form-row" },
      field("Sistema", h("select", { class: "input", name: "platform" }, [["android", "Android"], ["ios", "iOS"], ["windows", "Windows"], ["other", "Otro"]].map(([v, l]) => h("option", { value: v }, l)))),
      field("Modelo", h("input", { class: "input", name: "model", placeholder: "Moto G84" }))));
  dialog({
    title: "Registrar dispositivo", body: h("div", { class: "stack" },
      h("p", { class: "muted" }, "Normalmente la app Android registra el equipo sola. Use esto para vincular un agente instalado manualmente."), form),
    actions: [{ label: "Cancelar" }, { label: "Registrar", kind: "primary", onClick: async (close) => {
      if (!form.reportValidity()) return false;
      try {
        const r = await ctx.api.post("devices", { name: form.elements.namedItem("name").value.trim(), platform: form.elements.namedItem("platform").value, model: form.elements.namedItem("model").value.trim() || null });
        close();
        showToken(r.device_token);
        ctx.refresh();
      } catch (e) { toastError(e); }
      return false;
    } }],
  });
}

function showToken(token) {
  const code = h("p", { class: "mono panel" }, token);
  const copy = h("button", { class: "btn", onClick: async () => { await navigator.clipboard.writeText(token); toast("Copiado", "ok"); } }, icon("copiar"), "Copiar");
  dialog({ title: "Token del dispositivo", body: h("div", { class: "stack" },
    h("p", { class: "notice notice-warn" }, "Se muestra una sola vez. Configúrelo en el agente del equipo y no lo comparta: permite reportar como ese dispositivo."),
    code, copy), actions: [{ label: "Ya lo guardé", kind: "primary" }] });
}


// ───────────────────────────── vinculación sin copiar tokens
// Pedirle a alguien que copie un token de 43 caracteres entre el navegador y una terminal es donde
// la mayoría abandona. Un código de 6 dígitos (o un QR) hace lo mismo sin fricción, y el token
// viaja solo entre el equipo nuevo y el servidor.
function vincularDialog(ctx) {
  const cuerpo = h("div", { class: "stack" }, h("div", { class: "skeleton" }, h("span", {}), h("span", {})));
  let temporizador = null;
  const dlg = dialog({
    title: "Vincular equipo nuevo", wide: true, body: cuerpo,
    actions: [{ label: "Listo", kind: "primary" }],
    onClose: () => clearInterval(temporizador),
  });

  (async () => {
    let datos;
    try {
      datos = await ctx.api.post("devices/vinculacion", {});
    } catch (e) {
      return mount(cuerpo, h("p", { class: "notice notice-warn" }, errorText(e)));
    }
    const restante = h("span", { class: "muted" });
    const vence = new Date(datos.expira).getTime();
    const tic = () => {
      const s = Math.max(0, Math.round((vence - Date.now()) / 1000));
      restante.textContent = s ? `Vence en ${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`
                               : "El código venció. Cierre y vuelva a abrir para generar otro.";
      if (!s) clearInterval(temporizador);
    };
    temporizador = setInterval(tic, 1000);
    tic();

    const copiar = h("button", { class: "btn btn-sm" }, icon("copiar"), "Copiar código");
    copiar.addEventListener("click", async () => {
      await navigator.clipboard.writeText(datos.codigo);
      toast("Código copiado", "ok");
    });

    mount(cuerpo,
      h("div", { class: "vincular" },
        h("div", { class: "stack" },
          h("p", { class: "codigo-grande" }, datos.codigo.replace(/(\d{3})(\d{3})/, "$1 $2")),
          h("div", { class: "row" }, copiar, restante)),
        datos.qr ? h("img", { src: datos.qr, alt: "Código QR para vincular", class: "qr" }) : null),
      h("div", { class: "stack" },
        h("h3", {}, "Escanee el QR con el celular (sin instalar nada)"),
        h("ol", {},
          h("li", {}, "Abra la cámara del teléfono y apunte al QR de arriba."),
          h("li", {}, "Toque el enlace que aparece: abre una página web de GuardianIA en el navegador."),
          h("li", {}, "Escriba un nombre para el teléfono y acepte el permiso de ubicación."),
          h("li", {}, "Listo: el teléfono queda vinculado y empieza a reportar su ubicación.")),
        datos.misma_red === false
          ? h("p", { class: "notice notice-warn" }, "Aviso: no detecté la IP de este PC en la red WiFi, así que el "
            + "QR podría no abrir desde el celular. Asegúrese de que el PC esté conectado a un WiFi (no solo por "
            + "cable con red restringida) y de que el teléfono use ese mismo WiFi.")
          : h("p", { class: "muted" }, `El teléfono abrirá: ${datos.url_movil}. El PC y el celular deben estar en `
            + "el mismo WiFi. El código sirve una vez y vence en " + `${datos.vigencia_minutos} minutos.`),
        h("p", { class: "muted" }, "Honesto: una página web ubica el teléfono mientras esa pestaña esté abierta. "
          + "Para rastreo en segundo plano haría falta una app instalada; esta forma funciona ya, sin instalar nada.")));
  })();
}


// ───────────────────────────── IMEI, número y denuncia
// Ni una página web ni una app normal pueden leer el IMEI en Android 10+: lo escribe el dueño una vez,
// con el teléfono en la mano (*#06#), y se guarda cifrado. Es el dato que pide el operador para bloquearlo.
async function identificacionDialog(vivo, d) {
  const { ctx } = vivo;
  let datos = {};
  try { datos = await ctx.api.get(`devices/${d.id}/identificacion`); } catch (e) { return toastError(e); }
  const inp = (name, props) => h("input", { class: "input", name, value: datos[name] || "", ...props });
  const form = h("form", { class: "form" },
    h("p", { class: "notice" }, "En el teléfono abra el marcador y escriba *#06#. Aparece el IMEI (dos, si tiene doble SIM)."),
    field("IMEI 1", inp("imei", { required: true, inputmode: "numeric", maxlength: 17, placeholder: "15 dígitos" })),
    field("IMEI 2 (opcional)", inp("imei2", { inputmode: "numeric", maxlength: 17 })),
    h("div", { class: "form-row" },
      field("Número de la línea", inp("numero", { inputmode: "tel", placeholder: "300 123 4567" })),
      field("Operador", h("select", { class: "input", name: "operador" },
        h("option", { value: "" }, "—"),
        ["Claro", "Movistar", "Tigo", "WOM", "ETB", "Virgin", "Otro"].map((o) =>
          h("option", { value: o, selected: datos.operador === o }, o))))),
    h("div", { class: "form-row" },
      field("Color", inp("color", { maxlength: 40, placeholder: "Negro" })),
      field("Señas", inp("senas", { maxlength: 200, placeholder: "Forro azul, rayón en la esquina" }))),
    h("p", { class: "muted" }, "Se guarda cifrado (AES-256) y solo usted lo ve. No se envía a nadie."));
  dialog({
    title: `IMEI y número de ${d.name}`, body: form, wide: true,
    actions: [{ label: "Cancelar" }, { label: "Guardar", kind: "primary", onClick: async (close) => {
      if (!form.reportValidity()) return false;
      const v = (n) => form.elements.namedItem(n).value.trim() || null;
      try {
        await ctx.api.put(`devices/${d.id}/identificacion`, {
          imei: v("imei"), imei2: v("imei2"), numero: v("numero"), operador: v("operador"), color: v("color"), senas: v("senas") });
        vivo.upsert({ ...d, tiene_identificacion: true }, { analizar: false });
        toast("Datos guardados y cifrados", "ok");
        close();
      } catch (e) { toastError(e); }
      return false;
    } }],
  });
}

async function denunciaDialog(ctx, d) {
  const cuerpo = h("div", { class: "stack" }, h("div", { class: "skeleton" }, h("span", {}), h("span", {})));
  dialog({ title: `Denuncia · ${d.name}`, body: cuerpo, wide: true, actions: [{ label: "Cerrar", kind: "primary" }] });
  let x;
  try { x = await ctx.api.get(`devices/${d.id}/denuncia`); } catch (e) { return mount(cuerpo, h("p", {}, errorText(e))); }
  const texto = h("textarea", { class: "input denuncia-texto", readonly: true }, x.texto);
  const copiar = h("button", { class: "btn btn-primary", onClick: async () => {
    await navigator.clipboard.writeText(x.texto); toast("Resumen copiado: péguelo en la denuncia", "ok"); } }, icon("copiar"), "Copiar resumen");
  const u = x.ultima_ubicacion;
  mount(cuerpo,
    x.faltan.length ? h("p", { class: "notice notice-warn" },
      `Falta registrar: ${x.faltan.join(", ")}. Sin el IMEI el operador no puede bloquear el equipo.`) : null,
    u ? h("div", { class: "row" },
      h("a", { class: "btn", href: u.google_maps, target: "_blank", rel: "noopener noreferrer" }, "Última ubicación en Google Maps"),
      h("button", { class: "btn", onClick: () => abrirMapaVivo(ctx, d) }, "Mapa en vivo")) : null,
    h("h3", {}, "Resumen para la denuncia"), texto, h("div", { class: "row" }, copiar),
    h("h3", {}, "Qué hacer, en orden"),
    h("ol", { class: "stack-sm" }, x.pasos.map((p) => h("li", {},
      h("strong", {}, p.titulo), ": ", p.detalle,
      p.url ? h("span", {}, " ", h("a", { href: p.url, target: "_blank", rel: "noopener noreferrer" }, "Abrir")) : null))));
}
