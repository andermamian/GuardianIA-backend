// Construcción de interfaz sin innerHTML: todo dato del servidor entra como texto.
// Esto, sumado a la CSP sin 'unsafe-inline', cierra la puerta al XSS aunque un nombre de archivo o
// un mensaje del asistente contenga <script>.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k === "class") el.className = v;
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "href") el.setAttribute("href", safeUrl(v));
    // Estilos por CSSOM: la CSP (style-src 'self') bloquea el atributo style="…", pero no el.style.
    else if (k === "style") { if (typeof v === "string") el.style.cssText = v; else Object.assign(el.style, v); }
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, String(v));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export function safeUrl(url) {
  // Enlaces de fuentes del asistente u otros datos externos: solo http(s), rutas propias y otpauth.
  try {
    const u = new URL(url, location.origin);
    return ["http:", "https:", "otpauth:", "tel:"].includes(u.protocol) ? u.href : "#";
  } catch {
    return "#";
  }
}

export function mount(target, ...children) {
  target.replaceChildren();
  append(target, children);
}

// --------------------------------------------------------------- íconos
// Trazos propios en SVG (constantes del código, nunca datos del servidor).
const PATHS = {
  inicio: "M3 11 12 4l9 7v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z",
  salud: "M3 12h4l2-5 4 10 2-5h6",
  emergencia: "M12 3 2 20h20L12 3zm0 6v5m0 3v.5",
  dispositivos: "M8 2h8a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zm3 17h2",
  boveda: "M5 10V7a7 7 0 0 1 14 0v3M4 10h16v11H4zM12 14v3",
  proteccion: "M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3zm-3 10 2 2 4-4",
  asistente: "M4 5h16v11H9l-5 4zM8 10h.01M12 10h.01M16 10h.01",
  cuenta: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm-8 9a8 8 0 0 1 16 0",
  mas: "M5 12h.01M12 12h.01M19 12h.01",
  campana: "M6 17V11a6 6 0 0 1 12 0v6l2 2H4zM10 21h4",
  salir: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10",
  mas_simbolo: "M12 5v14M5 12h14",
  cerrar: "M6 6l12 12M18 6 6 18",
  bluetooth: "M7 7l10 10-5 4V3l5 4L7 17",
  ubicacion: "M12 22s7-6.2 7-12a7 7 0 0 0-14 0c0 5.8 7 12 7 12zm0-9a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
  archivo: "M6 2h8l4 4v16H6zM14 2v4h4",
  llave: "M14 10a4 4 0 1 0-3.5 4L4 20v2h3v-2h2v-2h2l1.5-1.5A4 4 0 0 0 14 10z",
  usuarios: "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21a7 7 0 0 1 14 0M16 3a4 4 0 0 1 0 8M22 21a7 7 0 0 0-5-6.7",
  alerta: "M12 8v5m0 3v.5M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  bitacora: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
  ajustes: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm7.4-3a7.4 7.4 0 0 0-.1-1.3l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2.2-1.3L14.3 3h-4l-.4 2.5a7 7 0 0 0-2.2 1.3l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.6l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2.2 1.3l.4 2.5h4l.4-2.5a7 7 0 0 0 2.2-1.3l2.4 1 2-3.4-2-1.6c.1-.4.1-.9.1-1.3z",
  servidor: "M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01",
  check: "M5 12l5 5L20 7",
  subir: "M12 16V4m-5 5 5-5 5 5M4 20h16",
  bajar: "M12 4v12m-5-5 5 5 5-5M4 20h16",
  papelera: "M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14",
  copiar: "M9 9h11v11H9zM5 15H4V4h11v1",
  ojo: "M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
};

export function icon(name, { size = 20, label } = {}) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.classList.add("icon");
  if (label) {
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label);
  } else svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", PATHS[name] || PATHS.mas);
  svg.append(path);
  return svg;
}

// ------------------------------------------------------------- avisos
let toastHost;
export function toast(message, kind = "info", { timeout = 5000 } = {}) {
  if (!toastHost) {
    toastHost = h("div", { class: "toasts", role: "status", "aria-live": "polite" });
    document.body.append(toastHost);
  }
  const el = h("div", { class: `toast toast-${kind}` }, message);
  toastHost.append(el);
  while (toastHost.childElementCount > 4) toastHost.firstElementChild.remove(); // nunca tapar la pantalla
  setTimeout(() => el.remove(), timeout);
}

export function errorText(err) {
  if (err?.fields?.length) return err.fields.map((f) => (f.campo ? `${f.campo}: ${f.error}` : f.error)).join("; ");
  if (err?.extra?.problemas) return err.extra.problemas.join("; ");
  // En desarrollo el servidor adjunta la causa real de un 500: mostrarla evita adivinar.
  // En producción nunca llega, así que el usuario solo ve el mensaje neutro.
  if (err?.extra?.detalle) return `${err.extra.detalle}${err.extra.donde ? ` (${err.extra.donde})` : ""}`;
  return err?.message || "No se pudo completar la acción";
}

export function toastError(err) {
  toast(errorText(err), "error", { timeout: 8000 });
}

// ----------------------------------------------------------- diálogos
// <dialog> nativo: foco atrapado, Esc para cerrar y lectores de pantalla sin librerías.
export function dialog({ title, body, actions = [], onClose, wide = false }) {
  const dlg = h("dialog", { class: wide ? "dialog dialog-wide" : "dialog", "aria-labelledby": "dlg-title" });
  const close = (value) => {
    dlg.close();
    dlg.remove();
    onClose?.(value);
  };
  const footer = h("div", { class: "dialog-actions" },
    actions.map((a) => h("button", {
      type: a.submit ? "submit" : "button",
      class: `btn ${a.kind ? "btn-" + a.kind : ""}`,
      onClick: a.submit ? null : async () => {
        if (a.onClick) {
          const keep = await a.onClick(close);
          if (keep === false) return;
        }
        if (!a.submit) close(a.value);
      },
    }, a.label)));
  dlg.append(
    h("header", { class: "dialog-head" },
      h("h2", { id: "dlg-title" }, title),
      h("button", { type: "button", class: "icon-btn", "aria-label": "Cerrar", onClick: () => close(null) }, icon("cerrar"))),
    h("div", { class: "dialog-body" }, body), footer);
  dlg.addEventListener("cancel", (e) => { e.preventDefault(); close(null); });
  document.body.append(dlg);
  dlg.showModal();
  return { el: dlg, close };
}

export function confirmDialog({ title, message, confirmLabel = "Confirmar", danger = false, typeToConfirm }) {
  return new Promise((resolve) => {
    const input = typeToConfirm ? h("input", { class: "input", autocomplete: "off", "aria-label": `Escriba ${typeToConfirm}` }) : null;
    const body = h("div", {}, h("p", {}, message),
      typeToConfirm ? h("label", { class: "field" }, h("span", {}, `Para confirmar, escriba ${typeToConfirm}`), input) : null);
    dialog({
      title, body,
      actions: [
        { label: "Cancelar", value: false },
        { label: confirmLabel, kind: danger ? "danger" : "primary", value: true,
          onClick: () => (typeToConfirm && input.value.trim() !== typeToConfirm ? (input.focus(), false) : true) },
      ],
      onClose: (v) => resolve(Boolean(v)),
    });
    input?.focus();
  });
}

export function promptDialog({ title, label, placeholder = "", minLength = 3, confirmLabel = "Aceptar" }) {
  return new Promise((resolve) => {
    const input = h("textarea", { class: "input", rows: 3, placeholder, minlength: minLength });
    dialog({
      title,
      body: h("label", { class: "field" }, h("span", {}, label), input),
      actions: [
        { label: "Cancelar", value: null },
        { label: confirmLabel, kind: "primary", onClick: (close) => {
          if (input.value.trim().length < minLength) { input.focus(); return false; }
          close(input.value.trim());
          return false;
        } },
      ],
      onClose: (v) => resolve(v ?? null),
    });
    input.focus();
  });
}

// ------------------------------------------------------------ formularios
export function formData(form) {
  const out = {};
  for (const el of form.elements) {
    if (!el.name || el.disabled) continue;
    if (el.type === "checkbox") out[el.name] = el.checked;
    else if (el.type === "number" || el.dataset.number !== undefined) out[el.name] = el.value === "" ? null : Number(el.value);
    else if (el.type === "radio") { if (el.checked) out[el.name] = el.value; }
    else out[el.name] = el.value.trim() === "" ? null : el.value.trim();
  }
  return out;
}

export function field(label, control, hint) {
  return h("label", { class: "field" }, h("span", { class: "field-label" }, label), control,
    hint ? h("small", { class: "field-hint" }, hint) : null);
}

export async function busy(button, fn) {
  // Evita doble envío (dos SOS, dos pagos, dos borrados) y da retroalimentación inmediata.
  if (button.disabled) return;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    return await fn();
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

// ---------------------------------------------------------------- formato
const TZ = "America/Bogota";
const dtf = new Intl.DateTimeFormat("es-CO", { dateStyle: "medium", timeStyle: "short", timeZone: TZ });
const tf = new Intl.DateTimeFormat("es-CO", { hour: "2-digit", minute: "2-digit", timeZone: TZ });
const rtf = new Intl.RelativeTimeFormat("es", { numeric: "auto" });

export const fmt = {
  date: (v) => (v ? dtf.format(new Date(v)) : "—"),
  time: (v) => (v ? tf.format(new Date(v)) : "—"),
  ago(v) {
    if (!v) return "nunca";
    const s = (new Date(v).getTime() - Date.now()) / 1000;
    const units = [["year", 31536000], ["month", 2592000], ["day", 86400], ["hour", 3600], ["minute", 60]];
    for (const [u, secs] of units) if (Math.abs(s) >= secs) return rtf.format(Math.round(s / secs), u);
    return "hace un momento";
  },
  bytes(n) {
    if (n == null) return "—";
    const u = ["B", "KB", "MB", "GB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
  },
  num: (n, d = 0) => (n == null ? "—" : new Intl.NumberFormat("es-CO", { maximumFractionDigits: d }).format(n)),
};

export function badge(text, tone = "neutral") {
  return h("span", { class: `badge badge-${tone}` }, text);
}

export const SEVERITY_TONE = { info: "neutral", low: "neutral", medium: "warn", high: "danger", critical: "critical" };
export const SEVERITY_LABEL = { info: "Informativa", low: "Baja", medium: "Media", high: "Alta", critical: "Crítica" };

export function emptyState(title, text, action) {
  return h("div", { class: "empty" }, h("p", { class: "empty-title" }, title), text ? h("p", {}, text) : null, action || null);
}

export function skeleton(lines = 3) {
  return h("div", { class: "skeleton", "aria-busy": "true", "aria-label": "Cargando" },
    Array.from({ length: lines }, () => h("span", {})));
}

// ------------------------------------------------------- texto con código
// El modelo devuelve markdown ligero: bloques ``` y algo de **negrita**. Se arma con nodos de texto
// (nunca innerHTML), así que un bloque que contenga <script> se ve como texto y no se ejecuta.
const CERCA = /```([\w+#-]*)\n?([\s\S]*?)```/g;

export function richText(texto, opciones = {}) {
  const frag = document.createDocumentFragment();
  let ultimo = 0;
  for (const m of String(texto ?? "").matchAll(CERCA)) {
    if (m.index > ultimo) frag.append(...parrafos(texto.slice(ultimo, m.index), opciones));
    frag.append(codeBlock(m[2].replace(/\n$/, ""), m[1], opciones));
    ultimo = m.index + m[0].length;
  }
  const resto = texto.slice(ultimo);
  if (resto.trim()) frag.append(...parrafos(resto, opciones));
  return frag;
}

// Señales de que un bloque es código aunque el modelo olvidara las comillas triples. Sin esto,
// una respuesta con HTML o PHP se ve como un párrafo corrido e ilegible (y con las etiquetas
// mezcladas en el texto), que es justo lo que pasaba.
const PISTAS_CODIGO = [
  /<\?php|<!DOCTYPE|<\/?[a-z][\w-]*\s*[^>]*>/i,
  /\b(function|const|let|var|def|class|import|from|public|private|return|foreach|SELECT|INSERT|UPDATE)\b/,
  /[{};]\s*$/m,
  /^\s*(#|\/\/|<!--)/m,
  /\$\w+|=>|->|::|\breturn\b/,
];

export function pareceCodigo(texto) {
  const t = texto.trim();
  if (t.length < 40) return false;
  const señales = PISTAS_CODIGO.filter((r) => r.test(t)).length;
  const lineas = t.split("\n");
  const conSangria = lineas.filter((l) => /^\s{2,}|\t/.test(l)).length;
  // Dos señales fuertes, o una más sangría/varias líneas cortas típicas de código.
  return señales >= 3 || (señales >= 2 && (conSangria > 0 || lineas.length > 3));
}

function idiomaProbable(texto) {
  if (/<\?php/.test(texto)) return "php";
  if (/<!DOCTYPE|<html|<div|<section/i.test(texto)) return "html";
  if (/\bdef |\bimport \w+|print\(/.test(texto)) return "python";
  if (/\bfunction\b|=>|console\.log/.test(texto)) return "javascript";
  if (/\bSELECT\b|\bINSERT\b/i.test(texto)) return "sql";
  return "";
}

function parrafos(texto, opciones = {}) {
  return texto.split(/\n{2,}/).filter((t) => t.trim()).map((t) => {
    const limpio = t.trim();
    return pareceCodigo(limpio) ? codeBlock(limpio, idiomaProbable(limpio), opciones) : h("p", { class: "msg-parrafo" }, limpio);
  });
}

// `opciones.ejecutar(codigo, lenguaje, panel, boton)`: si viene y el lenguaje se puede probar, aparece «▶ Ejecutar».
export function codeBlock(codigo, lenguaje = "", opciones = {}) {
  const copiar = h("button", { class: "btn btn-sm", type: "button" }, icon("copiar"), "Copiar");
  copiar.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(codigo);
      copiar.replaceChildren(icon("check"), document.createTextNode("Copiado"));
      setTimeout(() => copiar.replaceChildren(icon("copiar"), document.createTextNode("Copiar")), 2000);
    } catch {
      toast("El navegador no permitió copiar; seleccione el texto a mano", "error");
    }
  });
  const panel = h("div", { class: "sandbox-panel", hidden: true });
  const probar = opciones.ejecutar && opciones.puedeEjecutar?.(lenguaje, codigo)
    ? h("button", { class: "btn btn-sm btn-ejecutar", type: "button", title: "Probar en el sandbox" }, "▶ Ejecutar") : null;
  probar?.addEventListener("click", () => {
    probar.disabled = true;
    opciones.ejecutar(codigo, lenguaje, panel, () => { probar.disabled = false; });
  });
  return h("figure", { class: "code" },
    h("figcaption", { class: "code-head" },
      h("span", {}, lenguaje || "código"),
      h("span", { class: "muted" }, `${codigo.split("\n").length} líneas`), probar, copiar),
    h("pre", {}, h("code", {}, codigo)), panel);
}
