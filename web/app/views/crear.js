import { badge, busy, emptyState, fmt, h, icon, mount, toast, toastError } from "../../shared/dom.js";

const TIPOS = [
  ["docx", "Documento Word", "Informes, cartas, guías, planes de clase"],
  ["xlsx", "Hoja de Excel", "Tablas con fórmulas y gráfico incluido"],
  ["pptx", "Presentación", "Diapositivas con notas del expositor"],
  ["pdf", "PDF", "Documento listo para imprimir o enviar"],
  ["grafico", "Gráfico", "Barras, líneas o torta en PNG"],
  ["imagen", "Imagen o QR", "Tarjeta con texto o código QR"],
  ["musica", "Música (MIDI)", "Melodía corta que puede editar"],
  ["codigo", "Código", "Script con la sintaxis verificada"],
  ["csv", "CSV", "Datos para abrir en cualquier programa"],
  ["md", "Markdown", "Texto con formato, ideal para GitHub"],
  ["video", "Video", "Presentación animada en MP4"],
  ["zip", "Proyecto en ZIP", "Carpetas y archivos de código ordenados"],
];

const EJEMPLOS = {
  docx: "Plan de clase de matemáticas para segundo grado, tema sumas llevando, con objetivos y actividades",
  xlsx: "Planilla de notas de 10 estudiantes con tres cortes y promedio automático",
  pptx: "Presentación de 6 diapositivas para sustentar GuardianIA ante un jurado",
  pdf: "Circular para padres de familia sobre el uso seguro del celular",
  grafico: "Gráfico de barras con las notas promedio de enero a junio",
  imagen: "Código QR con el enlace de mi aula virtual",
  musica: "Melodía alegre en do mayor para la entrada de la clase",
  codigo: "Script en Python que renombre fotos por su fecha",
  csv: "Lista de útiles escolares con cantidad y precio",
  md: "Guía rápida de instalación de GuardianIA",
  video: "Video de 5 escenas explicando qué es el phishing",
  zip: "Proyecto en Python de una calculadora con carpeta src, pruebas y README",
};

export default async function crear(ctx) {
  const caps = await ctx.api.get("estudio/capacidades");
  const disponibles = TIPOS.filter(([id]) => caps.tipos[id]);
  let tipo = disponibles[0]?.[0] || "docx";

  const instruccion = h("textarea", { class: "input", rows: 4, maxlength: 4000,
    placeholder: EJEMPLOS[tipo], "aria-label": "Qué quiere crear" });
  const crearBtn = h("button", { class: "btn btn-primary", type: "submit" }, icon("mas_simbolo"), "Crear");
  const resultado = h("div", { "aria-live": "polite" });
  const listaEl = h("div", {});

  const selector = h("div", { class: "grid grid-3" }, disponibles.map(([id, titulo, sub]) => {
    const tarjeta = h("button", { type: "button", class: "panel stat", "aria-pressed": String(id === tipo),
      dataset: { tipo: id } },
      h("span", { class: "stat-label" }, titulo), h("span", {}, sub));
    tarjeta.addEventListener("click", () => {
      tipo = id;
      selector.querySelectorAll("[data-tipo]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.tipo === id)));
      instruccion.placeholder = EJEMPLOS[id] || "Describa lo que necesita";
      instruccion.focus();
    });
    return tarjeta;
  }));

  const form = h("form", { class: "form" },
    h("label", { class: "field" }, h("span", { class: "field-label" }, "Descríbalo con sus palabras"), instruccion),
    h("div", { class: "row row-between" },
      h("span", { class: "muted" }, caps.modelo === "ninguno"
        ? "Sin modelo conectado: se generará una versión básica que usted puede editar."
        : `Redactado con el modelo ${caps.modelo === "anthropic" ? "en la nube" : "local"}.`),
      crearBtn));

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const texto = instruccion.value.trim();
    if (texto.length < 4) return instruccion.focus();
    busy(crearBtn, async () => {
      mount(resultado, h("div", { class: "panel stack" },
        h("p", {}, "Creando el archivo…"),
        h("p", { class: "muted" }, caps.modelo === "ninguno" ? "" : "El modelo está redactando el contenido; puede tardar."),
        h("div", { class: "skeleton" }, h("span", {}), h("span", {}))));
      try {
        const r = await ctx.api.post("estudio/crear", { instruccion: texto, tipo }, { timeout: 300000 });
        mostrar(r);
        cargarLista();
      } catch (err) {
        mount(resultado);
        toastError(err);
      }
    });
  });

  function mostrar(r) {
    const descargar = h("button", { class: "btn btn-primary" }, icon("bajar"), "Descargar");
    descargar.addEventListener("click", () => busy(descargar, async () => {
      try { await ctx.api.download(r.descarga, r.nombre); } catch (e) { toastError(e); }
    }));
    mount(resultado, h("section", { class: "panel stack" },
      h("div", { class: "panel-head" },
        h("div", {}, h("h2", {}, r.nombre), h("p", {}, r.resumen)),
        badge(r.plan_de === "modelo" ? "Redactado por la IA" : "Versión básica", r.plan_de === "modelo" ? "ok" : "warn")),
      r.plan_de === "reglas" && caps.modelo !== "ninguno"
        ? h("p", { class: "notice notice-warn" }, "El modelo no devolvió un plan válido, así que se creó una versión "
          + "básica con su texto. Reintente o use una instrucción más concreta.")
        : null,
      h("p", { class: "muted" }, `${fmt.bytes(r.bytes)} · guardado cifrado en su bóveda`),
      h("div", { class: "row" }, descargar,
        h("a", { class: "btn", href: "#/boveda/archivos" }, "Ver en la bóveda"))));
  }

  async function cargarLista() {
    try {
      const creaciones = await ctx.api.get("estudio/creaciones", { query: { limit: 20 } });
      mount(listaEl, creaciones.length
        ? h("ul", { class: "list" }, creaciones.map((c) => {
          const btn = h("button", { class: "icon-btn", "aria-label": `Descargar ${c.nombre}` }, icon("bajar"));
          btn.addEventListener("click", () => busy(btn, async () => {
            try { await ctx.api.download(c.descarga, c.nombre); } catch (e) { toastError(e); }
          }));
          return h("li", {}, icon("archivo"),
            h("div", { class: "list-main" }, h("p", { class: "list-title" }, c.nombre),
              h("p", { class: "list-sub" }, `${fmt.bytes(c.bytes)} · ${fmt.ago(c.creado)}`)), btn);
        }))
        : emptyState("Nada creado todavía", "Lo que genere aparecerá aquí y en su bóveda."));
    } catch (e) { toastError(e); }
  }

  cargarLista();
  const faltantes = TIPOS.filter(([id]) => !caps.tipos[id]).map(([, t]) => t);

  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, "Crear"),
      h("p", {}, "Describa lo que necesita y GuardianIA lo arma como archivo real, listo para abrir en "
        + "Word, Excel, PowerPoint o el programa que corresponda. Queda cifrado en su bóveda."))),
    h("section", { class: "panel stack" }, h("h2", {}, "¿Qué quiere crear?"), selector),
    h("section", { class: "panel" }, form),
    resultado,
    h("section", { class: "panel" }, h("div", { class: "panel-head" }, h("h2", {}, "Creado recientemente")), listaEl),
    faltantes.length
      ? h("p", { class: "notice notice-warn" }, `No disponible en este servidor: ${faltantes.join(", ")}. ${caps.nota_video}`)
      : null,
    h("p", { class: "muted" }, caps.nota_imagen));
}
