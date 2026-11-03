import { badge, busy, confirmDialog, errorText, field, fmt, h, icon, mount, toast, toastError } from "../../shared/dom.js";

// Panel de las redes neuronales. Criterio de diseño: quien administra esto no necesita jerga, sino
// poder responder tres preguntas — ¿sirve?, ¿en qué se equivoca?, ¿puedo volver atrás? Cada métrica
// va con su explicación en español y la matriz de confusión se lee en palabras, no en siglas.
const METRICAS = {
  exactitud: ["Exactitud", "De todo lo que clasifica, cuánto acierta"],
  precision: ["Precisión", "De lo que marca como amenaza, cuánto lo era"],
  sensibilidad: ["Sensibilidad", "De las amenazas reales, cuántas detecta"],
  f1: ["F1", "Equilibrio entre precisión y sensibilidad"],
  auc: ["AUC", "Separa amenaza de limpio sin depender del umbral"],
};

export default async function modelos(ctx) {
  const contenedor = h("div", { class: "stack" });
  const sondas = new Map();
  ctx.onCleanup?.(() => sondas.forEach(clearInterval));

  async function cargar() {
    try {
      const datos = await ctx.api.get("ml/modelos");
      mount(contenedor, datos.map((m) => tarjeta(ctx, m, cargar, sondas)));
    } catch (e) {
      mount(contenedor, h("p", { class: "notice notice-warn" }, errorText(e)));
    }
  }
  await cargar();

  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {},
      h("h1", {}, "Redes neuronales"),
      h("p", {}, "Tres redes escritas en NumPy y entrenadas con los datos de este servidor. "
        + "Aportan señales al antivirus, a los signos vitales y al asistente; ninguna decide sola."))),
    contenedor,
    probador(ctx));
}

function tarjeta(ctx, m, recargar, sondas) {
  const activa = m.activa;
  const met = activa?.metricas || {};
  const cuerpo = h("div", { class: "stack" });

  // ── entrenar, con barra de progreso en vivo
  const entrenar = h("button", { class: "btn btn-primary" }, icon("ajustes"),
    m.entrenado ? "Reentrenar" : "Entrenar ahora");
  const progreso = h("div", {});
  entrenar.addEventListener("click", () => busy(entrenar, async () => {
    try {
      const r = await ctx.api.post("ml/entrenar", { modelo: m.nombre, epocas: 400 });
      toast(r.mensaje, "ok");
      vigilar(ctx, m.nombre, progreso, recargar, sondas);
    } catch (e) {
      mount(progreso, h("p", { class: "notice notice-warn" }, errorText(e)));
    }
  }));
  if (m.trabajo?.estado === "entrenando") vigilar(ctx, m.nombre, progreso, recargar, sondas);

  // ── métricas con su explicación
  const tarjetas = Object.entries(METRICAS)
    .filter(([k]) => met[k])
    .map(([k, [titulo, ayuda]]) => h("div", { class: "stat" },
      h("span", { class: "stat-label" }, titulo),
      h("span", { class: "stat-value" }, `${Math.round(met[k] * 100)}%`),
      h("small", { class: "muted" }, ayuda)));

  if (activa) {
    cuerpo.append(
      h("div", { class: "grid grid-3" }, tarjetas),
      h("p", { class: "muted" }, `Versión ${activa.version} · ${fmt.num(met.ejemplos_entrenamiento || 0)} `
        + `ejemplos de entrenamiento y ${fmt.num(met.ejemplos_validacion || 0)} de validación · `
        + `arquitectura ${(activa.capas || []).join("→")} · ${met.epocas || 0} épocas`),
      activa.nota ? h("p", { class: "notice" }, activa.nota) : null,
      curva(activa.historial || []),
      confusion(met, m.nombre),
      importancia(activa.importancia || []),
      versiones(ctx, m, recargar));
  } else {
    cuerpo.append(h("p", {}, "Todavía no se ha entrenado esta red."));
  }

  return h("section", { class: "panel stack" },
    h("div", { class: "panel-head" },
      h("div", {}, h("h2", {}, m.titulo), h("p", {}, m.para_que)),
      badge(m.entrenado ? "Activa" : "Sin entrenar", m.entrenado ? "ok" : "neutral")),
    cuerpo, progreso,
    h("div", { class: "row" }, entrenar));
}

function vigilar(ctx, nombre, destino, recargar, sondas) {
  clearInterval(sondas.get(nombre));
  const barra = h("span", {});
  const texto = h("p", { class: "muted", "aria-live": "polite" }, "Iniciando…");
  const mini = h("div", { class: "curva-mini" });
  mount(destino, h("div", { class: "stack" }, h("div", { class: "meter" }, barra), texto, mini));

  const sonda = setInterval(async () => {
    try {
      const t = await ctx.api.get(`ml/trabajos/${nombre}`);
      if (t.estado === "entrenando") {
        const pct = Math.min(99, Math.round((t.epoca / (t.epocas || 1)) * 100));
        barra.style.width = `${pct}%`;
        texto.textContent = `Época ${t.epoca} de ${t.epocas} · pérdida ${t.perdida ?? "—"}`;
        mount(mini, curva(t.curva || [], 60));
      } else if (t.estado === "listo") {
        clearInterval(sonda);
        sondas.delete(nombre);
        toast(`Entrenamiento terminado en ${t.segundos} s`, "ok");
        recargar();
      } else if (t.estado === "error") {
        clearInterval(sonda);
        sondas.delete(nombre);
        mount(destino, h("p", { class: "notice notice-warn" }, `Falló el entrenamiento: ${t.mensaje}`));
      }
    } catch { /* la siguiente vuelta lo intenta de nuevo */ }
  }, 1500);
  sondas.set(nombre, sonda);
}

// Curva de aprendizaje en SVG: sin librerías de gráficos, son 20 líneas y pesa nada.
function curva(puntos, alto = 90) {
  if (puntos.length < 2) return null;
  const ancho = 520;
  const perdidas = puntos.map((p) => p.perdida);
  const max = Math.max(...perdidas);
  const min = Math.min(...perdidas);
  const rango = max - min || 1;
  const coords = puntos.map((p, i) => {
    const x = (i / (puntos.length - 1)) * (ancho - 20) + 10;
    const y = alto - 14 - ((p.perdida - min) / rango) * (alto - 28);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${ancho} ${alto}`);
  svg.setAttribute("class", "curva");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label",
    `Curva de aprendizaje: la pérdida bajó de ${max.toFixed(3)} a ${perdidas.at(-1).toFixed(3)}`);
  const linea = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  linea.setAttribute("points", coords);
  svg.append(linea);
  return h("figure", { class: "stack" }, svg,
    h("figcaption", { class: "muted" }, `Curva de aprendizaje · la pérdida bajó de ${max.toFixed(3)} `
      + `a ${perdidas.at(-1).toFixed(3)}. Que baje y se aplane es lo que se busca: si sube, el modelo `
      + "se estaba memorizando los datos."));
}

function confusion(met, nombre) {
  const m = met.matriz;
  if (!Array.isArray(m) || m.length !== 2) return null;
  const [[vn, fp], [fn, vp]] = m;
  const positivo = nombre === "antivirus" ? "amenaza" : "positivo";
  return h("div", { class: "stack" },
    h("h3", {}, "En qué se equivoca"),
    h("div", { class: "grid grid-2" },
      h("div", { class: "stat" }, h("span", { class: "stat-label" }, "Falsos positivos"),
        h("span", { class: "stat-value" }, String(fp)),
        h("small", { class: "muted" }, `Archivos limpios marcados como ${positivo}. Molestan al usuario.`)),
      h("div", { class: "stat" }, h("span", { class: "stat-label" }, "Se escaparon"),
        h("span", { class: "stat-value" }, String(fn)),
        h("small", { class: "muted" }, "Amenazas que no detectó. Es el error caro."))),
    h("p", { class: "muted" }, `Acertó en ${vp + vn} de ${vp + vn + fp + fn} casos de validación. `
      + `Umbral de decisión: ${met.umbral ?? "—"} (elegido por F1, no por costumbre).`));
}

function importancia(pares) {
  if (!pares.length) return null;
  const max = Math.max(...pares.map(([, v]) => v)) || 1;
  return h("details", { class: "stack" },
    h("summary", {}, "Qué rasgos mira más la red"),
    h("ul", { class: "list barras" }, pares.slice(0, 8).map(([nombre, valor]) => {
      const barra = h("span", {});
      barra.style.width = `${Math.round((valor / max) * 100)}%`;
      return h("li", {},
        h("span", { class: "list-main" }, nombre.replace(/_/g, " ")),
        h("span", { class: "meter" }, barra),
        h("small", { class: "muted" }, `${Math.round(valor * 100)}%`));
    })),
    h("p", { class: "muted" }, "Aproximación por la magnitud de los pesos de la primera capa. No es "
      + "SHAP, pero alcanza para explicar por qué el modelo mira lo que mira."));
}

function versiones(ctx, m, recargar) {
  const lista = m.historial_versiones || [];
  if (lista.length < 2) return null;
  return h("details", { class: "stack" },
    h("summary", {}, `Historial de versiones (${lista.length})`),
    h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", {}, h("tr", {}, ["Versión", "Entrenada", "Ejemplos", "F1", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, lista.map((v) => {
        const volver = h("button", { class: "btn btn-sm" }, "Usar esta");
        volver.addEventListener("click", async () => {
          const ok = await confirmDialog({
            title: `Volver a la versión ${v.version}`, confirmLabel: "Activar",
            message: "El sistema usará esa versión a partir del próximo análisis. Nada se borra: "
              + "puede regresar a la actual cuando quiera.",
          });
          if (!ok) return;
          try {
            toast((await ctx.api.post(`ml/modelos/${m.nombre}/activar`, { version: v.version })).mensaje, "ok");
            recargar();
          } catch (e) { toastError(e); }
        });
        return h("tr", {}, h("td", {}, v.version), h("td", {}, v.creado ? fmt.date(v.creado) : "—"),
          h("td", {}, fmt.num(v.ejemplos || 0)),
          h("td", {}, v.f1 ? `${Math.round(v.f1 * 100)}%` : "—"),
          h("td", {}, v.activa ? badge("En uso", "ok") : volver));
      })))));
}

function probador(ctx) {
  const texto = h("input", { class: "input", placeholder: "asme una tabla de notaz en excel" });
  const salida = h("div", {});
  const btn = h("button", { class: "btn", type: "submit" }, "Probar");
  const form = h("form", { class: "form" },
    field("Escriba una frase y vea qué entiende la red de intención", texto,
      "La mejor forma de confiar en un modelo es probarlo con el lenguaje real de sus usuarios, erratas incluidas."),
    h("div", { class: "row" }, btn));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    if (!texto.value.trim()) return;
    busy(btn, async () => {
      try {
        const r = await ctx.api.post("ml/probar-intencion", { texto: texto.value.trim() });
        const max = r.todas[0].probabilidad || 1;
        mount(salida,
          h("p", {}, "Entiende: ", h("strong", {}, r.intencion),
            ` · ${Math.round(r.confianza * 100)}% de confianza`),
          h("ul", { class: "list barras" }, r.todas.slice(0, 5).map((t) => {
            const barra = h("span", {});
            barra.style.width = `${Math.round((t.probabilidad / max) * 100)}%`;
            return h("li", {}, h("span", { class: "list-main" }, t.intencion),
              h("span", { class: "meter" }, barra),
              h("small", { class: "muted" }, `${Math.round(t.probabilidad * 100)}%`));
          })),
          r.confianza < 0.7
            ? h("p", { class: "notice notice-warn" }, "Confianza baja: en este caso mandan las reglas, "
              + "no la red. Es el comportamiento correcto.")
            : null);
      } catch (e) { mount(salida, h("p", { class: "notice notice-warn" }, errorText(e))); }
    });
  });
  return h("section", { class: "panel stack" }, h("h2", {}, "Probar la red de intención"), form, salida);
}
