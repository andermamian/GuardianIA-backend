import { badge, busy, confirmDialog, emptyState, errorText, field, fmt, h, icon, mount, toast, toastError } from "../../shared/dom.js";
import { extractFeatures } from "../file-features.js";
import { panelTunelLocal, vistaAntivirus } from "./proteccion-local.js";

const NIVEL = { limpio: ["Sin amenazas", "ok"], sospechoso: ["Sospechoso", "warn"], malicioso: ["Malicioso", "danger"] };
const RIESGO = { bajo: ["Sin filtraciones", "ok"], medio: ["Exposición baja", "warn"],
                 alto: ["Exposición alta", "danger"], critico: ["Exposición crítica", "critical"] };

// Topes del análisis: leer y calcular la huella de cada archivo cuesta tiempo en el navegador, y el
// servidor acepta 200 por lote. Mejor un análisis acotado y rápido que uno eterno.
const MAX_ARCHIVOS = 600;
const LOTE = 100;
const MAX_BYTES_ARCHIVO = 64 * 1024 * 1024;
const OMITIR = /(^|[\\/])(node_modules|\.git|\.venv|venv|__pycache__|AppData|Windows|Program Files)([\\/]|$)/i;

export default async function proteccion(ctx) {
  // «agente» se conserva como alias: los enlaces viejos llevan al antivirus nuevo, que ya no lo necesita.
  const pedida = ctx.params[0] === "agente" ? "antivirus" : ctx.params[0];
  const pestana = ["antivirus", "equipo", "vpn", "exposicion"].includes(pedida) ? pedida : "antivirus";
  const estado = await ctx.api.get("proteccion/estado").catch(() => null);

  const cuerpo = h("div", { class: "stack" });
  const tabs = h("div", { class: "segmented", role: "tablist" },
    [["antivirus", "Antivirus"], ["equipo", "Revisar archivos sueltos"], ["vpn", "VPN"],
      ["exposicion", "Mis datos filtrados"]].map(([id, etiqueta]) =>
      h("button", { type: "button", role: "tab", "aria-selected": String(pestana === id),
        "aria-pressed": String(pestana === id), onClick: () => ctx.navigate(`proteccion/${id}`) }, etiqueta)));

  const resumenEl = h("div", {});
  const actualizarResumen = async () => {
    try { mount(resumenEl, resumen(await ctx.api.get("proteccion/estado"))); } catch { /* secundario */ }
  };
  if (estado) mount(resumenEl, resumen(estado));

  if (pestana === "antivirus") await vistaAntivirus(ctx, cuerpo, actualizarResumen);
  else if (pestana === "equipo") await vistaEquipo(ctx, cuerpo, actualizarResumen);
  else if (pestana === "vpn") await vistaVpn(ctx, cuerpo);
  else await vistaExposicion(ctx, cuerpo, actualizarResumen);

  return h("div", { class: "stack" },
    h("header", { class: "page-head" },
      h("div", {}, h("h1", {}, "Protección"),
        h("p", {}, "Análisis del equipo, red privada y revisión de filtraciones. El motor combina firmas "
          + "conocidas, reglas de comportamiento y un modelo de aprendizaje automático.")), tabs),
    resumenEl,
    cuerpo);
}

// ────────────────────────────────────────────────────────── resumen
function resumen(e) {
  const tarjeta = (etiqueta, valor, sub, tono) => h("div", { class: "panel stat" },
    h("span", { class: "stat-label" }, etiqueta), h("span", { class: "stat-value" }, valor),
    sub ? h("span", { class: tono ? `badge badge-${tono}` : "muted" }, sub) : null);
  const ultimo = e.ultimo_escaneo;
  return h("div", { class: "stack" },
    h("section", { class: "grid grid-3" },
      tarjeta("Último análisis", ultimo ? fmt.ago(ultimo.creado) : "Nunca",
        ultimo ? `${fmt.num(ultimo.total)} archivos · ${ultimo.maliciosos} maliciosos` : "Analice su equipo",
        ultimo?.maliciosos ? "danger" : null),
      tarjeta("Alertas sin resolver", e.alertas_abiertas,
        e.apps_riesgo ? `${e.apps_riesgo} apps de riesgo` : "", e.alertas_abiertas ? "warn" : null),
      tarjeta("Datos filtrados", e.exposicion ? String(e.exposicion.filtraciones) : "Sin revisar",
        e.exposicion ? RIESGO[e.exposicion.riesgo][0] : "Revise su correo",
        e.exposicion && e.exposicion.riesgo !== "bajo" ? "danger" : null)),
    e.pendientes.length
      ? h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, "Lo que falta por hacer")),
        h("ul", { class: "list" }, e.pendientes.map((p) => h("li", {}, icon("alerta"),
          h("span", { class: "list-main" }, p)))))
      : h("p", { class: "notice" }, "Su protección está al día."));
}

// ───────────────────────────────────────────── 1. análisis del equipo
async function vistaEquipo(ctx, cuerpo, actualizarResumen) {
  const progreso = h("div", {});
  const resultados = h("div", {});
  const historialEl = h("div", {});
  let cancelar = false;

  const soportaCarpetas = "showDirectoryPicker" in window;
  const entradaCarpeta = h("input", { type: "file", hidden: true, webkitdirectory: true, multiple: true });
  const entradaArchivos = h("input", { type: "file", hidden: true, multiple: true });

  const btnCarpeta = h("button", { class: "btn btn-primary" }, icon("proteccion"), "Analizar una carpeta");
  const btnArchivos = h("button", { class: "btn" }, icon("archivo"), "Analizar archivos sueltos");
  btnArchivos.addEventListener("click", () => entradaArchivos.click());
  entradaArchivos.addEventListener("change", () => {
    analizar([...entradaArchivos.files], "archivo").finally(() => { entradaArchivos.value = ""; });
  });
  btnCarpeta.addEventListener("click", async () => {
    if (!soportaCarpetas) return entradaCarpeta.click();
    try {
      const dir = await window.showDirectoryPicker({ mode: "read" });
      const archivos = [];
      await recorrer(dir, "", archivos);
      analizar(archivos, "carpeta");
    } catch (e) {
      if (e.name !== "AbortError") toast(`No se pudo abrir la carpeta: ${e.message}`, "error");
    }
  });
  entradaCarpeta.addEventListener("change", () => {
    analizar([...entradaCarpeta.files], "carpeta").finally(() => { entradaCarpeta.value = ""; });
  });

  // Recorre la carpeta elegida sin subir nada: los archivos se leen en el propio navegador.
  async function recorrer(dir, ruta, salida, nivel = 0) {
    if (salida.length >= MAX_ARCHIVOS || nivel > 6) return;
    for await (const [nombre, manejador] of dir.entries()) {
      if (salida.length >= MAX_ARCHIVOS) return;
      const completa = `${ruta}/${nombre}`;
      if (OMITIR.test(completa)) continue;   // carpetas del sistema: ruido, no riesgo
      if (manejador.kind === "directory") await recorrer(manejador, completa, salida, nivel + 1);
      else salida.push(await manejador.getFile());
    }
  }

  async function analizar(archivos, origen) {
    if (!archivos.length) return;
    cancelar = false;
    const candidatos = archivos.filter((f) => f.size > 0 && f.size <= MAX_BYTES_ARCHIVO);
    const omitidos = archivos.length - candidatos.length;
    const total = Math.min(candidatos.length, MAX_ARCHIVOS);
    const barra = h("span", {});
    const texto = h("p", { class: "muted", "aria-live": "polite" }, "Preparando…");
    const btnCancelar = h("button", { class: "btn btn-sm", onClick: () => { cancelar = true; } }, "Detener");
    mount(progreso, h("section", { class: "panel stack" },
      h("h2", {}, "Analizando su equipo"),
      h("div", { class: "meter" }, barra), texto,
      h("p", { class: "muted" }, "Los archivos no salen de su equipo: aquí se calcula su huella digital y solo "
        + "se envían rasgos técnicos."),
      h("div", { class: "row" }, btnCancelar)));

    const acumulado = { total: 0, limpios: 0, sospechosos: 0, maliciosos: 0, hallazgos: [] };
    let lote = [];
    const inicio = Date.now();

    for (let i = 0; i < total; i++) {
      if (cancelar) break;
      const archivo = candidatos[i];
      texto.textContent = `Leyendo ${i + 1} de ${total}: ${archivo.name.slice(0, 50)}`;
      barra.style.width = `${Math.round(((i + 1) / total) * 100)}%`;
      try {
        lote.push(await extractFeatures(archivo));
      } catch { /* archivo ilegible o bloqueado por el sistema: se omite */ }
      if (lote.length >= LOTE || i === total - 1) {
        if (!lote.length) continue;
        try {
          const r = await ctx.api.post("proteccion/escaneo", { origen, archivos: lote, omitidos },
            { timeout: 120000 });
          acumulado.total += r.total;
          acumulado.limpios += r.limpios;
          acumulado.sospechosos += r.sospechosos;
          acumulado.maliciosos += r.maliciosos;
          acumulado.hallazgos.push(...r.hallazgos);
        } catch (e) {
          toastError(e);
          break;
        }
        lote = [];
      }
    }

    mount(progreso);
    mostrarResultado(acumulado, omitidos, Date.now() - inicio, cancelar, acumulado.total < total);
    cargarHistorial();
    actualizarResumen?.();   // las tarjetas de arriba deben reflejar el análisis recién hecho
  }

  function mostrarResultado(r, omitidos, ms, detenido, parcial) {
    const tono = r.maliciosos ? "danger" : r.sospechosos ? "warn" : "ok";
    const titulo = r.maliciosos ? `${r.maliciosos} amenaza(s) encontradas`
      : r.sospechosos ? `${r.sospechosos} archivo(s) para revisar` : "Sin amenazas";
    mount(resultados, h("section", { class: "panel stack" },
      h("div", { class: "panel-head" },
        h("div", {}, h("h2", {}, titulo),
          h("p", {}, `${fmt.num(r.total)} archivos analizados en ${(ms / 1000).toFixed(1)} s`
            + (omitidos ? `, ${omitidos} omitidos por tamaño` : "")
            + (detenido ? ". Detenido por usted." : parcial ? ". Análisis parcial." : ""))),
        badge(titulo.split(" ")[0], tono)),
      h("div", { class: "grid grid-3" },
        h("div", { class: "stat" }, h("span", { class: "stat-label" }, "Limpios"),
          h("span", { class: "stat-value" }, r.limpios)),
        h("div", { class: "stat" }, h("span", { class: "stat-label" }, "Sospechosos"),
          h("span", { class: "stat-value" }, r.sospechosos)),
        h("div", { class: "stat" }, h("span", { class: "stat-label" }, "Maliciosos"),
          h("span", { class: "stat-value" }, r.maliciosos))),
      r.hallazgos.length
        ? h("div", { class: "stack" }, h("h3", {}, "Hallazgos"), r.hallazgos.slice(0, 20).map(hallazgo))
        : h("p", {}, "Ninguna de las capas de análisis encontró señales de riesgo."),
      r.maliciosos
        ? h("p", { class: "notice notice-danger" }, "No abra esos archivos. Elimínelos y, si llegaron por correo "
          + "o mensaje, avise a quien se los envió: su cuenta puede estar comprometida.")
        : h("p", { class: "muted" }, "Ningún antivirus detecta el 100 %. Si un archivo no lo esperaba, no lo abra "
          + "aunque salga limpio.")));
  }

  const hallazgo = (x) => h("div", { class: "finding",
    dataset: { tone: x.nivel === "malicioso" ? "danger" : "warn" } },
    h("div", {},
      h("p", {}, h("strong", {}, x.nombre), " ", badge(...(NIVEL[x.nivel] || [x.nivel, "neutral"])),
        h("span", { class: "muted" }, ` ${Math.round(x.probabilidad * 100)} % de probabilidad`)),
      x.familia ? h("p", { class: "muted" }, `Parece: ${x.familia}`) : null,
      h("ul", {}, x.motivos.map((m) => h("li", {}, m))),
      h("p", { class: "mono muted" }, `${x.sha256.slice(0, 32)}…`)));

  async function cargarHistorial() {
    try {
      const filas = await ctx.api.get("proteccion/escaneos", { query: { limit: 8 } });
      mount(historialEl, filas.length
        ? h("div", { class: "table-wrap" }, h("table", { class: "table" },
          h("thead", {}, h("tr", {}, ["Fecha", "Origen", "Archivos", "Maliciosos", "Sospechosos", "Duración"]
            .map((t) => h("th", {}, t)))),
          h("tbody", {}, filas.map((f) => h("tr", {},
            h("td", {}, fmt.date(f.creado)), h("td", {}, f.origen), h("td", {}, fmt.num(f.total)),
            h("td", {}, f.maliciosos ? badge(String(f.maliciosos), "danger") : "0"),
            h("td", {}, String(f.sospechosos || 0)), h("td", {}, `${(f.duracion_ms / 1000).toFixed(1)} s`))))))
        : emptyState("Sin análisis previos", "Aquí quedará el historial de cada revisión."));
    } catch { /* el historial es secundario */ }
  }

  mount(cuerpo,
    h("section", { class: "panel stack" },
      h("h2", {}, "Analizar este equipo"),
      h("p", {}, "Elija una carpeta (Descargas, Documentos, una memoria USB) y GuardianIA revisará cada archivo "
        + "con firmas conocidas, reglas de comportamiento y un modelo de aprendizaje automático."),
      h("div", { class: "row" }, btnCarpeta, btnArchivos, entradaCarpeta, entradaArchivos),
      soportaCarpetas
        ? h("p", { class: "muted" }, `Se revisan hasta ${MAX_ARCHIVOS} archivos por análisis y se omiten carpetas `
          + "del sistema como Windows o node_modules.")
        : h("p", { class: "notice notice-warn" }, "Su navegador no permite elegir carpetas con permiso de lectura; "
          + "se usará el selector clásico. Para la mejor experiencia use Chrome, Edge u Opera.")),
    progreso, resultados,
    h("section", { class: "panel" },
      h("div", { class: "panel-head" }, h("h2", {}, "Análisis anteriores")), historialEl));
  cargarHistorial();
}

// ─────────────────────────────────────────────── 2. VPN con IA
function duracion(segundos) {
  const h_ = Math.floor(segundos / 3600), m = Math.floor((segundos % 3600) / 60), s_ = segundos % 60;
  return h_ ? `${h_}h ${String(m).padStart(2, "0")}m ${String(s_).padStart(2, "0")}s`
            : `${m}:${String(s_).padStart(2, "0")}`;
}

async function vistaVpn(ctx, cuerpo) {
  // v3.8: solo su servidor GuardianIA VPN (Google Cloud) y Tor, con un botón y la IA que decide.
  const conexionEl = h("div", {});
  async function pintarConexion() {
    mount(conexionEl, await panelTunelLocal(ctx, () => pintarConexion()));
  }
  const historial = await ctx.api.get("vpn/sesiones", { query: { limit: 10 } }).catch(() => []);
  mount(cuerpo,
    conexionEl,
    historial.length
      ? h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, "Conexiones recientes")),
        h("div", { class: "table-wrap" }, h("table", { class: "table" },
          h("thead", {}, h("tr", {}, ["Inicio", "Servidor", "Duración", "Estado"].map((t) => h("th", {}, t)))),
          h("tbody", {}, historial.map((x) => h("tr", {},
            h("td", {}, fmt.date(x.iniciada)), h("td", {}, `${x.ciudad}, ${x.pais}`),
            h("td", {}, duracion(x.segundos_conectado)),
            h("td", {}, badge(x.estado === "cerrada" ? "Finalizada" : x.estado,
              x.estado === "conectada" ? "ok" : "neutral"))))))))
      : null);
  await pintarConexion();
}

// ──────────────────────────────────────── 3. exposición de datos
async function vistaExposicion(ctx, cuerpo, actualizarResumen) {
  const correo = h("input", { class: "input", type: "email", required: true, value: ctx.user.email,
    autocomplete: "email", "aria-label": "Correo a revisar" });
  const btn = h("button", { class: "btn btn-primary", type: "submit" }, icon("ojo"), "Revisar mi correo");
  const resultado = h("div", {});

  const form = h("form", { class: "form" },
    field("Correo electrónico", correo, "Se consulta un servicio especializado en filtraciones publicadas."),
    h("div", { class: "row" }, btn));

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    if (!form.reportValidity()) return;
    busy(btn, async () => {
      mount(resultado, h("div", { class: "panel" }, h("p", {}, "Consultando bases de filtraciones…"),
        h("div", { class: "skeleton" }, h("span", {}), h("span", {}))));
      try {
        mostrar(await ctx.api.post("proteccion/exposicion", { email: correo.value.trim() }, { timeout: 40000 }));
        actualizarResumen?.();
      } catch (err) {
        mount(resultado, h("p", { class: "notice notice-warn" }, errorText(err)));
      }
    });
  });

  function mostrar(r) {
    const [etiqueta, tono] = RIESGO[r.riesgo] || [r.riesgo, "neutral"];
    mount(resultado, h("section", { class: "panel stack" },
      h("div", { class: "panel-head" },
        h("div", {}, h("h2", {}, r.filtraciones
          ? `Aparece en ${r.filtraciones} filtración(es)` : "Sin coincidencias"),
          h("p", {}, `Consultado en ${r.proveedor}${r.cacheado ? " (resultado reciente)" : ""} · ${fmt.ago(r.revisado)}`)),
        badge(etiqueta, tono)),
      r.detalle.length
        ? h("div", { class: "table-wrap" }, h("table", { class: "table" },
          h("thead", {}, h("tr", {}, ["Sitio", "Fecha", "Datos expuestos", "Cuentas"].map((t) => h("th", {}, t)))),
          h("tbody", {}, r.detalle.map((d) => h("tr", {},
            h("td", {}, d.sitio || "—"), h("td", {}, d.fecha || "—"),
            h("td", {}, (d.datos || []).join(", ") || "No especificado"),
            h("td", {}, d.cuentas ? fmt.num(d.cuentas) : "—"))))))
        : null,
      h("div", {}, h("h3", {}, "Qué hacer ahora"), h("ol", {}, r.recomendaciones.map((x) => h("li", {}, x)))),
      h("div", { class: "row" },
        h("a", { class: "btn", href: "#/boveda/claves" }, icon("llave"), "Generar contraseñas nuevas"),
        h("a", { class: "btn", href: "#/cuenta" }, "Activar verificación en dos pasos"))));
  }

  const previo = await ctx.api.get("proteccion/exposicion").catch(() => null);
  if (previo) mostrar(previo);

  mount(cuerpo,
    h("section", { class: "panel stack" },
      h("h2", {}, "¿Mis datos están filtrados?"),
      h("p", {}, "Cuando una empresa sufre un robo de datos, esas bases terminan circulando en foros y mercados "
        + "de la dark web. Aquí se consulta si su correo aparece en las filtraciones ya catalogadas."),
      h("p", { class: "notice" }, "Con franqueza: nadie «rastrea la dark web» en vivo desde una app, y quien lo "
        + "promete casi siempre consulta estas mismas bases. Lo que sí sirve es saber en qué filtraciones aparece "
        + "usted y actuar sobre eso."),
      form),
    resultado,
    h("section", { class: "panel stack" },
      h("h2", {}, "Revisar una contraseña"),
      h("p", {}, "En la Bóveda puede verificar si una contraseña aparece en filtraciones sin enviarla: el navegador "
        + "manda solo los primeros cinco caracteres de su huella, así que nadie puede reconstruirla."),
      h("a", { class: "btn", href: "#/boveda/claves" }, "Ir a la Bóveda")));
}


// ─────────────────────────────── 4. agente: el equipo completo
// El navegador no puede escanear discos ni poner nada en cuarentena: su sandbox lo impide, y un
// sitio web capaz de borrar archivos sería justo el problema que decimos resolver. Por eso el
// trabajo pesado lo hace un agente con privilegios y esta pantalla lo dirige.
const ESTADO_CUARENTENA = {
  en_cuarentena: ["Aislado", "warn"], pendiente_restaurar: ["Restaurando…", "neutral"],
  pendiente_eliminar: ["Eliminando…", "neutral"], restaurado: ["Restaurado", "neutral"],
  eliminado: ["Eliminado", "ok"], error: ["Error", "danger"],
};

async function vistaAgente(ctx, cuerpo, actualizarResumen) {
  const agentesEl = h("div", {});
  const cuarentenaEl = h("div", {});

  async function cargar() {
    const [agentes, cuarentena] = await Promise.all([
      ctx.api.get("proteccion/agentes").catch(() => []),
      ctx.api.get("proteccion/cuarentena").catch(() => []),
    ]);
    mount(agentesEl, agentes.length
      ? h("div", { class: "stack" }, agentes.map((a) => tarjetaAgente(ctx, a, cargar, actualizarResumen)))
      : instalacion(ctx));
    mount(cuarentenaEl, cuarentena.length
      ? tablaCuarentena(ctx, cuarentena, cargar)
      : emptyState("Cuarentena vacía", "Aquí aparecerán los archivos que el agente aísle en sus equipos."));
  }

  mount(cuerpo,
    h("section", { class: "panel stack" },
      h("h2", {}, "Protección del equipo completo"),
      h("p", {}, "El agente se instala una vez y corre como servicio del sistema. Analiza discos y memorias "
        + "completas, vigila en tiempo real y aísla las amenazas. Desde aquí usted ordena y decide."),
      h("p", { class: "notice" }, "El navegador no puede escanear su disco ni borrar archivos: su aislamiento "
        + "lo impide, y está bien que así sea. Por eso el trabajo pesado lo hace el agente, con privilegios, "
        + "y esta pantalla solo le da órdenes de una lista cerrada: analizar, restaurar o eliminar.")),
    agentesEl,
    h("section", { class: "panel" },
      h("div", { class: "panel-head" }, h("h2", {}, "Cuarentena"),
        h("p", {}, "Los archivos quedan cifrados en el equipo, sin poder ejecutarse. Usted decide.")),
      cuarentenaEl));
  await cargar();
}

function tarjetaAgente(ctx, a, recargar, actualizarResumen) {
  const boton = (etiqueta, modo, clase = "btn") => {
    const b = h("button", { class: clase }, etiqueta);
    b.addEventListener("click", () => busy(b, async () => {
      try {
        let ruta = null;
        if (modo === "personalizado") {
          ruta = prompt("Ruta de la carpeta o unidad a analizar (ejemplo: D:\\ o C:\\Users\\usuario\\Downloads)");
          if (!ruta) return;
        }
        const r = await ctx.api.post(`proteccion/agentes/${a.id}/escanear`, { modo, ruta });
        toast(r.mensaje, "ok");
        setTimeout(() => { recargar(); actualizarResumen?.(); }, 3000);
      } catch (e) { toastError(e); }
    }));
    return b;
  };

  const conmutador = (etiqueta, campo, valor, ayuda) => {
    const input = h("input", { type: "checkbox", checked: valor });
    input.addEventListener("change", async () => {
      try {
        const r = await ctx.api.put(`proteccion/agentes/${a.id}/politica`, { [campo]: input.checked });
        toast(r.mensaje, "ok");
      } catch (e) { input.checked = !input.checked; toastError(e); }
    });
    return h("label", { class: "check" }, input, h("span", {}, etiqueta, h("br"), h("small", { class: "muted" }, ayuda)));
  };

  return h("article", { class: "panel stack" },
    h("div", { class: "panel-head" },
      h("div", {}, h("h2", {}, a.equipo), h("p", {}, `${a.so} · agente ${a.version}`)),
      badge(a.en_linea ? "En línea" : "Desconectado", a.en_linea ? "ok" : "neutral")),
    h("div", { class: "grid grid-3" },
      h("div", { class: "stat" }, h("span", { class: "stat-label" }, "Último análisis"),
        h("span", { class: "stat-value" }, a.ultimo_escaneo ? fmt.ago(a.ultimo_escaneo) : "Nunca")),
      h("div", { class: "stat" }, h("span", { class: "stat-label" }, "Archivos protegidos"),
        h("span", { class: "stat-value" }, fmt.num(a.archivos_protegidos))),
      h("div", { class: "stat" }, h("span", { class: "stat-label" }, "En cuarentena"),
        h("span", { class: "stat-value" }, a.en_cuarentena))),
    a.progreso
      ? progresoAnalisis(a.progreso)
      : a.escaneo_pendiente
        ? h("p", { class: "notice" }, `Análisis ${a.escaneo_pendiente} solicitado: el agente lo iniciará en `
          + "menos de un minuto.")
        : null,
    !a.en_linea
      ? h("p", { class: "notice notice-warn" }, `Sin señal desde ${fmt.ago(a.ultimo_latido)}. Las órdenes `
        + "quedan en cola y se ejecutarán cuando el equipo vuelva a estar en línea.")
      : null,
    h("div", { class: "row" },
      boton("Análisis rápido", "rapido", "btn btn-primary"),
      boton("Disco completo", "completo"),
      boton("Carpeta o USB…", "personalizado")),
    h("hr", { class: "divider" }),
    h("div", { class: "grid grid-2" },
      conmutador("Protección en tiempo real", "tiempo_real", a.tiempo_real,
        "Revisa cada archivo nuevo o modificado en carpetas sensibles."),
      conmutador("Cuarentena automática", "cuarentena_automatica", a.cuarentena_automatica,
        "Aísla lo malicioso sin preguntar. Lo sospechoso nunca se toca solo.")),
    automaticos(ctx, a),
    h("p", { class: "muted" }, ultimoAnalisis(a)));
}

function tablaCuarentena(ctx, filas, recargar) {
  return h("div", { class: "table-wrap" }, h("table", { class: "table" },
    h("thead", {}, h("tr", {}, ["Archivo", "Origen", "Amenaza", "Estado", "Fecha", "Acciones"]
      .map((t) => h("th", {}, t)))),
    h("tbody", {}, filas.map((f) => {
      const acciones = h("div", { class: "row" });
      if (f.estado === "en_cuarentena") {
        const eliminar = h("button", { class: "btn btn-sm btn-danger" }, "Eliminar");
        eliminar.addEventListener("click", async () => {
          const ok = await confirmDialog({
            title: "Eliminar definitivamente", danger: true, confirmLabel: "Eliminar", typeToConfirm: "ELIMINAR",
            message: `${f.archivo} se borrará del equipo sin posibilidad de recuperarlo. `
              + "El agente sobrescribe el archivo antes de borrarlo.",
          });
          if (!ok) return;
          try {
            toast((await ctx.api.post(`proteccion/cuarentena/${f.id}/decidir`, { accion: "eliminar" })).mensaje, "ok");
            recargar();
          } catch (e) { toastError(e); }
        });
        const restaurar = h("button", { class: "btn btn-sm" }, "Restaurar");
        restaurar.addEventListener("click", async () => {
          const ok = await confirmDialog({
            title: "Restaurar el archivo", danger: f.nivel === "malicioso", confirmLabel: "Restaurar",
            message: f.nivel === "malicioso"
              ? `${f.archivo} fue clasificado como malicioso${f.familia ? ` (${f.familia})` : ""}. `
                + "Restaurarlo lo devuelve a su carpeta original y podrá ejecutarse. Hágalo solo si está "
                + "seguro de que es un falso positivo."
              : `${f.archivo} volverá a ${f.ruta || "su carpeta original"}.`,
          });
          if (!ok) return;
          try {
            toast((await ctx.api.post(`proteccion/cuarentena/${f.id}/decidir`, { accion: "restaurar" })).mensaje, "ok");
            recargar();
          } catch (e) { toastError(e); }
        });
        acciones.append(restaurar, eliminar);
      }
      const [etiqueta, tono] = ESTADO_CUARENTENA[f.estado] || [f.estado, "neutral"];
      return h("tr", {},
        h("td", {}, h("strong", {}, f.archivo), h("br"), h("small", { class: "mono muted" }, `${f.sha256.slice(0, 20)}…`)),
        h("td", { class: "muted" }, f.ruta || "—"),
        h("td", {}, badge(f.nivel === "malicioso" ? "Malicioso" : "Sospechoso",
          f.nivel === "malicioso" ? "danger" : "warn"),
          f.familia ? h("div", { class: "muted" }, f.familia) : null,
          f.motivos?.length ? h("details", {}, h("summary", { class: "muted" }, "Por qué"),
            h("ul", {}, f.motivos.map((m) => h("li", {}, m)))) : null),
        h("td", {}, badge(etiqueta, tono), f.error ? h("div", { class: "muted" }, f.error) : null),
        h("td", {}, fmt.date(f.creado)),
        h("td", {}, acciones));
    }))));
}

function instalacion(ctx) {
  const comando = (texto) => {
    const copiar = h("button", { class: "btn btn-sm" }, icon("copiar"), "Copiar");
    copiar.addEventListener("click", async () => {
      await navigator.clipboard.writeText(texto);
      toast("Copiado", "ok");
    });
    return h("figure", { class: "code" },
      h("figcaption", { class: "code-head" }, h("span", {}, "PowerShell como administrador"), copiar),
      h("pre", {}, h("code", {}, texto)));
  };
  return h("section", { class: "panel stack" },
    h("h2", {}, "Instalar el agente en este equipo"),
    h("p", {}, "Tres pasos. El agente no necesita librerías adicionales: solo Python."),
    h("ol", { class: "stack" },
      h("li", {}, "Registre este equipo en la sección ", h("a", { href: "#/dispositivos" }, "Dispositivos"),
        " y copie el token que se muestra una sola vez."),
      h("li", {}, "Abra PowerShell ", h("strong", {}, "como administrador"),
        " (clic derecho → «Ejecutar como administrador»). Sin eso solo se revisan sus carpetas, no el disco completo."),
      h("li", {}, "Ejecute, en la carpeta del proyecto:")),
    comando([
      "cd agente",
      `python guardian_agent.py registrar --servidor ${location.origin} --token PEGUE_SU_TOKEN`,
      "python guardian_agent.py servicio",
    ].join("\n")),
    h("p", { class: "muted" }, "Para analizar el disco completo de inmediato: "),
    comando("python guardian_agent.py escanear --modo completo"),
    h("p", { class: "notice notice-warn" }, "Windows Defender y GuardianIA pueden convivir, pero si ambos vigilan "
      + "en tiempo real el equipo va más lento. Para la sustentación, deje uno de los dos."));
}


// ─────────────── análisis automáticos: el equipo se cuida solo
// Un antivirus que exige que la persona se acuerde de analizar, no protege. El agente ya programa
// sus propios análisis; aquí solo se ajusta cada cuánto, y se puede forzar uno con un botón.
function automaticos(ctx, a) {
  const rapido = h("select", { class: "input" },
    [[0, "Desactivado"], [3, "Cada 3 horas"], [6, "Cada 6 horas"], [12, "Cada 12 horas"], [24, "Una vez al día"]]
      .map(([v, l]) => h("option", { value: String(v), selected: Number(a.auto_rapido_horas) === v }, l)));
  const completo = h("select", { class: "input" },
    [[0, "Desactivado"], [1, "Diario"], [7, "Semanal"], [15, "Cada 15 días"], [30, "Mensual"]]
      .map(([v, l]) => h("option", { value: String(v), selected: Number(a.auto_completo_dias) === v }, l)));
  const guardar = async (campo, control) => {
    try {
      toast((await ctx.api.put(`proteccion/agentes/${a.id}/politica`,
        { [campo]: Number(control.value) })).mensaje, "ok");
    } catch (e) { toastError(e); }
  };
  rapido.addEventListener("change", () => guardar("auto_rapido_horas", rapido));
  completo.addEventListener("change", () => guardar("auto_completo_dias", completo));

  return h("div", { class: "stack" },
    h("h3", {}, "Análisis automáticos"),
    h("p", { class: "muted" }, "El agente los ejecuta solo, y espera a que el equipo esté desocupado "
      + "para no volverlo lento mientras usted trabaja."),
    h("div", { class: "form-row" },
      field("Análisis rápido", rapido, "Descargas, escritorio, temporales y carpeta de inicio"),
      field("Análisis completo", completo, "Todos los discos y las memorias conectadas")));
}

function progresoAnalisis(p) {
  const pct = p.total ? Math.min(99, Math.round((p.revisados / p.total) * 100)) : 0;
  const barra = h("span", {});
  barra.style.width = `${pct}%`;
  return h("div", { class: "stack" },
    h("p", {}, h("strong", {}, `Analizando (${p.modo})`), ` · ${fmt.num(p.revisados || 0)} de `
      + `${fmt.num(p.total || 0)} archivos`),
    h("div", { class: "meter" }, barra),
    h("p", { class: "muted" }, p.actual ? `Revisando: ${p.actual}` : ""));
}

function ultimoAnalisis(a) {
  const partes = [];
  if (a.ultimo_rapido) partes.push(`rápido ${fmt.ago(a.ultimo_rapido)}`);
  if (a.ultimo_completo) partes.push(`completo ${fmt.ago(a.ultimo_completo)}`);
  return partes.length
    ? `Último análisis automático: ${partes.join(" · ")}.`
    : "Aún no se ha ejecutado ningún análisis automático; el primero corre en la próxima hora.";
}
