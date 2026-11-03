// Protección de ESTE equipo: antivirus con progreso en vivo, tiempo real, cuarentena y túnel VPN.
// Todo lo hace el propio servidor de GuardianIA: no hay agente que vincular ni comandos que copiar.
import { badge, busy, confirmDialog, emptyState, errorText, field, fmt, h, icon, mount, toast, toastError } from "../../shared/dom.js";

const NIVEL = { limpio: ["Limpio", "ok"], sospechoso: ["Sospechoso", "warn"], malicioso: ["Malicioso", "danger"] };
const MODO = { rapido: "Análisis rápido", completo: "Análisis completo", personalizado: "Análisis personalizado",
               usb: "Análisis de memoria USB" };
const ESTADO = { preparando: "Preparando", enumerando: "Buscando archivos", analizando: "Analizando",
                 pausado: "En pausa", cancelando: "Deteniendo", terminado: "Terminado", cancelado: "Detenido",
                 error: "Error" };
const ACTIVOS = new Set(["preparando", "enumerando", "analizando", "pausado", "cancelando"]);

const tiempo = (s) => {
  if (s == null) return "—";
  s = Math.max(0, Math.round(s));
  const hh = Math.floor(s / 3600), mm = Math.floor((s % 3600) / 60), ss = s % 60;
  return hh ? `${hh} h ${String(mm).padStart(2, "0")} min` : mm ? `${mm} min ${String(ss).padStart(2, "0")} s` : `${ss} s`;
};
const tamano = (b) => b == null ? "—" : b >= 1073741824 ? `${(b / 1073741824).toFixed(1)} GB`
  : b >= 1048576 ? `${(b / 1048576).toFixed(0)} MB` : `${Math.round(b / 1024)} KB`;
// Rutas largas: se recorta el principio, porque lo que importa es el nombre del archivo.
const recortar = (ruta, max = 90) => ruta.length > max ? `…${ruta.slice(-max)}` : ruta;
const hace = (ts) => ts ? fmt.ago(new Date(ts * 1000).toISOString()) : "nunca";

function errorLocal(err) {
  if (err?.code === "solo_local") {
    return h("section", { class: "panel stack" }, h("h2", {}, "Solo desde el propio equipo"),
      h("p", {}, "La protección de un computador se controla sentado frente a él, en https://127.0.0.1:8443. "
        + "Así nadie en su red puede ordenar analizar o borrar archivos de este equipo."));
  }
  return h("p", { class: "notice notice-warn" }, err?.message || "No se pudo cargar la protección del equipo");
}

// ═══════════════════════════════════════════════════════ antivirus
export async function vistaAntivirus(ctx, cuerpo, actualizarResumen) {
  let estado;
  try {
    estado = await ctx.api.get("local/estado");
  } catch (e) {
    mount(cuerpo, errorLocal(e));
    return;
  }

  const monitorEl = h("div", {});
  const resumenEl = h("div", {});
  const profundoEl = h("div", {});
  const eventosEl = h("div", {});
  const cuarentenaEl = h("div", {});
  const ajustesEl = h("div", {});
  let temporizador = null;
  let ultimoId = null;
  let ultimoEstado = null;
  ctx.onCleanup(() => clearTimeout(temporizador));

  // ── lanzar análisis
  const rendimiento = h("select", { class: "input", "aria-label": "Rendimiento" },
    [["auto", "Automático: se aparta cuando usted trabaja"], ["turbo", "Máxima velocidad"],
     ["silencioso", "Silencioso: casi no se nota"]]
      .map(([v, l]) => h("option", { value: v, selected: estado.ajustes.rendimiento === v }, l)));
  const ruta = h("input", { class: "input", placeholder: "D:\\  o  C:\\Users\\usuario\\Documents",
    "aria-label": "Carpeta o unidad a analizar" });

  async function iniciar(modo, boton) {
    const cuerpo_ = { modo, rendimiento: rendimiento.value };
    if (modo === "personalizado") {
      if (!ruta.value.trim()) { ruta.focus(); return toast("Escriba la carpeta o unidad que quiere analizar", "error"); }
      cuerpo_.ruta = ruta.value.trim();
    }
    await busy(boton, async () => {
      try {
        pintarMonitor(await ctx.api.post("local/escaneo", cuerpo_));
        vigilar(true);
        monitorEl.scrollIntoView({ behavior: "smooth", block: "start" });
      } catch (e) { toastError(e); }
    });
  }
  const tarjetaModo = (modo, titulo, texto, primario) => {
    const b = h("button", { class: primario ? "btn btn-primary" : "btn" }, titulo);
    b.addEventListener("click", () => iniciar(modo, b));
    return h("div", { class: "modo-analisis" }, h("div", {}, h("h3", {}, titulo), h("p", { class: "muted" }, texto)), b);
  };
  const btnRuta = h("button", { class: "btn" }, "Analizar esta ruta");
  btnRuta.addEventListener("click", () => iniciar("personalizado", btnRuta));
  ruta.addEventListener("keydown", (e) => { if (e.key === "Enter") iniciar("personalizado", btnRuta); });

  // ── monitor del análisis en curso
  function pintarMonitor(s) {
    if (!s) {
      mount(monitorEl);
      return;
    }
    const activo = ACTIVOS.has(s.estado);
    const tono = s.maliciosos ? "danger" : s.sospechosos ? "warn" : "ok";
    const pct = Math.round(s.porcentaje * 10) / 10;

    const barra = h("span", {});
    barra.style.width = `${Math.max(pct, activo ? 1 : 0)}%`;
    const controles = h("div", { class: "row" });
    if (activo && s.estado !== "cancelando") {
      const pausa = h("button", { class: "btn btn-sm monitor-btn" }, s.estado === "pausado" ? "Reanudar" : "Pausar");
      pausa.addEventListener("click", () => busy(pausa, async () => {
        try { pintarMonitor(await ctx.api.post(`local/escaneo/${s.estado === "pausado" ? "reanudar" : "pausar"}`)); }
        catch (e) { toastError(e); }
      }));
      const detener = h("button", { class: "btn btn-sm monitor-btn" }, "Detener");
      detener.addEventListener("click", () => busy(detener, async () => {
        try { pintarMonitor(await ctx.api.post("local/escaneo/cancelar")); } catch (e) { toastError(e); }
      }));
      controles.append(pausa, detener);
    }

    const dato = (etiqueta, valor) => h("div", { class: "monitor-dato" },
      h("span", { class: "monitor-etiqueta" }, etiqueta), h("span", { class: "monitor-valor" }, valor));

    const total = s.total ?? s.descubiertos;
    mount(monitorEl, h("section", { class: "monitor-analisis", dataset: { estado: s.estado, tono },
      "aria-live": "polite" },
      h("div", { class: "monitor-cabeza" },
        h("div", {}, h("h2", {}, MODO[s.modo] || "Análisis"),
          h("p", {}, `${ESTADO[s.estado] || s.estado}${s.origen === "automatico" ? " (programado)" : ""}`
            + (s.estado === "pausado" || !activo ? "" : ` con ${s.hilos} de ${s.hilos_max} hilos`))),
        controles),
      h("div", { class: "monitor-cifra" },
        h("span", { class: "monitor-porcentaje" }, `${pct.toFixed(pct < 10 ? 1 : 0)} %`),
        h("span", { class: "monitor-sub" }, s.porcentaje_estimado && activo
          ? `${fmt.num(s.analizados)} analizados de ${fmt.num(s.descubiertos)} encontrados hasta ahora`
          : `${fmt.num(s.analizados)} de ${fmt.num(total || 0)} archivos`)),
      h("div", { class: "monitor-barra", role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100",
        "aria-valuenow": String(Math.round(pct)), "aria-label": "Progreso del análisis",
        dataset: { indeterminado: String(Boolean(s.porcentaje_estimado && activo)) } }, barra),
      h("p", { class: "monitor-archivo", title: s.archivo_actual || "" },
        activo ? (s.archivo_actual ? recortar(s.archivo_actual) : s.fase) : s.fase),
      h("div", { class: "monitor-datos" },
        dato("Transcurrido", tiempo(s.transcurrido_s)),
        dato("Restante", activo ? (s.eta_s != null ? tiempo(s.eta_s) : "calculando") : "—"),
        dato("Velocidad", activo ? `${fmt.num(s.velocidad_archivos_s)} arch/s, ${s.velocidad_mb_s} MB/s` : "—"),
        dato("Leídos", `${tamano(s.bytes_analizados)}${s.bytes_total ? ` de ${tamano(s.bytes_total)}` : ""}`),
        dato("Ya revisados antes", fmt.num(s.en_cache)),
        dato("CPU del equipo", activo ? `${Math.round(s.cpu_equipo)} % (otros programas ${Math.round(s.cpu_otros)} %)` : "—")),
      h("div", { class: "monitor-conteo" },
        h("span", { dataset: { tono: "ok" } }, `${fmt.num(s.limpios)} limpios`),
        h("span", { dataset: { tono: s.sospechosos ? "warn" : "" } }, `${fmt.num(s.sospechosos)} sospechosos`),
        h("span", { dataset: { tono: s.maliciosos ? "danger" : "" } }, `${fmt.num(s.maliciosos)} maliciosos`),
        h("span", {}, `${fmt.num(s.aislados)} en cuarentena`),
        s.omitidos ? h("span", {}, `${fmt.num(s.omitidos)} sin acceso`) : null),
      s.error ? h("p", { class: "notice notice-danger" }, s.error) : null,
      Array.isArray(s.amenazas) && s.amenazas.length
        ? h("div", { class: "monitor-amenazas stack" }, h("h3", {}, "Amenazas encontradas"),
          [...s.amenazas].reverse().slice(0, 40).map((a) => amenaza(a)))
        : !activo && s.estado === "terminado"
          ? h("p", { class: "monitor-limpio" }, "Ninguna capa de análisis encontró amenazas.")
          : null));
  }

  function amenaza(a) {
    const [etiqueta, tono] = NIVEL[a.nivel] || [a.nivel, "neutral"];
    const acciones = h("div", { class: "row" });
    if (a.estado === "aislado") acciones.append(badge("En cuarentena", "ok"));
    else if (a.estado === "no_aislado") acciones.append(badge("No se pudo aislar", "danger"));
    if (a.estado !== "aislado") {
      const aislar = h("button", { class: "btn btn-sm" }, "Poner en cuarentena");
      aislar.addEventListener("click", () => busy(aislar, async () => {
        try {
          toast((await ctx.api.post("local/cuarentena/aislar", { sha256: a.sha256 })).mensaje, "ok");
          a.estado = "aislado";
          cargarCuarentena();
          refrescar();
        } catch (e) { toastError(e); }
      }));
      acciones.append(aislar);
    }
    return h("div", { class: "finding", dataset: { tone: a.nivel === "malicioso" ? "danger" : "warn" } },
      h("div", { class: "stack-sm" },
        h("p", {}, h("strong", {}, a.nombre), " ", badge(etiqueta, tono),
          a.familia ? h("span", { class: "muted" }, ` ${a.familia}`) : null),
        h("p", { class: "mono muted" }, a.ruta),
        h("ul", {}, a.motivos.slice(0, 3).map((m) => h("li", {}, m))),
        a.estado === "detectado" && a.accion === "revisar"
          ? h("p", { class: "muted" }, "Solo hay señales heurísticas: no se aisló solo para no borrar un programa "
            + "legítimo por error. Si no reconoce el archivo, póngalo en cuarentena.")
          : null,
        acciones));
  }

  // Sondeo: rápido mientras hay análisis (la barra se mueve en vivo), lento en reposo para notar los
  // programados y los de USB.
  async function refrescar() {
    try {
      const s = await ctx.api.get("local/escaneo");
      pintarMonitor(s);
      const activo = s && ACTIVOS.has(s.estado);
      if (s && !activo && ultimoEstado && ACTIVOS.has(ultimoEstado) && s.id === ultimoId) {
        toast(s.maliciosos ? `Análisis terminado: ${s.maliciosos} amenaza(s)` : "Análisis terminado sin amenazas",
          s.maliciosos ? "error" : "ok");
        cargarCuarentena();
        cargarResumen(s);
        actualizarResumen?.();
      }
      ultimoId = s?.id; ultimoEstado = s?.estado;
      return activo;
    } catch { return false; }
  }
  async function cargarResumen(s) {
    if (!s || s.estado !== "terminado") { mount(resumenEl); return; }
    try {
      const r = await ctx.api.get("local/analisis/resumen");
      if (!r.hay) { mount(resumenEl); return; }
      const tono = s.maliciosos ? "danger" : s.sospechosos ? "warn" : "ok";
      mount(resumenEl, h("section", { class: "resumen-ia", dataset: { tono } },
        h("div", { class: "resumen-ia-icono" }, icon(s.maliciosos ? "alerta" : "check", { size: 24 })),
        h("div", { class: "stack-sm" },
          h("div", { class: "row", style: "gap:.5rem" }, h("strong", {}, "Resumen"),
            r.por_modelo ? badge("IA", "blue") : badge("Automático", "neutral")),
          h("p", {}, r.texto))));
    } catch { mount(resumenEl); }
  }

  function vigilar(inmediato = false) {
    clearTimeout(temporizador);
    const ciclo = async () => {
      const activo = await refrescar();
      if (!document.body.contains(monitorEl)) return;
      temporizador = setTimeout(ciclo, activo ? 500 : 4000);
    };
    if (inmediato) ciclo(); else temporizador = setTimeout(ciclo, 500);
  }

  // ── ajustes y tiempo real
  function pintarAjustes(e) {
    const conmutador = (campo, titulo, ayuda) => {
      const input = h("input", { type: "checkbox", checked: Boolean(e.ajustes[campo]) });
      input.addEventListener("change", async () => {
        try {
          const r = await ctx.api.put("local/ajustes", { [campo]: input.checked });
          e.ajustes = r.ajustes;
          toast(input.checked ? `${titulo}: activado` : `${titulo}: desactivado`, "ok");
          if (campo === "tiempo_real") cargarEventos();
        } catch (err) { input.checked = !input.checked; toastError(err); }
      });
      return h("label", { class: "check" }, input, h("span", {}, titulo, h("br"), h("small", { class: "muted" }, ayuda)));
    };
    const selector = (campo, opciones, etiqueta, ayuda) => {
      const s = h("select", { class: "input" }, opciones.map(([v, l]) =>
        h("option", { value: String(v), selected: Number(e.ajustes[campo]) === v }, l)));
      s.addEventListener("change", async () => {
        try { e.ajustes = (await ctx.api.put("local/ajustes", { [campo]: Number(s.value) })).ajustes; toast("Guardado", "ok"); }
        catch (err) { toastError(err); }
      });
      return field(etiqueta, s, ayuda);
    };
    const actualizar = h("button", { class: "btn btn-sm" }, "Actualizar firmas");
    actualizar.addEventListener("click", () => busy(actualizar, async () => {
      try {
        const r = await ctx.api.post("local/firmas/actualizar", {}, { timeout: 90000 });
        toast(r.mensaje, "ok");
        e.firmas = { ...e.firmas, total: r.total, actualizada: Date.now() / 1000 };
        pintarAjustes(e);
      } catch (err) { toastError(err); }
    }));

    const tr = e.tiempo_real;
    mount(ajustesEl, h("section", { class: "panel stack" },
      h("div", { class: "panel-head" },
        h("div", {}, h("h2", {}, "Protección permanente"),
          h("p", {}, tr.activo ? `Vigilando ${tr.carpetas.length} carpetas, los programas que arrancan y las memorias USB`
            : "El tiempo real está apagado: solo se analiza cuando usted lo pide o según la programación")),
        badge(tr.activo ? "Activa" : "Apagada", tr.activo ? "ok" : "warn")),
      h("div", { class: "grid grid-2" },
        conmutador("tiempo_real", "Protección en tiempo real",
          "Revisa al instante cada descarga, programa que se abre y memoria USB que se conecta."),
        conmutador("cuarentena_automatica", "Cuarentena automática",
          "Aísla solo lo que tiene evidencia fuerte (firma conocida o confirmado por Defender)."),
        e.defender ? conmutador("segunda_opinion_defender", "Segunda opinión de Windows Defender",
          "Cuando GuardianIA duda de un archivo, se lo pregunta también a Defender.") : null),
      h("div", { class: "form-row" },
        selector("auto_rapido_horas", [[0, "Desactivado"], [3, "Cada 3 horas"], [6, "Cada 6 horas"], [12, "Cada 12 horas"],
          [24, "Una vez al día"]], "Análisis rápido automático", `Último: ${hace(e.ultimo_rapido)}`),
        selector("auto_completo_dias", [[0, "Desactivado"], [1, "Diario"], [7, "Semanal"], [15, "Cada 15 días"],
          [30, "Mensual"]], "Análisis completo automático", `Último: ${hace(e.ultimo_completo)}`)),
      h("div", { class: "row row-between" },
        h("p", { class: "muted" }, `Base de firmas: ${fmt.num(e.firmas.total)} huellas de malware conocido, `
          + `actualizada ${hace(e.firmas.actualizada)}. Motor ${e.motor}.`),
        actualizar),
      e.equipo.administrador ? null
        : h("p", { class: "muted" }, "El servidor corre sin permisos de administrador: se analizan sus carpetas y "
          + "los programas que usted puede leer. Es lo recomendable; la VPN pedirá permiso solo al conectar.")));
  }

  async function cargarEventos() {
    try {
      const r = await ctx.api.get("local/eventos");
      const lista = r.eventos.filter((e) => e.nivel !== "limpio").slice(0, 12);
      mount(eventosEl, h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, "Actividad en tiempo real"),
          h("span", { class: "muted" }, `${fmt.num(r.tiempo_real.analizados)} revisados desde que arrancó`)),
        lista.length
          ? h("ul", { class: "list" }, lista.map((e) => h("li", {},
            icon(e.nivel === "info" ? "check" : "alerta"),
            h("div", { class: "list-main" },
              h("p", { class: "list-title" }, e.texto),
              h("p", { class: "list-sub" }, [hace(e.hora), e.accion].filter(Boolean).join(", "))),
            NIVEL[e.nivel] ? badge(...NIVEL[e.nivel]) : null)))
          : emptyState("Sin novedades", "Cuando algo llegue a Descargas, arranque o se conecte una USB, aparecerá aquí.")));
    } catch { /* secundario */ }
  }

  async function cargarCuarentena() {
    try {
      const filas = (await ctx.api.get("local/cuarentena")).filter((f) => f.estado === "en_cuarentena");
      mount(cuarentenaEl, h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("div", {}, h("h2", {}, "Cuarentena"),
          h("p", {}, "Archivos cifrados fuera de su carpeta: no pueden ejecutarse. Usted decide qué hacer."))),
        filas.length ? tablaCuarentena(filas)
          : emptyState("Cuarentena vacía", "Lo que se aísle aparecerá aquí, con el motivo.")));
    } catch { /* secundario */ }
  }

  function tablaCuarentena(filas) {
    return h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", {}, h("tr", {}, ["Archivo", "Amenaza", "Fecha", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, filas.map((f) => {
        const restaurar = h("button", { class: "btn btn-sm" }, "Restaurar");
        restaurar.addEventListener("click", async () => {
          const ok = await confirmDialog({
            title: "Restaurar el archivo", danger: f.nivel === "malicioso", confirmLabel: "Restaurar",
            message: `${f.archivo} volverá a ${f.ruta} y no se volverá a marcar. `
              + (f.nivel === "malicioso" ? "Fue clasificado como malicioso: hágalo solo si está seguro de que es "
                + "un falso positivo." : ""),
          });
          if (!ok) return;
          try { toast((await ctx.api.post(`local/cuarentena/${f.id}/restaurar`)).mensaje, "ok"); cargarCuarentena(); }
          catch (e) { toastError(e); }
        });
        const eliminar = h("button", { class: "btn btn-sm btn-danger" }, "Eliminar");
        eliminar.addEventListener("click", async () => {
          const ok = await confirmDialog({ title: "Eliminar definitivamente", danger: true, confirmLabel: "Eliminar",
            message: `${f.archivo} se borrará sin posibilidad de recuperarlo.` });
          if (!ok) return;
          try { toast((await ctx.api.post(`local/cuarentena/${f.id}/eliminar`)).mensaje, "ok"); cargarCuarentena(); }
          catch (e) { toastError(e); }
        });
        return h("tr", {},
          h("td", {}, h("strong", {}, f.archivo), h("br"), h("small", { class: "mono muted" }, f.ruta)),
          h("td", {}, badge(...(NIVEL[f.nivel] || [f.nivel, "neutral"])),
            f.familia ? h("div", { class: "muted" }, f.familia) : null,
            f.motivos?.length ? h("details", {}, h("summary", { class: "muted" }, "Por qué"),
              h("ul", {}, f.motivos.map((m) => h("li", {}, m)))) : null),
          h("td", {}, fmt.date(f.creado)),
          h("td", {}, h("div", { class: "row" }, restaurar, eliminar)));
      }))));
  }


  async function cargarProfundo() {
    const boton = h("button", { class: "btn btn-sm" }, "Revisar sistema y red");
    const cont = h("div", {});
    boton.addEventListener("click", () => busy(boton, async () => {
      try {
        const r = await ctx.api.get("local/revision-profunda", {}, { timeout: 60000 });
        pintarProfundo(cont, r);
      } catch (e) { toastError(e); }
    }));
    mount(profundoEl, h("section", { class: "panel stack" },
      h("div", { class: "panel-head" },
        h("div", {}, h("h2", {}, "Sistema y red (revisión profunda)"),
          h("p", {}, "Drivers sin firma, procesos suplantados, cambios en el arranque, conexiones y DNS "
            + "sospechosos. Observa el kernel desde afuera; para verlo desde dentro haría falta un driver "
            + "firmado por Microsoft, que este programa no tiene.")),
        boton),
      cont));
  }

  function pintarProfundo(cont, r) {
    const tono = r.estado === "peligro" ? "danger" : r.estado === "revisar" ? "warn" : "ok";
    const bloques = [];
    const seccion = (titulo, data) => {
      const items = (data.hallazgos || []).map((h_) => h("div", {
        class: "finding", dataset: { tone: h_.nivel === "peligroso" ? "danger" : "warn" } },
        h("div", { class: "stack-sm" },
          h("p", {}, h("strong", {}, h_.titulo), " ", badge(h_.nivel === "peligroso" ? "Peligroso" : "Revisar",
            h_.nivel === "peligroso" ? "danger" : "warn")),
          h("p", { class: "muted" }, h_.detalle))));
      return h("div", { class: "stack-sm" },
        h("h3", {}, titulo), h("p", { class: "muted" }, data.resumen),
        items.length ? h("div", { class: "stack-sm" }, items) : null);
    };
    mount(cont,
      h("div", { class: "resumen-ia", dataset: { tono } },
        h("div", { class: "resumen-ia-icono" }, icon(r.estado === "limpio" ? "check" : "alerta", { size: 22 })),
        h("div", { class: "stack-sm" }, h("strong", {}, "Resultado"), h("p", {}, r.resumen))),
      h("div", { class: "grid grid-2", style: "margin-top:1rem" },
        seccion("Núcleo del sistema", r.kernel),
        seccion("Red y DNS", r.red)));
  }

  mount(cuerpo,
    h("section", { class: "panel stack" },
      h("h2", {}, "Analizar este equipo"),
      h("div", { class: "grid grid-3" },
        tarjetaModo("rapido", "Análisis rápido", "Programas en ejecución, programas de inicio, Descargas, Escritorio "
          + "y temporales. Unos minutos.", true),
        tarjetaModo("completo", "Análisis completo", `Todos los discos: ${estado.equipo.unidades.join(", ") || "—"}. `
          + "El primero tarda; los siguientes solo revisan lo que cambió."),
        h("div", { class: "modo-analisis" },
          h("div", {}, h("h3", {}, "Carpeta o memoria USB"), h("p", { class: "muted" }, "Escriba la ruta completa.")),
          ruta, btnRuta)),
      field("Rendimiento", rendimiento, `Su equipo tiene ${estado.equipo.nucleos} hilos de CPU.`)),
    resumenEl, profundoEl, monitorEl, ajustesEl, eventosEl, cuarentenaEl);

  pintarAjustes(estado);
  cargarEventos();
  cargarCuarentena();
  cargarProfundo();
  vigilar(true);
}

// ═══════════════════════════════════════════════════════ túnel VPN
const bytes = (n) => n == null ? "—" : n >= 1073741824 ? `${(n / 1073741824).toFixed(2)} GB`
  : n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(0)} KB` : `${n} B`;
const reloj = (s) => {
  if (!s) return "0 s";
  const hh = Math.floor(s / 3600), mm = Math.floor((s % 3600) / 60), ss = s % 60;
  return hh ? `${hh}:${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`
    : `${mm}:${String(ss).padStart(2, "0")}`;
};

export async function panelTunelLocal(ctx, alCambiar) {
  // v3.8: SOLO su servidor GuardianIA VPN (Google Cloud) y Tor, con UN botón. La IA decide la vía
  // (modo «Automático»), vigila cada 30 s y cambia sola si algo empeora. ProtonVPN, WARP y los .conf
  // de terceros se retiraron: varias VPN a la vez generaban conflictos.
  const raiz = h("div", { class: "stack" });
  const botonEl = h("div", {});
  const propioEl = h("div", {});
  const statsEl = h("div", {});
  const anonEl = h("div", {});
  const torEl = h("div", {});
  let timerBoton = null, timerTor = null, timerStats = null;
  ctx.onCleanup(() => { clearTimeout(timerBoton); clearTimeout(timerTor); clearTimeout(timerStats); });
  const bandera = (cc) => (cc && /^[A-Z]{2}$/.test(cc))
    ? String.fromCodePoint(...[...cc].map((c) => 0x1F1E6 + c.charCodeAt(0) - 65)) : "🌐";
  const NOMBRE = { apagado: "Apagado", auto: "Automático (IA)", servidor: "WARP", tor: "Tor",
    servidor_tor: "WARP + Tor" };
  let wireguard = true;

  async function pintar() {
    try { wireguard = (await ctx.api.get("local/vpn")).wireguard_instalado !== false; } catch { /* sin datos */ }
    mount(raiz, botonEl, propioEl, statsEl, anonEl, torEl);
    pintarBoton();
    pintarPropio();
    pintarTor();
  }

  // ── el botón: modo, objetivo y decisión de la IA en vivo
  let modoSel = "auto", objetivoSel = "equilibrio", paisSel = "";
  async function pintarBoton() {
    clearTimeout(timerBoton);
    let st;
    try { st = await ctx.api.get("local/privacidad", { timeout: 20000 }); } catch (err) { mount(botonEl, errorLocal(err)); return; }
    const encendido = st.modo !== "apagado";
    if (encendido) { modoSel = st.modo; objetivoSel = st.objetivo; paisSel = st.pais || ""; }
    const ef = st.efectivo;
    const chip = (valor, texto, actual, fijar, titulo) => {
      const b = h("button", { class: `btn btn-sm ${valor === actual ? "btn-primary" : ""}`, type: "button",
        "aria-pressed": String(valor === actual), title: titulo || "" }, texto);
      b.addEventListener("click", () => { fijar(valor); if (encendido) activar(); else pintarBoton(); });
      return b;
    };
    const principal = h("button", { class: `btn btn-lg ${encendido ? "btn-danger" : "btn-primary"}` },
      encendido ? "Apagar protección" : "Proteger ahora");
    const activar = () => busy(principal, async () => {
      if (modoSel !== "tor") toast("Si Windows pide permiso de administrador para el túnel, acéptelo.", "info", { timeout: 7000 });
      try {
        const r = await ctx.api.put("local/privacidad", { modo: modoSel, objetivo: objetivoSel, pais: paisSel || null }, { timeout: 180000 });
        if (r.aviso) toast(r.aviso, "info", { timeout: 12000 });
        else if (r.razon) toast(`GuardianIA: ${r.razon}`, "ok", { timeout: 9000 });
        pintar();
        alCambiar?.();
      } catch (err) { toastError(err); pintarBoton(); }
    });
    principal.addEventListener("click", () => {
      if (!encendido) { activar(); return; }
      busy(principal, async () => {
        try { await ctx.api.put("local/privacidad", { modo: "apagado" }, { timeout: 120000 }); pintar(); alCambiar?.(); }
        catch (err) { toastError(err); }
      });
    });
    const relevos = st.tor?.circuito || [];
    const cadena = relevos.length ? relevos.map((r, i) => `${["Entrada", "Medio", "Salida"][i] || "Relevo"} ${bandera(r.pais)}`).join(" → ") : "";
    const nueva = h("button", { class: "btn btn-sm" }, "Nueva identidad Tor");
    nueva.addEventListener("click", () => busy(nueva, async () => {
      try { await ctx.api.post("local/privacidad/nueva-identidad", {}); toast("Circuitos Tor renovados: los sitios verán otra IP.", "ok"); pintarBoton(); }
      catch (err) { toastError(err); }
    }));
    const selPais = h("select", { class: "input", "aria-label": "País de salida de Tor" },
      [h("option", { value: "", selected: !paisSel }, "🌐 Cualquiera (el más rápido)"),
        ...Object.entries(PAISES_TOR).map(([c, n]) => h("option", { value: c, selected: paisSel === c }, `${bandera(c)} ${n}`))]);
    selPais.addEventListener("change", () => { paisSel = selPais.value; if (encendido) activar(); });
    const tono = st.protegido ? "ok" : encendido ? "warn" : "idle";
    const titulo = st.protegido ? `Protegido · ${NOMBRE[ef]}${st.modo === "auto" ? " (elegido por la IA)" : ""}`
      : encendido ? "Conectando…" : "Protección de su conexión";
    const srv = st.servidor || {};
    const detalle = st.protegido ? [
      (ef === "servidor" || ef === "servidor_tor") && srv.configurado ? `${bandera(srv.pais)} WARP` : "",
      st.tor?.listo ? `Tor${st.tor.aislamiento ? " · un circuito por sitio" : ""}` : "",
      st.anonimato ? `Anonimato ${st.anonimato.nivel} (${st.anonimato.puntaje}/100)` : ""].filter(Boolean).join(" · ")
      : "Un botón: la IA de GuardianIA elige entre WARP y Tor, conecta, verifica que su IP cambió y vigila cada 30 s.";
    mount(botonEl, h("section", { class: "panel stack privacidad", dataset: { tono } },
      h("div", { class: "panel-head" },
        h("div", {}, h("h2", {}, titulo), h("p", { class: "muted" }, detalle)),
        h("span", { class: "privacidad-orbe", "aria-hidden": "true" })),
      h("div", { class: "row" }, h("span", { class: "muted" }, "Vía:"),
        chip("auto", "🤖 Automático (IA)", modoSel, (v) => { modoSel = v; }, "La IA elige y cambia sola si algo empeora"),
        chip("servidor", "WARP", modoSel, (v) => { modoSel = v; }),
        chip("tor", "Tor", modoSel, (v) => { modoSel = v; }),
        chip("servidor_tor", "WARP + Tor", modoSel, (v) => { modoSel = v; })),
      h("div", { class: "row" }, h("span", { class: "muted" }, "Prioridad:"),
        chip("equilibrio", "Equilibrio", objetivoSel, (v) => { objetivoSel = v; }),
        chip("velocidad", "Velocidad", objetivoSel, (v) => { objetivoSel = v; }),
        chip("anonimato", "Anonimato máximo", objetivoSel, (v) => { objetivoSel = v; })),
      h("details", {}, h("summary", { class: "muted" }, "País de salida de Tor (opcional)"), selPais,
        h("p", { class: "muted" }, "Solo cambia el país que ven los sitios cuando la salida es Tor. WARP sale siempre por la red de Cloudflare.")),
      !wireguard && modoSel !== "tor" ? h("p", { class: "notice notice-warn" }, "Para usar su servidor falta WireGuard (gratis): ",
        h("a", { href: "https://www.wireguard.com/install/", target: "_blank", rel: "noopener noreferrer" }, "descargarlo"),
        ". Mientras tanto la IA usará Tor.") : null,
      st.respaldo ? h("p", { class: "notice notice-warn" }, "Su servidor no responde: le protegí con Tor y volveré a él en cuanto responda.") : null,
      tarjetaIA(st),
      st.tor?.activo && !st.tor?.listo ? h("div", { class: "progreso-tor", role: "progressbar", "aria-valuenow": st.tor.progreso || 0 },
        h("span", { style: `width:${Math.max(4, st.tor.progreso || 0)}%` })) : null,
      st.tor?.error ? h("p", { class: "notice notice-warn" }, st.tor.error) : null,
      cadena ? h("p", { class: "muted" }, `Circuito Tor: ${cadena}`) : null,
      ["reconectado", "tor_reiniciado", "cambio_ia", "restaurado", "respaldo_tor"].includes(st.ultimo?.evento)
        ? h("p", { class: "notice" }, `Vigilante: ${st.ultimo.razon}`)
        : st.ultimo?.evento === "fallo" ? h("p", { class: "notice notice-warn" }, st.ultimo.razon) : null,
      h("div", { class: "row" }, principal, st.tor?.listo ? nueva : null)));
    const vpnArriba = st.vpn_activa;
    if (vpnArriba) vigilarStats(true); else { clearTimeout(timerStats); mount(statsEl); }
    if (st.protegido && (ef === "servidor" || ef === "servidor_tor")) pintarAnonimato(false); else mount(anonEl);
    if (encendido) timerBoton = setTimeout(() => { if (document.body.contains(botonEl)) pintarBoton(); }, 4000);
  }

  // ── lo que la IA ve y por qué decide (explicable: nada de caja negra)
  function tarjetaIA(st) {
    const d = st.ia?.decision;
    if (!d || !d.modo) return null;
    const s = st.ia.senales || {};
    const barras = Object.entries(d.puntajes || {}).sort((a, b) => b[1] - a[1]).map(([m, v]) =>
      h("div", { class: "stack-sm" },
        h("div", { class: "row row-between" }, h("span", {}, `${m === d.modo ? "★ " : ""}${NOMBRE[m]}`),
          h("span", { class: "muted" }, `${Math.round(Math.max(0, v) * 100)}`)),
        h("div", { class: "progreso-tor" }, h("span", { style: `width:${Math.max(3, Math.min(100, v * 100))}%` }))));
    const dato = (etq, val) => h("span", { class: "badge" }, `${etq}: ${val}`);
    const aprend = st.ia.aprendizaje || {};
    return h("div", { class: "resumen-ia", dataset: { tono: "blue" } },
      h("div", { class: "resumen-ia-icono" }, icon("servidor", { size: 22 })),
      h("div", { class: "stack-sm" },
        h("div", { class: "row", style: "gap:.5rem" }, h("strong", {}, st.modo === "auto" ? "Decisión de la IA" : "La IA recomienda"),
          badge(`${NOMBRE[d.modo]} · confianza ${Math.round((d.confianza || 0) * 100)} %`, "blue")),
        h("p", {}, (d.razones || []).join(" ")),
        h("div", { class: "row" },
          s.servidor_configurado ? dato("Servidor", s.servidor_en_linea === false ? "sin respuesta" : s.servidor_en_linea ? "en línea" : "sin comprobar") : dato("Servidor", "no conectado"),
          s.latencia_servidor_ms != null ? dato("Respuesta", `${s.latencia_servidor_ms} ms`) : null,
          s.consumo_pct != null ? dato("Cupo del mes", `${s.consumo_pct} %`) : null,
          dato("Tor", s.tor_disponible ? "disponible" : "no instalado"),
          s.red_insegura != null ? dato("Red", s.red_insegura ? "pública" : "privada") : null),
        h("details", {}, h("summary", { class: "muted" }, "Puntajes y lo que aprendió en este equipo"),
          h("div", { class: "stack-sm" }, barras,
            h("p", { class: "muted" }, Object.entries(aprend).filter(([, v]) => v.intentos)
              .map(([m, v]) => `${NOMBRE[m]}: ${v.fiabilidad} % de éxito en ${v.intentos} intento(s)${v.segundos != null ? `, ~${v.segundos} s en conectar` : ""}`)
              .join(" · ") || "Aún no hay conexiones registradas: la IA empieza con valores prudentes y aprende de cada una.")))));
  }

  // ── Cloudflare WARP: gratis, sin cuenta, un solo botón. Reemplaza al servidor propio (Google Cloud).
  async function pintarPropio() {
    let e;
    try { e = await ctx.api.get("local/vpn/warp", { timeout: 25000 }); } catch { mount(propioEl); return; }
    if (!e.activo) {
      const activar = h("button", { class: "btn btn-primary" }, "Activar WARP (gratis)");
      activar.addEventListener("click", () => busy(activar, async () => {
        try {
          await ctx.api.post("local/vpn/warp", {}, { timeout: 30000 });
          toast("WARP activado. Presione «Proteger ahora» para conectar.", "ok", { timeout: 8000 });
          pintar();
        } catch (err) { toastError(err); }
      }));
      mount(propioEl, h("section", { class: "panel stack" },
        h("div", { class: "panel-head" }, h("h2", {}, "WARP (Cloudflare)")),
        h("p", { class: "muted" }, "Un toque, sin cuenta ni pasos técnicos. Cloudflare opera el servidor; "
          + "protege su tráfico frente a su operador o al WiFi público, aunque Cloudflare sí conoce su IP real "
          + "(para anonimato frente a eso también, combine con Tor)."),
        activar));
      return;
    }
    const desconectar = h("button", { class: "btn btn-sm" }, "Desconectar");
    desconectar.addEventListener("click", () => busy(desconectar, async () => {
      try { await ctx.api.post("local/vpn/desconectar"); toast("WARP desconectado.", "ok"); pintar(); }
      catch (err) { toastError(err); }
    }));
    const quitar = h("button", { class: "btn btn-sm btn-ghost" }, "Olvidar WARP en este equipo");
    quitar.addEventListener("click", async () => {
      if (!(await confirmDialog({ title: "Olvidar WARP", danger: true, confirmLabel: "Olvidar",
        message: "GuardianIA borrará el registro de WARP en este equipo. Puede volver a activarlo cuando quiera." }))) return;
      try { await ctx.api.del("local/vpn/warp"); pintar(); } catch (err) { toastError(err); }
    });
    mount(propioEl, h("section", { class: "panel stack" },
      h("div", { class: "panel-head" }, h("h2", {}, "WARP (Cloudflare)"),
        h("span", { class: "badge badge-ok" }, "Activo")),
      h("p", { class: "muted" }, "Listo para conectar. Sin registros, sin cuenta, gratis."),
      h("div", { class: "row" }, desconectar, quitar)));
  }

  // ── Tor: solo información y verificación (se enciende con el botón de arriba)
  async function pintarTor(verificar = false) {
    clearTimeout(timerTor);
    let t;
    try { t = await ctx.api.get(`local/tor?verificar=${verificar ? "true" : "false"}`, { timeout: 40000 }); }
    catch { mount(torEl); return; }
    const acciones = h("div", { class: "row" });
    if (t.listo) {
      const probar = h("button", { class: "btn" }, "Verificar con el Tor Project");
      probar.addEventListener("click", () => busy(probar, () => pintarTor(true)));
      acciones.append(probar);
    }
    if (!t.instalado) acciones.append(h("a", { class: "btn btn-primary", href: "https://www.torproject.org/download/",
      target: "_blank", rel: "noopener noreferrer" }, "Descargar Tor Browser (gratis)"));
    const estado = !t.activo ? "Apagado" : !t.listo ? `Conectando… ${t.progreso}%`
      : t.origen === "tor_browser" ? "Activo (Tor de Tor Browser)" : "Activo";
    mount(torEl, h("section", { class: "panel stack" },
      h("div", { class: "panel-head" }, h("h2", {}, "Tor"),
        h("span", { class: `badge ${t.listo ? "badge-ok" : t.activo ? "badge-warn" : ""}` }, estado)),
      h("p", { class: "muted" }, "Tres relevos cifrados en capas: ninguno sabe a la vez quién es usted y qué visita. "
        + "Se enciende con el botón de arriba (vía Tor o WARP + Tor, o cuando la IA lo elige)."),
      !t.instalado ? h("p", { class: "notice notice-warn" }, "Tor no está instalado: la IA solo podrá usar su servidor. Instale Tor Browser y recargue.") : null,
      t.is_tor === true ? h("p", { class: "notice" }, `Verificado por el Tor Project: sale por Tor con la IP ${t.ip_salida}. `
        + `Anonimato ${t.anonimato?.nivel || "alto"} (${t.anonimato?.puntaje ?? "—"}/100).`) : null,
      t.is_tor === false && verificar ? h("p", { class: "notice notice-warn" }, t.error || "El Tor Project dice que esta conexión NO sale por Tor.") : null,
      t.listo ? h("p", { class: "muted" }, t.como_usar) : null,
      acciones.children.length ? acciones : null));
    if (t.activo && !t.listo) timerTor = setTimeout(() => { if (document.body.contains(torEl)) pintarTor(); }, 3000);
  }

  // ── nivel de anonimato del túnel: IP, IPv6, DNS, kill switch, jurisdicción, operador y registros
  async function pintarAnonimato(repetir) {
    let a;
    try { a = await ctx.api.get(`local/vpn/anonimato?repetir=${repetir ? "true" : "false"}`, { timeout: 60000 }); }
    catch { mount(anonEl); return; }
    const tono = a.nivel === "alto" ? "ok" : a.nivel === "medio" ? "warn" : "danger";
    const marca = { ok: "✓", aviso: "⚠", falla: "✗" };
    const probar = h("button", { class: "btn btn-sm" }, "Probar fugas otra vez");
    probar.addEventListener("click", () => busy(probar, () => pintarAnonimato(true)));
    mount(anonEl, h("section", { class: "panel stack", "aria-live": "polite" },
      h("div", { class: "panel-head" },
        h("h2", {}, `Nivel de anonimato: ${a.nivel} (${a.puntaje}/100)`),
        h("span", { class: `badge badge-${tono === "ok" ? "ok" : tono === "warn" ? "warn" : "danger"}` }, a.nivel)),
      h("ul", { class: "list" }, a.revisiones.map((r) => h("li", {},
        h("div", { class: "list-main" }, h("p", { class: "list-title" }, `${marca[r.estado] || "·"} ${r.texto}`))))),
      h("details", {}, h("summary", {}, "Lo que una VPN no puede ocultar"),
        h("ul", {}, a.limites.map((l) => h("li", {}, l)))),
      h("div", { class: "row" }, probar)));
  }

  // ── estadísticas en vivo del túnel
  async function refrescarStats() {
    try {
      const st = await ctx.api.get("local/vpn/estadisticas");
      if (!st.activo) { mount(statsEl); return false; }
      const dato = (etq, val, sub) => h("div", { class: "monitor-dato" },
        h("span", { class: "monitor-etiqueta" }, etq),
        h("span", { class: "monitor-valor" }, val), sub ? h("span", { class: "monitor-etiqueta" }, sub) : null);
      const verificar = h("button", { class: "btn btn-sm monitor-btn" }, "Verificar salida");
      verificar.addEventListener("click", () => busy(verificar, async () => {
        try {
          const r = await ctx.api.post("local/vpn/verificar");
          toast(r.verificado ? `Verificado: su IP pública es ${r.ip} (${r.pais || "?"})`
            : "El túnel está activo pero su IP no cambió", r.verificado ? "ok" : "error");
          refrescarStats();
        } catch (err) { toastError(err); }
      }));
      mount(statsEl, h("section", { class: "monitor-analisis", dataset: { estado: "analizando",
        tono: st.verificado ? "ok" : "warn" }, "aria-live": "polite" },
        h("div", { class: "monitor-cabeza" },
          h("div", {}, h("h2", {}, st.proveedor === "warp" ? "Túnel WARP (Cloudflare)" : "Túnel a su servidor"),
            h("p", {}, st.verificado ? "Todo el equipo va cifrado" : "Túnel activo; confirme la salida con «Verificar»")),
          h("div", { class: "row" }, verificar)),
        h("div", { class: "monitor-cifra" },
          h("span", { class: "monitor-porcentaje", style: "font-size:clamp(2rem,5vw,3rem)" }, reloj(st.segundos_conectado)),
          h("span", { class: "monitor-sub" }, "conectado")),
        h("div", { class: "monitor-datos" },
          dato("IP de salida", st.ip_salida || "—", st.pais_salida ? `país ${st.pais_salida}` : ""),
          dato("Latencia", st.latencia_ms != null ? `${st.latencia_ms} ms` : "midiendo…"),
          dato("Descargado", bytes(st.recibidos_bytes)),
          dato("Subido", bytes(st.enviados_bytes)),
          dato("Último enlace", st.ultimo_handshake_hace_s != null ? `hace ${st.ultimo_handshake_hace_s} s` : "—",
            st.handshake_ok ? "activo" : "sin datos aún"),
          st.proveedor === "warp" ? dato("Cloudflare WARP", st.warp === "plus" ? "Plus" : st.warp === "on" ? "Encendido" : "Sin confirmar",
            st.colo ? `centro de datos ${st.colo}` : "") : null)));
      return true;
    } catch { return false; }
  }
  function vigilarStats(inmediato = false) {
    clearTimeout(timerStats);
    const ciclo = async () => {
      const sigue = await refrescarStats();
      if (!document.body.contains(statsEl) || !sigue) return;
      timerStats = setTimeout(ciclo, 3000);
    };
    if (inmediato) ciclo(); else timerStats = setTimeout(ciclo, 3000);
  }

  await pintar();
  return raiz;
}

// Países de salida de Tor (lista cerrada, igual que app/local/tor.py).
const PAISES_TOR = {"US": "Estados Unidos", "CA": "Canadá", "MX": "México", "BR": "Brasil", "AR": "Argentina", "CL": "Chile", "ES": "España", "GB": "Reino Unido", "FR": "Francia", "DE": "Alemania", "NL": "Países Bajos", "CH": "Suiza", "SE": "Suecia", "IT": "Italia", "PL": "Polonia", "RO": "Rumania", "JP": "Japón", "SG": "Singapur", "AU": "Australia", "IN": "India"};
