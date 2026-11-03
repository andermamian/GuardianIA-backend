// «Pantalla» de progreso del asistente (al estilo de la computadora de Manus): muestra en vivo lo que hace —buscar,
// escribir un documento, ejecutar código en el sandbox, armar un ZIP—, con la herramienta, sus argumentos, la salida
// de la terminal y una línea de tiempo para revisar cualquier paso ya terminado o saltar al directo.
import { h } from "../shared/dom.js";

const ICONO = { activo: "●", hecho: "✔", error: "✖" };
const NOMBRE_HERRAMIENTA = {
  "sandbox.ejecutar": "Sandbox", "estudio.crear": "Estudio", "web.buscar": "Navegador", "zip.crear": "Archivos",
  "modelo.responder": "Modelo", "modelo.corregir": "Modelo", "documentos.leer": "Documentos",
};

function json(valor) {
  try { return JSON.stringify(valor, null, 2); } catch { return String(valor); }
}

/** Devuelve {el, manejar(evento)}: `el` se inserta en el mensaje; `manejar` recibe los eventos del chat. */
export function pantallaProgreso() {
  const pasos = [];             // {id, titulo, herramienta, args, detalle, estado, salida, resultado, t0, t1}
  let seleccion = -1;           // paso que se está mirando
  let enVivo = true;            // sigue siempre el último paso
  let terminado = false;
  let reloj = null;

  const estado = h("span", { class: "pantalla-estado" }, "Trabajando");
  const alternar = h("button", { class: "btn btn-sm", type: "button", "aria-label": "Contraer la pantalla" }, "–");
  const barra = h("div", { class: "pantalla-barra" });
  const visor = h("div", { class: "pantalla-visor", "aria-live": "off" });
  const anterior = h("button", { class: "pantalla-nav", type: "button", "aria-label": "Paso anterior" }, "⏮");
  const siguiente = h("button", { class: "pantalla-nav", type: "button", "aria-label": "Paso siguiente" }, "⏭");
  const deslizador = h("input", { class: "pantalla-slider", type: "range", min: 0, max: 0, value: 0,
    "aria-label": "Línea de tiempo de los pasos" });
  const directo = h("button", { class: "pantalla-directo", type: "button" }, "● En vivo");
  const lista = h("ol", { class: "pantalla-pasos" });
  const cuerpo = h("div", { class: "pantalla-cuerpo" }, barra, visor,
    h("div", { class: "pantalla-linea" }, anterior, deslizador, siguiente, directo), lista);
  const el = h("section", { class: "pantalla", hidden: true, "aria-label": "Pantalla de progreso del asistente" },
    h("header", { class: "pantalla-cabeza" }, h("strong", {}, "🖥 Pantalla de GuardianIA"), estado, alternar), cuerpo);

  alternar.addEventListener("click", () => {
    cuerpo.hidden = !cuerpo.hidden;
    alternar.textContent = cuerpo.hidden ? "+" : "–";
    alternar.setAttribute("aria-label", cuerpo.hidden ? "Expandir la pantalla" : "Contraer la pantalla");
  });
  const ir = (i) => {
    seleccion = Math.max(0, Math.min(pasos.length - 1, i));
    enVivo = seleccion === pasos.length - 1 && !terminado;
    pintar();
  };
  anterior.addEventListener("click", () => { enVivo = false; ir(seleccion - 1); });
  siguiente.addEventListener("click", () => ir(seleccion + 1));
  deslizador.addEventListener("input", () => ir(Number(deslizador.value)));
  directo.addEventListener("click", () => { enVivo = true; ir(pasos.length - 1); });

  const seg = (p) => (((p.t1 || Date.now()) - p.t0) / 1000).toFixed(1);

  function pintarVisor(p) {
    const partes = [
      h("div", { class: "pantalla-herr" }, h("span", { class: "pantalla-chip" }, NOMBRE_HERRAMIENTA[p.herramienta] || p.herramienta || "Asistente"),
        h("code", {}, p.herramienta || "paso")),
    ];
    if (p.args && Object.keys(p.args).length) {
      partes.push(h("h4", {}, "Argumentos"), h("pre", { class: "pantalla-args" }, json(p.args)));
    }
    const terminal = p.salida || "";
    if (terminal) {
      const pre = h("pre", { class: "pantalla-terminal" });
      for (const [canal, texto] of p.trozos) pre.append(canal === "stderr" ? h("span", { class: "sandbox-err" }, texto) : document.createTextNode(texto));
      partes.push(h("h4", {}, "Terminal"), pre);
      queueMicrotask(() => { pre.scrollTop = pre.scrollHeight; });
    }
    partes.push(h("h4", {}, "Resultado"),
      h("p", { class: "pantalla-resultado", "data-estado": p.estado },
        p.estado === "activo" ? `En ejecución… ${seg(p)} s${p.detalle ? ` · ${p.detalle}` : ""}` : (p.resultado || (p.estado === "error" ? "Falló" : "Listo"))));
    visor.replaceChildren(...partes);
  }

  function pintar() {
    if (!pasos.length) return;
    el.hidden = false;
    if (enVivo) seleccion = pasos.length - 1;
    const p = pasos[seleccion];
    barra.replaceChildren(h("span", { class: `pantalla-icono pantalla-${p.estado}` }, ICONO[p.estado]),
      h("span", {}, p.titulo), h("span", { class: "muted" }, `${seleccion + 1}/${pasos.length}`));
    pintarVisor(p);
    deslizador.max = String(pasos.length - 1);
    deslizador.value = String(seleccion);
    directo.hidden = enVivo || terminado;
    directo.textContent = "⏩ Saltar al directo";
    lista.replaceChildren(...pasos.map((x, i) => {
      const li = h("li", { class: `pantalla-paso pantalla-${x.estado}${i === seleccion ? " actual" : ""}` },
        h("button", { type: "button", class: "pantalla-paso-btn" }, h("span", { class: "pantalla-icono" }, ICONO[x.estado]), x.titulo,
          h("span", { class: "muted" }, ` ${seg(x)} s`)));
      li.firstChild.addEventListener("click", () => { enVivo = false; ir(i); });
      return li;
    }));
  }

  function manejar(ev) {
    if (ev.tipo === "paso") {
      pasos.push({ id: ev.id, titulo: ev.titulo, herramienta: ev.herramienta, args: ev.args, detalle: ev.detalle || "",
        estado: "activo", salida: "", trozos: [], resultado: "", t0: Date.now(), t1: 0 });
      if (!reloj) reloj = setInterval(() => { if (!terminado && enVivo) pintar(); }, 500);
      pintar();
    } else if (ev.tipo === "paso_info" || ev.tipo === "paso_salida" || ev.tipo === "paso_fin") {
      const p = pasos.find((x) => x.id === ev.id);
      if (!p) return;
      if (ev.tipo === "paso_info") p.detalle = ev.detalle;
      if (ev.tipo === "paso_salida") { p.salida += ev.texto; p.trozos.push([ev.canal, ev.texto]); }
      if (ev.tipo === "paso_fin") { p.estado = ev.estado; p.resultado = ev.resultado || ""; p.t1 = Date.now(); }
      pintar();
    } else if (ev.tipo === "fin" || ev.tipo === "cancelado" || ev.tipo === "error") {
      if (!pasos.length) return;
      terminado = true;
      clearInterval(reloj);
      for (const p of pasos) if (p.estado === "activo") { p.estado = "hecho"; p.t1 = Date.now(); }
      estado.textContent = ev.tipo === "fin" ? "Terminado" : ev.tipo === "cancelado" ? "Detenido" : "Con errores";
      el.classList.add("pantalla-fin");
      pintar();
      if (ev.tipo === "fin" && !pasos.some((p) => p.estado === "error")) {   // todo bien: se pliega para dejar leer la respuesta
        cuerpo.hidden = true; alternar.textContent = "+";
      }
    }
  }
  return { el, manejar };
}
