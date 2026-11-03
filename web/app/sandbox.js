// Sandbox de código: ejecuta lo que escribió el asistente (o lo que pegue la persona) en el servidor local,
// con la salida en vivo. Cada ejecución la inicia una persona con un botón; nunca corre sola.
import { ApiError } from "../shared/api.js";
import { h, toast, toastError } from "../shared/dom.js";

// Lenguajes que el sandbox sabe correr (si están instalados en el equipo) y sus alias más comunes.
const LENGUAJES = { py: "python", python: "python", python3: "python", js: "javascript", javascript: "javascript",
  node: "javascript", nodejs: "javascript", mjs: "javascript", ts: "typescript", typescript: "typescript",
  sh: "bash", bash: "bash", shell: "bash", zsh: "bash", php: "php", rb: "ruby", ruby: "ruby", pl: "perl",
  perl: "perl", lua: "lua", go: "go", golang: "go", java: "java", c: "c", cpp: "cpp", "c++": "cpp", cc: "cpp",
  rs: "rust", rust: "rust", cs: "csharp", csharp: "csharp", "c#": "csharp" };

export const lenguajeSandbox = (nombre) => LENGUAJES[String(nombre || "").trim().toLowerCase()] || null;

async function abrirFlujo(api, cuerpo, senal) {
  const pedir = () => fetch("/v1/sandbox/ejecutar", {
    method: "POST", signal: senal, credentials: "same-origin",
    headers: { "Content-Type": "application/json", Accept: "text/event-stream", Authorization: `Bearer ${api.token}` },
    body: JSON.stringify(cuerpo),
  });
  let res = await pedir();
  if (res.status === 401) { await api.refresh(); res = await pedir(); }
  if (!res.ok || !res.body) throw new ApiError(res.status, await res.json().catch(() => ({})));
  return res;
}

/**
 * Ejecuta `codigo` y pinta el avance en `panel`: etapa y tiempo corriendo, salida línea a línea (stderr en rojo)
 * y un resumen al terminar. Devuelve una función para detener la ejecución.
 */
export function correr(api, { lenguaje, codigo, timeout = 15 }, panel, { alTerminar } = {}) {
  const control = new AbortController();
  const estado = h("p", { class: "sandbox-estado" }, "Preparando el sandbox…");
  const salida = h("pre", { class: "sandbox-salida", "aria-live": "polite" });
  const detener = h("button", { class: "btn btn-sm", type: "button" }, "Detener");
  panel.hidden = false;
  panel.replaceChildren(h("div", { class: "sandbox-cabeza" }, estado, detener), salida);
  let inicio = null, modo = "", terminado = false;
  const reloj = setInterval(() => {
    if (inicio && !terminado) estado.textContent = `▶ Ejecutando… ${((Date.now() - inicio) / 1000).toFixed(1)} s · ${modo}`;
  }, 200);
  detener.addEventListener("click", () => { detener.disabled = true; control.abort(); });

  const terminar = (texto, tono) => {
    terminado = true; clearInterval(reloj); detener.remove();
    estado.textContent = texto; estado.dataset.tono = tono;
    alTerminar?.(tono);
  };
  const MOTIVOS = { timeout: "se cortó por superar el tiempo límite", salida_excesiva: "se cortó: demasiada salida",
    cancelado: "detenido", compilacion: "no compiló: revise los errores de arriba" };

  (async () => {
    try {
      const res = await abrirFlujo(api, { language: lenguaje, code: codigo, timeout }, control.signal);
      const lector = res.body.getReader(), dec = new TextDecoder();
      let pendiente = "";
      for (;;) {
        const { value, done } = await lector.read();
        if (done) break;
        pendiente += dec.decode(value, { stream: true });
        const partes = pendiente.split("\n\n");
        pendiente = partes.pop();
        for (const parte of partes) {
          if (!parte.startsWith("data:")) continue;
          let ev; try { ev = JSON.parse(parte.slice(5)); } catch { continue; }
          if (ev.tipo === "inicio") { inicio = Date.now(); modo = ev.modo === "docker" ? "aislado con Docker" : "proceso con límites"; }
          else if (ev.tipo === "etapa") { modo = `${ev.etapa === "compilando" ? "compilando" : "ejecutando"} · ${modo.split(" · ").pop()}`; }
          else if (ev.tipo === "salida") {
            const trozo = ev.canal === "stderr" ? h("span", { class: "sandbox-err" }, ev.texto) : document.createTextNode(ev.texto);
            const abajo = salida.scrollHeight - salida.scrollTop - salida.clientHeight < 40;
            salida.append(trozo);
            if (abajo) salida.scrollTop = salida.scrollHeight;
          } else if (ev.tipo === "error") { terminar(`✖ ${ev.mensaje}`, "error"); return; }
          else if (ev.tipo === "fin") {
            const motivo = MOTIVOS[ev.motivo];
            if (!salida.textContent) salida.append(h("span", { class: "muted" }, "(sin salida)"));
            if (motivo) terminar(`⏱ ${motivo} · ${ev.segundos} s`, "aviso");
            else if (ev.codigo === 0) terminar(`✔ Terminó bien en ${ev.segundos} s`, "ok");
            else terminar(`✖ Terminó con error (código ${ev.codigo}) en ${ev.segundos} s`, "error");
            return;
          }
        }
      }
      if (!terminado) terminar("Conexión cerrada", "aviso");
    } catch (e) {
      if (control.signal.aborted) terminar("⏹ Detenido", "aviso");
      else { terminar("✖ No se pudo ejecutar", "error"); toastError(e); }
    }
  })();
  return () => control.abort();
}

/** Diálogo libre: escribir o pegar código, elegir lenguaje y ejecutar. */
export function sandboxDialog(ctx, dialog, field) {
  const lenguaje = h("select", { class: "input", "aria-label": "Lenguaje" },
    h("option", { value: "python" }, "Python"), h("option", { value: "javascript" }, "JavaScript (Node)"));
  const POR_DEFECTO = { python: "print('Hola desde el sandbox')", javascript: "console.log('Hola desde el sandbox')",
    bash: "echo Hola desde el sandbox", go: 'package main\nimport "fmt"\nfunc main() { fmt.Println("Hola desde el sandbox") }',
    c: '#include <stdio.h>\nint main() { puts("Hola desde el sandbox"); return 0; }' };
  const codigo = h("textarea", { class: "input input-codigo", rows: 10, maxlength: 100000, spellcheck: "false",
    placeholder: "Escriba o pegue código en cualquier lenguaje instalado en este equipo" });
  const panel = h("div", { class: "sandbox-panel", hidden: true });
  const info = h("p", { class: "muted" }, "Consultando el sandbox…");
  ctx.api.get("sandbox/estado").then((e) => {
    info.textContent = e.nota;
    const actual = lenguaje.value;
    lenguaje.replaceChildren(...e.lenguajes.map((l) => h("option", { value: l.id, disabled: !l.disponible },
      l.nombre + (l.disponible ? (l.compila ? " · compila" : "") : " (no instalado)"))));
    lenguaje.value = actual;
  }).catch(() => { info.textContent = "El sandbox solo funciona desde este mismo equipo."; });
  lenguaje.addEventListener("change", () => { if (!codigo.value.trim()) codigo.placeholder = POR_DEFECTO[lenguaje.value] || codigo.placeholder; });
  const ejecutar = h("button", { class: "btn btn-primary", type: "button" }, "▶ Ejecutar");
  ejecutar.addEventListener("click", () => {
    if (!codigo.value.trim()) { toast("Escriba o pegue código primero", "info"); return; }
    ejecutar.disabled = true;
    correr(ctx.api, { lenguaje: lenguaje.value, codigo: codigo.value }, panel, { alTerminar: () => { ejecutar.disabled = false; } });
  });
  dialog({ title: "Sandbox de código", wide: true, body: h("div", { class: "stack" }, info,
    field("Lenguaje", lenguaje), field("Código", codigo), h("div", { class: "row" }, ejecutar), panel),
    actions: [{ label: "Cerrar" }] });
}
