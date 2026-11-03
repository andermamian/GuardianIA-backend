import { badge, busy, confirmDialog, dialog, emptyState, field, fmt, h, icon, mount, toast, toastError } from "../../shared/dom.js";
import { breachCount, deriveKey, generatePassword, ITERATIONS, openEntry, sealEntry, strength } from "../vault-crypto.js";

const CATS = { photos: "Fotos", documents: "Documentos", videos: "Videos", financial: "Financiero", evidence: "Evidencia" };
const STRENGTH = { fuerte: ["Fuerte", "ok"], media: ["Media", "warn"], debil: ["Débil", "danger"] };
const AUTOLOCK_MS = 5 * 60 * 1000;

// La clave derivada vive solo en este módulo y se borra por inactividad o al salir de la vista.
let vaultKey = null;
let lockTimer = null;
const lock = () => { vaultKey = null; clearTimeout(lockTimer); };
const touch = () => { clearTimeout(lockTimer); lockTimer = setTimeout(lock, AUTOLOCK_MS); };

export default async function boveda(ctx) {
  let tab = ctx.params[0] === "claves" ? "claves" : "archivos";
  const body = h("div", { class: "stack" });
  const tabs = h("div", { class: "segmented", role: "tablist" },
    [["archivos", "Archivos"], ["claves", "Contraseñas"]].map(([id, label]) =>
      h("button", { type: "button", role: "tab", "aria-selected": String(tab === id), "aria-pressed": String(tab === id), onClick: () => ctx.navigate(`boveda/${id}`) }, label)));
  ctx.onCleanup(() => { if (document.visibilityState === "hidden") lock(); });
  const onHide = () => { if (document.visibilityState === "hidden") lock(); };
  document.addEventListener("visibilitychange", onHide);
  ctx.onCleanup(() => document.removeEventListener("visibilitychange", onHide));

  if (tab === "archivos") await filesTab(ctx, body); else await secretsTab(ctx, body);
  return h("div", { class: "stack" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, "Bóveda"),
      h("p", {}, tab === "archivos"
        ? "Documentos y fotos cifrados con una clave distinta por archivo."
        : "Sus contraseñas se cifran en este navegador. Ni GuardianIA ni su equipo de soporte pueden leerlas.")), tabs),
    body);
}

// =================================================================== archivos
async function filesTab(ctx, body) {
  let category = null;
  const quotaEl = h("div", {});
  const listEl = h("div", {});

  const input = h("input", { type: "file", multiple: true, hidden: true });
  const catSelect = h("select", { class: "input", "aria-label": "Categoría para subir" }, Object.entries(CATS).map(([k, v]) => h("option", { value: k }, v)));
  const pick = h("button", { class: "btn btn-primary", type: "button" }, icon("subir"), "Elegir archivos");
  const drop = h("div", { class: "drop" }, h("p", {}, "Arrastre archivos aquí o"), h("div", { class: "row" }, catSelect, pick),
    h("small", {}, "Imágenes, PDF, video, audio, Office, TXT y CSV. Hasta 25 MB por archivo."), input);
  pick.addEventListener("click", () => input.click());
  input.addEventListener("change", () => upload([...input.files]).finally(() => { input.value = ""; }));
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.dataset.over = ""; });
  drop.addEventListener("dragleave", () => delete drop.dataset.over);
  drop.addEventListener("drop", (e) => { e.preventDefault(); delete drop.dataset.over; upload([...e.dataTransfer.files]); });

  async function upload(files) {
    if (!files.length) return;
    await busy(pick, async () => {
      let ok = 0;
      for (const f of files) {
        if (f.size > 25 * 1024 * 1024) { toast(`${f.name}: supera 25 MB`, "error"); continue; }
        const form = new FormData();
        form.append("category", catSelect.value);
        form.append("file", f, f.name);
        try { await ctx.api.upload("vault/files", form); ok++; } catch (e) { toast(`${f.name}: ${e.message}`, "error"); }
      }
      if (ok) toast(`${ok} ${ok === 1 ? "archivo guardado" : "archivos guardados"}`, "ok");
      load();
    });
  }

  async function load() {
    try {
      const [q, v] = await Promise.all([ctx.api.get("vault/quota"), ctx.api.get("vault", { query: { category } })]);
      const tone = q.porcentaje >= 90 ? "danger" : q.porcentaje >= 75 ? "warn" : null;
      const bar = h("span", {});
      bar.style.width = `${Math.min(100, q.porcentaje)}%`;
      mount(quotaEl, h("div", { class: "row row-between" }, h("span", {}, `${fmt.num(q.usado_mb, 1)} MB de ${fmt.num(q.limite_mb)} MB`), h("span", { class: "muted" }, `Plan ${q.plan}`)),
        h("div", { class: "meter", dataset: tone ? { tone } : {} }, bar));
      const chips = h("div", { class: "segmented", role: "group", "aria-label": "Filtrar" },
        [[null, `Todos (${v.total_archivos})`], ...Object.entries(CATS).map(([k, l]) => [k, `${l} (${v.por_categoria[k] || 0})`])]
          .map(([k, l]) => h("button", { type: "button", "aria-pressed": String(category === k), onClick: () => { category = k; load(); } }, l)));
      mount(listEl, chips, v.archivos.length ? h("ul", { class: "list" }, v.archivos.map((f) => fileRow(ctx, f, load)))
        : emptyState("Nada por aquí", category ? "No hay archivos en esta categoría." : "Suba su cédula, historia clínica o fotos importantes para tenerlas a salvo."));
    } catch (e) { toastError(e); }
  }
  mount(body, h("section", { class: "panel stack" }, quotaEl, drop), h("section", { class: "panel" }, listEl));
  await load();
}

function fileRow(ctx, f, reload) {
  const dl = h("button", { class: "icon-btn", "aria-label": `Descargar ${f.filename}` }, icon("bajar"));
  dl.addEventListener("click", () => busy(dl, async () => { try { await ctx.api.download(`vault/files/${f.id}/download`, f.filename); } catch (e) { toastError(e); } }));
  const del = h("button", { class: "icon-btn", "aria-label": `Eliminar ${f.filename}` }, icon("papelera"));
  del.addEventListener("click", async () => {
    if (!(await confirmDialog({ title: "Eliminar archivo", message: `${f.filename} se borrará de forma permanente.`, confirmLabel: "Eliminar", danger: true }))) return;
    try { await ctx.api.del(`vault/files/${f.id}`); toast("Archivo eliminado", "ok"); reload(); } catch (e) { toastError(e); }
  });
  return h("li", {}, icon("archivo"),
    h("div", { class: "list-main" }, h("p", { class: "list-title" }, f.filename), h("p", { class: "list-sub" }, `${fmt.bytes(f.size_bytes)}. ${fmt.date(f.created_at)}`)),
    badge(CATS[f.category] || f.category), dl, del);
}

// ================================================================ contraseñas
async function secretsTab(ctx, body) {
  if (!vaultKey) return mount(body, unlockPanel(ctx, body));
  touch();
  let entries = [];
  try {
    const rows = await ctx.api.get("vault/secrets");
    entries = await Promise.all(rows.map(async (r) => {
      try { return { ...r, data: await openEntry(vaultKey, r.ciphertext) }; } catch { return { ...r, data: null }; }
    }));
  } catch (e) { return toastError(e); }
  const unreadable = entries.filter((e) => !e.data).length;
  const audit = await ctx.api.get("vault/secrets/audit");
  const q = h("input", { class: "input", type: "search", placeholder: "Buscar sitio o usuario", "aria-label": "Buscar" });
  const listEl = h("ul", { class: "list" });
  const draw = () => {
    const term = q.value.toLowerCase();
    const shown = entries.filter((e) => e.data && `${e.data.sitio} ${e.data.usuario}`.toLowerCase().includes(term));
    listEl.replaceChildren(...(shown.length ? shown.map((e) => secretRow(ctx, e, body)) : [h("li", {}, h("p", { class: "muted" }, entries.length ? "Sin resultados." : "Aún no guarda contraseñas."))]));
  };
  q.addEventListener("input", draw);
  const add = h("button", { class: "btn btn-primary" }, icon("mas_simbolo"), "Agregar");
  add.addEventListener("click", () => secretDialog(ctx, null, body));
  const lockBtn = h("button", { class: "btn" }, icon("boveda"), "Bloquear");
  lockBtn.addEventListener("click", () => { lock(); secretsTab(ctx, body); });
  mount(body,
    h("section", { class: "grid grid-3" },
      h("div", { class: "panel stat" }, h("span", { class: "stat-label" }, "Guardadas"), h("span", { class: "stat-value" }, audit.total)),
      h("div", { class: "panel stat" }, h("span", { class: "stat-label" }, "Débiles"), h("span", { class: "stat-value" }, audit.debiles)),
      h("div", { class: "panel stat" }, h("span", { class: "stat-label" }, "Aparecen en filtraciones"), h("span", { class: "stat-value" }, audit.comprometidas))),
    unreadable ? h("p", { class: "notice notice-warn" }, `${unreadable} entradas no se pudieron abrir con esta contraseña maestra. Se crearon con otra.`) : null,
    h("section", { class: "panel stack" }, h("div", { class: "row" }, h("div", { class: "field" }, q), add, lockBtn), listEl));
  draw();
}

function unlockPanel(ctx, body) {
  const pw = h("input", { class: "input", type: "password", autocomplete: "current-password", required: true, minlength: 10 });
  const btn = h("button", { class: "btn btn-primary", type: "submit" }, "Desbloquear");
  const form = h("form", { class: "form" },
    h("h2", {}, "Desbloquee su bóveda"),
    h("p", { class: "muted" }, "Use su contraseña maestra. Es distinta a la de su cuenta y nunca se envía al servidor. Si la olvida, nadie puede recuperar sus contraseñas guardadas."),
    field("Contraseña maestra", pw),
    h("div", { class: "row" }, btn));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    busy(btn, async () => {
      btn.textContent = "Derivando clave";
      try {
        const key = await deriveKey(pw.value, ctx.user.id);
        const rows = await ctx.api.get("vault/secrets");
        if (rows.length) {
          const opened = await Promise.allSettled(rows.slice(0, 3).map((r) => openEntry(key, r.ciphertext)));
          if (!opened.some((o) => o.status === "fulfilled")) {
            btn.textContent = "Desbloquear";
            pw.setAttribute("aria-invalid", "true");
            pw.value = "";
            return toast("Contraseña maestra incorrecta", "error");
          }
        } else if (strength(pw.value).level === "debil") {
          btn.textContent = "Desbloquear";
          return toast("Para crear la bóveda use una contraseña maestra más larga (una frase de 4 o más palabras).", "error");
        }
        vaultKey = key;
        pw.value = "";
        secretsTab(ctx, body);
      } catch (e2) { btn.textContent = "Desbloquear"; toastError(e2); }
    });
  });
  setTimeout(() => pw.focus());
  return h("section", { class: "panel" }, form, h("p", { class: "muted" }, `Cifrado AES-256-GCM con clave derivada por PBKDF2-SHA256 (${fmt.num(ITERATIONS)} iteraciones).`));
}

function secretRow(ctx, e, body) {
  const [label, tone] = STRENGTH[e.strength] || ["—", "neutral"];
  const copy = h("button", { class: "icon-btn", "aria-label": `Copiar contraseña de ${e.data.sitio}` }, icon("copiar"));
  copy.addEventListener("click", async () => {
    touch();
    await navigator.clipboard.writeText(e.data.clave);
    toast("Copiada. Se borrará del portapapeles en 30 s.", "ok");
    setTimeout(async () => { try { if ((await navigator.clipboard.readText()) === e.data.clave) await navigator.clipboard.writeText(""); } catch { /* sin permiso de lectura */ } }, 30000);
  });
  const edit = h("button", { class: "btn btn-sm" }, "Editar");
  edit.addEventListener("click", () => secretDialog(ctx, e, body));
  return h("li", {},
    h("div", { class: "list-main" }, h("p", { class: "list-title" }, e.data.sitio), h("p", { class: "list-sub" }, e.data.usuario || "Sin usuario")),
    e.breached ? badge("Filtrada", "danger") : badge(label, tone), copy, edit);
}

function secretDialog(ctx, entry, body) {
  touch();
  const d = entry?.data || {};
  const pw = h("input", { class: "input mono", name: "clave", type: "password", required: true, value: d.clave || "", autocomplete: "new-password" });
  const meter = h("p", { class: "muted", "aria-live": "polite" });
  const updateMeter = () => {
    const s = strength(pw.value);
    meter.textContent = pw.value ? `Fortaleza ${STRENGTH[s.level][0].toLowerCase()} (${s.bits} bits)` : "";
  };
  pw.addEventListener("input", updateMeter);
  const show = h("button", { type: "button", class: "btn btn-sm", onClick: () => { pw.type = pw.type === "password" ? "text" : "password"; } }, icon("ojo"), "Mostrar");
  const gen = h("button", { type: "button", class: "btn btn-sm", onClick: () => { pw.value = generatePassword(20, true); pw.type = "text"; updateMeter(); } }, "Generar segura");
  const form = h("form", { class: "form" },
    field("Sitio o aplicación", h("input", { class: "input", name: "sitio", required: true, value: d.sitio || "" })),
    field("Usuario o correo", h("input", { class: "input", name: "usuario", value: d.usuario || "", autocomplete: "off" })),
    field("Contraseña", pw), h("div", { class: "row" }, show, gen), meter,
    field("Notas", h("textarea", { class: "input", name: "notas" }, d.notas || "")));
  updateMeter();
  const actions = [{ label: "Cancelar" }];
  if (entry) actions.unshift({ label: "Eliminar", onClick: async (close) => {
    if (!(await confirmDialog({ title: "Eliminar contraseña", message: `Se borrará la entrada de ${d.sitio}.`, danger: true, confirmLabel: "Eliminar" }))) return false;
    try { await ctx.api.del(`vault/secrets/${entry.id}`); close(); secretsTab(ctx, body); } catch (e) { toastError(e); }
    return false;
  } });
  actions.push({ label: "Guardar", kind: "primary", onClick: async (close) => {
    if (!form.reportValidity() || !vaultKey) return false;
    const data = { sitio: form.elements.namedItem("sitio").value.trim(), usuario: form.elements.namedItem("usuario").value.trim(), clave: pw.value, notas: form.elements.namedItem("notas").value.trim() };
    let breached = false;
    try { breached = ((await breachCount(ctx.api, data.clave)) || 0) > 0; } catch { /* servicio no disponible: se guarda igual */ }
    if (breached && !(await confirmDialog({ title: "Contraseña filtrada", message: "Esta contraseña aparece en filtraciones públicas. Los atacantes la prueban primero. ¿Guardarla de todos modos?", confirmLabel: "Guardar igual", danger: true }))) return false;
    try {
      const payload = { ciphertext: await sealEntry(vaultKey, data), strength: strength(data.clave).level, breached };
      entry ? await ctx.api.put(`vault/secrets/${entry.id}`, payload) : await ctx.api.post("vault/secrets", payload);
      toast("Guardada", "ok");
      close();
      secretsTab(ctx, body);
    } catch (e) { toastError(e); }
    return false;
  } });
  dialog({ title: entry ? d.sitio : "Nueva contraseña", body: form, actions });
}
