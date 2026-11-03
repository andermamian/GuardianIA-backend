// Enrutador por hash (#/salud). Sin servidor de rutas extra y compatible con la CSP 'self'.
// Cada vista recibe `ctx.onCleanup` para cerrar temporizadores, streams y Bluetooth al salir.

export function createRouter({ routes, outlet, ctx, fallback, onChange }) {
  let cleanups = [];
  let token = 0;

  async function render() {
    const [name, ...rest] = (location.hash.replace(/^#\/?/, "") || fallback).split("/");
    const route = routes[name] || routes[fallback];
    const current = ++token;
    cleanups.forEach((fn) => { try { fn(); } catch { /* ignorar */ } });
    cleanups = [];
    onChange?.(routes[name] ? name : fallback);
    outlet.setAttribute("aria-busy", "true");
    try {
      const view = await route.render({ ...ctx, params: rest, onCleanup: (fn) => cleanups.push(fn),
        isCurrent: () => current === token });
      if (current !== token) return; // el usuario ya navegó a otra vista
      outlet.replaceChildren(view);
      document.title = `${route.title} · ${ctx.appName}`;
      const heading = outlet.querySelector("h1");
      if (heading) { heading.tabIndex = -1; heading.focus({ preventScroll: true }); } // anuncia el cambio a lectores de pantalla
      window.scrollTo(0, 0);
    } catch (err) {
      if (current !== token) return;
      ctx.renderError?.(outlet, err);
    } finally {
      outlet.removeAttribute("aria-busy");
    }
  }

  window.addEventListener("hashchange", render);
  return { render, go: (path) => { location.hash = `#/${path}`; } };
}
