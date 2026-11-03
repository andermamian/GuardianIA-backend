// Cliente HTTP de GuardianIA.
// - Access token solo en memoria (se pierde al cerrar la pestaña, a propósito).
// - Refresh token en cookie HttpOnly que JavaScript nunca ve (ver app/api/v1/web_auth.py).
// - Renovación "single-flight": si diez peticiones reciben 401 a la vez, se renueva una sola vez.
// - Errores RFC 7807 convertidos en ApiError con código estable para la interfaz.

export class ApiError extends Error {
  constructor(status, body = {}) {
    super(body.title || (status === 0 ? "Sin conexión con el servidor" : `Error ${status}`));
    this.status = status;
    this.code = body.code || "unknown";
    this.fields = body.errores || [];
    this.requestId = body.request_id;
    this.extra = body;
  }
}

const RENEWABLE = new Set(["token_expired", "invalid_token", "not_authenticated"]);

export function createClient({ webAuthBase, onSessionEnd }) {
  let accessToken = null;
  let refreshing = null;
  const listeners = new Set();

  function setToken(token) {
    accessToken = token;
    listeners.forEach((fn) => fn(token));
  }

  async function raw(method, path, { json, form, query, timeout = 20000, auth = true, web = false } = {}) {
    const url = new URL(path.startsWith("/") ? path : `/v1/${path}`, location.origin);
    for (const [k, v] of Object.entries(query || {})) if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
    const headers = { Accept: "application/json, application/problem+json" };
    if (auth && accessToken) headers.Authorization = `Bearer ${accessToken}`;
    if (web) headers["X-Guardian-Web"] = "1";
    let body;
    if (json !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(json); }
    if (form) body = form;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    let res;
    try {
      res = await fetch(url, { method, headers, body, signal: ctrl.signal, credentials: "same-origin" });
    } catch (e) {
      throw new ApiError(0, { title: e.name === "AbortError" ? "El servidor tardó demasiado en responder" : "Sin conexión con el servidor" });
    } finally {
      clearTimeout(timer);
    }
    return res;
  }

  async function parse(res) {
    if (res.status === 204) return null;
    const type = res.headers.get("content-type") || "";
    if (type.includes("json")) {
      const data = await res.json();
      if (!res.ok) throw new ApiError(res.status, data);
      return data;
    }
    if (!res.ok) throw new ApiError(res.status, { title: await res.text() });
    return res;
  }

  async function refresh() {
    if (!refreshing) {
      refreshing = (async () => {
        try {
          const res = await raw("POST", `${webAuthBase}/refresh`, { auth: false, web: true });
          const data = await parse(res);
          setToken(data.access_token);
          return data;
        } catch (e) {
          setToken(null);
          throw e;
        } finally {
          setTimeout(() => { refreshing = null; }, 0);
        }
      })();
    }
    return refreshing;
  }

  async function request(method, path, opts = {}) {
    let res = await raw(method, path, opts);
    if (res.status === 401 && opts.auth !== false) {
      const body = await res.clone().json().catch(() => ({}));
      if (RENEWABLE.has(body.code)) {
        try {
          await refresh();
          res = await raw(method, path, opts);
        } catch {
          onSessionEnd?.("expired");
          throw new ApiError(401, body);
        }
      } else if (["session_revoked", "account_inactive"].includes(body.code)) {
        setToken(null);
        onSessionEnd?.(body.code);
      }
    }
    return opts.rawResponse ? res : parse(res);
  }

  return {
    get token() { return accessToken; },
    setToken,
    onToken: (fn) => (listeners.add(fn), () => listeners.delete(fn)),
    refresh,
    get: (p, o) => request("GET", p, o),
    post: (p, json, o = {}) => request("POST", p, { ...o, json }),
    put: (p, json, o = {}) => request("PUT", p, { ...o, json }),
    patch: (p, json, o = {}) => request("PATCH", p, { ...o, json }),
    del: (p, o) => request("DELETE", p, o),
    upload: (p, form, o = {}) => request("POST", p, { ...o, form, timeout: 3600000 }),
    webAuth: (action, json) => request("POST", `${webAuthBase}/${action}`, { json, auth: action === "logout", web: true }),
    async download(path, fallbackName) {
      const res = await request("GET", path, { rawResponse: true, timeout: 120000 });
      if (!res.ok) await parse(res);
      const disp = res.headers.get("content-disposition") || "";
      const m = /filename\*=UTF-8''([^;]+)/i.exec(disp);
      const name = m ? decodeURIComponent(m[1]) : fallbackName;
      const blob = await res.blob();
      const href = URL.createObjectURL(blob);
      const a = Object.assign(document.createElement("a"), { href, download: name, rel: "noopener" });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(href), 10000);
    },
  };
}
