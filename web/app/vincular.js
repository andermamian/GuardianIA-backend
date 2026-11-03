// Página /vincular: el celular se vincula con un código, reporta su estado en vivo y ejecuta las
// acciones remotas que envía el dueño desde el PC.
// Va en archivo aparte (no en línea) porque la CSP del servidor bloquea scripts y onclick en línea.
(function () {
  "use strict";
  var CLAVE = "gia_device_token", CLAVE_N = "gia_device_nombre";
  var MIN_ENTRE_ENVIOS_MS = 6000;           // el servidor acepta 12 por minuto: nunca lo rozamos
  var s = {                                 // estado de la página
    tk: null, watchId: null, timer: null, ultima: null, bat: null, cargando: null,
    gps: "waiting", seguimiento: true, estado: "ok", intervalo: 30,
    ultimoEnvio: 0, envioPendiente: null, info: {}, wake: null, quiereWake: false,
    alarma: null, bloqueo: false,
  };

  function $(id) { return document.getElementById(id); }
  function ver(id, mostrar) { var e = $(id); if (e) e.classList.toggle("oculto", !mostrar); }
  function nota(t) { var e = $("estado-js"); if (e) e.textContent = t; }
  function gGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function gSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  function gDel(k) { try { localStorage.removeItem(k); } catch (e) {} }
  function msg(donde, tipo, texto) {
    var e = $(donde); if (!e) return;
    e.textContent = "";
    if (!texto) return;
    var d = document.createElement("div"); d.className = "aviso " + tipo; d.textContent = texto; e.appendChild(d);
  }

  window.addEventListener("error", function (ev) { nota("Error en la página: " + (ev.message || "desconocido")); });
  window.addEventListener("unhandledrejection", function (ev) {
    nota("Error: " + ((ev.reason && ev.reason.message) || ev.reason || "desconocido"));
  });

  // ─────────────────────────── estado del GPS
  // Chrome solo entrega el GPS en https:// o en localhost. En http://192.168.x.x lo niega sin preguntar.
  var TEXTO_GPS = {
    ok: "Ubicación activa",
    waiting: "Buscando señal GPS…",
    https_required: "El GPS está bloqueado porque la página se abrió con http:// y no https://. En el PC arranca " +
      "GuardianIA con INICIAR_GUARDIANIA.bat y vuelve a escanear el QR. Mientras tanto el teléfono sí reporta " +
      "batería, red y conexión.",
    denied: "Permiso de ubicación denegado. Toca el candado junto a la dirección → Permisos → Ubicación → Permitir.",
    unavailable: "No se pudo leer el GPS. Revisa que la ubicación del teléfono esté encendida.",
    paused: "Seguimiento pausado desde tu PC. El teléfono solo avisa que sigue conectado; no envía su ubicación.",
  };
  function ponerGps(estado) {
    s.gps = estado;
    var e = $("estado-gps"); if (e) { e.textContent = TEXTO_GPS[estado] || estado; e.dataset.estado = estado; }
  }

  // ─────────────────────────── datos reales del equipo
  function recogerInfo() {
    var ua = navigator.userAgent || "", info = {};
    var mAnd = /Android\s+([\d.]+)/.exec(ua), mIos = /OS (\d+[_\d]*) like Mac/.exec(ua);
    info.sistema = mAnd ? "Android" : mIos ? "iOS" : (navigator.platform || "Otro");
    if (mAnd) info.version_sistema = mAnd[1]; else if (mIos) info.version_sistema = mIos[1].replace(/_/g, ".");
    var mChr = /(?:Chrome|CriOS)\/(\d+)/.exec(ua), mFf = /Firefox\/(\d+)/.exec(ua), mSam = /SamsungBrowser\/(\d+)/.exec(ua);
    info.navegador = mSam ? "Samsung Internet " + mSam[1] : mFf ? "Firefox " + mFf[1] : mChr ? "Chrome " + mChr[1] : "Navegador";
    var dpr = window.devicePixelRatio || 1;
    info.pantalla = Math.round(screen.width * dpr) + "x" + Math.round(screen.height * dpr);
    info.idioma = navigator.language || null;
    try { info.zona_horaria = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) {}
    var c = navigator.connection;
    if (c) {
      if (c.type) info.red = c.type;
      if (c.effectiveType) info.red_calidad = c.effectiveType;
      if (typeof c.downlink === "number") info.red_mbps = c.downlink;
    }
    if (navigator.deviceMemory) info.memoria_gb = navigator.deviceMemory;
    if (navigator.hardwareConcurrency) info.nucleos = navigator.hardwareConcurrency;
    info.pestana_visible = document.visibilityState === "visible";
    info.pantalla_activa = !!s.wake;
    for (var k in s.info) if (!(k in info) || k === "modelo" || k === "version_sistema") info[k] = s.info[k];
    return info;
  }
  // Chrome moderno oculta el modelo en el User-Agent; se pide por la API oficial (Client Hints).
  function infoAltaPrecision() {
    var uad = navigator.userAgentData;
    if (!uad || !uad.getHighEntropyValues) return Promise.resolve();
    return uad.getHighEntropyValues(["model", "platformVersion"]).then(function (v) {
      if (v.model) s.info.modelo = v.model;
      if (v.platformVersion && /Android/.test(navigator.userAgent)) s.info.version_sistema = v.platformVersion.split(".")[0];
    }).catch(function () {});
  }
  function leerBateria() {
    if (!navigator.getBattery) return Promise.resolve();
    return navigator.getBattery().then(function (b) {
      var actualizar = function () { s.bat = Math.round(b.level * 100); s.cargando = !!b.charging; pintarDatos(); };
      actualizar();
      if (!b._gia) { b._gia = true; b.addEventListener("levelchange", actualizar); b.addEventListener("chargingchange", function () { actualizar(); enviar(false); }); }
    }).catch(function () {});
  }

  // ─────────────────────────── envío al PC (latido + GPS)
  function enviar(forzar) {
    var t = s.tk || gGet(CLAVE);
    if (!t) return Promise.resolve(null);
    var espera = MIN_ENTRE_ENVIOS_MS - (Date.now() - s.ultimoEnvio);
    if (espera > 0) {
      // Demasiado seguido: se agenda UN envío al final de la ventana con los datos más nuevos, y quien
      // llamó recibe el resultado de ese envío (antes recibía null y mostraba «No se pudo enviar»).
      if (!s.envioPendiente) {
        s.envioPendiente = new Promise(function (ok) {
          s.envioTimer = setTimeout(function () { s.envioPendiente = null; ok(enviar(forzar)); }, espera);
        });
      }
      return s.envioPendiente;
    }
    s.ultimoEnvio = Date.now();
    var cuerpo = { device_token: t, battery: s.bat, charging: s.cargando, gps: s.gps, info: recogerInfo() };
    if (s.seguimiento && s.ultima) {
      var c = s.ultima.coords;
      cuerpo.lat = c.latitude; cuerpo.lon = c.longitude; cuerpo.accuracy_m = c.accuracy;
      if (typeof c.speed === "number" && c.speed >= 0) cuerpo.speed_ms = c.speed;
    }
    return fetch("/v1/devices/telemetry", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(cuerpo),
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) {
        if (r.status === 401) { perdioVinculo(); return null; }
        if (!r.ok) { nota("El PC respondió " + r.status + ". Reintentando…"); return null; }
        aplicarRespuesta(d);
        nota("Conectado · último reporte " + new Date().toLocaleTimeString());
        return d;
      });
    }).catch(function () { nota("Sin conexión con tu PC. Reintentando…"); return null; });
  }

  function aplicarRespuesta(d) {
    var antes = s.seguimiento;
    s.estado = d.estado || "ok";
    s.seguimiento = d.seguimiento !== false;
    if (d.siguiente_reporte_s && d.siguiente_reporte_s !== s.intervalo) { s.intervalo = d.siguiente_reporte_s; programarLatido(); }
    if (antes && !s.seguimiento) detenerGps("paused");
    if (!antes && s.seguimiento) iniciarGps();
    ver("aviso-reportado", s.estado === "lost" || s.estado === "stolen");
    if (s.bloqueo && s.estado === "ok") quitarCapa();          // el dueño lo marcó como recuperado
    if (d.comandos_pendientes > 0) traerComandos();
  }

  // ─────────────────────────── canal en vivo con el PC (WebSocket)
  // Las órdenes del dueño llegan al instante por aquí; el latido HTTP sigue como respaldo, así que si
  // una red bloquea WebSocket todo funciona igual, solo que con la demora del latido.
  function abrirCanal() {
    var t = s.tk || gGet(CLAVE);
    if (!t || !("WebSocket" in window) || (s.ws && s.ws.readyState <= 1)) return;
    var ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/v1/ws/equipo");
    s.ws = ws;
    ws.onopen = function () { s.wsIntentos = 0; ws.send(JSON.stringify({ device_token: t })); };
    ws.onmessage = function (e) {
      var m; try { m = JSON.parse(e.data); } catch (x) { return; }
      if (m.tipo === "conectado") { s.canal = true; pintarCanal(); return; }
      if (m.tipo !== "orden") return;
      aplicarRespuesta({ estado: m.estado, seguimiento: m.seguimiento, comandos_pendientes: m.comandos ? 1 : 0 });
      s.ultimoEnvio = 0; enviar(true);          // el PC ve el cambio aplicado sin esperar el latido
    };
    ws.onclose = function (e) {
      s.canal = false; pintarCanal();
      if (s.ws !== ws) return;                  // se cerró a propósito
      s.ws = null;
      if (e.code === 4401) return;              // token inválido: el latido HTTP mostrará el porqué
      var espera = Math.min(30000, 1000 * Math.pow(2, s.wsIntentos || 0)) * (0.5 + Math.random() / 2);
      s.wsIntentos = (s.wsIntentos || 0) + 1;
      s.wsTimer = setTimeout(abrirCanal, espera);
    };
  }
  function cerrarCanal() {
    if (s.wsTimer) clearTimeout(s.wsTimer);
    var ws = s.ws; s.ws = null; s.canal = false;
    if (ws) { try { ws.close(); } catch (e) {} }
  }
  function pintarCanal() {
    var e = $("canal"); if (!e) return;
    e.textContent = s.canal ? "● En vivo con tu PC" : "○ Reconectando con tu PC…";
    e.dataset.estado = s.canal ? "ok" : "no";
  }

  function programarLatido() {
    if (s.timer) clearInterval(s.timer);
    s.timer = setInterval(function () { enviar(false); }, s.intervalo * 1000);
  }

  function perdioVinculo() {
    detenerTodo();
    gDel(CLAVE); gDel(CLAVE_N);
    ver("paso-activo", false); ver("paso-vincular", true);
    msg("msg-vincular", "err", "Este teléfono ya no está vinculado en tu PC (lo eliminaron o se borró). Vincúlalo de nuevo con un código.");
  }

  // ─────────────────────────── GPS
  function iniciarGps() {
    if (!window.isSecureContext) { ponerGps("https_required"); return; }
    if (!navigator.geolocation) { ponerGps("unavailable"); return; }
    if (!s.seguimiento) { ponerGps("paused"); return; }
    if (s.watchId != null) return;
    ponerGps("waiting");
    s.watchId = navigator.geolocation.watchPosition(function (pos) {
      var primera = !s.ultima;
      s.ultima = pos; ponerGps("ok"); pintarDatos();
      enviar(primera);
    }, function (err) {
      ponerGps(err.code === 1 ? "denied" : "unavailable");
      enviar(false);
    }, { enableHighAccuracy: true, maximumAge: 10000, timeout: 30000 });
  }
  function detenerGps(motivo) {
    if (s.watchId != null && navigator.geolocation) { try { navigator.geolocation.clearWatch(s.watchId); } catch (e) {} }
    s.watchId = null; s.ultima = null;
    ponerGps(motivo); pintarDatos();
  }
  function posicionAhora() {
    return new Promise(function (ok, mal) {
      if (!window.isSecureContext) return mal(new Error("https_required"));
      if (!navigator.geolocation) return mal(new Error("unavailable"));
      navigator.geolocation.getCurrentPosition(ok, function (e) { mal(new Error(e.code === 1 ? "denied" : "unavailable")); },
        { enableHighAccuracy: true, timeout: 20000, maximumAge: 0 });
    });
  }

  // ─────────────────────────── pantalla de datos
  function fila(etiqueta, valor) {
    var f = document.createElement("div"); f.className = "fila";
    var a = document.createElement("span"); a.textContent = etiqueta;
    var b = document.createElement("span");
    if (valor instanceof Node) b.appendChild(valor); else b.textContent = valor;
    f.appendChild(a); f.appendChild(b); return f;
  }
  function pintarDatos() {
    var box = $("datos"); if (!box) return;
    box.textContent = "";
    if (s.bat != null) box.appendChild(fila("Batería", s.bat + " %" + (s.cargando ? " (cargando)" : "")));
    else if (!window.isSecureContext) box.appendChild(fila("Batería", "bloqueada sin https://"));
    var i = recogerInfo();
    if (i.red || i.red_calidad) box.appendChild(fila("Red", [i.red, i.red_calidad].filter(Boolean).join(" · ")));
    if (s.ultima) {
      var c = s.ultima.coords, a = document.createElement("a");
      a.href = "https://www.openstreetmap.org/?mlat=" + c.latitude + "&mlon=" + c.longitude + "#map=17/" + c.latitude + "/" + c.longitude;
      a.target = "_blank"; a.rel = "noopener"; a.textContent = c.latitude.toFixed(5) + ", " + c.longitude.toFixed(5);
      box.appendChild(fila("Precisión", "±" + Math.round(c.accuracy) + " m"));
      box.appendChild(fila("Posición", a));
    }
    var w = $("btn-wake"); if (w) w.textContent = s.wake ? "Permitir que la pantalla se apague" : "Mantener pantalla encendida";
  }

  // ─────────────────────────── acciones remotas (enviadas desde el PC)
  // Una página web NO puede bloquear el sistema del teléfono ni borrar sus fotos: bloquear y borrar
  // actúan sobre GuardianIA en este navegador, y así se le informa al dueño en el acuse.
  function traerComandos() {
    var t = s.tk || gGet(CLAVE); if (!t) return;
    if (s.trayendo) { s.otraVez = true; return; }
    s.trayendo = true;
    fetch("/v1/devices/commands/pending", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_token: t }) })
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (lista) { return lista.reduce(function (p, c) { return p.then(function () { return ejecutar(c); }); }, Promise.resolve()); })
      .catch(function () {})
      .then(function () { s.trayendo = false; if (s.otraVez) { s.otraVez = false; traerComandos(); } });
  }
  function acuse(c, estado, resultado) {
    var t = s.tk || gGet(CLAVE); if (!t) return Promise.resolve();
    return fetch("/v1/devices/commands/" + encodeURIComponent(c.id) + "/ack", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_token: t, signature: c.signature, status: estado, result: resultado || {} }),
    }).catch(function () {});
  }
  function ejecutar(c) {
    var p = c.payload || {};
    if (c.kind === "locate") {
      if (!s.seguimiento) return acuse(c, "failed", { motivo: "seguimiento pausado" });
      return posicionAhora().then(function (pos) {
        s.ultima = pos; ponerGps("ok"); pintarDatos(); s.ultimoEnvio = 0;
        return enviar(true).then(function () {
          return acuse(c, "completed", { lat: pos.coords.latitude, lon: pos.coords.longitude, precision_m: Math.round(pos.coords.accuracy) });
        });
      }, function (e) { ponerGps(e.message); return acuse(c, "failed", { motivo: TEXTO_GPS[e.message] || e.message }); });
    }
    if (c.kind === "ring") return sonar().then(function (r) { return acuse(c, "completed", r); });
    if (c.kind === "message") { mostrarCapa("Mensaje del dueño", p.mensaje || "", true); return acuse(c, "completed", { mostrado: true }); }
    if (c.kind === "lock") {
      s.bloqueo = true;
      mostrarCapa("Teléfono reportado", p.mensaje || "Este equipo está reportado como perdido.", false);
      return acuse(c, "completed", { alcance: "pagina", nota: "Una página web no puede bloquear el sistema del teléfono." });
    }
    if (c.kind === "wipe") {
      return acuse(c, "completed", { alcance: "navegador", nota: "Se borraron los datos de GuardianIA en este navegador." })
        .then(function () {
          detenerTodo(); gDel(CLAVE); gDel(CLAVE_N);
          try { localStorage.clear(); sessionStorage.clear(); } catch (e) {}
          ver("paso-activo", false); ver("paso-vincular", true);
          mostrarCapa("Datos borrados", "El dueño borró los datos de GuardianIA de este teléfono.", true);
        });
    }
    return acuse(c, "failed", { motivo: "acción desconocida" });
  }

  function mostrarCapa(titulo, texto, cerrable) {
    $("capa-titulo").textContent = titulo;
    $("capa-texto").textContent = texto;
    ver("capa-cerrar", cerrable);
    ver("capa", true);
  }
  function quitarCapa() { s.bloqueo = false; pararAlarma(); ver("capa", false); }

  // Alarma: sirena con Web Audio + vibración. Los navegadores solo dejan sonar si la persona ya tocó
  // la página alguna vez; si no, se muestra la capa roja y el acuse lo informa con honestidad.
  function sonar() {
    mostrarCapa("¡Aquí estoy!", "Este teléfono está sonando porque su dueño lo está buscando. Toca «Detener».", true);
    $("capa").classList.add("alarma");
    var vibra = false;
    try { vibra = !!(navigator.vibrate && navigator.vibrate([600, 300, 600, 300, 600, 300, 600, 300, 600])); } catch (e) {}
    var Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return Promise.resolve({ sonido: false, vibracion: vibra, motivo: "sin audio web" });
    try {
      var ctx = new Ctx(), osc = ctx.createOscillator(), vol = ctx.createGain();
      osc.type = "square"; vol.gain.value = 0.9;
      osc.connect(vol); vol.connect(ctx.destination);
      var t0 = ctx.currentTime;
      for (var i = 0; i < 60; i++) {                 // 30 s de sirena subiendo y bajando
        osc.frequency.setValueAtTime(880, t0 + i * 0.5);
        osc.frequency.linearRampToValueAtTime(1500, t0 + i * 0.5 + 0.25);
        osc.frequency.linearRampToValueAtTime(880, t0 + i * 0.5 + 0.5);
      }
      osc.start(); osc.stop(t0 + 30);
      s.alarma = ctx;
      return ctx.resume().then(function () {
        return { sonido: ctx.state === "running", vibracion: vibra,
                 motivo: ctx.state === "running" ? undefined : "el navegador exige tocar la pantalla antes de sonar" };
      }, function () { return { sonido: false, vibracion: vibra, motivo: "audio bloqueado por el navegador" }; });
    } catch (e) { return Promise.resolve({ sonido: false, vibracion: vibra, motivo: e.message }); }
  }
  function pararAlarma() {
    $("capa").classList.remove("alarma");
    try { navigator.vibrate && navigator.vibrate(0); } catch (e) {}
    if (s.alarma) { try { s.alarma.close(); } catch (e) {} s.alarma = null; }
  }

  // ─────────────────────────── mantener la pantalla encendida (Wake Lock)
  function pedirWake() {
    if (!("wakeLock" in navigator)) { msg("msg-activo", "err", "Este navegador no permite mantener la pantalla encendida."); return; }
    navigator.wakeLock.request("screen").then(function (w) {
      s.wake = w; pintarDatos(); enviar(false);
      w.addEventListener("release", function () { s.wake = null; pintarDatos(); });
    }).catch(function (e) { msg("msg-activo", "err", "No se pudo: " + e.message); });
  }
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible") {
      if (s.quiereWake && !s.wake) pedirWake();
      if (s.tk) { abrirCanal(); enviar(true); }
    }
  });

  // ─────────────────────────── flujo
  function codigoDeURL() { var m = /[?&]codigo=([0-9]{4,8})/.exec(location.search || ""); return m ? m[1] : ""; }

  function vincular() {
    var codigo = ($("codigo").value || "").replace(/[^0-9]/g, "");
    var nombre = ($("nombre").value || "").trim() || "Mi teléfono";
    if (codigo.length !== 6) { msg("msg-vincular", "err", "El código son 6 dígitos."); return; }
    msg("msg-vincular", "info", "Vinculando…");
    fetch("/v1/devices/vinculacion/canjear", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ codigo: codigo, nombre: nombre, model: s.info.modelo || null,
        os_version: s.info.version_sistema || null,
        platform: /Android/.test(navigator.userAgent) ? "android" : /iPhone|iPad/.test(navigator.userAgent) ? "ios" : "other" }),
    }).then(function (r) {
      return r.text().then(function (txt) {
        var d = {}; try { d = JSON.parse(txt); } catch (e) {}
        if (!r.ok) throw new Error(d.title || d.detail || ("El servidor respondió " + r.status));
        return d;
      });
    }).then(function (d) {
      s.tk = d.device_token; gSet(CLAVE, s.tk); gSet(CLAVE_N, d.nombre || nombre);
      msg("msg-vincular", "", "");
      irActivo(d.nombre || nombre);
    }).catch(function (e) { msg("msg-vincular", "err", (e && e.message) || "No se pudo conectar con tu PC."); });
  }

  function irActivo(nombre) {
    ver("paso-vincular", false); ver("paso-activo", true);
    $("nombre-activo").textContent = nombre + " está conectado a tu cuenta.";
    leerBateria().then(function () { iniciarGps(); enviar(true); });
    programarLatido();
    abrirCanal();
  }

  function detenerTodo() {
    detenerGps("waiting");
    if (s.timer) clearInterval(s.timer);
    if (s.envioTimer) clearTimeout(s.envioTimer);
    if (s.wake) { try { s.wake.release(); } catch (e) {} }
    cerrarCanal();
    s.timer = s.envioPendiente = s.envioTimer = s.wake = null; s.quiereWake = false; s.tk = null;
    quitarCapa();
  }

  var ACCIONES = {
    vincular: vincular,
    reportar: function () {
      if (!s.seguimiento) { msg("msg-activo", "info", TEXTO_GPS.paused); return; }
      msg("msg-activo", "info", "Leyendo el GPS…");
      posicionAhora().then(function (pos) {
        s.ultima = pos; ponerGps("ok"); pintarDatos(); s.ultimoEnvio = 0;
        return enviar(true).then(function (d) { msg("msg-activo", d ? "ok" : "err", d ? "Ubicación enviada a tu cuenta." : "No se pudo enviar."); });
      }, function (e) {
        ponerGps(e.message); s.ultimoEnvio = 0; enviar(true);
        msg("msg-activo", "err", TEXTO_GPS[e.message] || e.message);
      });
    },
    wake: function () {
      if (s.wake) { s.quiereWake = false; s.wake.release(); } else { s.quiereWake = true; pedirWake(); }
    },
    desvincular: function () {
      if (!confirm("¿Desvincular este teléfono? Dejará de reportar a tu cuenta.")) return;
      detenerTodo(); gDel(CLAVE); gDel(CLAVE_N);
      ver("paso-activo", false); ver("paso-vincular", true);
      msg("msg-vincular", "info", "Teléfono desvinculado en este navegador. Elimínalo también en Dispositivos del PC.");
    },
    limpiar: function () {
      detenerTodo(); gDel(CLAVE); gDel(CLAVE_N);
      ver("paso-activo", false); ver("paso-vincular", true);
      msg("msg-vincular", "ok", "Datos borrados. Este teléfono quedó como nuevo: escribe un código para vincular.");
    },
    cerrarCapa: function () { if (!s.bloqueo) quitarCapa(); else pararAlarma(); },
  };

  function iniciar() {
    document.addEventListener("click", function (ev) {
      var b = ev.target.closest && ev.target.closest("[data-accion]");
      if (b && ACCIONES[b.getAttribute("data-accion")]) ACCIONES[b.getAttribute("data-accion")]();
    });
    var c = codigoDeURL(); if (c) $("codigo").value = c;
    if (!window.isSecureContext) ponerGps("https_required");
    infoAltaPrecision().then(function () {
      var ya = gGet(CLAVE);
      if (ya) { s.tk = ya; irActivo(gGet(CLAVE_N) || "Este teléfono"); }
      else {
        ver("paso-vincular", true); ver("paso-activo", false);
        nota(window.isSecureContext ? "Listo. Escribe el código y toca Vincular."
          : "Aviso: conexión http://. Puedes vincular, pero el GPS solo funciona con https://.");
      }
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", iniciar);
  else iniciar();
})();
