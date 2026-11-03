// Reloj inteligente por Web Bluetooth usando el perfil estándar Heart Rate (GATT 0x180D).
//
// Qué funciona: Chrome/Edge en Android, Windows, macOS y ChromeOS, en HTTPS o localhost.
// Qué no: Safari/iOS y Firefox no implementan Web Bluetooth.
// Relojes: Polar, Garmin (modo "transmitir FC"), Coros, Wahoo, Amazfit con "compartir FC" y la mayoría
// de bandas de pecho. Xiaomi/Huawei/Samsung usan protocolos propietarios: para ellos está la app Android
// con Health Connect. Lo decimos en la interfaz en vez de fingir compatibilidad universal.

export const bleSupported = () => "bluetooth" in navigator && window.isSecureContext;

// Parseo según la especificación Bluetooth SIG "Heart Rate Measurement" (0x2A37).
export function parseHeartRate(view) {
  const flags = view.getUint8(0);
  const wide = flags & 0x01;
  const contactSupported = flags & 0x04;
  const contact = contactSupported ? Boolean(flags & 0x02) : null;
  let offset = 1;
  const bpm = wide ? view.getUint16(offset, true) : view.getUint8(offset);
  offset += wide ? 2 : 1;
  if (flags & 0x08) offset += 2; // energía gastada: no se usa
  const rr = [];
  if (flags & 0x10) {
    for (; offset + 1 < view.byteLength; offset += 2) rr.push((view.getUint16(offset, true) / 1024) * 1000);
  }
  return { bpm, contact, rr };
}

// RMSSD: variabilidad de la frecuencia cardiaca, marcador de estrés/recuperación.
// Se descartan intervalos fisiológicamente imposibles y latidos ectópicos (>20 % de cambio).
export function rmssd(intervals) {
  const clean = intervals.filter((v) => v >= 300 && v <= 2000);
  const diffs = [];
  for (let i = 1; i < clean.length; i++) {
    if (Math.abs(clean[i] - clean[i - 1]) / clean[i - 1] <= 0.2) diffs.push(clean[i] - clean[i - 1]);
  }
  if (diffs.length < 8) return null;
  return Math.sqrt(diffs.reduce((a, d) => a + d * d, 0) / diffs.length);
}

const median = (arr) => {
  const s = [...arr].sort((a, b) => a - b);
  return s.length ? s[Math.floor(s.length / 2)] : null;
};

export class WatchLink extends EventTarget {
  constructor() {
    super();
    this.device = null;
    this.window = [];   // muestras de los últimos 5 s
    this.rr = [];       // intervalos RR recientes para HRV
    this.pending = [];  // lecturas agregadas listas para enviar
    this.battery = null;
    this._tick = null;
    this._manualDisconnect = false;
  }

  async connect() {
    this.device = await navigator.bluetooth.requestDevice({
      filters: [{ services: ["heart_rate"] }],
      optionalServices: ["battery_service", "device_information"],
    });
    this.device.addEventListener("gattserverdisconnected", () => this._onDisconnect());
    await this._attach();
    this._tick = setInterval(() => this._aggregate(), 5000);
    return this.device.name || "Reloj Bluetooth";
  }

  async _attach() {
    const server = await this.device.gatt.connect();
    const hr = await (await server.getPrimaryService("heart_rate")).getCharacteristic("heart_rate_measurement");
    hr.addEventListener("characteristicvaluechanged", (e) => {
      const m = parseHeartRate(e.target.value);
      if (m.bpm < 25 || m.bpm > 240) return;
      this.window.push(m);
      this.rr.push(...m.rr);
      if (this.rr.length > 120) this.rr.splice(0, this.rr.length - 120);
      this.dispatchEvent(new CustomEvent("beat", { detail: m }));
    });
    await hr.startNotifications();
    try {
      const bat = await (await server.getPrimaryService("battery_service")).getCharacteristic("battery_level");
      this.battery = (await bat.readValue()).getUint8(0);
    } catch { /* el reloj no expone batería */ }
    this.dispatchEvent(new CustomEvent("status", { detail: "connected" }));
  }

  _aggregate() {
    if (!this.window.length) return;
    const samples = this.window.splice(0);
    const withContact = samples.filter((s) => s.contact !== false);
    const quality = withContact.length / samples.length;
    const bpm = median((withContact.length ? withContact : samples).map((s) => s.bpm));
    this.pending.push({
      measured_at: new Date().toISOString(),
      heart_rate: Math.round(bpm),
      hrv_rmssd: (() => { const v = rmssd(this.rr); return v ? Math.min(300, Math.max(1, Math.round(v * 10) / 10)) : null; })(),
      activity: "rest",
      signal_quality: Math.round(quality * 100) / 100,
    });
    if (this.pending.length > 500) this.pending.splice(0, this.pending.length - 500);
  }

  takePending() {
    return this.pending.splice(0);
  }

  requeue(readings) {
    this.pending.unshift(...readings);
  }

  async _onDisconnect() {
    this.dispatchEvent(new CustomEvent("status", { detail: "reconnecting" }));
    if (this._manualDisconnect) return this.dispatchEvent(new CustomEvent("status", { detail: "disconnected" }));
    // El reloj sale de rango o duerme la radio: se reintenta con espera creciente.
    for (let i = 0; i < 5 && !this._manualDisconnect; i++) {
      await new Promise((r) => setTimeout(r, 1000 * 2 ** i));
      try { await this._attach(); return; } catch { /* sigue intentando */ }
    }
    this.dispatchEvent(new CustomEvent("status", { detail: "disconnected" }));
  }

  disconnect() {
    this._manualDisconnect = true;
    clearInterval(this._tick);
    this._aggregate();
    if (this.device?.gatt.connected) this.device.gatt.disconnect();
  }
}
