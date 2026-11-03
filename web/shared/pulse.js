// Trazo tipo monitor de signos vitales. La frecuencia del dibujo es la frecuencia cardiaca real
// del usuario (no una animación decorativa): a 58 lpm los complejos se separan, a 120 se juntan.
// Sin datos, la línea queda plana. Con "reducir movimiento" se dibuja un trazo estático.

const REDUCED = matchMedia("(prefers-reduced-motion: reduce)");

// Forma aproximada de un complejo P-QRS-T normalizado en [0, 1] de fase.
function waveform(phase) {
  const g = (mu, sigma, amp) => amp * Math.exp(-((phase - mu) ** 2) / (2 * sigma ** 2));
  return g(0.18, 0.025, 0.12) - g(0.3, 0.008, 0.12) + g(0.33, 0.011, 1) - g(0.36, 0.01, 0.25) + g(0.58, 0.045, 0.28);
}

export function pulseTrace(canvas, { color = "#00e676", grid = "#173049" } = {}) {
  const ctx = canvas.getContext("2d");
  let bpm = null;
  let raf = 0;
  let x = 0;
  let phase = 0;
  let last = performance.now();
  let prevY = null;
  let w = 0, hgt = 0, dpr = 1;
  let visible = true;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    const rect = canvas.getBoundingClientRect();
    w = Math.max(1, rect.width);
    hgt = Math.max(1, rect.height);
    canvas.width = w * dpr;
    canvas.height = hgt * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    drawGrid();
    x = 0;
    prevY = null;
    if (REDUCED.matches) drawStatic();
  }

  function drawGrid() {
    ctx.fillStyle = getComputedStyle(canvas).getPropertyValue("--monitor") || "#0b1d2e";
    ctx.clearRect(0, 0, w, hgt);
    ctx.strokeStyle = grid;
    ctx.lineWidth = 1;
    for (let gx = 0; gx < w; gx += 24) { ctx.beginPath(); ctx.moveTo(gx + 0.5, 0); ctx.lineTo(gx + 0.5, hgt); ctx.stroke(); }
    for (let gy = 0; gy < hgt; gy += 24) { ctx.beginPath(); ctx.moveTo(0, gy + 0.5); ctx.lineTo(w, gy + 0.5); ctx.stroke(); }
  }

  const yFor = (value) => hgt * 0.62 - value * hgt * 0.42;

  function drawStatic() {
    drawGrid();
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    const beatPx = bpm ? (60 / bpm) * 90 : Infinity;
    for (let px = 0; px <= w; px++) {
      const v = bpm ? waveform((px % beatPx) / beatPx) : 0;
      px ? ctx.lineTo(px, yFor(v)) : ctx.moveTo(px, yFor(v));
    }
    ctx.stroke();
  }

  function frame(now) {
    const dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    const speed = 90; // píxeles por segundo, como el barrido de un monitor real
    const steps = Math.max(1, Math.round(dt * speed));
    for (let i = 0; i < steps; i++) {
      const value = bpm ? waveform(phase) : (Math.random() - 0.5) * 0.01;
      if (bpm) phase = (phase + (bpm / 60) / speed) % 1;
      const y = yFor(value);
      // Borra una franja por delante del cabezal: efecto de barrido.
      ctx.save();
      ctx.beginPath();
      ctx.rect(x + 1, 0, 14, hgt);
      ctx.clip();
      drawGrid();
      ctx.restore();
      if (prevY !== null) {
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(x - 1, prevY);
        ctx.lineTo(x, y);
        ctx.stroke();
      }
      prevY = y;
      x += 1;
      if (x > w) { x = 0; prevY = null; }
    }
    if (visible) raf = requestAnimationFrame(frame);
  }

  const ro = new ResizeObserver(resize);
  ro.observe(canvas);
  const onVisibility = () => {
    visible = document.visibilityState === "visible";
    cancelAnimationFrame(raf);
    if (visible && !REDUCED.matches) { last = performance.now(); raf = requestAnimationFrame(frame); }
  };
  document.addEventListener("visibilitychange", onVisibility);
  resize();
  if (!REDUCED.matches) raf = requestAnimationFrame(frame);

  return {
    setBpm(value) {
      bpm = value && value > 20 && value < 250 ? value : null;
      if (REDUCED.matches) drawStatic();
    },
    setColor(c) { color = c; },
    stop() {
      cancelAnimationFrame(raf);
      ro.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
    },
  };
}
