// Extracción de rasgos para el antivirus, 100 % en el navegador.
// El archivo NO se sube: se envían hash, cabecera, entropía y cadenas legibles.
// Privacidad (un PDF médico no viaja) y ancho de banda (un APK de 80 MB no viaja).

const MAGIC = [
  ["4d5a", "pe"], ["7f454c46", "elf"], ["25504446", "pdf"], ["504b0304", "zip"], ["d0cf11e0", "office"],
];

function kindOf(headerHex, name) {
  const lower = name.toLowerCase();
  for (const [sig, kind] of MAGIC) {
    if (headerHex.startsWith(sig)) {
      if (kind !== "zip") return kind;
      if (lower.endsWith(".apk")) return "apk";
      if (/\.(docx|xlsx|pptx|docm|xlsm)$/.test(lower)) return "office";
      return "unknown";
    }
  }
  if (/\.(js|vbs|ps1|bat|cmd|sh|py|hta|jse|wsf)$/.test(lower)) return "script";
  return "unknown";
}

function entropy(bytes) {
  if (!bytes.length) return 0;
  const counts = new Uint32Array(256);
  for (const b of bytes) counts[b]++;
  let e = 0;
  for (const c of counts) if (c) { const p = c / bytes.length; e -= p * Math.log2(p); }
  return Math.round(e * 1000) / 1000;
}

function printableStrings(bytes, { min = 6, max = 400 } = {}) {
  const out = new Set();
  let cur = "";
  for (const b of bytes) {
    if (b >= 0x20 && b < 0x7f) { cur += String.fromCharCode(b); continue; }
    if (cur.length >= min) out.add(cur.slice(0, 200));
    if (out.size >= max) break;
    cur = "";
  }
  if (cur.length >= min && out.size < max) out.add(cur.slice(0, 200));
  return [...out];
}

export const MAX_HASH_BYTES = 512 * 1024 * 1024;

export async function extractFeatures(file, onProgress) {
  if (file.size > MAX_HASH_BYTES) throw new Error("El archivo supera 512 MB; analícelo desde la app de escritorio o Android.");
  onProgress?.("Calculando huella SHA-256");
  const buffer = await file.arrayBuffer();
  const sha = await crypto.subtle.digest("SHA-256", buffer);
  const bytes = new Uint8Array(buffer);
  const headerHex = [...bytes.slice(0, 64)].map((b) => b.toString(16).padStart(2, "0")).join("");
  onProgress?.("Analizando contenido");
  const sample = bytes.subarray(0, 2 * 1024 * 1024);
  return {
    name: file.name.slice(0, 260),
    size: file.size,
    sha256: [...new Uint8Array(sha)].map((b) => b.toString(16).padStart(2, "0")).join(""),
    kind: kindOf(headerHex, file.name),
    header_hex: headerHex.slice(0, 256),
    strings: printableStrings(sample),
    entropy: entropy(bytes.subarray(0, 1024 * 1024)),
  };
}
