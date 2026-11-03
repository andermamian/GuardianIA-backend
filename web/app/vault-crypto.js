// Cifrado de extremo a extremo de la bóveda de contraseñas, en el navegador (Web Crypto).
//
// Contraseña maestra ─PBKDF2-SHA256 (600 000 iteraciones, recomendación OWASP 2023)─► clave AES-256-GCM
// que NUNCA sale de esta pestaña. El servidor recibe {v, iv, ct} y no puede descifrar.
// (La app Android usa Argon2id; Web Crypto no lo trae y cargar WASM de un tercero rompería la CSP.)
//
// La sal es única por usuario y no secreta: SHA-256 del id de la cuenta. No hay "recuperar contraseña
// maestra": si se olvida, las entradas son irrecuperables. Eso es la garantía, no un defecto.

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export const ITERATIONS = 600000;

export async function deriveKey(masterPassword, userId) {
  const salt = await crypto.subtle.digest("SHA-256", enc.encode(`guardianai-vault-v1:${userId}`));
  const base = await crypto.subtle.importKey("raw", enc.encode(masterPassword), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ITERATIONS },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function sealEntry(key, entry) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(entry)));
  return JSON.stringify({ v: 1, iv: b64(iv), ct: b64(ct) });
}

export async function openEntry(key, ciphertext) {
  const env = JSON.parse(ciphertext);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(env.iv) }, key, unb64(env.ct));
  return JSON.parse(dec.decode(pt));
}

// Generador con CSPRNG local y muestreo sin sesgo (rechazo), no Math.random ni módulo simple.
export function generatePassword(length = 20, symbols = true) {
  const sets = ["abcdefghijkmnpqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789"];
  if (symbols) sets.push("!@#$%&*-_=+?");
  const all = sets.join("");
  const pick = (alphabet) => {
    const limit = 256 - (256 % alphabet.length);
    const buf = new Uint8Array(1);
    do crypto.getRandomValues(buf); while (buf[0] >= limit);
    return alphabet[buf[0] % alphabet.length];
  };
  for (;;) {
    const pw = Array.from({ length }, () => pick(all)).join("");
    if (sets.every((set) => [...pw].some((c) => set.includes(c)))) return pw;
  }
}

export function strength(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  const unique = new Set(pw).size / Math.max(1, pw.length);
  const bits = pw.length * Math.log2(Math.max(pool, 1)) * Math.min(1, 0.5 + unique);
  return { bits: Math.round(bits), level: bits >= 80 ? "fuerte" : bits >= 50 ? "media" : "debil" };
}

// Have I Been Pwned por k-anonimato: solo salen del navegador 5 caracteres del SHA-1.
let breachServiceOff = false; // si el servidor lo tiene deshabilitado, no se vuelve a consultar en la sesión

export async function breachCount(api, password) {
  if (breachServiceOff) return null;
  const digest = await crypto.subtle.digest("SHA-1", enc.encode(password));
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  const res = await api.get(`vault/passwords/breach-range/${hex.slice(0, 5)}`, { rawResponse: true });
  if (!res.ok) { if (res.status === 503) breachServiceOff = true; return null; }
  const suffix = hex.slice(5);
  for (const line of (await res.text()).split("\n")) {
    const [s, count] = line.trim().split(":");
    if (s === suffix) return Number(count);
  }
  return 0;
}
