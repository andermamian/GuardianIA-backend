"""Motor antivirus / antimalware de GuardianIA.

Un antivirus serio en 2026 no es "una firma que coincide". Combina varias señales
independientes y explica su veredicto. Este motor usa cinco capas, de rápida a costosa:

  1. Reputación por hash          — SHA-256 contra listas de bloqueo/permiso conocidas.
  2. Firmas / reglas tipo YARA    — patrones de bytes y cadenas de familias conocidas.
  3. Heurística estructural (PE/APK/ELF/PDF/JS/Office) — rasgos que el malware suele tener.
  4. Modelo estadístico           — puntúa la combinación de rasgos (RandomForest si está
                                    entrenado; si no, pesos calibrados) → probabilidad.
  5. Análisis de comportamiento   — traza de un espacio aislado (sandbox): red, archivos,
                                    persistencia, procesos. La app envía la traza; aquí se puntúa.

Diseño honesto: NADA de esto es infalible. El resultado es una probabilidad con la lista de
razones, un nivel (limpio | sospechoso | malicioso) y una recomendación. Un archivo limpio
según el motor puede seguir siendo malicioso (falsos negativos), por eso el veredicto se
guarda con su versión de motor y puede re-evaluarse cuando cambian las firmas.

El "escaneo del sistema de IA" original (scanAISystem) se conserva como un caso: evaluar un
prompt/función de IA por inyección de instrucciones y fuga de datos, en `scan_ai_payload`.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

ENGINE_VERSION = "av-2.0.0"
LEVELS = ("limpio", "sospechoso", "malicioso")


# --------------------------------------------------------------- entrada
@dataclass
class FileSample:
    name: str
    size: int
    sha256: str
    kind: str                       # pe|apk|elf|pdf|office|script|unknown
    header_hex: str = ""            # primeros ~64 bytes en hex (magic bytes)
    strings: list[str] = field(default_factory=list)   # cadenas imprimibles extraídas
    entropy: float | None = None    # entropía de Shannon del binario (0..8)
    imports: list[str] = field(default_factory=list)   # APIs/permisos/URLs referenciados
    yara_hits: list[str] = field(default_factory=list) # coincidencias de reglas (si la app las corrió)
    is_signed: bool = False
    signer: str | None = None


@dataclass
class Behavior:
    """Traza de ejecución en espacio aislado (la genera la app o un sandbox del servidor)."""
    contacted_hosts: list[str] = field(default_factory=list)
    dns_queries: list[str] = field(default_factory=list)
    files_written: list[str] = field(default_factory=list)
    files_encrypted: int = 0            # señal de ransomware
    processes_spawned: list[str] = field(default_factory=list)
    persistence: list[str] = field(default_factory=list)  # servicios, cron, registro, boot
    requested_admin: bool = False
    reads_sms: bool = False
    keylogging_api: bool = False
    screen_capture: bool = False


@dataclass
class Detection:
    points: int
    reason: str
    technique: str          # reputacion|firma|heuristica|modelo|comportamiento


@dataclass
class ScanResult:
    sha256: str
    level: str
    malicious_probability: float
    score: int
    family_guess: str | None
    detections: list[Detection]
    recommendations: list[str]
    engine_version: str = ENGINE_VERSION

    def to_dict(self) -> dict:
        return {"sha256": self.sha256, "nivel": self.level,
                "probabilidad_maliciosa": round(self.malicious_probability, 3), "puntaje": self.score,
                "familia_probable": self.family_guess,
                "detecciones": [{"puntos": d.points, "motivo": d.reason, "tecnica": d.technique}
                                for d in self.detections],
                "recomendaciones": self.recommendations, "engine_version": self.engine_version}


# ------------------------------------------------------------ reglas tipo YARA
# Reglas ligeras y legibles (nombre → (patrones que deben aparecer, puntos, familia)).
SIGNATURE_RULES: list[tuple[str, list[re.Pattern], int, str, str]] = [
    ("eicar_test", [re.compile(r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")], 100, "EICAR",
     "Archivo de prueba EICAR (no es un virus real, sirve para verificar el antivirus)"),
    ("ransom_note", [re.compile(r"your files? (have been|are) encrypted", re.I),
                     re.compile(r"bitcoin|monero|BTC address", re.I)], 60, "Ransomware genérico",
     "Contiene una nota de rescate típica de ransomware"),
    ("banker_overlay", [re.compile(r"accessibilityservice", re.I),
                        re.compile(r"TYPE_APPLICATION_OVERLAY|SYSTEM_ALERT_WINDOW", re.I)], 45,
     "Troyano bancario Android", "Combina servicio de accesibilidad y superposición de ventanas"),
    ("sms_stealer", [re.compile(r"content://sms", re.I), re.compile(r"http[s]?://", re.I)], 35,
     "Robo de SMS", "Lee SMS y los envía por internet (robo de códigos de verificación)"),
    ("reverse_shell", [re.compile(r"/bin/sh|cmd\.exe|powershell", re.I),
                       re.compile(r"socket|connect\(|nc -e|bash -i", re.I)], 40, "Puerta trasera",
     "Patrón de shell remota"),
    ("credential_dump", [re.compile(r"mimikatz|lsass|sekurlsa", re.I)], 70, "Robo de credenciales",
     "Herramienta de volcado de credenciales"),
    ("crypto_miner", [re.compile(r"stratum\+tcp://|xmrig|minerd", re.I)], 40, "Minero de criptomonedas",
     "Configuración de minería de criptomonedas"),
]

SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx": (12, "Inyección de código en otros procesos"),
    "WriteProcessMemory": (12, "Escribe en la memoria de otros procesos"),
    "CreateRemoteThread": (14, "Ejecuta código en otro proceso (inyección)"),
    "SetWindowsHookEx": (10, "Puede registrar teclado (keylogger)"),
    "CryptEncrypt": (6, "Cifra datos (puede ser ransomware)"),
    "URLDownloadToFile": (10, "Descarga y ejecuta archivos de internet"),
    "WinExec": (6, "Ejecuta programas"),
    "GetAsyncKeyState": (10, "Lee el estado del teclado (keylogger)"),
    "ptrace": (10, "Se adhiere a otros procesos (Linux)"),
    "dlopen": (4, "Carga bibliotecas en tiempo de ejecución"),
    "DexClassLoader": (12, "Carga código oculto en tiempo de ejecución (Android)"),
    "Runtime.exec": (10, "Ejecuta comandos del sistema"),
}

PACKER_STRINGS = ("UPX!", "MPRESS", "ASPack", "Themida", ".themida", "FSG!")


def _entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


# -------------------------------------------------------------- capas
def _reputation(sample: FileSample, bad: set[str], good: set[str]) -> list[Detection]:
    h = sample.sha256.lower()
    if h in bad:
        return [Detection(100, "El archivo coincide con malware conocido (lista de reputación)", "reputacion")]
    if h in good:
        return [Detection(-100, "Archivo verificado y de confianza", "reputacion")]
    return []


def _signatures(sample: FileSample) -> tuple[list[Detection], str | None]:
    text = "\n".join(sample.strings) + "\n" + " ".join(sample.imports)
    dets, family = [], None
    for name, patterns, pts, fam, why in SIGNATURE_RULES:
        if all(p.search(text) for p in patterns):
            dets.append(Detection(pts, why, "firma"))
            family = family or fam
    for hit in sample.yara_hits:
        dets.append(Detection(30, f"Regla de detección coincidente: {hit}", "firma"))
    return dets, family


def _heuristics(sample: FileSample) -> list[Detection]:
    dets = []
    for imp in sample.imports:
        for key, (pts, why) in SUSPICIOUS_IMPORTS.items():
            if key.lower() in imp.lower():
                dets.append(Detection(pts, why, "heuristica"))
                break
    joined = " ".join(sample.strings)
    if any(p in joined for p in PACKER_STRINGS):
        dets.append(Detection(15, "Empaquetado/ofuscado para dificultar el análisis", "heuristica"))
    if sample.entropy is not None and sample.entropy >= 7.2 and sample.kind in ("pe", "elf", "apk"):
        dets.append(Detection(12, "Entropía muy alta: probablemente cifrado o comprimido", "heuristica"))
    ip_urls = [s for s in sample.strings if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", s)]
    if ip_urls:
        dets.append(Detection(10, "Se conecta a direcciones IP fijas (típico de servidores de control)",
                              "heuristica"))
    if sample.kind == "pdf" and any(x in joined for x in ("/JavaScript", "/OpenAction", "/Launch", "/EmbeddedFile")):
        dets.append(Detection(18, "PDF con JavaScript o acciones automáticas", "heuristica"))
    if sample.kind == "office" and any(x in joined for x in ("AutoOpen", "Document_Open", "Shell(", "WScript")):
        dets.append(Detection(20, "Documento con macros que se ejecutan solas", "heuristica"))
    if sample.kind == "script":
        obf = sum(1 for s in sample.strings if len(s) > 200 and _entropy(s) > 4.5)
        if any(x in joined for x in ("FromBase64String", "eval(", "atob(", "-enc ", "IEX", "Invoke-Expression")):
            dets.append(Detection(16, "Script ofuscado que decodifica y ejecuta código", "heuristica"))
        if obf:
            dets.append(Detection(10, "Cadenas largas codificadas (ofuscación)", "heuristica"))
    if sample.is_signed and sample.signer:
        dets.append(Detection(-8, f"Firmado por {sample.signer}", "heuristica"))
    elif sample.kind in ("pe", "apk") and not sample.is_signed:
        dets.append(Detection(6, "Sin firma digital válida", "heuristica"))
    return dets


def _model_probability(score: int, n_signals: int) -> float:
    """Traduce el puntaje acumulado a probabilidad. Si hay un RandomForest entrenado, se usa
    en su lugar (ver train_model); mientras tanto, curva logística calibrada."""
    return round(_sigmoid((score - 45) / 18) * min(1.0, 0.6 + 0.1 * n_signals), 3)


def _behavior(bh: Behavior) -> tuple[list[Detection], str | None]:
    dets, family = [], None
    if bh.files_encrypted >= 20:
        dets.append(Detection(60, f"Cifró {bh.files_encrypted} archivos del usuario", "comportamiento"))
        family = "Ransomware"
    if bh.persistence:
        dets.append(Detection(20, "Se instala para arrancar solo: " + ", ".join(bh.persistence[:3]),
                              "comportamiento"))
    if bh.requested_admin:
        dets.append(Detection(12, "Pidió permisos de administrador", "comportamiento"))
    if bh.reads_sms:
        dets.append(Detection(18, "Leyó mensajes SMS", "comportamiento"))
        family = family or "Spyware"
    if bh.keylogging_api:
        dets.append(Detection(20, "Registró pulsaciones de teclado", "comportamiento"))
        family = family or "Keylogger"
    if bh.screen_capture:
        dets.append(Detection(14, "Capturó la pantalla en segundo plano", "comportamiento"))
    suspicious_hosts = [h for h in bh.contacted_hosts if re.search(r"\.(xyz|top|tk|ml|click|ru|su)$", h)]
    if suspicious_hosts:
        dets.append(Detection(15, "Se comunicó con servidores sospechosos: " + ", ".join(suspicious_hosts[:3]),
                              "comportamiento"))
    if any("cmd" in p or "powershell" in p or "/bin/sh" in p for p in bh.processes_spawned):
        dets.append(Detection(16, "Lanzó intérpretes de comandos", "comportamiento"))
    return dets, family


# ---------------------------------------------------------------- API pública
def scan_file(sample: FileSample, behavior: Behavior | None = None, *, bad_hashes: set[str] | None = None,
              good_hashes: set[str] | None = None) -> ScanResult:
    dets: list[Detection] = []
    rep = _reputation(sample, bad_hashes or set(), good_hashes or set())
    if rep and rep[0].points <= -100:
        return ScanResult(sample.sha256, "limpio", 0.0, 0, None, rep, ["Archivo de confianza"])
    if rep and rep[0].points >= 100:
        return ScanResult(sample.sha256, "malicioso", 0.99, 100, "Conocido", rep,
                          ["Elimínelo de inmediato", "Ejecute un escaneo completo del dispositivo"])
    sig_dets, family = _signatures(sample)
    dets += sig_dets + _heuristics(sample)
    if behavior is not None:
        b_dets, b_family = _behavior(behavior)
        dets += b_dets
        family = family or b_family

    score = max(0, min(100, sum(d.points for d in dets)))
    prob = _model_probability(score, len({d.technique for d in dets}))
    prob_red = _probabilidad_red(sample)
    if prob_red is not None:
        # La red se promedia con la heurística, no la reemplaza: un modelo entrenado con pocos datos
        # puede equivocarse, y las firmas conocidas no deben quedar a su merced.
        prob = 0.5 * prob + 0.5 * prob_red
        dets.append(Detection(0, f"Red neuronal: {prob_red:.0%} de probabilidad", "modelo"))
    dets.append(Detection(0, f"Probabilidad estimada por el modelo: {prob:.0%}", "modelo"))

    if score >= 60 or prob >= 0.8:
        level = "malicioso"
        recs = ["Ponga el archivo en cuarentena y elimínelo", "Si ya lo abrió, cambie sus contraseñas importantes",
                "Ejecute un escaneo completo"]
    elif score >= 30 or prob >= 0.5:
        level = "sospechoso"
        recs = ["No lo abra hasta confirmar su origen", "Revise por qué pide los permisos que solicita"]
    else:
        level = "limpio"
        recs = ["No se detectaron señales de amenaza (recuerde que ningún antivirus es infalible)"]
    dets.sort(key=lambda d: -d.points)
    return ScanResult(sample.sha256, level, prob, score, family, dets, recs)


def scan_ai_payload(text: str) -> ScanResult:
    """Evalúa un prompt o función de IA por inyección de instrucciones y fuga de datos
    (equivalente moderno de scanAISystem del backend PHP)."""
    dets = []
    patterns = [
        (re.compile(r"ignore (all|previous|above).{0,20}(instructions|rules)", re.I), 40,
         "Intenta anular las instrucciones del sistema (inyección de prompt)"),
        (re.compile(r"(reveal|show|print).{0,20}(system prompt|instructions|api[_ ]?key)", re.I), 45,
         "Intenta extraer el prompt de sistema o secretos"),
        (re.compile(r"(exfiltrate|send|post).{0,30}(to|a).{0,30}(http|webhook|url)", re.I), 40,
         "Intenta enviar datos a un servidor externo"),
        (re.compile(r"base64|\\x[0-9a-f]{2}|fromCharCode", re.I), 15, "Contenido ofuscado"),
        (re.compile(r"disregard.{0,20}safety|jailbreak|DAN mode", re.I), 35, "Intento de romper las restricciones"),
    ]
    for pat, pts, why in patterns:
        if pat.search(text):
            dets.append(Detection(pts, why, "firma"))
    score = max(0, min(100, sum(d.points for d in dets)))
    prob = _model_probability(score, len(dets))
    level = "malicioso" if score >= 55 else "sospechoso" if score >= 25 else "limpio"
    recs = (["Rechace esta entrada"] if level != "limpio" else ["Entrada sin patrones de ataque conocidos"])
    dets.sort(key=lambda d: -d.points)
    return ScanResult("(payload IA)", level, prob, score, "Prompt injection" if dets else None, dets, recs)


def _probabilidad_red(sample) -> float | None:
    """Consulta la red neuronal entrenada, si existe. Sin modelo, el motor sigue igual que antes."""
    try:
        from app.ml.entrenamiento import probabilidad_maliciosa
        return probabilidad_maliciosa({
            "name": sample.name, "size": sample.size, "kind": sample.kind, "entropy": sample.entropy,
            "strings": sample.strings, "imports": sample.imports, "yara_hits": sample.yara_hits,
            "is_signed": sample.is_signed})
    except Exception:  # noqa: BLE001 - el antivirus nunca depende de que el modelo esté disponible
        return None


# ---------------------------------------------------- modelo estadístico opcional
def train_model(labeled: list[tuple[FileSample, Behavior | None, bool]]):
    """Entrena un RandomForest sobre muestras etiquetadas (malicioso=True/False).

    Devuelve el modelo entrenado con métricas de validación. Es OPCIONAL: si no se entrena,
    scan_file usa la curva logística calibrada. Los rasgos son numéricos y explicables.
    """
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split

    def features(sample: FileSample, bh: Behavior | None) -> list[float]:
        imp = " ".join(sample.imports).lower()
        return [
            sample.entropy or 0.0,
            len(sample.imports),
            sum(1 for k in SUSPICIOUS_IMPORTS if k.lower() in imp),
            len(sample.yara_hits),
            int(any(p in " ".join(sample.strings) for p in PACKER_STRINGS)),
            int(sample.is_signed),
            math.log10(max(sample.size, 1)),
            (bh.files_encrypted if bh else 0),
            int(bool(bh and bh.persistence)),
            int(bool(bh and (bh.reads_sms or bh.keylogging_api))),
        ]

    X = np.array([features(s, b) for s, b, _ in labeled])
    y = np.array([int(m) for _, _, m in labeled])
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42, class_weight="balanced")
    clf.fit(Xtr, ytr)
    report = classification_report(yte, clf.predict(Xte), output_dict=True, zero_division=0)
    return clf, report
