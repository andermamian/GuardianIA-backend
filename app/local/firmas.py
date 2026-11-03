"""Base de firmas por hash: la capa de «reputación» del antivirus.

Es lo que Kaspersky llama «actualizar las bases de datos». Se alimenta de MalwareBazaar (abuse.ch),
un repositorio público de muestras de malware reales que publica sus huellas SHA-256. Además acepta
cualquier archivo .txt que usted ponga en data/local/firmas/ con un hash por línea (por ejemplo, las
listas de su institución).

Los hashes se guardan en memoria como bytes de 32, no como texto de 64: medio millón de firmas ocupan
unos 40 MB en vez de más de 100 MB. Su equipo tiene 16 GB, pero el servidor también corre el
asistente y los modelos, y la memoria no se regala.
"""
from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

import httpx

from app.local import ajustes

# El archivo de prueba EICAR: no es malware, existe para comprobar que un antivirus funciona.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
FUENTE_RECIENTES = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
MAX_FIRMAS = 600_000
_HEX64 = re.compile(r"\b[0-9a-f]{64}\b")


class BaseFirmas:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._malos: set[bytes] = set()
        self.cargadas_en: float = 0.0
        self.actualizada: float | None = None
        self.version = "0"
        self.cargar()

    @property
    def carpeta(self) -> Path:
        return ajustes.sub("firmas")

    def cargar(self) -> None:
        nuevos: set[bytes] = {bytes.fromhex(EICAR_SHA256)}
        ultima = None
        for archivo in sorted(self.carpeta.glob("*.txt")):
            try:
                with open(archivo, encoding="utf-8", errors="ignore") as fh:
                    for linea in fh:
                        if linea.startswith("#"):
                            continue
                        for h in _HEX64.findall(linea.lower()):
                            nuevos.add(bytes.fromhex(h))
                            if len(nuevos) >= MAX_FIRMAS:
                                break
                ultima = max(ultima or 0.0, archivo.stat().st_mtime)
            except OSError:
                continue
        with self._lock:
            self._malos = nuevos
            self.actualizada = ultima
            self.cargadas_en = time.time()
            # La versión cambia cuando cambian las firmas: invalida la caché de «ya revisado y limpio».
            self.version = f"{len(nuevos)}-{int(ultima or 0)}"

    def __len__(self) -> int:
        return len(self._malos)

    def es_malo(self, sha256_hex: str) -> bool:
        try:
            return bytes.fromhex(sha256_hex) in self._malos
        except ValueError:
            return False

    def conjunto_hex(self) -> set[str]:
        """Para el motor existente, que recibe un set de texto. Solo se usa en pruebas y casos puntuales."""
        with self._lock:
            return {h.hex() for h in self._malos}

    def actualizar(self, timeout: float = 60.0) -> dict:
        """Descarga las huellas recientes de MalwareBazaar y las suma a las ya guardadas."""
        encabezados = {"User-Agent": "GuardianIA/2 (+antivirus local)"}
        clave = os.environ.get("GUARDIAN_ABUSECH_KEY")
        if clave:
            encabezados["Auth-Key"] = clave   # abuse.ch da claves gratuitas; con ella no hay límites
        try:
            from app.core import red
            r = red.get(FUENTE_RECIENTES, headers=encabezados, timeout=timeout, follow_redirects=True)
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise RuntimeError(f"No se pudo descargar la lista de MalwareBazaar: {e}") from e
        recibidos = set(_HEX64.findall(r.text.lower()))
        if not recibidos:
            raise RuntimeError("MalwareBazaar respondió, pero sin firmas. Si pide clave, registre una gratis en "
                               "https://auth.abuse.ch y póngala en GUARDIAN_ABUSECH_KEY del .env")
        destino = self.carpeta / "malwarebazaar.txt"
        previos: list[str] = []
        if destino.exists():
            previos = [x for x in destino.read_text("utf-8", "ignore").split() if _HEX64.fullmatch(x)]
        # Los nuevos al final; si se pasa del tope, se descartan los más viejos.
        combinados = list(dict.fromkeys(previos + sorted(recibidos)))[-MAX_FIRMAS:]
        tmp = destino.with_suffix(".tmp")
        tmp.write_text("# Huellas SHA-256 de MalwareBazaar (abuse.ch)\n" + "\n".join(combinados) + "\n", "utf-8")
        os.replace(tmp, destino)
        antes = len(self)
        self.cargar()
        return {"recibidas": len(recibidos), "nuevas": max(0, len(self) - antes), "total": len(self),
                "version": self.version}

    def estado(self) -> dict:
        return {"total": len(self), "version": self.version, "actualizada": self.actualizada,
                "fuente": "MalwareBazaar (abuse.ch) + EICAR + listas propias en data/local/firmas"}


_base: BaseFirmas | None = None
_base_lock = threading.Lock()


def base() -> BaseFirmas:
    global _base
    with _base_lock:
        if _base is None:
            _base = BaseFirmas()
        return _base


def reiniciar() -> None:
    """Para pruebas: vuelve a leer desde la carpeta configurada."""
    global _base
    with _base_lock:
        _base = None
