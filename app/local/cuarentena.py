"""Cuarentena local: el archivo sale de su carpeta, cifrado e inerte.

Mejora sobre la del agente anterior (XOR con una clave derivada del nombre del equipo):
* **AES-256-GCM por bloques de 1 MB.** Nada puede ejecutar, indexar ni «restaurar sin querer» el
  archivo, y cualquier alteración se detecta al restaurar (GCM autentica cada bloque).
* **Clave aleatoria**, guardada junto a la cuarentena con permisos restringidos. No pretende proteger
  del dueño del equipo (nadie puede), sino volver el malware aislado inofensivo.
* **Registro en la base de datos** (tabla quarantine_items): la web lista, restaura y elimina.
"""
from __future__ import annotations

import os
import stat
import struct
import threading
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import utcnow
from app.db.models import QuarantineItem
from app.local import ajustes, sistema

EQUIPO = "este-equipo"          # device_id de lo aislado por la protección local
MAGIA = b"GQTN2"
BLOQUE = 1024 * 1024
_lock = threading.Lock()


def _carpeta() -> Path:
    return ajustes.sub("cuarentena")


def _clave() -> bytes:
    archivo = _carpeta() / ".clave"
    with _lock:
        if not archivo.exists():
            archivo.write_bytes(os.urandom(32))
            try:
                os.chmod(archivo, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        return archivo.read_bytes()


def _cifrar_archivo(origen: Path, destino: Path) -> int:
    aes = AESGCM(_clave())
    total = 0
    with open(origen, "rb") as src, open(destino, "wb") as dst:
        dst.write(MAGIA)
        indice = 0
        while bloque := src.read(BLOQUE):
            nonce = os.urandom(12)
            # El índice va como dato asociado: reordenar bloques también se detecta.
            cifrado = aes.encrypt(nonce, bloque, struct.pack("<Q", indice))
            dst.write(nonce + struct.pack("<I", len(cifrado)) + cifrado)
            total += len(bloque)
            indice += 1
    return total


def _descifrar_archivo(origen: Path, destino: Path) -> None:
    aes = AESGCM(_clave())
    with open(origen, "rb") as src, open(destino, "wb") as dst:
        if src.read(len(MAGIA)) != MAGIA:
            raise ValueError("No es un archivo de cuarentena de GuardianIA")
        indice = 0
        while cabecera := src.read(16):
            nonce, largo = cabecera[:12], struct.unpack("<I", cabecera[12:])[0]
            dst.write(aes.decrypt(nonce, src.read(largo), struct.pack("<Q", indice)))
            indice += 1


def aislar(db: Session, user_id: str, veredicto: dict) -> QuarantineItem:
    """Cifra el archivo en la cuarentena, lo borra de su sitio y deja el registro."""
    ruta = Path(veredicto["ruta"])
    if ">" in veredicto["ruta"]:
        # Amenaza dentro de un ZIP: se aísla el ZIP completo.
        ruta = Path(veredicto["ruta"].split(">", 1)[0])
    if sistema.intocable(ruta):
        raise PermissionError("Está en una carpeta del sistema: aislarlo podría dejar Windows sin arrancar")
    if not ruta.is_file():
        raise FileNotFoundError("El archivo ya no existe (quizá lo borró usted u otro antivirus)")
    sha = veredicto["sha256"]
    destino = _carpeta() / f"{sha}.qtn"
    tamano = _cifrar_archivo(ruta, destino)
    try:
        os.chmod(destino, stat.S_IRUSR | stat.S_IWUSR)
        os.chmod(ruta, stat.S_IWRITE | stat.S_IREAD)   # quita «solo lectura», que impide borrar
        ruta.unlink()
    except OSError as e:
        destino.unlink(missing_ok=True)
        raise PermissionError(f"No se pudo mover: {e.strerror or e}. Si está abierto o ejecutándose, "
                              "ciérrelo y vuelva a intentar.") from e
    item = QuarantineItem(user_id=user_id, device_id=EQUIPO, sha256=sha, filename=ruta.name[:200],
                          ruta_original=str(ruta)[:400], size_bytes=min(tamano, 2**31 - 1),
                          nivel=veredicto.get("nivel", "malicioso"), familia=(veredicto.get("familia") or None),
                          motivos=list(veredicto.get("motivos", []))[:6], estado="en_cuarentena")
    db.add(item)
    db.flush()
    return item


def restaurar(db: Session, item: QuarantineItem) -> str:
    origen = _carpeta() / f"{item.sha256}.qtn"
    destino = Path(item.ruta_original)
    if destino.exists():
        destino = destino.with_name(destino.stem + " (restaurado)" + destino.suffix)
    destino.parent.mkdir(parents=True, exist_ok=True)
    _descifrar_archivo(origen, destino)
    origen.unlink(missing_ok=True)
    item.estado = "restaurado"
    item.resuelto_at = utcnow()
    # Restaurar = «es un falso positivo»: no se vuelve a marcar ese mismo archivo.
    a = ajustes.leer()
    ajustes.guardar({"exclusiones_sha256": sorted(set(a["exclusiones_sha256"]) | {item.sha256})[-5000:]})
    return str(destino)


def eliminar(db: Session, item: QuarantineItem) -> None:
    archivo = _carpeta() / f"{item.sha256}.qtn"
    if archivo.exists():
        with open(archivo, "r+b") as fh:   # se sobrescribe antes de borrar
            fh.write(os.urandom(min(archivo.stat().st_size, BLOQUE)))
            fh.flush()
            os.fsync(fh.fileno())
        archivo.unlink()
    item.estado = "eliminado"
    item.resuelto_at = utcnow()


def listar(db: Session, user_id: str, limite: int = 100) -> list[QuarantineItem]:
    return db.execute(select(QuarantineItem).where(QuarantineItem.user_id == user_id,
                                                   QuarantineItem.device_id == EQUIPO)
                      .order_by(QuarantineItem.created_at.desc()).limit(limite)).scalars().all()
