"""Guardado de archivos en la bóveda, compartido por las subidas del usuario y el estudio de creación.

Una sola implementación del cifrado y la cuota: si mañana cambia el esquema de claves, cambia aquí y
vale para todo. Ver app/api/v1/vault.py para el modelo de amenaza completo.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.crypto import seal, seal_text
from app.core.errors import ApiError
from app.db.models import User, VaultFile

QUOTA_MB = {"BASIC": 100, "PREMIUM": 2048, "ENTERPRISE": 10240}


def vault_dir() -> Path:
    p = Path(get_settings().vault_dir)
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


def ctx(user_id: str, file_id: str) -> str:
    return f"vault:{user_id}:{file_id}"


def espacio(db, user: User) -> tuple[int, int]:
    usado = db.execute(select(func.coalesce(func.sum(VaultFile.size_bytes), 0))
                       .where(VaultFile.user_id == user.id)).scalar_one()
    return usado, QUOTA_MB.get(user.plan, QUOTA_MB["BASIC"]) * 1048576


def guardar(db, user: User, *, categoria: str, nombre: str, datos: bytes, mime: str) -> VaultFile:
    """Cifra y guarda un archivo. No hace commit: lo decide quien llama."""
    usado, limite = espacio(db, user)
    if usado + len(datos) > limite:
        raise ApiError(402, "quota_exceeded", "Sin espacio en la bóveda para su plan",
                       {"usado_mb": round(usado / 1048576, 2), "limite_mb": limite // 1048576})

    f = VaultFile(user_id=user.id, category=categoria, filename_enc="", mime=mime, size_bytes=len(datos),
                  sha256=hashlib.sha256(datos).hexdigest(), key_version="", wrapped_dek="",
                  storage_name=secrets.token_hex(32))
    db.add(f)
    db.flush()
    sellado = seal(datos, ctx(user.id, f.id))
    f.key_version, f.wrapped_dek = sellado.key_version, sellado.wrapped_dek
    f.filename_enc = seal_text(nombre, ctx(user.id, f.id))

    final = vault_dir() / f.storage_name
    tmp = final.with_suffix(".tmp")
    with open(tmp, "wb") as fh:  # escritura atómica: nunca queda un archivo a medias
        fh.write(sellado.ciphertext)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, final)
    return f


def borrar_archivo_fisico(f: VaultFile) -> None:
    (vault_dir() / f.storage_name).unlink(missing_ok=True)
