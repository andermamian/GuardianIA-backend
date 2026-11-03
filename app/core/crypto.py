"""Cifrado en reposo con esquema de sobre (envelope encryption).

Sustituye la "encriptación cuántica" del proyecto original por algo verificable:

* Cada registro o archivo tiene su propia clave de datos (DEK) aleatoria de 256 bits.
* Los datos se cifran con AES-256-GCM (confidencialidad + integridad autenticada).
* La DEK se guarda envuelta con la clave maestra (KEK) versionada del anillo de claves.
* Rotar la KEK solo re-envuelve DEKs: no hay que recifrar gigabytes de archivos.
* El contexto (AAD) ata el texto cifrado a su dueño: copiar un blob de un usuario a otro falla.

Nota post-cuántica: AES-256 conserva ~128 bits de seguridad incluso ante Grover;
el riesgo cuántico real está en el intercambio de claves (TLS), que se resuelve en el
balanceador con TLS 1.3 híbrido (X25519MLKEM768), no dentro de la aplicación.
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings
from app.core.errors import ApiError

_NONCE = 12


@dataclass(frozen=True)
class Sealed:
    key_version: str
    wrapped_dek: str   # base64(nonce || AESGCM(KEK, DEK))
    ciphertext: bytes  # nonce || AESGCM(DEK, data)


def _kek(version: str) -> bytes:
    keys = get_settings().keys()
    if version not in keys:
        raise ApiError(500, "key_unavailable", "Clave de cifrado no disponible")
    return keys[version]


def _enc(key: bytes, data: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(_NONCE)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def _dec(key: bytes, blob: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(blob[:_NONCE], blob[_NONCE:], aad)
    except InvalidTag:
        raise ApiError(409, "integrity_error", "Los datos cifrados fueron alterados o no pertenecen a este contexto")


def seal(data: bytes, context: str) -> Sealed:
    version = get_settings().active_key_version
    dek = AESGCM.generate_key(bit_length=256)
    aad = context.encode()
    return Sealed(
        key_version=version,
        wrapped_dek=base64.b64encode(_enc(_kek(version), dek, b"dek|" + aad)).decode(),
        ciphertext=_enc(dek, data, aad),
    )


def open_sealed(key_version: str, wrapped_dek: str, ciphertext: bytes, context: str) -> bytes:
    aad = context.encode()
    dek = _dec(_kek(key_version), base64.b64decode(wrapped_dek), b"dek|" + aad)
    return _dec(dek, ciphertext, aad)


def rewrap(key_version: str, wrapped_dek: str, context: str) -> tuple[str, str]:
    """Re-envuelve una DEK con la versión activa de la KEK (rotación sin recifrar datos)."""
    target = get_settings().active_key_version
    aad = b"dek|" + context.encode()
    dek = _dec(_kek(key_version), base64.b64decode(wrapped_dek), aad)
    return target, base64.b64encode(_enc(_kek(target), dek, aad)).decode()


def seal_text(text: str, context: str) -> str:
    """Campo de texto sensible (p. ej. notas médicas) → cadena autocontenida."""
    s = seal(text.encode(), context)
    return f"{s.key_version}.{s.wrapped_dek}.{base64.b64encode(s.ciphertext).decode()}"


def open_text(token: str | None, context: str) -> str | None:
    if not token:
        return None
    version, wrapped, ct = token.split(".", 2)
    return open_sealed(version, wrapped, base64.b64decode(ct), context).decode()
