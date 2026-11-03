"""Bóveda digital — interfaz activity_guardian_ai_vault_digital_seguro.xml.

Dos tipos de contenido con modelos de amenaza distintos:

1. Archivos (nav_vault, btn_add_files): cifrado en reposo con AES-256-GCM y una clave por archivo
   (ver core/crypto.py). El servidor puede descifrar para devolverlos, así que protege contra robo
   del disco o de copias de seguridad, no contra un operador con acceso a las claves.
2. Contraseñas (nav_passwords): cifrado de extremo a extremo. El cliente cifra con una clave
   derivada de la contraseña maestra (Argon2id en el teléfono) y el servidor solo guarda el blob.
   Ni una filtración total de la base de datos ni un administrador pueden leerlas.

Defensas de subida: tamaño máximo, cuota por plan, tipo detectado por firma de bytes (no por la
extensión que declare el cliente), nombre saneado y escritura atómica en disco.
"""
from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from typing import Literal
from urllib.parse import quote

import httpx

from app.core import red
from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import Response
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser, client_ip
from app.core import audit
from app.core.config import get_settings
from app.core.crypto import open_sealed, open_text
from app.core.errors import ApiError, conflict, not_found
from app.core.ratelimit import limiter
from app.core.security import generate_password, password_entropy_bits
from app.db.models import VaultFile, VaultSecret
from app.schemas.common import Msg
from app.services import boveda
from app.schemas.vault import (PasswordAuditOut, PasswordGenIn, PasswordGenOut, SecretIn, SecretOut, VaultFileOut,
                               VaultOverview)

router = APIRouter(tags=["Bóveda digital"])

Category = Literal["photos", "documents", "videos", "financial", "evidence"]
QUOTA_MB = {"BASIC": 100, "PREMIUM": 2048, "ENTERPRISE": 10240}
MAX_SECRETS = 2000

# Firma de bytes → tipo. Lo que no está aquí no entra: ejecutables, scripts, HTML y SVG (que puede
# llevar JavaScript) se rechazan aunque se llamen «foto.jpg».
_MAGIC: list[tuple[bytes, int, str]] = [
    (b"\xff\xd8\xff", 0, "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", 0, "image/png"),
    (b"GIF87a", 0, "image/gif"),
    (b"GIF89a", 0, "image/gif"),
    (b"WEBP", 8, "image/webp"),
    (b"ftypheic", 4, "image/heic"),
    (b"ftypmif1", 4, "image/heic"),
    (b"%PDF-", 0, "application/pdf"),
    (b"ftypisom", 4, "video/mp4"),
    (b"ftypmp42", 4, "video/mp4"),
    (b"ftyp3gp", 4, "video/3gpp"),
    (b"\x1aE\xdf\xa3", 0, "video/webm"),
    (b"ID3", 0, "audio/mpeg"),
    (b"OggS", 0, "audio/ogg"),
]
_ZIP = b"PK\x03\x04"  # docx/xlsx son ZIP: se aceptan solo con extensión de Office


def sniff_mime(head: bytes, filename: str) -> str | None:
    for sig, offset, mime in _MAGIC:
        if head[offset:offset + len(sig)] == sig:
            return mime
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if head.startswith(_ZIP) and ext in ("docx", "xlsx", "pptx", "odt", "ods"):
        return {"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                "odt": "application/vnd.oasis.opendocument.text",
                "ods": "application/vnd.oasis.opendocument.spreadsheet"}[ext]
    if ext in ("txt", "csv"):
        try:
            head.decode("utf-8")
            return "text/plain" if ext == "txt" else "text/csv"
        except UnicodeDecodeError:
            return None
    return None


def safe_filename(name: str) -> str:
    name = unicodedata.normalize("NFKC", os.path.basename(name.replace("\\", "/")))
    name = re.sub(r"[\x00-\x1f\x7f/\\:*?\"<>|]", "_", name).strip(" .")
    return (name or "archivo")[:120]


_vault_dir = boveda.vault_dir
_ctx = boveda.ctx
QUOTA_MB = boveda.QUOTA_MB


def _own_file(db, user_id: str, file_id: str) -> VaultFile:
    f = db.get(VaultFile, file_id)
    if f is None or f.user_id != user_id:
        raise not_found("archivo")
    return f


def _to_out(f: VaultFile) -> VaultFileOut:
    return VaultFileOut(id=f.id, category=f.category, filename=open_text(f.filename_enc, _ctx(f.user_id, f.id)),
                        mime=f.mime, size_bytes=f.size_bytes, created_at=f.created_at)


# ------------------------------------------------------------------ archivos
@router.get("/vault", response_model=VaultOverview)
def vault_overview(p: CurrentUser, db: DB, category: Category | None = None):
    rows = db.execute(select(VaultFile).where(VaultFile.user_id == p.user.id)
                      .order_by(VaultFile.created_at.desc())).scalars().all()
    por_categoria: dict[str, int] = {}
    for f in rows:
        por_categoria[f.category] = por_categoria.get(f.category, 0) + 1
    shown = [f for f in rows if category is None or f.category == category]
    return VaultOverview(total_archivos=len(rows), por_categoria=por_categoria,
                         espacio_usado_mb=round(sum(f.size_bytes for f in rows) / 1048576, 2),
                         archivos=[_to_out(f) for f in shown[:200]])


@router.get("/vault/quota")
def quota(p: CurrentUser, db: DB):
    used = db.execute(select(func.coalesce(func.sum(VaultFile.size_bytes), 0))
                      .where(VaultFile.user_id == p.user.id)).scalar_one()
    limit_mb = QUOTA_MB.get(p.user.plan, QUOTA_MB["BASIC"])
    return {"plan": p.user.plan, "usado_mb": round(used / 1048576, 2), "limite_mb": limit_mb,
            "porcentaje": round(100 * used / (limit_mb * 1048576), 1)}


@router.post("/vault/files", response_model=VaultFileOut, status_code=201)
async def upload(p: CurrentUser, db: DB, request: Request, category: Category = Form(...),
                 file: UploadFile = File(...)):
    limiter.hit(f"vault-upload:{p.user.id}", 30, 600)
    max_bytes = get_settings().max_upload_mb * 1048576
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ApiError(413, "file_too_large", f"El archivo supera {get_settings().max_upload_mb} MB")
    if not data:
        raise ApiError(422, "empty_file", "El archivo está vacío")
    name = safe_filename(file.filename or "archivo")
    mime = sniff_mime(data[:64], name)
    if mime is None:
        raise ApiError(415, "unsupported_type", "Tipo de archivo no permitido en la bóveda",
                       {"permitidos": "imágenes, PDF, video, audio, documentos de Office, TXT y CSV"})
    f = boveda.guardar(db, p.user, categoria=category, nombre=name, datos=data, mime=mime)
    try:
        audit.record(db, "vault.upload", actor_id=p.user.id, target_type="vault_file", target_id=f.id,
                     ip=client_ip(request), detail={"categoria": category, "bytes": len(data)}, commit=False)
        db.commit()
    except Exception:
        boveda.borrar_archivo_fisico(f)  # sin fila en la base, no queda basura cifrada huérfana
        raise
    return _to_out(f)


@router.get("/vault/files/{file_id}/download")
def download(file_id: str, request: Request, p: CurrentUser, db: DB):
    f = _own_file(db, p.user.id, file_id)
    limiter.hit(f"vault-download:{p.user.id}", 60, 600)
    path = _vault_dir() / f.storage_name
    if not path.exists():
        raise ApiError(410, "file_missing", "El contenido del archivo no está disponible")
    data = open_sealed(f.key_version, f.wrapped_dek, path.read_bytes(), _ctx(p.user.id, f.id))
    if hashlib.sha256(data).hexdigest() != f.sha256:
        raise ApiError(409, "integrity_error", "La verificación de integridad falló")
    name = open_text(f.filename_enc, _ctx(p.user.id, f.id))
    audit.record(db, "vault.download", actor_id=p.user.id, target_type="vault_file", target_id=f.id,
                 ip=client_ip(request))
    return Response(content=data, media_type=f.mime, headers={
        # attachment + nosniff: el navegador descarga, nunca interpreta el contenido como página
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    })


@router.delete("/vault/files/{file_id}", response_model=Msg)
def delete_file(file_id: str, request: Request, p: CurrentUser, db: DB):
    f = _own_file(db, p.user.id, file_id)
    path = _vault_dir() / f.storage_name
    audit.record(db, "vault.delete", actor_id=p.user.id, target_type="vault_file", target_id=f.id,
                 ip=client_ip(request), commit=False)
    db.delete(f)
    db.commit()
    path.unlink(missing_ok=True)  # borrado criptográfico: sin la DEK envuelta, los bytes restantes son ruido
    return Msg(mensaje="Archivo eliminado")


# --------------------------------------------------------------- contraseñas
@router.get("/vault/secrets", response_model=list[SecretOut])
def list_secrets(p: CurrentUser, db: DB):
    return db.execute(select(VaultSecret).where(VaultSecret.user_id == p.user.id)
                      .order_by(VaultSecret.updated_at.desc())).scalars().all()


@router.post("/vault/secrets", response_model=SecretOut, status_code=201)
def add_secret(body: SecretIn, p: CurrentUser, db: DB):
    count = db.execute(select(func.count()).select_from(VaultSecret)
                       .where(VaultSecret.user_id == p.user.id)).scalar_one()
    if count >= MAX_SECRETS:
        raise conflict("too_many_secrets", f"Máximo {MAX_SECRETS} entradas")
    s = VaultSecret(user_id=p.user.id, ciphertext=body.ciphertext, strength=body.strength, breached=body.breached)
    db.add(s)
    db.commit()
    return s


@router.put("/vault/secrets/{secret_id}", response_model=SecretOut)
def update_secret(secret_id: str, body: SecretIn, p: CurrentUser, db: DB):
    s = db.get(VaultSecret, secret_id)
    if s is None or s.user_id != p.user.id:
        raise not_found("entrada")
    s.ciphertext, s.strength, s.breached = body.ciphertext, body.strength, body.breached
    db.commit()
    return s


@router.delete("/vault/secrets/{secret_id}", response_model=Msg)
def delete_secret(secret_id: str, p: CurrentUser, db: DB):
    s = db.get(VaultSecret, secret_id)
    if s is None or s.user_id != p.user.id:
        raise not_found("entrada")
    db.delete(s)
    db.commit()
    return Msg(mensaje="Entrada eliminada")


@router.get("/vault/secrets/audit", response_model=PasswordAuditOut)
def audit_secrets(p: CurrentUser, db: DB):
    """Resumen con los metadatos que calcula el cliente; el servidor no ve las contraseñas."""
    rows = db.execute(select(VaultSecret.strength, VaultSecret.breached)
                      .where(VaultSecret.user_id == p.user.id)).all()
    return PasswordAuditOut(total=len(rows), fuertes=sum(r.strength == "fuerte" for r in rows),
                            medias=sum(r.strength == "media" for r in rows),
                            debiles=sum(r.strength == "debil" for r in rows),
                            comprometidas=sum(bool(r.breached) for r in rows))


@router.post("/vault/passwords/generate", response_model=PasswordGenOut)
def gen_password(body: PasswordGenIn, p: CurrentUser):
    """btn_generate_password. Se genera con `secrets` (CSPRNG) y no se registra en ningún log."""
    pw = generate_password(body.length, body.symbols)
    bits = password_entropy_bits(pw)
    return PasswordGenOut(password=pw, entropy_bits=round(bits, 1),
                          fortaleza="fuerte" if bits >= 80 else "media" if bits >= 50 else "debil")


@router.get("/vault/passwords/breach-range/{prefix}")
def breach_range(prefix: str, p: CurrentUser):
    """k-anonimato (Have I Been Pwned): el teléfono envía solo los 5 primeros caracteres del SHA-1.

    Pasar por el servidor oculta la IP del usuario ante el tercero; ni el servidor ni HIBP
    llegan a conocer la contraseña. Devuelve sufijos para que el cliente compare localmente.
    """
    if not re.fullmatch(r"[0-9A-Fa-f]{5}", prefix):
        raise ApiError(422, "invalid_prefix", "El prefijo debe ser de 5 caracteres hexadecimales")
    if not get_settings().hibp_enabled:
        raise ApiError(503, "breach_check_disabled", "La verificación de filtraciones no está habilitada")
    limiter.hit(f"hibp:{p.user.id}", 100, 3600)
    try:
        r = red.get(f"https://api.pwnedpasswords.com/range/{prefix.upper()}",
                      headers={"Add-Padding": "true", "User-Agent": "GuardianIA"}, timeout=5.0)
        r.raise_for_status()
    except red.SinTor as e:
        raise ApiError(503, "tor_requerido", str(e)) from e
    except httpx.HTTPError:
        raise ApiError(502, "breach_service_unavailable", "El servicio de filtraciones no respondió")
    return Response(content=r.text, media_type="text/plain", headers={"Cache-Control": "no-store"})
