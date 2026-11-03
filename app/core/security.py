"""Primitivas de autenticación.

- Contraseñas: Argon2id (ganador de la Password Hashing Competition, recomendado por OWASP).
- Tokens: JWT de vida corta con audiencia separada para la app y para la consola admin,
  y refresh tokens opacos, rotativos, guardados solo como hash.
- 2FA: TOTP (RFC 6238), obligatorio para cuentas administrativas.
- Biometría: el servidor NUNCA recibe la huella. El teléfono guarda una clave ECDSA P-256
  en el Android Keystore, desbloqueada con BiometricPrompt, y firma un reto del servidor.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import math
import secrets
import string
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.core.config import get_settings
from app.core.errors import ApiError

AUD_APP = "guardian-app"
AUD_ADMIN = "guardian-admin"

_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
# Hash ficticio para igualar el tiempo de respuesta cuando el usuario no existe.
_DUMMY_HASH = _hasher.hash(secrets.token_hex(16))

_COMMON = {
    "123456", "12345678", "123456789", "password", "contraseña", "qwerty", "111111", "admin123",
    "colombia", "colombia123", "iloveyou", "abc123", "123123", "guardian", "guardianai", "000000",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ----------------------------------------------------------------- contraseñas
def hash_password(raw: str) -> str:
    return _hasher.hash(raw)


def verify_password(raw: str, hashed: str | None) -> bool:
    try:
        return _hasher.verify(hashed or _DUMMY_HASH, raw) and hashed is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    return _hasher.check_needs_rehash(hashed)


def password_entropy_bits(pw: str) -> float:
    pool = 0
    pool += 26 if any(c.islower() for c in pw) else 0
    pool += 26 if any(c.isupper() for c in pw) else 0
    pool += 10 if any(c.isdigit() for c in pw) else 0
    pool += 33 if any(not c.isalnum() for c in pw) else 0
    unique_ratio = len(set(pw)) / max(len(pw), 1)
    return len(pw) * math.log2(max(pool, 1)) * min(1.0, 0.5 + unique_ratio)


def password_problems(pw: str, *, email: str = "", name: str = "") -> list[str]:
    """Política NIST SP 800-63B: longitud y listas negras, no reglas caprichosas."""
    issues = []
    if len(pw) < 12:
        issues.append("Debe tener al menos 12 caracteres")
    if len(pw) > 128:
        issues.append("No puede superar 128 caracteres")
    low = pw.lower()
    if low in _COMMON or any(low.startswith(c) and len(low) - len(c) <= 3 for c in _COMMON):
        issues.append("Es una contraseña demasiado común")
    for token in filter(lambda t: len(t) >= 4, [email.split("@")[0].lower(), *name.lower().split()]):
        if token in low:
            issues.append("No debe contener su nombre o correo")
            break
    if password_entropy_bits(pw) < 50:
        issues.append("Es predecible; combine palabras o agregue variedad")
    return issues


def generate_password(length: int = 20, symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits + ("!@#$%&*-_=+?" if symbols else "")
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and (not symbols or any(not c.isalnum() for c in pw))):
            return pw


# ----------------------------------------------------------------------- tokens
def create_access_token(*, subject: str, audience: str, role: str, session_id: str,
                        minutes: int, extra: dict | None = None) -> str:
    s = get_settings()
    now = utcnow()
    payload = {
        "iss": s.jwt_issuer, "aud": audience, "sub": subject, "role": role, "sid": session_id,
        "iat": int(now.timestamp()), "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()), "jti": secrets.token_hex(12),
    }
    payload.update(extra or {})
    return jwt.encode(payload, s.jwt_secret, algorithm="HS256")


def decode_access_token(token: str, audience: str) -> dict:
    s = get_settings()
    try:
        return jwt.decode(token, s.jwt_secret, algorithms=["HS256"], audience=audience, issuer=s.jwt_issuer,
                          options={"require": ["exp", "sub", "aud", "sid"]})
    except jwt.ExpiredSignatureError:
        raise ApiError(401, "token_expired", "La sesión expiró")
    except jwt.PyJWTError:
        raise ApiError(401, "invalid_token", "Credenciales inválidas")


def new_opaque_token() -> str:
    return secrets.token_urlsafe(48)


def token_hash(token: str) -> str:
    """Hash con clave: aunque roben la base de datos, los refresh tokens no sirven."""
    return hmac.new(get_settings().jwt_secret.encode(), token.encode(), hashlib.sha256).hexdigest()


# -------------------------------------------------------------------------- 2FA
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name="GuardianIA")


def verify_totp(secret: str | None, code: str | None) -> bool:
    if not secret or not code or not code.isdigit():
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def recovery_codes(n: int = 8) -> list[str]:
    return [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(n)]


# --------------------------------------------------------- biometría (Keystore)
def load_device_public_key(pem_or_b64der: str) -> ec.EllipticCurvePublicKey:
    data = pem_or_b64der.strip()
    try:
        key = (serialization.load_pem_public_key(data.encode()) if data.startswith("-----")
               else serialization.load_der_public_key(base64.b64decode(data)))
    except Exception:
        raise ApiError(422, "invalid_public_key", "La clave pública del dispositivo no es válida")
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ApiError(422, "invalid_public_key", "Se requiere una clave ECDSA P-256 del Android Keystore")
    return key


def verify_device_signature(public_key_text: str, challenge: str, signature_b64: str) -> bool:
    key = load_device_public_key(public_key_text)
    try:
        key.verify(base64.b64decode(signature_b64), challenge.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
