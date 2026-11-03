"""Configuración 12-factor: todo sale del entorno, nada sensible en el código."""
from __future__ import annotations

import base64
import os
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from typing import Annotated


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    # El .env se busca junto al proyecto Y en la carpeta actual (esta última manda).
    # Antes solo se miraba la carpeta actual: arrancar el servidor desde otro directorio
    # ignoraba las claves en silencio y todo fallaba con «Error interno» al firmar el primer token.
    model_config = SettingsConfigDict(
        env_file=(str(PROJECT_ROOT / ".env"), ".env"), env_file_encoding="utf-8",
        env_prefix="GUARDIAN_", extra="ignore",
    )

    env: str = "development"  # development | test | production
    app_name: str = "GuardianIA API"
    version: str = "4.0.0"
    database_url: str = "sqlite:///./guardian.db"
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    timezone: str = "America/Bogota"

    # --- Tokens -----------------------------------------------------------
    jwt_secret: str = Field(default="", repr=False)
    jwt_issuer: str = "guardianai"
    access_token_minutes: int = 15
    admin_access_token_minutes: int = 10
    refresh_token_days: int = 30
    admin_refresh_token_hours: int = 12

    # --- Cifrado en reposo: anillo de claves versionado ---------------------
    # Formato: "v1:<base64 de 32 bytes>,v2:<base64 de 32 bytes>"
    keyring: str = Field(default="", repr=False)
    active_key_version: str = "v1"

    # --- Protección de acceso ---------------------------------------------
    max_failed_logins: int = 5
    lockout_base_seconds: int = 30
    rate_limit_login_per_minute: int = 10
    rate_limit_default_per_minute: int = 240
    max_upload_mb: int = 25
    adjunto_max_mb: int = 4096   # adjuntos del chat (fotos, videos, ZIP): se reciben por partes, sin cargarlos en memoria

    # --- IA -----------------------------------------------------------------
    anthropic_api_key: str = Field(default="", repr=False)
    anthropic_model: str = "claude-sonnet-5"
    # Alternativa compatible con la API de OpenAI: OpenAI, Groq, OpenRouter, LM Studio u Ollama
    # local (http://localhost:11434/v1, sin clave y sin costo). "auto" usa Anthropic si hay clave.
    llm_provider: str = "auto"   # auto | anthropic | openai | ninguno
    llm_base_url: str = ""       # p. ej. http://localhost:11434/v1
    llm_api_key: str = Field(default="", repr=False)
    llm_model: str = ""          # p. ej. llama3.1:8b
    # Tiempo máximo ENTRE trozos de respuesta. 20 s cortaba a cualquier modelo local mientras «pensaba» o
    # procesaba un chat largo, y el asistente caía al modo sin modelo. Ahora hay margen de sobra.
    llm_timeout_seconds: float = 600.0
    # Tokens que puede escribir en CADA llamada. 2400 cortaba las respuestas largas a media frase; con 16000
    # caben ~12 000 palabras. Si aun así llega al tope, el asistente continúa solo (llm_continuations).
    # Para código el tope sube al doble en tiempo de ejecución, hasta llm_max_tokens_tope.
    llm_max_tokens: int = 16000
    llm_max_tokens_tope: int = 32000
    llm_continuations: int = 12          # veces que continúa solo una respuesta cortada por el tope
    # Cuánto historial recuerda en cada respuesta (caracteres ≈ 4 por token). Antes: 12 turnos fijos.
    llm_history_chars: int = 120_000
    # --- Documentos largos ---
    # 0 = AUTOMÁTICO: cada trabajo recibe la extensión que necesita (una carta, 1 página; un manual, decenas).
    # Un número > 0 fuerza ese mínimo en todo documento (modo anterior, 50).
    doc_min_paginas: int = 0
    doc_paginas_una_llamada: int = 4     # hasta estas páginas se escribe de una sola vez; más, por capítulos
    doc_palabras_por_pagina: int = 420   # para estimar páginas sin abrir Word
    doc_palabras_por_seccion: int = 900
    doc_max_paginas: int = 300
    # Piezas cortas por naturaleza (cuento, taller, carta, evaluación…) no se inflan a 50 páginas: salen en
    # segundos con su extensión natural. «extenso», «completo» o un número de páginas las pasa al modo largo.
    doc_cortos_sin_minimo: bool = True
    # Capítulos que se escriben a la vez. 0 = automático: 4 con un modelo en la nube (Anthropic u otro servidor),
    # 1 con un modelo local (una sola GPU/CPU no gana nada escribiendo en paralelo).
    doc_paralelo: int = 0
    # Velocidad (v4.2): con un modelo local los documentos cortos se piden directo en Markdown (una sola
    # llamada, sin el intento previo en JSON que un modelo pequeño casi siempre falla) y el aviso final
    # «listo, aquí está su archivo» sale de una plantilla, sin gastar otra generación del modelo.
    # Con un modelo local (sin GPU) lo caro es procesar el prompt: historial y skills se recortan y se continúa
    # menos veces. Con modelos en la nube no hay recorte.
    llm_history_chars_local: int = 12_000
    llm_continuations_local: int = 2
    skills_chars_local: int = 3_500
    doc_directo_markdown: bool = True
    respuesta_rapida_archivo: bool = True
    doc_skills_max_chars: int = 2500     # las skills por capítulo van resumidas: cada llamada reprocesa el prompt
    doc_presupuesto_segundos: float = 7200.0
    hibp_enabled: bool = False
    # Revisión de filtraciones por correo. "xposedornot" es gratuito y sin clave; "hibp" requiere
    # suscripción de pago (https://haveibeenpwned.com/API/Key) y se activa poniendo la clave.
    breach_provider: str = "xposedornot"
    breach_api_key: str = Field(default="", repr=False)

    # --- Navegación web del asistente ---------------------------------------
    web_browsing_enabled: bool = True
    web_timeout_seconds: float = 8.0

    # --- Almacenamiento -----------------------------------------------------
    vault_dir: str = "./data/vault"
    backup_dir: str = "./data/backups"

    @field_validator("database_url", mode="before")
    @classmethod
    def _url_postgres(cls, v):
        """Neon, Supabase y Render entregan «postgres://…» o «postgresql://…»; SQLAlchemy necesita el driver psycopg."""
        if isinstance(v, str):
            if v.startswith("postgres://"):
                v = "postgresql://" + v[len("postgres://"):]
            if v.startswith("postgresql://"):
                v = "postgresql+psycopg://" + v[len("postgresql://"):]
        return v

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @property
    def llm_read_timeout(self) -> float:
        """Espera máxima entre trozos: nunca menos de 5 minutos, aunque el .env pida menos."""
        return max(self.llm_timeout_seconds, 300.0)

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    def keys(self) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        for part in filter(None, (p.strip() for p in self.keyring.split(","))):
            version, b64 = part.split(":", 1)
            key = base64.b64decode(b64)
            if len(key) != 32:
                raise ValueError(f"La clave {version} debe tener 32 bytes (AES-256)")
            out[version] = key
        return out

    def env_file_in_use(self) -> Path | None:
        """Ruta del .env que se está usando (para el diagnóstico y el aviso de arranque)."""
        for candidate in (Path.cwd() / ".env", PROJECT_ROOT / ".env"):
            if candidate.is_file():
                return candidate
        return None

    @property
    def llm_es_local(self) -> bool:
        return self.llm_kind == "openai" and any(h in self.llm_base_url for h in ("localhost", "127.0.0.1", "[::1]"))

    @property
    def historial_chars(self) -> int:
        return min(self.llm_history_chars, self.llm_history_chars_local) if self.llm_es_local else self.llm_history_chars

    @property
    def continuaciones(self) -> int:
        return min(self.llm_continuations, self.llm_continuations_local) if self.llm_es_local else self.llm_continuations

    @property
    def llm_kind(self) -> str:
        """Qué proveedor usará el asistente, según lo configurado."""
        if self.llm_provider == "ninguno":
            return "ninguno"
        if self.llm_provider == "openai" or (self.llm_provider == "auto" and self.llm_base_url
                                             and not self.anthropic_api_key):
            return "openai" if self.llm_base_url else "ninguno"
        if self.llm_provider in ("anthropic", "auto") and self.anthropic_api_key:
            return "anthropic"
        return "ninguno"

    def ensure_dev_secrets(self) -> list[str]:
        """Fuera de producción, genera claves efímeras si faltan.

        Antes, con el .env sin claves, la app arrancaba y fallaba con «Error interno» al firmar el
        primer token: el error aparecía al registrarse, lejos de su causa. Ahora arranca usable y
        avisa. Las claves viven solo en memoria: al reiniciar, las sesiones se cierran y lo que se
        haya guardado cifrado (bóveda, notas de salud, 2FA) queda ilegible. Para trabajo real,
        ejecute `python -m app.cli generate-keys` y péguelas en el .env.
        """
        if self.is_production:
            return []
        generated = []
        if len(self.jwt_secret) < 48:
            self.jwt_secret = secrets.token_urlsafe(48)
            generated.append("GUARDIAN_JWT_SECRET")
        try:
            missing = self.active_key_version not in self.keys()
        except ValueError:
            missing = True
        if missing:
            self.keyring = f"{self.active_key_version}:{base64.b64encode(os.urandom(32)).decode()}"
            generated.append("GUARDIAN_KEYRING")
        return generated

    def validate_for_runtime(self) -> None:
        """Falla rápido: no se arranca con secretos débiles."""
        problems = []
        if len(self.jwt_secret) < 48:
            problems.append("GUARDIAN_JWT_SECRET debe tener al menos 48 caracteres")
        if self.active_key_version not in self.keys():
            problems.append("GUARDIAN_KEYRING no contiene la versión activa")
        if self.is_production and self.database_url.startswith("sqlite"):
            problems.append("En producción use PostgreSQL, no SQLite")
        if self.is_production and not self.cors_origins:
            problems.append("En producción defina GUARDIAN_CORS_ORIGINS")
        if problems:
            raise RuntimeError("Configuración insegura:\n- " + "\n- ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()
