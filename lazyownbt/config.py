"""Carga de configuración desde variables de entorno y .env.

Contrato: CFG-001 — Configuración desde entorno.
"""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from dotenv import load_dotenv

# Llaves de secretos que el SecretsFilter debe redactar en logs.
SECRETS_ENV_KEYS: List[str] = [
    "JWT_SECRET_KEY",
    "ADMIN_PASSWORD",
    "ADMIN_PASSWORD_HASH",
    "DB_PASSWORD",
    "API_TOKEN",
    "OLLAMA_API_KEY",
]


class ConfigError(RuntimeError):
    """Error de configuración. Falla ruidosamente con mensaje accionable."""


def _load_dotenv() -> None:
    """Carga .env si existe. No falla si no existe (CFG-001.2)."""
    env_path = Path.cwd() / ".env"
    if env_path.is_file():
        load_dotenv(env_path, override=False)


def _resolve_jwt_secret() -> str:
    """Resuelve el secreto de JWT según SEC-001.2 y SEC-001.3."""
    raw = os.environ.get("JWT_SECRET_KEY")
    env = os.environ.get("FLASK_ENV", "production").lower()
    secret = raw.strip() if raw else ""

    # SEC-001.2: ausente (None o vacío) y en producción → abortar.
    if not secret:
        if env == "production":
            raise ConfigError(
                "SEC-001.2: JWT_SECRET_KEY no está definida. "
                "En producción es obligatoria. Genera una con: "
                "`python -c 'import secrets; print(secrets.token_urlsafe(64))'` "
                "y colócala en el entorno o en .env."
            )
        # development: generar efímero
        secret = secrets.token_urlsafe(64)
        print(
            "[WARN] JWT_SECRET_KEY no definida. Se generó una efímera para "
            "esta sesión de desarrollo. Los tokens emitidos serán inválidos "
            "al reiniciar.",
            file=sys.stderr,
        )

    # SEC-001.3: fortaleza mínima (incluye el caso de string vacío, ya
    # manejado arriba, pero un valor presente pero corto dispara esto).
    if len(secret.encode("utf-8")) < 32:
        raise ConfigError(
            f"SEC-001.3: JWT_SECRET_KEY debe tener al menos 32 bytes. "
            f"Longitud actual: {len(secret)}."
        )
    return secret


def _resolve_admin_password_hash() -> str:
    """Resuelve el hash de la contraseña admin según SEC-001.4.

    Si ADMIN_PASSWORD está definida, se hashea con bcrypt y se retorna.
    Si ADMIN_PASSWORD_HASH está definida (ya hasheada), se retorna tal cual.
    Si ninguna está definida y estamos en development, se usa 'admin' como
    contraseña de desarrollo con un warning.
    """
    import bcrypt

    env = os.environ.get("FLASK_ENV", "production").lower()
    plain = os.environ.get("ADMIN_PASSWORD")
    hashed = os.environ.get("ADMIN_PASSWORD_HASH")

    if hashed:
        return hashed
    if plain:
        return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    if env == "development":
        # contraseña de desarrollo: "admin" con hash bcrypt
        return bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")

    raise ConfigError(
        "SEC-001.4: se requiere ADMIN_PASSWORD o ADMIN_PASSWORD_HASH. "
        "Genera un hash con: "
        "`python -c 'import bcrypt; print(bcrypt.hashpw(b\"tu_password\", bcrypt.gensalt()).decode())'`"
    )


@dataclass(frozen=True)
class Settings:
    """Configuración inmutable de la aplicación."""

    flask_env: str
    jwt_secret_key: str
    admin_password_hash: str
    database_path: str
    bind_host: str
    bind_port: int
    command_timeout: int
    secrets_env_keys: List[str] = field(default_factory=lambda: list(SECRETS_ENV_KEYS))

    @property
    def is_production(self) -> bool:
        return self.flask_env == "production"

    @property
    def is_development(self) -> bool:
        return self.flask_env == "development"


def load_settings() -> Settings:
    """Carga y valida la configuración. Falla ruidosamente (CFG-001.3)."""
    _load_dotenv()

    flask_env = os.environ.get("FLASK_ENV", "production").lower()
    if flask_env not in {"production", "development", "testing"}:
        raise ConfigError(f"FLASK_ENV inválido: {flask_env!r}")

    bind_host = os.environ.get("LAZYOWN_BIND", "127.0.0.1")
    bind_port = int(os.environ.get("LAZYOWN_PORT", "5000"))
    command_timeout = int(os.environ.get("LAZYOWN_COMMAND_TIMEOUT", "30"))
    database_path = os.environ.get("LAZYOWN_DB_PATH", "./lazyown.db")

    return Settings(
        flask_env=flask_env,
        jwt_secret_key=_resolve_jwt_secret(),
        admin_password_hash=_resolve_admin_password_hash(),
        database_path=database_path,
        bind_host=bind_host,
        bind_port=bind_port,
        command_timeout=command_timeout,
    )
