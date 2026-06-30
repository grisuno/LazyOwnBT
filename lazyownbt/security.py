"""Filtros de seguridad y helpers criptográficos.

Contrato: SEC-001 — Manejo seguro de secretos.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable


class SecretsFilter(logging.Filter):
    """Filtro de logging que redacta valores de secretos.

    Cubre el contrato SEC-001.6.
    """

    REDACTED = "[REDACTED]"

    def __init__(self, env_keys: Iterable[str]):
        super().__init__()
        self._keys = tuple(k.upper() for k in env_keys)

    def _redact(self, message: str) -> str:
        out = message
        for key in self._keys:
            pattern = re.compile(
                rf"({re.escape(key)}\s*[:=]\s*)([^\s,;]+)",
                flags=re.IGNORECASE,
            )
            out = pattern.sub(rf"\1{self.REDACTED}", out)
        return out

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        if isinstance(record.msg, str):
            record.msg = self._redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: self._redact(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self._redact(a) if isinstance(a, str) else a for a in record.args
                )
        return True


def install_secrets_filter(logger: logging.Logger, env_keys: Iterable[str]) -> None:
    """Instala el SecretsFilter en un logger."""
    flt = SecretsFilter(env_keys)
    logger.addFilter(flt)
    for handler in logger.handlers:
        handler.addFilter(flt)


def verify_password(plain: str, hashed: str) -> bool:
    """Compara una contraseña contra un hash bcrypt (SEC-001.4)."""
    import bcrypt

    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False
