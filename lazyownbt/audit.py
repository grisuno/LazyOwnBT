"""Registro de auditoría de acciones.

Contrato: SEC-002.5 — Toda invocación de acción debe quedar registrada.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger("lazyownbt.audit")


@dataclass(frozen=True)
class AuditRecord:
    action: str
    user: str
    params: Dict[str, Any]
    result: str
    duration_ms: int
    timestamp: str
    error: Optional[str] = None


class AuditLog:
    """Log de auditoría respaldado por SQLite."""

    _lock = threading.Lock()

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS action_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    user TEXT NOT NULL,
                    params TEXT NOT NULL,
                    result TEXT NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    error TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON action_audit(timestamp DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_action ON action_audit(action)"
            )

    def record(
        self,
        action: str,
        user: str,
        params: Dict[str, Any],
        result: str,
        duration_ms: int,
        error: Optional[str] = None,
    ) -> AuditRecord:
        rec = AuditRecord(
            action=action,
            user=user,
            params=params,
            result=result,
            duration_ms=duration_ms,
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=error,
        )
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO action_audit (action, user, params, result, duration_ms, timestamp, error) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    rec.action,
                    rec.user,
                    json.dumps(rec.params, sort_keys=True),
                    rec.result,
                    rec.duration_ms,
                    rec.timestamp,
                    rec.error,
                ),
            )
        logger.info("audit action=%s user=%s result=%s duration_ms=%d", action, user, result, duration_ms)
        return rec

    @contextmanager
    def track(self, action: str, user: str, params: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
        """Context manager que mide tiempo y registra resultado/errores."""
        ctx: Dict[str, Any] = {"error": None, "result": "ok"}
        t0 = time.monotonic()
        try:
            yield ctx
        except Exception as exc:  # noqa: BLE001 — auditoría captura toda excepción
            ctx["error"] = str(exc)
            ctx["result"] = "error"
            raise
        finally:
            self.record(
                action=action,
                user=user,
                params=params,
                result=ctx["result"],
                duration_ms=int((time.monotonic() - t0) * 1000),
                error=ctx["error"],
            )

    def fetch(self, limit: int = 100) -> List[AuditRecord]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM action_audit ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            AuditRecord(
                action=r["action"],
                user=r["user"],
                params=json.loads(r["params"]),
                result=r["result"],
                duration_ms=r["duration_ms"],
                timestamp=r["timestamp"],
                error=r["error"],
            )
            for r in rows
        ]
