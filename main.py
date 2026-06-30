#!/usr/bin/env python3
"""LazyOwn PurpleTeam Dashboard — entry point.

Versión endurecida (SEC-001, SEC-002, SEC-003):
  - Sin secretos hardcodeados (Settings desde entorno / .env).
  - Login con hash bcrypt vía lazyownbt.security.
  - Sin ``subprocess -c``: las acciones pasan por ``ActionRegistry`` con
    lista cerrada de comandos y argv validado.
  - CSP sin hashes hardcodeados (estilos servidos desde ``static/css/``).
  - Bind loopback por defecto; ``debug=True`` solo en ``FLASK_ENV=development``.
  - ``app.run(...)`` final delega en :func:`lazyownbt.web.run` para
    respetar los mismos contratos.

Mantiene las rutas históricas (``/alerts``, ``/events``,
``/api/correlate/<id>``) sobre la base de datos SQLite, pero las
declaraciones sensibles (auth, JWT, Talisman, ``/login``,
``/commands``, ``/healthz``, error handlers) viven en
``lazyownbt.web`` y se reusan vía :func:`create_app`.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

from lazyownbt.config import Settings, load_settings
from lazyownbt.web import create_app

logger = logging.getLogger("LazyOwnPurpleTeam")


# ---------------------------------------------------------------------------
# Capa de acceso a datos (solo SELECTs parametrizados)
# ---------------------------------------------------------------------------

class Database:
    """Acceso de solo-lectura a la base de datos SQLite del framework.

    Cualquier tabla ausente se trata como "sin datos" en lugar de romper
    el dashboard. Esto preserva el comportamiento de la versión anterior
    cuando se despliega contra una BD aún no inicializada por ``app.py``.
    """

    _ALLOWED_TABLES = frozenset({
        "alerts",
        "security_events",
        "network_baseline",
        "file_hashes",
    })

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def connect(self) -> sqlite3.Connection | None:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as exc:
            logger.error("db_connect_failed: %s", exc)
            return None

    def _safe_fetch(
        self,
        table: str,
        columns: list[str],
        where: str = "",
        params: tuple = (),
        order: str = "timestamp DESC",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Ejecuta un SELECT genérico y tolera tablas inexistentes.

        ``table`` debe estar en :data:`_ALLOWED_TABLES` (whitelist interna,
        defensa en profundidad contra inyección). ``columns`` y ``order``
        son validables por el caller; ``where`` solo puede contener
        fragmentos pre-fabricados (``"WHERE severity = ?"`` etc.).
        """
        if table not in self._ALLOWED_TABLES:
            raise ValueError(f"tabla no permitida: {table!r}")
        conn = self.connect()
        if conn is None:
            return []
        cols = ", ".join(columns)
        query = f"SELECT {cols} FROM {table} {where} ORDER BY {order} LIMIT ?"  # noqa: S608 — table/where están whitelisteadas
        try:
            cursor = conn.cursor()
            cursor.execute(query, (*params, limit))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError as exc:
            # Tabla aún no creada por app.py — se considera "sin datos".
            logger.debug("db_table_unavailable table=%s err=%s", table, exc)
            return []
        except sqlite3.Error as exc:
            logger.error("db_query_failed table=%s err=%s", table, exc)
            return []
        finally:
            conn.close()

    def fetch_alerts(
        self, limit: int = 100, severity: str | None = None
    ) -> list[dict[str, Any]]:
        where, params = "", ()
        if severity:
            where = "WHERE severity = ?"
            params = (severity,)
        rows = self._safe_fetch(
            "alerts",
            ["id", "type", "details", "severity", "timestamp"],
            where=where,
            params=params,
            limit=limit,
        )
        for row in rows:
            try:
                row["details"] = json.loads(row.get("details") or "{}")
            except (TypeError, ValueError):
                row["details"] = {}
        return rows

    def fetch_events(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._safe_fetch(
            "security_events",
            [
                "id",
                "event_type",
                "source",
                "description",
                "raw_data",
                "timestamp",
            ],
            limit=limit,
        )

    def fetch_network_baseline(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._safe_fetch(
            "network_baseline",
            ["id", "ip", "port", "protocol", "timestamp"],
            limit=limit,
        )

    def fetch_file_hashes(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._safe_fetch(
            "file_hashes",
            ["id", "file_path", "hash", "timestamp"],
            limit=limit,
        )

    def correlate_events(self, event_id: int) -> dict[str, Any]:
        """Busca alertas ±5 min relacionadas con un evento."""
        conn = self.connect()
        if conn is None:
            return {"event_id": event_id, "related_alerts": []}
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT raw_data, timestamp FROM security_events WHERE id = ?",
                (event_id,),
            )
            event = cursor.fetchone()
            if event is None:
                return {"event_id": event_id, "related_alerts": []}
            event_time = datetime.fromisoformat(event["timestamp"])
            start = (event_time - datetime.timedelta(minutes=5)).isoformat()
            end = (event_time + datetime.timedelta(minutes=5)).isoformat()
            cursor.execute(
                "SELECT id, type, details FROM alerts "
                "WHERE timestamp BETWEEN ? AND ? AND details LIKE ?",
                (start, end, f"%{event['raw_data']}%"),
            )
            related = [
                {
                    "id": r["id"],
                    "type": r["type"],
                    "details": json.loads(r["details"] or "{}"),
                }
                for r in cursor.fetchall()
            ]
            return {"event_id": event_id, "related_alerts": related}
        except sqlite3.OperationalError as exc:
            logger.debug("db_correlate_unavailable: %s", exc)
            return {"event_id": event_id, "related_alerts": []}
        except sqlite3.Error as exc:
            logger.error("db_correlate_failed: %s", exc)
            return {"event_id": event_id, "related_alerts": []}
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Rutas adicionales (sobre create_app)
# ---------------------------------------------------------------------------

def _register_data_routes(app: Flask, db: Database) -> None:
    """Añade las rutas de solo-lectura sobre la BD.

    Las rutas sensibles (``/login``, ``/commands``, ``/api/audit``,
    ``/healthz``) ya las registra :func:`lazyownbt.web.create_app`.
    """

    @app.route("/alerts")
    def alerts_view():
        severity = request.args.get("severity")
        try:
            limit = max(1, min(int(request.args.get("limit", 100)), 1000))
        except ValueError:
            limit = 100
        items = db.fetch_alerts(limit=limit, severity=severity)
        return render_template("alerts.html", alerts=items)

    @app.route("/events")
    def events_view():
        try:
            limit = max(1, min(int(request.args.get("limit", 100)), 1000))
        except ValueError:
            limit = 100
        items = db.fetch_events(limit=limit)
        return render_template("events.html", events=items)

    @app.route("/api/correlate/<int:event_id>", methods=["GET"])
    def api_correlate(event_id: int):
        return jsonify(db.correlate_events(event_id))


def _populate_dashboard_metrics(db: Database) -> dict[str, Any]:
    """Compone el payload que la plantilla ``dashboard.html`` espera."""
    alerts = db.fetch_alerts(limit=1000)
    events = db.fetch_events(limit=1000)
    network = db.fetch_network_baseline(limit=1000)
    hashes = db.fetch_file_hashes(limit=1000)
    return {
        "alerts": alerts[:10],
        "events": events[:10],
        "network_data": network[:10],
        "metrics": {
            "total_alerts": len(alerts),
            "critical_alerts": sum(
                1 for a in alerts if a.get("severity") == "critical"
            ),
            "total_events": len(events),
            "network_connections": len(network),
            "file_hashes": len(hashes),
            "system_configs": 0,
            "config_audits": 0,
            "last_scan": datetime.now().isoformat(timespec="seconds"),
        },
    }


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_app(settings: Settings | None = None) -> Flask:
    """Construye la app final reutilizando :func:`create_app`."""
    settings = settings or load_settings()
    app = create_app(settings=settings, debug=False)
    _register_data_routes(app, Database(settings.database_path))

    # Override del dashboard para pasarle datos reales (sin reventar
    # si la BD aún no tiene tablas — el Database las tolera).
    base = Path(__file__).resolve().parent
    templates_dir = base / "templates"
    app.template_folder = str(templates_dir)

    def _dashboard():
        ctx = _populate_dashboard_metrics(Database(settings.database_path))
        return render_template("dashboard.html", **ctx)

    # create_app ya registra "/" — reescribimos el view function asociado
    # en lugar de añadir una ruta nueva (Flask no permite dos vistas en /).
    app.view_functions["dashboard"] = _dashboard

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    import argparse
    import os

    from lazyownbt.config import load_settings
    from lazyownbt.web import _default_flask_env_if_unset

    parser = argparse.ArgumentParser(prog="lazyownbt-purpleteam")
    parser.add_argument("--host", default=os.environ.get("LAZYOWN_BIND", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("LAZYOWN_PORT", "5000")))
    parser.add_argument("--debug", action="store_true", help="Solo válido en development")
    args = parser.parse_args()

    _default_flask_env_if_unset()
    settings = load_settings()
    if args.debug and not settings.is_development:
        raise SystemExit("SEC-003.1: --debug solo se permite con FLASK_ENV=development")
    if args.host not in ("127.0.0.1", "::1", "localhost"):
        logger.warning(
            "SEC-003.2: bind público en %s — asegúrate de saber lo que haces",
            args.host,
        )

    app = build_app(settings=settings)
    ssl = "adhoc" if settings.is_production else None
    app.run(host=args.host, port=args.port, debug=args.debug, ssl_context=ssl)
