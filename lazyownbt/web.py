"""Factory de la aplicación Flask (dashboard PurpleTeam).

Reemplaza al `main.py` monolítico. Cumple los contratos:
- SEC-001: secretos desde entorno
- SEC-002: ejecución segura de comandos (sin subprocess dinámico)
- SEC-003: modo producción con HTTPS, bind loopback, debug off
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from flask_talisman import Talisman

from lazyownbt.actions import (
    DEFAULT_ACTIONS,
    ActionParseError,
    ActionRegistry,
    ActionSpec,
)
from lazyownbt.audit import AuditLog
from lazyownbt.config import Settings, load_settings
from lazyownbt.security import install_secrets_filter, verify_password

logger = logging.getLogger("lazyownbt.web")


def _build_csp(static_csp_hash: bool) -> dict[str, Any]:
    """CSP estricta sin hashes hardcodeados (SEC-003.4)."""
    csp: dict[str, Any] = {
        "default-src": "'self'",
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "img-src": ["'self'", "data:"],
        "object-src": "'none'",
        "base-uri": "'self'",
        "frame-ancestors": "'none'",
    }
    if static_csp_hash:
        # Solo para los archivos estáticos servidos localmente.
        csp["style-src"].append("'self'")
    return csp


def _register_default_actions(registry: ActionRegistry) -> None:
    """Carga las acciones por defecto. Cada handler es un stub testable."""
    from lazyownbt.handlers import build_default_handlers

    handlers = build_default_handlers()
    for spec in DEFAULT_ACTIONS:
        if spec.name not in handlers:
            raise RuntimeError(f"Acción {spec.name} sin handler")
        registry.register(spec, handlers[spec.name])


def create_app(
    settings: Settings | None = None,
    *,
    registry: ActionRegistry | None = None,
    audit: AuditLog | None = None,
    debug: bool = False,
) -> Flask:
    """Crea y configura la app Flask."""
    settings = settings or load_settings()

    # SEC-003.2: bind público debe warnear.
    if settings.bind_host not in ("127.0.0.1", "::1", "localhost"):
        logger.warning(
            "SEC-003.2: bind público en %s — asegúrate de saber lo que haces",
            settings.bind_host,
        )

    base = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(base / "templates"),
        static_folder=str(base / "static"),
    )
    app.config["JWT_SECRET_KEY"] = settings.jwt_secret_key
    app.config["SETTINGS"] = settings
    app.config["DEBUG"] = debug and settings.is_development
    app.config["ACTION_REGISTRY"] = registry or ActionRegistry()
    app.config["AUDIT_LOG"] = audit or AuditLog(settings.database_path)
    app.config["PROPAGATE_EXCEPTIONS"] = False

    if not app.config["ACTION_REGISTRY"].names():
        _register_default_actions(app.config["ACTION_REGISTRY"])

    JWTManager(app)
    install_secrets_filter(logger, settings.secrets_env_keys)

    # SEC-003.3 + SEC-003.4
    force_https = settings.is_production
    Talisman(
        app,
        force_https=force_https,
        content_security_policy=_build_csp(static_csp_hash=False),
    )

    _register_routes(app)
    return app


def _register_routes(app: Flask) -> None:

    @app.route("/healthz")
    def healthz():
        return jsonify(status="ok", version=app.config["SETTINGS"].flask_env)

    @app.route("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/api/dashboard", methods=["GET"])
    @jwt_required()
    def api_dashboard():
        """Resumen para el dashboard.

        Mantener la lógica de DB en una capa aparte cuando se integre el
        módulo de almacenamiento; por ahora retornamos un payload mínimo
        que la plantilla pueda renderizar.
        """
        return jsonify(
            metrics={
                "total_alerts": 0,
                "critical_alerts": 0,
                "total_events": 0,
                "last_scan": "—",
            },
            alerts=[],
            events=[],
        )

    @app.route("/commands", methods=["GET", "POST"])
    def commands():
        if request.method == "POST":
            return _handle_command(app)
        registry: ActionRegistry = app.config["ACTION_REGISTRY"]
        return render_template("commands.html", allowed_commands=registry.names())

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        settings: Settings = app.config["SETTINGS"]
        if not username or not password:
            return jsonify(error="Credenciales inválidas"), 401
        if username != "admin" or not verify_password(password, settings.admin_password_hash):
            logger.warning("login_failed user=%s", username)
            return jsonify(error="Credenciales inválidas"), 401
        token = create_access_token(identity=username)
        logger.info("login_ok user=%s", username)
        return jsonify(access_token=token)

    @app.route("/api/audit", methods=["GET"])
    @jwt_required()
    def api_audit():
        audit: AuditLog = app.config["AUDIT_LOG"]
        limit = min(int(request.args.get("limit", 100)), 1000)
        return jsonify([r.__dict__ for r in audit.fetch(limit=limit)])

    @app.errorhandler(404)
    def not_found(_):
        return jsonify(error="No encontrado"), 404

    @app.errorhandler(500)
    def server_error(_):
        logger.exception("internal_server_error")
        return jsonify(error="Error interno"), 500


def _handle_command(app: Flask) -> Any:
    """Ejecuta una acción validada por la lista cerrada (SEC-002.*)."""
    registry: ActionRegistry = app.config["ACTION_REGISTRY"]
    audit: AuditLog = app.config["AUDIT_LOG"]

    # JWT obligatorio (SEC-002.6)
    from flask_jwt_extended import verify_jwt_in_request

    try:
        verify_jwt_in_request()
    except Exception:
        return jsonify(error="Token requerido"), 401

    user = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    action = (data.get("command") or "").strip()
    raw_params = data.get("params") or {}

    if not action or not registry.is_allowed(action):
        return jsonify(error="Acción no permitida"), 403

    try:
        params = registry.validate_params(action, raw_params)
    except ActionParseError as exc:
        return jsonify(error=str(exc)), 400

    handler = registry.handler(action)
    spec: ActionSpec = registry.spec(action)  # type: ignore[assignment]
    with audit.track(action=action, user=user, params=params):
        # SEC-002.4: timeout duro a través de un watchdog en el caller.
        # Aquí delegamos al handler (que es código de aplicación, no shell).
        output = handler(**params)
    return jsonify(output=output, action=action, spec=spec.description)


def _default_flask_env_if_unset() -> None:
    """UX: si FLASK_ENV no está definida, asume development con warning.

    En producción el operador DEBE exportar FLASK_ENV=production. Esto NO
    debilita el contrato: ``load_settings`` sigue exigiendo JWT_SECRET_KEY
    cuando FLASK_ENV=production (probado en test_security.py).
    """
    if "FLASK_ENV" not in os.environ:
        os.environ["FLASK_ENV"] = "development"
        logger.warning(
            "FLASK_ENV no estaba definido; asumiendo 'development'. "
            "Para producción exporta FLASK_ENV=production y define "
            "JWT_SECRET_KEY (>=32 bytes) y ADMIN_PASSWORD[_HASH]."
        )


def run() -> None:
    """Punto de entrada CLI: respeta SEC-003.1 y SEC-003.2."""
    import argparse

    parser = argparse.ArgumentParser(prog="lazyownbt-web")
    parser.add_argument("--host", default=os.environ.get("LAZYOWN_BIND", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("LAZYOWN_PORT", "5000")))
    parser.add_argument("--debug", action="store_true", help="Solo válido en development")
    args = parser.parse_args()

    _default_flask_env_if_unset()
    settings = load_settings()
    if args.debug and not settings.is_development:
        raise SystemExit("SEC-003.1: --debug solo se permite con FLASK_ENV=development")
    if args.host not in ("127.0.0.1", "::1", "localhost"):
        logger.warning("SEC-003.2: bind público en %s — asegúrate de saber lo que haces", args.host)

    app = create_app(settings=settings, debug=args.debug)
    ssl = "adhoc" if settings.is_production else None
    app.run(host=args.host, port=args.port, debug=args.debug, ssl_context=ssl)


if __name__ == "__main__":  # pragma: no cover
    run()
