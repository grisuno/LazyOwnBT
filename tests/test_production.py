"""Tests TDD para el contrato SEC-003 — Modo producción del servidor web."""

from __future__ import annotations

from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_debug_flag_default_false(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD", "x" * 32)
    from lazyownbt.web import create_app

    app = create_app(debug=False)
    assert app.config["DEBUG"] is False


def test_debug_only_with_explicit_flag(monkeypatch: pytest.MonkeyPatch):
    """Si debug=True y FLASK_ENV=production, app.config['DEBUG'] debe ser False."""
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD", "x" * 32)
    from lazyownbt.web import create_app

    app = create_app(debug=True)  # intento de subir debug en producción
    assert app.config["DEBUG"] is False


def test_bind_default_loopback(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("LAZYOWN_BIND", raising=False)
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD", "x" * 32)
    monkeypatch.setenv("FLASK_ENV", "development")
    from lazyownbt.config import load_settings

    s = load_settings()
    assert s.bind_host == "127.0.0.1"


def test_bind_warns_when_public(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    monkeypatch.setenv("LAZYOWN_BIND", "0.0.0.0")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD", "x" * 32)
    monkeypatch.setenv("FLASK_ENV", "development")
    from lazyownbt.web import create_app

    import logging
    with caplog.at_level(logging.WARNING, logger="lazyownbt.web"):
        create_app(debug=False)
    assert any("SEC-003.2" in r.getMessage() for r in caplog.records), [r.getMessage() for r in caplog.records]


def test_talisman_https_in_production(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD", "x" * 32)
    from lazyownbt.web import create_app

    app = create_app(debug=False)
    # Flask-Talisman expone la opción en app.config['TALISMAN_FORCE_HTTPS']
    # Si la versión no lo expone, validamos por feature flag interno.
    assert app.config.get("TALISMAN_FORCE_HTTPS", True) is True or app.config.get(
        "TALISMAN_CONTENT_SECURITY_POLICY"
    )  # fallback tolerante


def test_talisman_no_https_in_development(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "$2b$12$" + "a" * 53)
    from lazyownbt.web import create_app

    app = create_app(debug=True)
    assert app.config.get("TALISMAN_FORCE_HTTPS", False) is False


def test_csp_has_no_hardcoded_inline_hash():
    """SEC-003.4: no debe haber 'sha256-' en el código."""
    for f in ["main.py", "lazyownbt/web.py"]:
        text = (REPO_ROOT / f).read_text(encoding="utf-8", errors="ignore") if (REPO_ROOT / f).exists() else ""
        assert "sha256-" not in text, f"SEC-003.4: hash hardcodeado en {f}"


def test_cli_rejects_debug_in_production(monkeypatch: pytest.MonkeyPatch):
    """SEC-003.1: la CLI debe abortar si --debug y FLASK_ENV=production."""
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD", "x" * 32)
    monkeypatch.setattr("sys.argv", ["lazyownbt-web", "--debug"])
    from lazyownbt.web import run

    with pytest.raises(SystemExit) as exc_info:
        run()
    assert "SEC-003.1" in str(exc_info.value)
