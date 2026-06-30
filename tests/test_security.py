"""Tests TDD para el contrato SEC-001 — Manejo seguro de secretos."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from lazyownbt.config import ConfigError, load_settings
from lazyownbt.security import SecretsFilter, install_secrets_filter, verify_password


# ---------- SEC-001.1: no hardcoded secrets en el código ----------

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_GLOBS = ("*.py", "lazyownbt/**/*.py", "skills/**/*.py", "main.py", "app.py")


def _iter_source_files() -> list[Path]:
    files: list[Path] = []
    for pattern in SOURCE_GLOBS:
        files.extend(REPO_ROOT.glob(pattern))
    return [f for f in files if f.is_file() and "tests/" not in str(f)]


def test_no_hardcoded_jwt_secret():
    """SEC-001.1: la cadena literal 'your-secret-key' no debe existir en el código."""
    offenders: list[str] = []
    for f in _iter_source_files():
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "your-secret-key" in text:
            offenders.append(str(f))
    assert not offenders, f"SEC-001.1 violado en: {offenders}"


def test_no_hardcoded_admin_password():
    """SEC-001.1: la comparación admin/password hardcodeada no debe existir."""
    pattern = re.compile(r"username\s*==\s*['\"]admin['\"]\s+and\s+password\s*==\s*['\"]password['\"]")
    offenders: list[str] = []
    for f in _iter_source_files():
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if pattern.search(text):
            offenders.append(str(f))
    assert not offenders, f"SEC-001.1 violado en: {offenders}"


# ---------- SEC-001.2: secret obligatorio en prod ----------

def test_app_aborts_when_jwt_secret_missing_in_prod(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD_HASH", raising=False)
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    assert "SEC-001.2" in str(exc_info.value)


def test_app_generates_ephemeral_secret_in_dev(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    monkeypatch.setenv("ADMIN_PASSWORD", "x" * 32)
    settings = load_settings()
    assert len(settings.jwt_secret_key) >= 32
    captured = capsys.readouterr()
    assert "JWT_SECRET_KEY" in captured.err or "JWT_SECRET_KEY" in captured.out


# ---------- SEC-001.3: fortaleza mínima ----------

@pytest.mark.parametrize("bad_secret", ["short", "x" * 31])
def test_jwt_secret_below_minimum_length_aborts(monkeypatch: pytest.MonkeyPatch, bad_secret: str):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", bad_secret)
    monkeypatch.setenv("ADMIN_PASSWORD", "x" * 32)
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    assert "SEC-001.3" in str(exc_info.value)


def test_empty_jwt_secret_triggers_absence_rule(monkeypatch: pytest.MonkeyPatch):
    """Una variable presente pero vacía se trata como ausente (SEC-001.2)."""
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", "")
    monkeypatch.setenv("ADMIN_PASSWORD", "x" * 32)
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    assert "SEC-001.2" in str(exc_info.value)


# ---------- SEC-001.4: hash bcrypt ----------

def test_password_is_hashed_not_plain(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import bcrypt
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    hashed = bcrypt.hashpw(b"my-secret", bcrypt.gensalt()).decode("utf-8")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", hashed)
    monkeypatch.setenv("LAZYOWN_DB_PATH", str(tmp_path / "audit.db"))
    settings = load_settings()
    assert verify_password("my-secret", settings.admin_password_hash) is True
    assert verify_password("wrong", settings.admin_password_hash) is False
    assert "$2b$" in settings.admin_password_hash or "$2a$" in settings.admin_password_hash


# ---------- SEC-001.5: .env fuera del repo ----------

def test_env_file_is_gitignored():
    gitignore = REPO_ROOT / ".gitignore"
    assert gitignore.exists(), ".gitignore debe existir"
    content = gitignore.read_text(encoding="utf-8")
    # Aceptar ".env" exacto o ".env*" para cubrir .env, .env.local, etc.
    assert re.search(r"^\.env(\b|\.|\*|$)", content, re.MULTILINE), (
        "SEC-001.5: '.env' debe estar en .gitignore"
    )


def test_env_example_exists():
    assert (REPO_ROOT / ".env.example").exists(), "SEC-001.5: .env.example debe existir"


# ---------- SEC-001.6: secrets filter ----------

def test_secrets_filter_redacts_values():
    flt = SecretsFilter(["JWT_SECRET_KEY", "ADMIN_PASSWORD"])
    record = type("R", (), {"msg": "JWT_SECRET_KEY=secret123 ADMIN_PASSWORD=foo", "args": None})()
    assert flt.filter(record) is True
    assert "[REDACTED]" in record.msg
    assert "secret123" not in record.msg
    assert "foo" not in record.msg


def test_secrets_filter_redacts_in_args():
    flt = SecretsFilter(["API_TOKEN"])
    record = type("R", (), {"msg": "hello %s", "args": ("API_TOKEN=xyz",)})()
    flt.filter(record)
    assert record.args == ("API_TOKEN=[REDACTED]",)


def test_secrets_filter_redacts_in_dict_args():
    flt = SecretsFilter(["DB_PASSWORD"])
    record = type("R", (), {"msg": "k=%(k)s", "args": {"k": "DB_PASSWORD=zzz"}})()
    flt.filter(record)
    assert record.args == {"k": "DB_PASSWORD=[REDACTED]"}
