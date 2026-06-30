"""Tests TDD para el contrato CFG-001 / CFG-002 — Configuración."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

from lazyownbt.config import ConfigError, load_settings


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_config_loads_from_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "$2b$12$" + "a" * 53)
    s = load_settings()
    assert s.jwt_secret_key == "x" * 64
    assert s.flask_env == "development"


def test_config_fails_loudly_on_missing_var(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD_HASH", raising=False)
    with pytest.raises(ConfigError):
        load_settings()


def _extract_top_level_imports(source_files: list[Path]) -> set[str]:
    """Extrae los nombres de paquetes top-level importados en cada archivo."""
    pkgs: set[str] = set()
    for path in source_files:
        if not path.exists() or "/tests/" in str(path):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    pkgs.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue
                if node.module:
                    pkgs.add(node.module.split(".")[0])
    return pkgs


def _declared_deps() -> set[str]:
    import tomllib
    with (REPO_ROOT / "pyproject.toml").open("rb") as f:
        data = tomllib.load(f)
    declared: set[str] = set()
    for entry in data.get("project", {}).get("dependencies", []):
        declared.add(re.split(r"[<>=!~]", entry)[0].strip().lower())
    for group in data.get("project", {}).get("optional-dependencies", {}).values():
        for entry in group:
            declared.add(re.split(r"[<>=!~]", entry)[0].strip().lower())
    return declared


STDLIB = set(sys.stdlib_module_names)

# Mapeo de nombre de import a nombre de paquete en PyPI cuando difieren.
IMPORT_TO_PKG = {
    "dotenv": "python-dotenv",
    "sklearn": "scikit-learn",
    "yaml": "PyYAML",
    "cv2": "opencv-python",
    "PIL": "pillow",
    "bs4": "beautifulsoup4",
    "attr": "attrs",
}


def _canonical(pkg: str) -> set[str]:
    """Devuelve los nombres canónicos posibles para un paquete."""
    candidates = {pkg.lower(), pkg.replace("_", "-").lower()}
    mapped = IMPORT_TO_PKG.get(pkg)
    if mapped:
        candidates.add(mapped.lower())
    return candidates


def test_requirements_contains_all_imports():
    """CFG-002.1/CFG-002.2: cada import del código debe estar declarado."""
    src_files = [
        REPO_ROOT / "lazyownbt" / "__init__.py",
        REPO_ROOT / "lazyownbt" / "config.py",
        REPO_ROOT / "lazyownbt" / "security.py",
        REPO_ROOT / "lazyownbt" / "actions.py",
        REPO_ROOT / "lazyownbt" / "audit.py",
        REPO_ROOT / "lazyownbt" / "web.py",
        REPO_ROOT / "lazyownbt" / "handlers.py",
    ]
    src_files = [p for p in src_files if p.exists()]
    imports = _extract_top_level_imports(src_files)
    declared = _declared_deps()

    missing: set[str] = set()
    for pkg in imports:
        if pkg in STDLIB or pkg.startswith("lazyownbt"):
            continue
        if not _canonical(pkg) & declared:
            missing.add(pkg)
    assert not missing, f"Faltan en pyproject.toml: {sorted(missing)}"


def test_pyproject_extras_declared():
    """Los grupos cli, web, ai, rag, fim, utils, dev deben existir."""
    import tomllib
    with (REPO_ROOT / "pyproject.toml").open("rb") as f:
        data = tomllib.load(f)
    extras = data.get("project", {}).get("optional-dependencies", {})
    for required in ("cli", "web", "ai", "rag", "fim", "utils", "dev"):
        assert required in extras, f"Falta extra group: {required}"
