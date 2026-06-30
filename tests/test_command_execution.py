"""Tests TDD para el contrato SEC-002 — Ejecución segura de comandos."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
APP_FILES = ["main.py", "app.py", "lazyownbt/web.py", "lazyownbt/handlers.py", "skills/lazyownbt_mcp.py"]


def _read(path: str) -> str:
    p = REPO_ROOT / path
    return p.read_text(encoding="utf-8", errors="ignore") if p.exists() else ""


# ---------- SEC-002.1: no subprocess dinámico ----------

def test_subprocess_dynamic_python_is_gone():
    """SEC-002.1: no debe haber subprocess con 'python3', '-c' o f-string hacia -c."""
    offenders: list[str] = []
    pattern_dynamic = re.compile(
        r"subprocess\.(?:run|Popen|call|check_output|check_call)\s*\("
        r"[^)]*?['\"]python3?['\"][^)]*?['\"]-c['\"]"
        r"|os\.system\s*\(\s*[fF]?['\"]python[^\n]*-c"
        r"|subprocess\.[A-Za-z_]+\([^)]*?-c\s*['\"]"
    )
    for f in APP_FILES:
        text = _read(f)
        if pattern_dynamic.search(text):
            offenders.append(f)
    assert not offenders, f"SEC-002.1 violado en: {offenders}"


def test_no_eval_on_user_input():
    """SEC-002.1: no debe haber eval/exec sobre input del usuario."""
    pattern = re.compile(
        r"\beval\s*\(\s*(?:request\.|data\[|input\(|.*form\.|.*json\.)"
        r"|\bexec\s*\(\s*(?:request\.|data\[|input\(|.*form\.|.*json\.)"
    )
    offenders: list[str] = []
    for f in APP_FILES:
        text = _read(f)
        if pattern.search(text):
            offenders.append(f)
    assert not offenders, f"SEC-002.1 violado en: {offenders}"


# ---------- SEC-002.2: lista cerrada ----------

def test_command_not_in_allowlist_is_rejected(client):
    response = client.post(
        "/commands",
        data=json.dumps({"command": "do_evil_rm_rf", "params": {"path": "/"}}),
        content_type="application/json",
    )
    # Sin JWT: 401 primero; con JWT: 403
    assert response.status_code in (401, 403)


def test_command_not_in_allowlist_returns_403(auth_client):
    response = auth_client.post(
        "/commands",
        data=json.dumps({"command": "do_evil_rm_rf", "params": {}}),
        content_type="application/json",
    )
    assert response.status_code == 403
    assert "no permitida" in response.get_json()["error"]


# ---------- SEC-002.3: validación de parámetros ----------

def test_command_validates_params(auth_client):
    response = auth_client.post(
        "/commands",
        data=json.dumps({"command": "do_resp_kill_proc", "params": {"pid": "abc"}}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert "pid" in response.get_json()["error"]


def test_command_missing_required_param(auth_client):
    response = auth_client.post(
        "/commands",
        data=json.dumps({"command": "do_resp_block_ip", "params": {}}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert "ip_address" in response.get_json()["error"]


def test_command_rejects_unknown_params(auth_client):
    response = auth_client.post(
        "/commands",
        data=json.dumps({"command": "do_net_scan", "params": {"rogue": "x"}}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert "desconocidos" in response.get_json()["error"]


# ---------- SEC-002.6: autenticación obligatoria ----------

def test_command_requires_jwt(client):
    response = client.post(
        "/commands",
        data=json.dumps({"command": "do_net_scan", "params": {}}),
        content_type="application/json",
    )
    assert response.status_code == 401


# ---------- SEC-002.5: auditoría ----------

def test_command_audit_recorded(auth_client, app):
    response = auth_client.post(
        "/commands",
        data=json.dumps({"command": "do_net_scan", "params": {}}),
        content_type="application/json",
    )
    assert response.status_code == 200
    with app.app_context():
        audit_log = app.config["AUDIT_LOG"]
        records = audit_log.fetch(limit=10)
    assert any(r.action == "do_net_scan" and r.result == "ok" for r in records), records


def test_command_audit_records_error(auth_client, app):
    response = auth_client.post(
        "/commands",
        data=json.dumps({"command": "do_resp_kill_proc", "params": {"pid": -1}}),
        content_type="application/json",
    )
    assert response.status_code == 500
    with app.app_context():
        audit_log = app.config["AUDIT_LOG"]
        records = audit_log.fetch(limit=10)
    assert any(r.action == "do_resp_kill_proc" and r.result == "error" for r in records), records


def test_audit_endpoint_returns_records(auth_client):
    auth_client.post(
        "/commands",
        data=json.dumps({"command": "do_net_scan", "params": {}}),
        content_type="application/json",
    )
    response = auth_client.get("/api/audit")
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)
    assert any(r["action"] == "do_net_scan" for r in data)


# ---------- SEC-002: ejecución vía Python call ----------

def test_command_executes_via_python_call(auth_client, monkeypatch: pytest.MonkeyPatch):
    """Verifica que el handler se llama como función Python, no como shell."""
    called: dict = {}

    def fake_handler(**kwargs):
        called["args"] = kwargs
        return "ok-from-fake"

    from lazyownbt.actions import ActionRegistry, ActionSpec

    registry = ActionRegistry()
    registry.register(
        ActionSpec(name="test_action", description="t", params={"x": int}, required=("x",)),
        fake_handler,
    )

    from lazyownbt.web import create_app

    test_app = create_app(debug=False)
    test_app.config["ACTION_REGISTRY"] = registry
    test_app.config["TESTING"] = True
    test_client = test_app.test_client()
    test_client.environ_base["HTTP_AUTHORIZATION"] = auth_client.environ_base["HTTP_AUTHORIZATION"]

    response = test_client.post(
        "/commands",
        data=json.dumps({"command": "test_action", "params": {"x": 5}}),
        content_type="application/json",
    )
    assert response.status_code == 200
    assert response.get_json()["output"] == "ok-from-fake"
    assert called["args"] == {"x": 5}
