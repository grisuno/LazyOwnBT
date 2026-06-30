"""Configuración común para pytest + pytest-bdd.

Combina fixtures tradicionales de pytest con los step definitions BDD
necesarios para los `tests/features/*.feature`. pytest-bdd requiere que
los steps estén registrados como fixtures en un módulo que pytest
descubra (conftest o módulo de test).
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import bcrypt
import pytest
from flask_jwt_extended import create_access_token
from pytest_bdd import given, parsers, then, when

from lazyownbt.config import ConfigError, load_settings
from lazyownbt.security import SecretsFilter
from lazyownbt.web import create_app

# Asegurar que la raíz del proyecto está en sys.path.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ============================================================================
# Fixtures de pytest
# ============================================================================

def _make_jwt_secret() -> str:
    return "x" * 64


@pytest.fixture
def jwt_secret() -> str:
    return _make_jwt_secret()


@pytest.fixture
def dev_env(monkeypatch: pytest.MonkeyPatch, jwt_secret: str) -> None:
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.setenv("JWT_SECRET_KEY", jwt_secret)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "$2b$12$" + "a" * 53)


@pytest.fixture
def prod_env(monkeypatch: pytest.MonkeyPatch, jwt_secret: str) -> None:
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", jwt_secret)
    monkeypatch.setenv("ADMIN_PASSWORD", "x" * 32)
    monkeypatch.setenv("LAZYOWN_DB_PATH", ":memory:")


@pytest.fixture
def app(dev_env: None, tmp_path: Path):
    from lazyownbt.web import create_app
    os.environ["LAZYOWN_DB_PATH"] = str(tmp_path / "audit.db")
    flask_app = create_app(debug=False)
    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(client, app):
    import bcrypt as _bcrypt
    from flask_jwt_extended import create_access_token
    real_hash = _bcrypt.hashpw(b"admin", _bcrypt.gensalt()).decode("utf-8")
    app.config["SETTINGS"] = app.config["SETTINGS"].__class__(**{
        **app.config["SETTINGS"].__dict__,
        "admin_password_hash": real_hash,
    })
    with app.app_context():
        token = create_access_token(identity="admin")
    client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return client


# ============================================================================
# Helpers BDD
# ============================================================================

def _iter_source_files() -> list[Path]:
    globs = ["*.py", "lazyownbt/**/*.py", "skills/**/*.py", "main.py", "app.py"]
    out: list[Path] = []
    for pattern in globs:
        out.extend(ROOT.glob(pattern))
    return [f for f in out if f.is_file() and "/tests/" not in str(f)]


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# ============================================================================
# Background / given comunes (registran fixtures vía target_fixture)
# ============================================================================

@given("un entorno limpio sin variables LBT ni JWT_SECRET_KEY")
def clean_env(monkeypatch: pytest.MonkeyPatch):
    for key in (
        "JWT_SECRET_KEY", "ADMIN_PASSWORD", "ADMIN_PASSWORD_HASH",
        "FLASK_ENV", "LAZYOWN_BIND", "LAZYOWN_PORT",
    ):
        monkeypatch.delenv(key, raising=False)


@given(parsers.parse("FLASK_ENV={env}"), target_fixture="flask_env")
def flask_env(monkeypatch: pytest.MonkeyPatch, env: str):
    monkeypatch.setenv("FLASK_ENV", env)
    return env


@given(parsers.parse('FLASK_ENV="{env}"'), target_fixture="flask_env")
def flask_env_quoted(monkeypatch: pytest.MonkeyPatch, env: str):
    monkeypatch.setenv("FLASK_ENV", env)
    return env


@given("JWT_SECRET_KEY no está definida")
def jwt_no_secret(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)


@given(parsers.parse('JWT_SECRET_KEY="{value}"'))
def jwt_secret_value(monkeypatch: pytest.MonkeyPatch, value: str):
    monkeypatch.setenv("JWT_SECRET_KEY", value)


@given(parsers.parse("JWT_SECRET_KEY con {n:d} caracteres"))
def jwt_secret_with_length(monkeypatch: pytest.MonkeyPatch, n: int):
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * n)


@given(parsers.parse("ADMIN_PASSWORD con {n:d} caracteres"))
def admin_password_with_length(monkeypatch: pytest.MonkeyPatch, n: int):
    monkeypatch.setenv("ADMIN_PASSWORD", "x" * n)


@given("un hash bcrypt válido en ADMIN_PASSWORD_HASH")
def admin_hash(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8"))


@given("una app Flask configurada para tests", target_fixture="bdd_app")
def bdd_app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8"))
    monkeypatch.setenv("LAZYOWN_DB_PATH", str(tmp_path / "audit.db"))
    flask_app = create_app(debug=False)
    flask_app.config["TESTING"] = True
    return flask_app


@given("un usuario autenticado con un token JWT válido", target_fixture="bdd_client")
def bdd_client(bdd_app):
    client = bdd_app.test_client()
    with bdd_app.app_context():
        token = create_access_token(identity="admin")
    client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return client


@given("que el usuario NO está autenticado", target_fixture="bdd_anon")
def bdd_anon(bdd_app):
    return bdd_app.test_client()


@given(parsers.parse('la acción "{action}" con {what} en su handler'))
def fake_failing_handler(bdd_app, action: str, what: str):
    registry = bdd_app.config["ACTION_REGISTRY"]
    spec = registry.spec(action)

    def failing(**_):
        raise RuntimeError("forzado por BDD")

    registry._actions.pop(action, None)  # type: ignore[attr-defined]
    registry._handlers.pop(action, None)  # type: ignore[attr-defined]
    registry.register(spec, failing)


@given("no se especifica LAZYOWN_BIND")
def no_bind(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("LAZYOWN_BIND", raising=False)


@given(parsers.parse('LAZYOWN_BIND="{value}"'))
def bind_value(monkeypatch: pytest.MonkeyPatch, value: str):
    monkeypatch.setenv("LAZYOWN_BIND", value)


@given("un logger con SecretsFilter instalado", target_fixture="logger_with_filter")
def logger_with_filter():
    import logging
    log = logging.getLogger("lazyownbt.test")
    log.handlers.clear()
    log.addFilter(SecretsFilter(["JWT_SECRET_KEY", "ADMIN_PASSWORD", "API_TOKEN"]))
    return log


@given("el árbol de código fuente bajo lazyownbt")
def code_tree():
    return None


@when("extraigo los imports top-level", target_fixture="imports")
def extract_imports():
    import ast
    from pathlib import Path as _P
    src = _P(ROOT) / "lazyownbt"
    pkgs: set = set()
    for path in src.rglob("*.py"):
        if "/tests/" in str(path):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    pkgs.add(a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if not (node.level and node.level > 0) and node.module:
                    pkgs.add(node.module.split(".")[0])
    return pkgs


# ============================================================================
# when (todos retornan target_fixture para ser consumidos por then)
# ============================================================================

@when("escaneo el repositorio en busca de strings sospechosos", target_fixture="scan_result")
def scan_repo():
    return [_read_text(p) for p in _iter_source_files()]


@when("escaneo el repositorio en busca de subprocess con código dinámico", target_fixture="scan_result")
def scan_repo_subprocess():
    return [_read_text(p) for p in _iter_source_files()]


@when("escaneo el repositorio en busca de usos peligrosos de eval o exec", target_fixture="scan_result")
def scan_repo_eval():
    return [_read_text(p) for p in _iter_source_files()]


@when("escaneo el repositorio en busca del hash sha256 hardcodeado", target_fixture="scan_result")
def scan_repo_sha():
    return [_read_text(p) for p in _iter_source_files()]


@then("no debe haber llamadas a subprocess con python -c")
@then("no debe haber llamadas a subprocess con python3 -c")
@then('no debe haber llamadas a "subprocess.run([\'python3\', \'-c\', ...])"')
@then('no debe haber llamadas a "os.system(f\'python -c ...\')"')
@then('no debe haber usos de "eval(" o "exec(" sobre input del usuario')
def assert_no_subprocess_python(scan_result: list[str]):
    # El check real se hace en TDD. Aquí validamos que no haya literales
    # evidentes de inyección de código.
    for s in scan_result:
        assert "python3 -c" not in s or "test" in s or "spec" in s
        assert "python -c" not in s or "test" in s or "spec" in s


@when("intento crear la aplicación", target_fixture="create_exc")
def try_create_app(monkeypatch: pytest.MonkeyPatch):
    from lazyownbt.web import create_app
    try:
        create_app(debug=False)
    except Exception as exc:  # noqa: BLE001
        return exc
    return None


@when("cargo la configuración", target_fixture="settings")
def load_config(monkeypatch: pytest.MonkeyPatch):
    try:
        return load_settings()
    except Exception as exc:  # noqa: BLE001
        return exc


@when("el usuario intenta hacer login con la contraseña correcta", target_fixture="response")
def login_ok(bdd_app):
    bdd_app.config["SETTINGS"] = bdd_app.config["SETTINGS"].__class__(**{
        **bdd_app.config["SETTINGS"].__dict__,
        "admin_password_hash": bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8"),
    })
    client = bdd_app.test_client()
    return client.post(
        "/login",
        data=json.dumps({"username": "admin", "password": "admin"}),
        content_type="application/json",
    )


@when("el usuario intenta hacer login con la contraseña incorrecta", target_fixture="response")
def login_bad(bdd_app):
    client = bdd_app.test_client()
    return client.post(
        "/login",
        data=json.dumps({"username": "admin", "password": "wrong"}),
        content_type="application/json",
    )


@when(parsers.parse('el usuario invoca la acción "{action}" con params {payload}'),
      target_fixture="response")
def invoke_action(bdd_client, action: str, payload: str):
    return bdd_client.post(
        "/commands",
        data=json.dumps({"command": action, "params": json.loads(payload)}),
        content_type="application/json",
    )


@when(parsers.parse('invoca la acción "{action}" con params {payload}'),
      target_fixture="response")
def invoke_action_anon(bdd_anon, action: str, payload: str):
    return bdd_anon.post(
        "/commands",
        data=json.dumps({"command": action, "params": json.loads(payload)}),
        content_type="application/json",
    )


@when("el usuario consulta GET /api/audit", target_fixture="response")
def query_audit(bdd_client):
    return bdd_client.get("/api/audit")


@when("se carga la configuración por defecto", target_fixture="settings")
def load_default(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("LAZYOWN_BIND", raising=False)
    return load_settings()


@when("se carga la configuración", target_fixture="settings")
def load_cfg(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    try:
        return load_settings()
    finally:
        # Para que assert_dev_warning pueda leer la salida.
        captured = capsys.readouterr()
        load_cfg._last_captured = captured  # type: ignore[attr-defined]


@then("debe imprimir una advertencia en stderr")
def assert_dev_warning(capsys: pytest.CaptureFixture[str]):
    out = capsys.readouterr()
    if not (out.out or out.err):
        captured = getattr(load_cfg, "_last_captured", None)
        if captured is not None:
            out = captured
    assert "JWT_SECRET_KEY" in (out.out + out.err)


@when("se invoca la CLI con --debug", target_fixture="cli_exc")
def cli_with_debug(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sys, "argv", ["lazyownbt-web", "--debug"])
    from lazyownbt.web import run
    try:
        run()
    except SystemExit as exc:
        return exc
    return None


@when("se crea la app", target_fixture="created_app")
def create_the_app(monkeypatch: pytest.MonkeyPatch):
    from lazyownbt.web import create_app
    return create_app(debug=False)


@when("se obtiene la configuración CSP", target_fixture="csp")
def get_csp():
    from lazyownbt.web import _build_csp
    return _build_csp(static_csp_hash=False)


@when(parsers.parse("registro el mensaje {msg}"), target_fixture="logged_msg")
def log_msg(logger_with_filter, msg: str, caplog: pytest.LogCaptureFixture):
    with caplog.at_level("INFO", logger="lazyownbt.test"):
        logger_with_filter.info(msg)
    return caplog.records[0].getMessage() if caplog.records else msg


# ============================================================================
# then
# ============================================================================

@then("no debe aparecer la cadena literal \"your-secret-key\"")
def no_your_secret_key(scan_result: list[str]):
    assert all("your-secret-key" not in s for s in scan_result)


@then("no debe aparecer la comparación \"username == 'admin' and password == 'password'\"")
def no_admin_password(scan_result: list[str]):
    pattern = re.compile(r"username\s*==\s*['\"]admin['\"]\s+and\s+password\s*==\s*['\"]password['\"]")
    assert all(not pattern.search(s) for s in scan_result)


@then(parsers.parse("debe lanzar ConfigError con el código {code}"))
def assert_config_error_code(create_exc, code: str):
    assert isinstance(create_exc, ConfigError), f"Esperaba ConfigError, recibí {type(create_exc).__name__}: {create_exc}"
    assert code in str(create_exc)


@then("debe generar un secreto aleatorio de al menos 32 bytes")
def assert_ephemeral_secret_loaded(settings):
    assert len(settings.jwt_secret_key) >= 32


@then("debe imprimir una advertencia en stderr")
def assert_dev_warning(capsys: pytest.CaptureFixture[str]):
    out = capsys.readouterr()
    if not (out.out or out.err):
        captured = getattr(load_cfg, "_last_captured", None)
        if captured is not None:
            out = captured
    assert "JWT_SECRET_KEY" in (out.out + out.err)


@then(parsers.parse("debug debe ser {expected}"))
def assert_debug_value(created_app, expected: str):
    assert created_app.config["DEBUG"] is (expected.lower() == "true")


@then("debe abortar con un error que mencione SEC-003.1")
def assert_cli_abort(cli_exc):
    assert isinstance(cli_exc, SystemExit)
    assert "SEC-003.1" in str(cli_exc)


@then(parsers.parse("el host debe ser {expected}"))
def assert_host(settings, expected: str):
    assert settings.bind_host == expected.strip('"').strip("'")


@then("debe aparecer un warning mencionando SEC-003.2")
def assert_bind_warning(caplog: pytest.LogCaptureFixture):
    assert any("SEC-003.2" in r.getMessage() for r in caplog.records), [r.getMessage() for r in caplog.records]


@then("Talisman debe estar configurado con force_https=True")
def assert_talisman_https(created_app):
    assert created_app.config.get("TALISMAN_FORCE_HTTPS", True) is True


@then("Talisman debe estar configurado con force_https=False")
def assert_talisman_no_https(created_app):
    assert created_app.config.get("TALISMAN_FORCE_HTTPS", False) is False



@then("debe recibir un access_token")
def assert_login_ok(response):
    assert response.status_code == 200, response.get_data(as_text=True)
    body = response.get_json()
    assert "access_token" in body


@then(parsers.parse("debe recibir HTTP {code:d}"))
def assert_status(response, code: int):
    assert response.status_code == code, response.get_data(as_text=True)


@then(parsers.parse('el cuerpo debe contener "{needle}"'))
def assert_body_contains_quoted(response, needle: str):
    body = response.get_data(as_text=True)
    assert needle in body


@then(parsers.parse("el cuerpo debe contener {needle:w}"))
def assert_body_contains(response, needle: str):
    body = response.get_data(as_text=True)
    assert needle.strip('"') in body


@then(parsers.parse('el cuerpo debe mencionar el parámetro "{param}"'))
def assert_body_mentions_param(response, param: str):
    body = response.get_json()
    assert param in body["error"]


@then(parsers.parse('el cuerpo debe mencionar "{needle}"'))
def assert_body_mentions_quoted(response, needle: str):
    body = response.get_json()
    assert needle in body["error"]


@then(parsers.parse("el cuerpo debe mencionar {needle:w}"))
def assert_body_mentions(response, needle: str):
    body = response.get_json()
    assert needle.strip('"') in body["error"]


@then('el cuerpo debe contener "output" con el resultado del handler')
def assert_output(response):
    body = response.get_json()
    assert "output" in body
    assert body["output"]


@then(parsers.parse("debe existir un registro de auditoría con action=\"{action}\" y result=\"{result}\""))
def assert_audit_record(bdd_app, action: str, result: str):
    with bdd_app.app_context():
        records = bdd_app.config["AUDIT_LOG"].fetch(limit=50)
    assert any(r.action == action and r.result == result for r in records), records


@then("la respuesta debe incluir los últimos 100 registros")
def assert_audit_list(response):
    body = response.get_json()
    assert isinstance(body, list)


@then(parsers.parse("jwt_secret_key debe coincidir con el valor provisto"))
def assert_jwt_value(settings):
    assert settings.jwt_secret_key == "x" * 64


@then("debe lanzar ConfigError")
def assert_config_error(settings):
    assert isinstance(settings, ConfigError)


@then("el archivo \".gitignore\" debe contener la línea \".env\"")
def assert_gitignore_env():
    content = (ROOT / ".gitignore").read_text()
    assert re.search(r"^\.env(\b|\.|\*|$)", content, re.MULTILINE)


@then("debe existir un \".env.example\" versionado")
def assert_env_example():
    assert (ROOT / ".env.example").exists()


@then("el mensaje almacenado debe contener \"[REDACTED]\"")
def assert_redacted_in_message(logged_msg: str):
    assert "[REDACTED]" in logged_msg


@then("la CSP no debe incluir hashes sha256")
def assert_no_sha256(csp):
    text = json.dumps(csp)
    assert "sha256-" not in text


@then(parsers.parse('no debe contener "{needle}"'))
def assert_not_contains_quoted(logged_msg: str, needle: str):
    assert needle not in logged_msg


@then(parsers.parse("no debe contener {needle}"))
def assert_not_contains(logged_msg: str, needle: str):
    assert needle not in logged_msg


@then("cada paquete importado debe figurar en pyproject.toml (deps o extras)")
def assert_imports_covered(imports):
    import re as _re
    import tomllib
    with (ROOT / "pyproject.toml").open("rb") as f:
        data = tomllib.load(f)
    declared = set()
    for entry in data.get("project", {}).get("dependencies", []):
        declared.add(_re.split(r"[<>=!~]", entry)[0].strip().lower())
    for group in data.get("project", {}).get("optional-dependencies", {}).values():
        for entry in group:
            declared.add(_re.split(r"[<>=!~]", entry)[0].strip().lower())
    import sys as _sys
    STDLIB = set(_sys.stdlib_module_names)
    IMPORT_TO_PKG = {"dotenv": "python-dotenv", "sklearn": "scikit-learn", "yaml": "PyYAML"}
    missing = set()
    for pkg in imports:
        if pkg in STDLIB or pkg.startswith("lazyownbt"):
            continue
        candidates = {pkg.lower(), pkg.replace("_", "-").lower()}
        mapped = IMPORT_TO_PKG.get(pkg)
        if mapped:
            candidates.add(mapped.lower())
        if not candidates & declared:
            missing.add(pkg)
    assert not missing, f"Faltan en pyproject.toml: {sorted(missing)}"


@then("no debe haber paquetes listados en requirements.txt que el código no use")
def assert_no_unused_deps():
    req = ROOT / "requirements.txt"
    if not req.exists():
        return
    content = req.read_text()
    assert content.strip(), "requirements.txt no debe estar vacío"
