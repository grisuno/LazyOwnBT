# lazyownbt: security

*Community 2 | 3 files | cohesion 0.33*

## Definition

This community groups 3 file(s) rooted at `tests` with dominant language py (cohesion 0.33). Central symbols: `SecretsFilter`, `__init__`, `_iter_source_files`, `_make_jwt_secret`, `_read_text`, `_redact`, `admin_hash`, `admin_password_with_length`. Core file: `tests/conftest.py` (77 symbols). Documented purpose: Filtros de seguridad y helpers criptográficos.  Contrato: SEC-001 — Manejo seguro de secretos..

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `lazyownbt/security.py` | py | utility | 6 | yes |
| `tests/conftest.py` | py | testing | 77 | yes |
| `tests/test_security.py` | py | testing | 13 | yes |

## Key Symbols

- `SecretsFilter` (class, `lazyownbt/security.py:13`) `class SecretsFilter(Filter)` - Filtro de logging que redacta valores de secretos.
- `__init__` (method, `lazyownbt/security.py:21`) `def __init__(self, env_keys)`
- `_redact` (method, `lazyownbt/security.py:25`) `def _redact(self, message)`
- `filter` (method, `lazyownbt/security.py:35`) `def filter(self, record)`
- `install_secrets_filter` (method, `lazyownbt/security.py:51`) `def install_secrets_filter(logger, env_keys)` - Instala el SecretsFilter en un logger.
- `verify_password` (method, `lazyownbt/security.py:59`) `def verify_password(plain, hashed)` - Compara una contraseña contra un hash bcrypt (SEC-001.4).
- `_make_jwt_secret` (function, `tests/conftest.py:35`) `def _make_jwt_secret()`
- `jwt_secret` (function, `tests/conftest.py:40`) `def jwt_secret()`
- `dev_env` (function, `tests/conftest.py:45`) `def dev_env(monkeypatch, jwt_secret)`
- `prod_env` (function, `tests/conftest.py:52`) `def prod_env(monkeypatch, jwt_secret)`
- `app` (function, `tests/conftest.py:60`) `def app(dev_env, tmp_path)`
- `client` (function, `tests/conftest.py:69`) `def client(app)`
- `auth_client` (function, `tests/conftest.py:74`) `def auth_client(client, app)`
- `_iter_source_files` (function, `tests/conftest.py:92`) `def _iter_source_files()`
- `_read_text` (function, `tests/conftest.py:100`) `def _read_text(path)`
- `clean_env` (function, `tests/conftest.py:112`) `def clean_env(monkeypatch)`
- `flask_env` (function, `tests/conftest.py:121`) `def flask_env(monkeypatch, env)`
- `flask_env_quoted` (function, `tests/conftest.py:127`) `def flask_env_quoted(monkeypatch, env)`
- `jwt_no_secret` (function, `tests/conftest.py:133`) `def jwt_no_secret(monkeypatch)`
- `jwt_secret_value` (function, `tests/conftest.py:138`) `def jwt_secret_value(monkeypatch, value)`
- `jwt_secret_with_length` (function, `tests/conftest.py:143`) `def jwt_secret_with_length(monkeypatch, n)`
- `admin_password_with_length` (function, `tests/conftest.py:148`) `def admin_password_with_length(monkeypatch, n)`
- `admin_hash` (function, `tests/conftest.py:153`) `def admin_hash(monkeypatch)`
- `bdd_app` (function, `tests/conftest.py:158`) `def bdd_app(monkeypatch, tmp_path)`
- `bdd_client` (function, `tests/conftest.py:169`) `def bdd_client(bdd_app)`
- `bdd_anon` (function, `tests/conftest.py:178`) `def bdd_anon(bdd_app)`
- `fake_failing_handler` (function, `tests/conftest.py:183`) `def fake_failing_handler(bdd_app, action, what)`
- `failing` (function, `tests/conftest.py:187`) `def failing()`
- `no_bind` (function, `tests/conftest.py:196`) `def no_bind(monkeypatch)`
- `bind_value` (function, `tests/conftest.py:201`) `def bind_value(monkeypatch, value)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 2
- Cross-boundary resolved imports (EXTRACTED): 9

## Connections

- [EXTRACTED] depends_on community 0 <-> 2 (strength 0.9): Extracted import edge crosses communities: lazyownbt/web.py imports lazyownbt/security.py.
- [EXTRACTED] depends_on community 2 <-> 1 (strength 0.9): Extracted import edge crosses communities: tests/conftest.py imports lazyownbt/config.py.
- [INFERRED] bridges community 0 <-> 2 (strength 0.7): Inferred cross-community bridge: lazyownbt/actions.py reaches tests/test_security.py in 3 hops.
- [INFERRED] bridges community 0 <-> 2 (strength 0.7): Inferred cross-community bridge: lazyownbt/audit.py reaches tests/test_security.py in 3 hops.
- [INFERRED] shares_context community 2 <-> 3 (strength 0.5): Inferred shared context (language py) with no import path between community 2 (lazyownbt: security) and community 3 (orphans).

## Risks

- [layer strict] `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation)

## Open Questions

- What would break if the most connected file in lazyownbt: security changed?
- Should lazyownbt: security be split, given cohesion 0.33?

## Sources

- `lazyownbt/security.py`
- `tests/conftest.py`
- `tests/test_security.py`
