# Subsystem: tests

## tests/conftest.py
- Doc: Configuración común para pytest + pytest-bdd.
- Layer: testing
- Language: py
- Symbols:
  - `_make_jwt_secret` (function, line 35) `def _make_jwt_secret()`
  - `jwt_secret` (function, line 40) `def jwt_secret()`
  - `dev_env` (function, line 45) `def dev_env(monkeypatch, jwt_secret)`
  - `prod_env` (function, line 52) `def prod_env(monkeypatch, jwt_secret)`
  - `app` (function, line 60) `def app(dev_env, tmp_path)`
  - `client` (function, line 69) `def client(app)`
  - `auth_client` (function, line 74) `def auth_client(client, app)`
  - `_iter_source_files` (function, line 92) `def _iter_source_files()`
  - `_read_text` (function, line 100) `def _read_text(path)`
  - `clean_env` (function, line 112) `def clean_env(monkeypatch)`
  - `flask_env` (function, line 121) `def flask_env(monkeypatch, env)`
  - `flask_env_quoted` (function, line 127) `def flask_env_quoted(monkeypatch, env)`
  - `jwt_no_secret` (function, line 133) `def jwt_no_secret(monkeypatch)`
  - `jwt_secret_value` (function, line 138) `def jwt_secret_value(monkeypatch, value)`
  - `jwt_secret_with_length` (function, line 143) `def jwt_secret_with_length(monkeypatch, n)`
  - `admin_password_with_length` (function, line 148) `def admin_password_with_length(monkeypatch, n)`
  - `admin_hash` (function, line 153) `def admin_hash(monkeypatch)`
  - `bdd_app` (function, line 158) `def bdd_app(monkeypatch, tmp_path)`
  - `bdd_client` (function, line 169) `def bdd_client(bdd_app)`
  - `bdd_anon` (function, line 178) `def bdd_anon(bdd_app)`
  - `fake_failing_handler` (function, line 183) `def fake_failing_handler(bdd_app, action, what)`
  - `no_bind` (function, line 196) `def no_bind(monkeypatch)`
  - `bind_value` (function, line 201) `def bind_value(monkeypatch, value)`
  - `logger_with_filter` (function, line 206) `def logger_with_filter()`
  - `code_tree` (function, line 215) `def code_tree()`
  - `extract_imports` (function, line 220) `def extract_imports()`
  - `scan_repo` (function, line 247) `def scan_repo()`
  - `scan_repo_subprocess` (function, line 252) `def scan_repo_subprocess()`
  - `scan_repo_eval` (function, line 257) `def scan_repo_eval()`
  - `scan_repo_sha` (function, line 262) `def scan_repo_sha()`
  - `assert_no_subprocess_python` (function, line 271) `def assert_no_subprocess_python(scan_result)`
  - `try_create_app` (function, line 280) `def try_create_app(monkeypatch)`
  - `load_config` (function, line 290) `def load_config(monkeypatch)`
  - `login_ok` (function, line 298) `def login_ok(bdd_app)`
  - `login_bad` (function, line 312) `def login_bad(bdd_app)`
  - `invoke_action` (function, line 323) `def invoke_action(bdd_client, action, payload)`
  - `invoke_action_anon` (function, line 333) `def invoke_action_anon(bdd_anon, action, payload)`
  - `query_audit` (function, line 342) `def query_audit(bdd_client)`
  - `load_default` (function, line 347) `def load_default(monkeypatch)`
  - `load_cfg` (function, line 353) `def load_cfg(monkeypatch, capsys)`
  - `assert_dev_warning` (function, line 363) `def assert_dev_warning(capsys)`
  - `cli_with_debug` (function, line 373) `def cli_with_debug(monkeypatch)`
  - `create_the_app` (function, line 384) `def create_the_app(monkeypatch)`
  - `get_csp` (function, line 390) `def get_csp()`
  - `log_msg` (function, line 396) `def log_msg(logger_with_filter, msg, caplog)`
  - `no_your_secret_key` (function, line 407) `def no_your_secret_key(scan_result)`
  - `no_admin_password` (function, line 412) `def no_admin_password(scan_result)`
  - `assert_config_error_code` (function, line 418) `def assert_config_error_code(create_exc, code)`
  - `assert_ephemeral_secret_loaded` (function, line 424) `def assert_ephemeral_secret_loaded(settings)`
  - `assert_dev_warning` (function, line 429) `def assert_dev_warning(capsys)`
  - `assert_debug_value` (function, line 439) `def assert_debug_value(created_app, expected)`
  - `assert_cli_abort` (function, line 444) `def assert_cli_abort(cli_exc)`
  - `assert_host` (function, line 450) `def assert_host(settings, expected)`
  - `assert_bind_warning` (function, line 455) `def assert_bind_warning(caplog)`
  - `assert_talisman_https` (function, line 460) `def assert_talisman_https(created_app)`
  - `assert_talisman_no_https` (function, line 465) `def assert_talisman_no_https(created_app)`
  - `assert_login_ok` (function, line 471) `def assert_login_ok(response)`
  - `assert_status` (function, line 478) `def assert_status(response, code)`
  - `assert_body_contains_quoted` (function, line 483) `def assert_body_contains_quoted(response, needle)`
  - `assert_body_contains` (function, line 489) `def assert_body_contains(response, needle)`
  - `assert_body_mentions_param` (function, line 495) `def assert_body_mentions_param(response, param)`
  - `assert_body_mentions_quoted` (function, line 501) `def assert_body_mentions_quoted(response, needle)`
  - `assert_body_mentions` (function, line 507) `def assert_body_mentions(response, needle)`
  - `assert_output` (function, line 513) `def assert_output(response)`
  - `assert_audit_record` (function, line 520) `def assert_audit_record(bdd_app, action, result)`
  - `assert_audit_list` (function, line 527) `def assert_audit_list(response)`
  - `assert_jwt_value` (function, line 533) `def assert_jwt_value(settings)`
  - `assert_config_error` (function, line 538) `def assert_config_error(settings)`
  - `assert_gitignore_env` (function, line 543) `def assert_gitignore_env()`
  - `assert_env_example` (function, line 549) `def assert_env_example()`
  - `assert_redacted_in_message` (function, line 554) `def assert_redacted_in_message(logged_msg)`
  - `assert_no_sha256` (function, line 559) `def assert_no_sha256(csp)`
  - `assert_not_contains_quoted` (function, line 565) `def assert_not_contains_quoted(logged_msg, needle)`
  - `assert_not_contains` (function, line 570) `def assert_not_contains(logged_msg, needle)`
  - `assert_imports_covered` (function, line 575) `def assert_imports_covered(imports)`
  - `assert_no_unused_deps` (function, line 603) `def assert_no_unused_deps()`
  - `failing` (function, line 187) `def failing()`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

## tests/test_command_execution.py
- Doc: Tests TDD para el contrato SEC-002 — Ejecución segura de comandos.
- Layer: testing
- Language: py
- Symbols:
  - `_read` (function, line 16) `def _read(path)`
  - `test_subprocess_dynamic_python_is_gone` (function, line 23) `def test_subprocess_dynamic_python_is_gone()`
  - `test_no_eval_on_user_input` (function, line 39) `def test_no_eval_on_user_input()`
  - `test_command_not_in_allowlist_is_rejected` (function, line 55) `def test_command_not_in_allowlist_is_rejected(client)`
  - `test_command_not_in_allowlist_returns_403` (function, line 65) `def test_command_not_in_allowlist_returns_403(auth_client)`
  - `test_command_validates_params` (function, line 77) `def test_command_validates_params(auth_client)`
  - `test_command_missing_required_param` (function, line 87) `def test_command_missing_required_param(auth_client)`
  - `test_command_rejects_unknown_params` (function, line 97) `def test_command_rejects_unknown_params(auth_client)`
  - `test_command_requires_jwt` (function, line 109) `def test_command_requires_jwt(client)`
  - `test_command_audit_recorded` (function, line 120) `def test_command_audit_recorded(auth_client, app)`
  - `test_command_audit_records_error` (function, line 133) `def test_command_audit_records_error(auth_client, app)`
  - `test_audit_endpoint_returns_records` (function, line 146) `def test_audit_endpoint_returns_records(auth_client)`
  - `test_command_executes_via_python_call` (function, line 161) `def test_command_executes_via_python_call(auth_client, monkeypatch)`
  - `fake_handler` (function, line 165) `def fake_handler()`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

## tests/test_command_execution_bdd.py
- Doc: BDD runner para `command_execution.feature`.
- Layer: testing
- Language: py

## tests/test_configuration.py
- Doc: Tests TDD para el contrato CFG-001 / CFG-002 — Configuración.
- Layer: testing
- Language: py
- Symbols:
  - `test_config_loads_from_env` (function, line 18) `def test_config_loads_from_env(monkeypatch)`
  - `test_config_fails_loudly_on_missing_var` (function, line 27) `def test_config_fails_loudly_on_missing_var(monkeypatch)`
  - `_extract_top_level_imports` (function, line 36) `def _extract_top_level_imports(source_files)`
  - `_declared_deps` (function, line 58) `def _declared_deps()`
  - `_canonical` (function, line 85) `def _canonical(pkg)`
  - `test_requirements_contains_all_imports` (function, line 94) `def test_requirements_contains_all_imports()`
  - `test_pyproject_extras_declared` (function, line 118) `def test_pyproject_extras_declared()`
- Depends on: `lazyownbt/config.py`

## tests/test_configuration_bdd.py
- Doc: BDD runner para `configuration.feature`.
- Layer: testing
- Language: py

## tests/test_production.py
- Doc: Tests TDD para el contrato SEC-003 — Modo producción del servidor web.
- Layer: testing
- Language: py
- Symbols:
  - `test_debug_flag_default_false` (function, line 13) `def test_debug_flag_default_false(monkeypatch)`
  - `test_debug_only_with_explicit_flag` (function, line 23) `def test_debug_only_with_explicit_flag(monkeypatch)`
  - `test_bind_default_loopback` (function, line 34) `def test_bind_default_loopback(monkeypatch)`
  - `test_bind_warns_when_public` (function, line 45) `def test_bind_warns_when_public(monkeypatch, caplog)`
  - `test_talisman_https_in_production` (function, line 58) `def test_talisman_https_in_production(monkeypatch)`
  - `test_talisman_no_https_in_development` (function, line 72) `def test_talisman_no_https_in_development(monkeypatch)`
  - `test_csp_has_no_hardcoded_inline_hash` (function, line 82) `def test_csp_has_no_hardcoded_inline_hash()`
  - `test_cli_rejects_debug_in_production` (function, line 89) `def test_cli_rejects_debug_in_production(monkeypatch)`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

## tests/test_production_bdd.py
- Doc: BDD runner para `production_readiness.feature`.
- Layer: testing
- Language: py

## tests/test_secrets_bdd.py
- Doc: BDD runner para `secrets.feature`.  pytest-bdd convierte cada Scenario en un test individual.
- Layer: testing
- Language: py

## tests/test_security.py
- Doc: Tests TDD para el contrato SEC-001 — Manejo seguro de secretos.
- Layer: testing
- Language: py
- Symbols:
  - `_iter_source_files` (function, line 20) `def _iter_source_files()`
  - `test_no_hardcoded_jwt_secret` (function, line 27) `def test_no_hardcoded_jwt_secret()`
  - `test_no_hardcoded_admin_password` (function, line 40) `def test_no_hardcoded_admin_password()`
  - `test_app_aborts_when_jwt_secret_missing_in_prod` (function, line 56) `def test_app_aborts_when_jwt_secret_missing_in_prod(monkeypatch)`
  - `test_app_generates_ephemeral_secret_in_dev` (function, line 66) `def test_app_generates_ephemeral_secret_in_dev(monkeypatch, capsys)`
  - `test_jwt_secret_below_minimum_length_aborts` (function, line 79) `def test_jwt_secret_below_minimum_length_aborts(monkeypatch, bad_secret)`
  - `test_empty_jwt_secret_triggers_absence_rule` (function, line 88) `def test_empty_jwt_secret_triggers_absence_rule(monkeypatch)`
  - `test_password_is_hashed_not_plain` (function, line 100) `def test_password_is_hashed_not_plain(monkeypatch, tmp_path)`
  - `test_env_file_is_gitignored` (function, line 115) `def test_env_file_is_gitignored()`
  - `test_env_example_exists` (function, line 125) `def test_env_example_exists()`
  - `test_secrets_filter_redacts_values` (function, line 131) `def test_secrets_filter_redacts_values()`
  - `test_secrets_filter_redacts_in_args` (function, line 140) `def test_secrets_filter_redacts_in_args()`
  - `test_secrets_filter_redacts_in_dict_args` (function, line 147) `def test_secrets_filter_redacts_in_dict_args()`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`
