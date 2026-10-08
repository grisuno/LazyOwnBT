# Subsystem: lazyownbt

## lazyownbt/__init__.py
- Doc: LazyOwnBT — Blue Team defensive framework for Linux.
- Layer: utility
- Language: py

## lazyownbt/actions.py
- Doc: Registro cerrado de acciones permitidas y parser de parámetros.
- Layer: presentation
- Language: py
- Symbols:
  - `ActionSpec` (class, line 13) `class ActionSpec`
  - `ActionParseError` (class, line 24) `class ActionParseError(ValueError)`
  - `ActionRegistry` (class, line 28) `class ActionRegistry`
  - `__init__` (method, line 31) `def __init__(self)`
  - `register` (method, line 35) `def register(self, spec, handler)`
  - `is_allowed` (method, line 41) `def is_allowed(self, name)`
  - `spec` (method, line 44) `def spec(self, name)`
  - `handler` (method, line 47) `def handler(self, name)`
  - `names` (method, line 50) `def names(self)`
  - `validate_params` (method, line 53) `def validate_params(self, name, params)`
- Imported by: `lazyownbt/handlers.py`, `lazyownbt/web.py`, `tests/test_command_execution.py`

## lazyownbt/audit.py
- Doc: Registro de auditoría de acciones.
- Layer: utility
- Language: py
- Symbols:
  - `AuditRecord` (class, line 23) `class AuditRecord`
  - `AuditLog` (class, line 33) `class AuditLog`
  - `__init__` (method, line 38) `def __init__(self, db_path)`
  - `_conn` (method, line 43) `def _conn(self)`
  - `_init_db` (method, line 53) `def _init_db(self)`
  - `record` (method, line 77) `def record(self, action, user, params, result, duration_ms, error)`
  - `track` (method, line 113) `def track(self, action, user, params)`
  - `fetch` (method, line 133) `def fetch(self, limit)`
- Imported by: `lazyownbt/web.py`

## lazyownbt/config.py
- Doc: Carga de configuración desde variables de entorno y .env.
- Layer: infrastructure
- Language: py
- Symbols:
  - `ConfigError` (class, line 28) `class ConfigError(RuntimeError)`
  - `_load_dotenv` (method, line 32) `def _load_dotenv()`
  - `_resolve_jwt_secret` (method, line 39) `def _resolve_jwt_secret()`
  - `_resolve_admin_password_hash` (method, line 73) `def _resolve_admin_password_hash()`
  - `Settings` (class, line 104) `class Settings`
  - `load_settings` (method, line 125) `def load_settings()`
  - `is_production` (method, line 117) `def is_production(self)`
  - `is_development` (method, line 121) `def is_development(self)`
- Imported by: `lazyownbt/web.py`, `main.py`, `tests/conftest.py`, `tests/test_configuration.py`, `tests/test_production.py`, `tests/test_security.py`

## lazyownbt/detection.py
- Doc: Detection engine: auditd + Sigma rules for real-time threat detection.
- Layer: utility
- Language: py
- Symbols:
  - `SigmaRule` (class, line 30) `class SigmaRule`
  - `Alert` (class, line 42) `class Alert`
  - `DetectionEngine` (class, line 151) `class DetectionEngine`
  - `get_engine` (method, line 316) `def get_engine(db_path)`
  - `__init__` (method, line 154) `def __init__(self, db_path)`
  - `_init_db` (method, line 160) `def _init_db(self)`
  - `_conn` (method, line 180) `def _conn(self)`
  - `_load_custom_rules` (method, line 185) `def _load_custom_rules(self)`
  - `get_rules` (method, line 196) `def get_rules(self)`
  - `check_command` (method, line 199) `def check_command(self, command, args)`
  - `check_audit_log` (method, line 217) `def check_audit_log(self, log_line)`
  - `_extract_field` (method, line 240) `def _extract_field(self, log_line, field)`
  - `_store_alert` (method, line 244) `def _store_alert(self, alert)`
  - `get_alerts` (method, line 255) `def get_alerts(self, since_minutes, category, level)`
  - `get_stats` (method, line 278) `def get_stats(self, since_minutes)`
  - `is_auditd_available` (method, line 291) `def is_auditd_available(self)`
  - `install_auditd_rule` (method, line 301) `def install_auditd_rule(self, key)`

## lazyownbt/handlers.py
- Doc: Handlers de acciones: código de aplicación, no shell.
- Layer: presentation
- Language: py
- Symbols:
  - `_validate_ip` (function, line 22) `def _validate_ip(ip)`
  - `handle_resp_block_ip` (function, line 32) `def handle_resp_block_ip(ip_address, interface)`
  - `handle_resp_kill_proc` (function, line 52) `def handle_resp_kill_proc(pid, signal)`
  - `handle_net_scan` (function, line 64) `def handle_net_scan()`
  - `handle_fim_scan` (function, line 68) `def handle_fim_scan()`
  - `handle_lazynmap` (function, line 72) `def handle_lazynmap(target)`
  - `handle_ai_playbook` (function, line 78) `def handle_ai_playbook(scenario)`
  - `build_default_handlers` (function, line 84) `def build_default_handlers()`
- Depends on: `lazyownbt/actions.py`
- Imported by: `lazyownbt/web.py`

## lazyownbt/security.py
- Doc: Filtros de seguridad y helpers criptográficos.
- Layer: utility
- Language: py
- Symbols:
  - `SecretsFilter` (class, line 13) `class SecretsFilter(Filter)`
  - `install_secrets_filter` (method, line 51) `def install_secrets_filter(logger, env_keys)`
  - `verify_password` (method, line 59) `def verify_password(plain, hashed)`
  - `__init__` (method, line 21) `def __init__(self, env_keys)`
  - `_redact` (method, line 25) `def _redact(self, message)`
  - `filter` (method, line 35) `def filter(self, record)`
- Imported by: `lazyownbt/web.py`, `tests/conftest.py`, `tests/test_security.py`

## lazyownbt/web.py
- Doc: Factory de la aplicación Flask (dashboard PurpleTeam).
- Layer: presentation
- Language: py
- Symbols:
  - `_build_csp` (function, line 38) `def _build_csp(static_csp_hash)`
  - `_register_default_actions` (function, line 55) `def _register_default_actions(registry)`
  - `create_app` (function, line 66) `def create_app(settings)`
  - `_register_routes` (function, line 114) `def _register_routes(app)`
  - `_handle_command` (function, line 185) `def _handle_command(app)`
  - `_default_flask_env_if_unset` (function, line 220) `def _default_flask_env_if_unset()`
  - `run` (function, line 236) `def run()`
  - `healthz` (function, line 117) `def healthz()`
  - `dashboard` (function, line 121) `def dashboard()`
  - `api_dashboard` (function, line 126) `def api_dashboard()`
  - `commands` (function, line 145) `def commands()`
  - `login` (function, line 152) `def login()`
  - `api_audit` (function, line 170) `def api_audit()`
  - `not_found` (function, line 176) `def not_found(_)`
  - `server_error` (function, line 180) `def server_error(_)`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`
