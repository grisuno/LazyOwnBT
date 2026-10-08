# lazyownbt: web

*Community 0 | 5 files | cohesion 0.55*

## Definition

This community groups 5 file(s) rooted at `lazyownbt` with dominant language py (cohesion 0.55). Central symbols: `ActionParseError`, `ActionRegistry`, `ActionSpec`, `AuditLog`, `AuditRecord`, `__init__`, `_build_csp`, `_conn`. Core file: `lazyownbt/web.py` (15 symbols). Documented purpose: Registro cerrado de acciones permitidas y parser de parámetros.  Contrato: SEC-002 — Ejecución segura de comandos..

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `lazyownbt/actions.py` | py | presentation | 10 | yes |
| `lazyownbt/audit.py` | py | utility | 8 | yes |
| `lazyownbt/handlers.py` | py | presentation | 8 | yes |
| `lazyownbt/web.py` | py | presentation | 15 | yes |
| `tests/test_command_execution.py` | py | testing | 14 | yes |

## Key Symbols

- `ActionSpec` (class, `lazyownbt/actions.py:13`) `class ActionSpec` - Especificación declarativa de una acción ejecutable.
- `ActionParseError` (class, `lazyownbt/actions.py:24`) `class ActionParseError(ValueError)` - Error de validación de parámetros.
- `ActionRegistry` (class, `lazyownbt/actions.py:28`) `class ActionRegistry` - Registro cerrado de acciones permitidas (SEC-002.2).
- `__init__` (method, `lazyownbt/actions.py:31`) `def __init__(self)`
- `register` (method, `lazyownbt/actions.py:35`) `def register(self, spec, handler)`
- `is_allowed` (method, `lazyownbt/actions.py:41`) `def is_allowed(self, name)`
- `spec` (method, `lazyownbt/actions.py:44`) `def spec(self, name)`
- `handler` (method, `lazyownbt/actions.py:47`) `def handler(self, name)`
- `names` (method, `lazyownbt/actions.py:50`) `def names(self)`
- `validate_params` (method, `lazyownbt/actions.py:53`) `def validate_params(self, name, params)` - Valida y coerciona parámetros (SEC-002.3).
- `AuditRecord` (class, `lazyownbt/audit.py:23`) `class AuditRecord`
- `AuditLog` (class, `lazyownbt/audit.py:33`) `class AuditLog` - Log de auditoría respaldado por SQLite.
- `__init__` (method, `lazyownbt/audit.py:38`) `def __init__(self, db_path)`
- `_conn` (method, `lazyownbt/audit.py:43`) `def _conn(self)`
- `_init_db` (method, `lazyownbt/audit.py:53`) `def _init_db(self)`
- `record` (method, `lazyownbt/audit.py:77`) `def record(self, action, user, params, result, duration_ms, error)`
- `track` (method, `lazyownbt/audit.py:113`) `def track(self, action, user, params)` - Context manager que mide tiempo y registra resultado/errores.
- `fetch` (method, `lazyownbt/audit.py:133`) `def fetch(self, limit)`
- `_validate_ip` (function, `lazyownbt/handlers.py:22`) `def _validate_ip(ip)`
- `handle_resp_block_ip` (function, `lazyownbt/handlers.py:32`) `def handle_resp_block_ip(ip_address, interface)` - Stub seguro. En un despliegue real invocaría iptables con argv.
- `handle_resp_kill_proc` (function, `lazyownbt/handlers.py:52`) `def handle_resp_kill_proc(pid, signal)` - Stub seguro. En un despliegue real enviaría la señal al PID.
- `handle_net_scan` (function, `lazyownbt/handlers.py:64`) `def handle_net_scan()`
- `handle_fim_scan` (function, `lazyownbt/handlers.py:68`) `def handle_fim_scan()`
- `handle_lazynmap` (function, `lazyownbt/handlers.py:72`) `def handle_lazynmap(target)`
- `handle_ai_playbook` (function, `lazyownbt/handlers.py:78`) `def handle_ai_playbook(scenario)`
- `build_default_handlers` (function, `lazyownbt/handlers.py:84`) `def build_default_handlers()`
- `_build_csp` (function, `lazyownbt/web.py:38`) `def _build_csp(static_csp_hash)` - CSP estricta sin hashes hardcodeados (SEC-003.4).
- `_register_default_actions` (function, `lazyownbt/web.py:55`) `def _register_default_actions(registry)` - Carga las acciones por defecto. Cada handler es un stub testable.
- `create_app` (function, `lazyownbt/web.py:66`) `def create_app(settings)` - Crea y configura la app Flask.
- `_register_routes` (function, `lazyownbt/web.py:114`) `def _register_routes(app)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 6
- Cross-boundary resolved imports (EXTRACTED): 16

## Connections

- [EXTRACTED] depends_on community 0 <-> 1 (strength 0.9): Extracted import edge crosses communities: lazyownbt/web.py imports lazyownbt/config.py.
- [EXTRACTED] depends_on community 0 <-> 2 (strength 0.9): Extracted import edge crosses communities: lazyownbt/web.py imports lazyownbt/security.py.
- [INFERRED] bridges community 0 <-> 1 (strength 0.7): Inferred cross-community bridge: lazyownbt/actions.py reaches tests/test_configuration.py in 3 hops.
- [INFERRED] bridges community 0 <-> 2 (strength 0.7): Inferred cross-community bridge: lazyownbt/actions.py reaches tests/test_security.py in 3 hops.
- [INFERRED] bridges community 0 <-> 1 (strength 0.7): Inferred cross-community bridge: lazyownbt/audit.py reaches tests/test_configuration.py in 3 hops.
- [INFERRED] bridges community 0 <-> 2 (strength 0.7): Inferred cross-community bridge: lazyownbt/audit.py reaches tests/test_security.py in 3 hops.
- [INFERRED] bridges community 0 <-> 1 (strength 0.7): Inferred cross-community bridge: lazyownbt/handlers.py reaches tests/test_configuration.py in 3 hops.
- [INFERRED] shares_context community 0 <-> 3 (strength 0.5): Inferred shared context (language py) with no import path between community 0 (lazyownbt: web) and community 3 (orphans).

## Risks

- [taint high] `lazyownbt/handlers.py` -> `lazyownbt/handlers.py` via `subprocess` (0 hops)
- [taint high] `lazyownbt/handlers.py` -> `lazyownbt/actions.py` via `subprocess` (1 hops)
- [layer strict] `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/test_command_execution.py` (testing) -> `lazyownbt/actions.py` (presentation)
- [layer strict] `tests/test_command_execution.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation)

## Open Questions

- Is the dangerous import `subprocess` in `lazyownbt/handlers.py` still required, or can it be isolated?
- What would break if the most connected file in lazyownbt: web changed?
- Should lazyownbt: web be split, given cohesion 0.55?

## Sources

- `lazyownbt/actions.py`
- `lazyownbt/audit.py`
- `lazyownbt/handlers.py`
- `lazyownbt/web.py`
- `tests/test_command_execution.py`
