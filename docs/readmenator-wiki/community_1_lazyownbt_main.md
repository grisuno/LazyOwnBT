# lazyownbt: main

*Community 1 | 4 files | cohesion 0.38*

## Definition

This community groups 4 file(s) rooted at `tests` with dominant language py (cohesion 0.38). Central symbols: `ConfigError`, `Database`, `Settings`, `__init__`, `_canonical`, `_dashboard`, `_declared_deps`, `_extract_top_level_imports`. Core file: `main.py` (16 symbols). Documented purpose: Carga de configuración desde variables de entorno y .env.  Contrato: CFG-001 — Configuración desde entorno..

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `lazyownbt/config.py` | py | infrastructure | 8 | yes |
| `main.py` | py | presentation | 16 | yes |
| `tests/test_configuration.py` | py | testing | 7 | yes |
| `tests/test_production.py` | py | testing | 8 | yes |

## Key Symbols

- `ConfigError` (class, `lazyownbt/config.py:28`) `class ConfigError(RuntimeError)` - Error de configuración. Falla ruidosamente con mensaje accionable.
- `_load_dotenv` (method, `lazyownbt/config.py:32`) `def _load_dotenv()` - Carga .env si existe. No falla si no existe (CFG-001.2).
- `_resolve_jwt_secret` (method, `lazyownbt/config.py:39`) `def _resolve_jwt_secret()` - Resuelve el secreto de JWT según SEC-001.2 y SEC-001.3.
- `_resolve_admin_password_hash` (method, `lazyownbt/config.py:73`) `def _resolve_admin_password_hash()` - Resuelve el hash de la contraseña admin según SEC-001.4.
- `Settings` (class, `lazyownbt/config.py:104`) `class Settings` - Configuración inmutable de la aplicación.
- `is_production` (method, `lazyownbt/config.py:117`) `def is_production(self)`
- `is_development` (method, `lazyownbt/config.py:121`) `def is_development(self)`
- `load_settings` (method, `lazyownbt/config.py:125`) `def load_settings()` - Carga y valida la configuración. Falla ruidosamente (CFG-001.3).
- `Database` (class, `main.py:42`) `class Database` - Acceso de solo-lectura a la base de datos SQLite del framework.
- `__init__` (method, `main.py:57`) `def __init__(self, db_path)`
- `connect` (method, `main.py:60`) `def connect(self)`
- `_safe_fetch` (method, `main.py:69`) `def _safe_fetch(self, table, columns, where, params, order, limit)` - Ejecuta un SELECT genérico y tolera tablas inexistentes.
- `fetch_alerts` (method, `main.py:106`) `def fetch_alerts(self, limit, severity)`
- `fetch_events` (method, `main.py:127`) `def fetch_events(self, limit)`
- `fetch_network_baseline` (method, `main.py:141`) `def fetch_network_baseline(self, limit)`
- `fetch_file_hashes` (method, `main.py:148`) `def fetch_file_hashes(self, limit)`
- `correlate_events` (method, `main.py:155`) `def correlate_events(self, event_id)` - Busca alertas ±5 min relacionadas con un evento.
- `_register_data_routes` (method, `main.py:200`) `def _register_data_routes(app, db)` - Añade las rutas de solo-lectura sobre la BD.
- `alerts_view` (method, `main.py:208`) `def alerts_view()`
- `events_view` (method, `main.py:218`) `def events_view()`
- `api_correlate` (method, `main.py:227`) `def api_correlate(event_id)`
- `_populate_dashboard_metrics` (method, `main.py:231`) `def _populate_dashboard_metrics(db)` - Compone el payload que la plantilla ``dashboard.html`` espera.
- `build_app` (method, `main.py:260`) `def build_app(settings)` - Construye la app final reutilizando :func:`create_app`.
- `_dashboard` (method, `main.py:272`) `def _dashboard()`
- `test_config_loads_from_env` (function, `tests/test_configuration.py:18`) `def test_config_loads_from_env(monkeypatch)`
- `test_config_fails_loudly_on_missing_var` (function, `tests/test_configuration.py:27`) `def test_config_fails_loudly_on_missing_var(monkeypatch)`
- `_extract_top_level_imports` (function, `tests/test_configuration.py:36`) `def _extract_top_level_imports(source_files)` - Extrae los nombres de paquetes top-level importados en cada archivo.
- `_declared_deps` (function, `tests/test_configuration.py:58`) `def _declared_deps()`
- `_canonical` (function, `tests/test_configuration.py:85`) `def _canonical(pkg)` - Devuelve los nombres canónicos posibles para un paquete.
- `test_requirements_contains_all_imports` (function, `tests/test_configuration.py:94`) `def test_requirements_contains_all_imports()` - CFG-002.1/CFG-002.2: cada import del código debe estar declarado.

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 4
- Cross-boundary resolved imports (EXTRACTED): 11

## Connections

- [EXTRACTED] depends_on community 0 <-> 1 (strength 0.9): Extracted import edge crosses communities: lazyownbt/web.py imports lazyownbt/config.py.
- [EXTRACTED] depends_on community 2 <-> 1 (strength 0.9): Extracted import edge crosses communities: tests/conftest.py imports lazyownbt/config.py.
- [INFERRED] bridges community 0 <-> 1 (strength 0.7): Inferred cross-community bridge: lazyownbt/actions.py reaches tests/test_configuration.py in 3 hops.
- [INFERRED] bridges community 0 <-> 1 (strength 0.7): Inferred cross-community bridge: lazyownbt/audit.py reaches tests/test_configuration.py in 3 hops.
- [INFERRED] bridges community 0 <-> 1 (strength 0.7): Inferred cross-community bridge: lazyownbt/handlers.py reaches tests/test_configuration.py in 3 hops.
- [INFERRED] shares_context community 1 <-> 3 (strength 0.5): Inferred shared context (language py) with no import path between community 1 (lazyownbt: main) and community 3 (orphans).

## Risks

- [layer strict] `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation)
- [layer strict] `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation)

## Open Questions

- What would break if the most connected file in lazyownbt: main changed?
- Should lazyownbt: main be split, given cohesion 0.38?

## Sources

- `lazyownbt/config.py`
- `main.py`
- `tests/test_configuration.py`
- `tests/test_production.py`
