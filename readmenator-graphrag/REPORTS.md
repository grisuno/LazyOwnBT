# GraphRAG Community Reports

Entities: 550 | Relationships: 1449 | Communities: 4 | Themes: 2 | Text units: 429

Query with `readmenator . ask "<question>"` (local: BM25 + Personalized PageRank; global: map-reduce over these reports) or the MCP tool `readmenator.graphrag`.

## Project overview (`root`, root, rating 7.0)

23 files in 4 communities and 2 themes. Highest-impact communities: unassigned files (7.0), lazyownbt: web (6.7), lazyownbt: main (4.1). God nodes: lazyownbt/web.py, app.py, tests/conftest.py, lazyownbt/config.py, lazyownbt/actions.py.

- [unassigned files] rating 7.0: `app.py` ranks 1 by PageRank, 0 importers, 193 symbols: LazyOwn BlueTeam Framework Una herramienta monolítica de seguridad defensiva para detección de amenazas, respuesta a incidentes y endurecimiento de sistemas Linux.
- [lazyownbt: web] rating 6.7: `lazyownbt/actions.py` ranks 1 by PageRank, 3 importers, 10 symbols: Registro cerrado de acciones permitidas y parser de parámetros.
- [lazyownbt: main] rating 4.1: `lazyownbt/config.py` ranks 1 by PageRank, 7 importers, 8 symbols: Carga de configuración desde variables de entorno y .env.
- [lazyownbt: security] rating 2.6: `lazyownbt/security.py` ranks 1 by PageRank, 3 importers, 6 symbols: Filtros de seguridad y helpers criptográficos.
- Key entities: file:app.py, sym:static/js/auth.js::get@9, file:lazyownbt/web.py, file:tests/test_command_execution.py, file:main.py, file:lazyownbt/config.py
- Children: t0, t1
- Root rating = highest community rating.

## unassigned files (`t1`, theme, rating 7.0)

Theme of 1 communities and 11 files: unassigned files (11 files, rating 7.0).

- [unassigned files] `app.py` ranks 1 by PageRank, 0 importers, 193 symbols: LazyOwn BlueTeam Framework Una herramienta monolítica de seguridad defensiva para detección de amenazas, respuesta a incidentes y endurecimiento de sistemas Linux.
- [unassigned files] `install.sh` ranks 2 by PageRank, 0 importers, 0 symbols.
- Key entities: file:app.py, sym:static/js/auth.js::get@9
- Children: c3
- Theme rating = highest child community rating.

## lazyownbt: web + lazyownbt: main +1 (`t0`, theme, rating 6.7)

Theme of 3 communities and 12 files: lazyownbt: web (5 files, rating 6.7); lazyownbt: main (4 files, rating 4.1); lazyownbt: security (3 files, rating 2.6).

- [lazyownbt: web] `lazyownbt/actions.py` ranks 1 by PageRank, 3 importers, 10 symbols: Registro cerrado de acciones permitidas y parser de parámetros.
- [lazyownbt: web] `lazyownbt/web.py` ranks 2 by PageRank, 15 importers, 15 symbols: Factory de la aplicación Flask (dashboard PurpleTeam).
- [lazyownbt: main] `lazyownbt/config.py` ranks 1 by PageRank, 7 importers, 8 symbols: Carga de configuración desde variables de entorno y .env.
- [lazyownbt: main] `main.py` ranks 2 by PageRank, 0 importers, 16 symbols: LazyOwn PurpleTeam Dashboard — entry point.
- [lazyownbt: security] `lazyownbt/security.py` ranks 1 by PageRank, 3 importers, 6 symbols: Filtros de seguridad y helpers criptográficos.
- [lazyownbt: security] `tests/conftest.py` ranks 2 by PageRank, 0 importers, 77 symbols: Configuración común para pytest + pytest-bdd.
- Key entities: file:lazyownbt/web.py, file:tests/test_command_execution.py, file:main.py, file:lazyownbt/config.py, file:tests/conftest.py, file:tests/test_security.py
- Children: c0, c1, c2
- Theme rating = highest child community rating.

## unassigned files (`c3`, community, rating 7.0)

11 files under tests (py 7, js 3, sh 1), mostly utility. Core file app.py (PageRank 0.0311, imported by 0 files): LazyOwn BlueTeam Framework Una herramienta monolítica de seguridad defensiva para detección de amenazas, respuesta a incidentes y endurecimiento de sistemas Linux. Key abstractions: Fg, FgColor, Cyan, Red, RAGManager, Database.

- `app.py` ranks 1 by PageRank, 0 importers, 193 symbols: LazyOwn BlueTeam Framework Una herramienta monolítica de seguridad defensiva para detección de amenazas, respuesta a incidentes y endurecimiento de sistemas Linux.
- `install.sh` ranks 2 by PageRank, 0 importers, 0 symbols.
- `lazyownbt/__init__.py` ranks 3 by PageRank, 0 importers, 0 symbols: LazyOwnBT — Blue Team defensive framework for Linux.
- Hotspot `app.py`: 193 symbols, 61 connections (score 1.00).
- Hotspot `static/js/commands.js`: 3 symbols, 31 connections (score 0.31).
- Taint: 3 paths reach this group via requests, subprocess.
- Key entities: file:app.py, sym:static/js/auth.js::get@9, file:skills/lazyownbt_mcp.py, sym:app.py::__init__@252, sym:app.py::style@75, sym:app.py::save_to_db@625, sym:app.py::scan@761, sym:app.py::Alert@605
- Rating 7.0/10 = 7 x PageRank share 1.00 + 3 x risk 0.00. Internal imports: 0.

## lazyownbt: web (`c0`, community, rating 6.7)

5 files under lazyownbt (py 5), mostly presentation. Core file lazyownbt/actions.py (PageRank 0.1022, imported by 3 files): Registro cerrado de acciones permitidas y parser de parámetros. Key abstractions: ActionSpec, ActionParseError, ActionRegistry, register, is_allowed, spec. Depends on lazyownbt: main (1), lazyownbt: security (1). Used by lazyownbt: main (8), lazyownbt: security (6).

- `lazyownbt/actions.py` ranks 1 by PageRank, 3 importers, 10 symbols: Registro cerrado de acciones permitidas y parser de parámetros.
- `lazyownbt/web.py` ranks 2 by PageRank, 15 importers, 15 symbols: Factory de la aplicación Flask (dashboard PurpleTeam).
- `lazyownbt/audit.py` ranks 3 by PageRank, 1 importers, 8 symbols: Registro de auditoría de acciones.
- Hotspot `lazyownbt/web.py`: 15 symbols, 35 connections (score 0.38).
- Hotspot `lazyownbt/audit.py`: 8 symbols, 12 connections (score 0.13).
- 2 layer violations, e.g. test_command_execution.py (testing) -> actions.py (presentation).
- Taint: 2 paths reach this group via subprocess.
- Surprising bridge: actions.py <-> test_configuration.py (3 hops across communities).
- Key entities: file:lazyownbt/web.py, file:tests/test_command_execution.py, file:lazyownbt/handlers.py, file:lazyownbt/audit.py, sym:lazyownbt/web.py::create_app@66, file:lazyownbt/actions.py, sym:lazyownbt/web.py::run@236, sym:lazyownbt/web.py::_handle_command@185
- Rating 6.7/10 = 7 x PageRank share 0.96 + 3 x risk 0.00. Internal imports: 6.

## lazyownbt: main (`c1`, community, rating 4.1)

4 files under tests (py 4), mostly testing. Core file lazyownbt/config.py (PageRank 0.1081, imported by 7 files): Carga de configuración desde variables de entorno y .env. Key abstractions: ConfigError, Settings, is_production, is_development, load_settings, Database. Depends on lazyownbt: web (8). Used by lazyownbt: security (2), lazyownbt: web (1).

- `lazyownbt/config.py` ranks 1 by PageRank, 7 importers, 8 symbols: Carga de configuración desde variables de entorno y .env.
- `main.py` ranks 2 by PageRank, 0 importers, 16 symbols: LazyOwn PurpleTeam Dashboard — entry point.
- `tests/test_configuration.py` ranks 3 by PageRank, 0 importers, 7 symbols: Tests TDD para el contrato CFG-001 / CFG-002 — Configuración.
- Hotspot `main.py`: 16 symbols, 18 connections (score 0.21).
- Hotspot `tests/test_production.py`: 8 symbols, 18 connections (score 0.19).
- 6 layer violations, e.g. test_production.py (testing) -> web.py (presentation).
- Surprising bridge: actions.py <-> test_configuration.py (3 hops across communities).
- Key entities: file:main.py, file:lazyownbt/config.py, sym:lazyownbt/config.py::load_settings@125, file:tests/test_production.py, file:tests/test_configuration.py, sym:main.py::_populate_dashboard_metrics@231, sym:main.py::connect@60, sym:main.py::build_app@260
- Rating 4.1/10 = 7 x PageRank share 0.59 + 3 x risk 0.00. Internal imports: 4.

## lazyownbt: security (`c2`, community, rating 2.6)

3 files under tests (py 3), mostly testing. Core file lazyownbt/security.py (PageRank 0.0646, imported by 3 files): Filtros de seguridad y helpers criptográficos. Key abstractions: SecretsFilter, filter, install_secrets_filter, verify_password, jwt_secret, dev_env. Depends on lazyownbt: web (6), lazyownbt: main (2). Used by lazyownbt: web (1).

- `lazyownbt/security.py` ranks 1 by PageRank, 3 importers, 6 symbols: Filtros de seguridad y helpers criptográficos.
- `tests/conftest.py` ranks 2 by PageRank, 0 importers, 77 symbols: Configuración común para pytest + pytest-bdd.
- `tests/test_security.py` ranks 3 by PageRank, 0 importers, 13 symbols: Tests TDD para el contrato SEC-001 — Manejo seguro de secretos.
- Hotspot `tests/conftest.py`: 77 symbols, 34 connections (score 0.49).
- Hotspot `tests/test_security.py`: 13 symbols, 9 connections (score 0.12).
- 6 layer violations, e.g. conftest.py (testing) -> web.py (presentation).
- Surprising bridge: actions.py <-> test_security.py (3 hops across communities).
- Key entities: file:tests/conftest.py, file:tests/test_security.py, file:lazyownbt/security.py, sym:lazyownbt/security.py::SecretsFilter@13, sym:tests/conftest.py::_iter_source_files@92, sym:tests/conftest.py::_read_text@100, sym:lazyownbt/security.py::filter@35, sym:lazyownbt/security.py::verify_password@59
- Rating 2.6/10 = 7 x PageRank share 0.37 + 3 x risk 0.00. Internal imports: 2.
