# Index

| File | Purpose | Subsystem | Symbols | Used by |
|------|---------|-----------|---------|---------|
| `app.py` | LazyOwn BlueTeam Framework Una herramienta monolítica de seguridad defensiva para detección de... | root | 193 | 0 |
| `install.sh` | - | root | 0 | 0 |
| `lazyownbt/__init__.py` | LazyOwnBT — Blue Team defensive framework for Linux. | lazyownbt | 0 | 0 |
| `lazyownbt/actions.py` | Registro cerrado de acciones permitidas y parser de parámetros. | lazyownbt | 10 | 3 |
| `lazyownbt/audit.py` | Registro de auditoría de acciones. | lazyownbt | 8 | 1 |
| `lazyownbt/config.py` | Carga de configuración desde variables de entorno y .env. | lazyownbt | 8 | 6 |
| `lazyownbt/detection.py` | Detection engine: auditd + Sigma rules for real-time threat detection. | lazyownbt | 17 | 0 |
| `lazyownbt/handlers.py` | Handlers de acciones: código de aplicación, no shell. | lazyownbt | 8 | 1 |
| `lazyownbt/security.py` | Filtros de seguridad y helpers criptográficos. | lazyownbt | 6 | 3 |
| `lazyownbt/web.py` | Factory de la aplicación Flask (dashboard PurpleTeam). | lazyownbt | 15 | 4 |
| `main.py` | LazyOwn PurpleTeam Dashboard — entry point. | root | 16 | 0 |
| `skills/lazyownbt_mcp.py` | LazyOwnBT MCP Server Exposes LazyOwnBT Blue Team framework capabilities as MCP tools for Claude... | misc | 13 | 0 |
| `static/js/auth.js` | LazyOwnBT — helpers comunes de autenticación en el cliente. | js | 1 | 0 |
| `static/js/commands.js` | LazyOwnBT — formulario de comandos. | js | 3 | 0 |
| `static/js/table-filter.js` | LazyOwnBT — filtro de tabla en cliente (vanilla JS). | js | 2 | 0 |
| `tests/conftest.py` | Configuración común para pytest + pytest-bdd. | tests | 77 | 0 |
| `tests/test_command_execution.py` | Tests TDD para el contrato SEC-002 — Ejecución segura de comandos. | tests | 14 | 0 |
| `tests/test_command_execution_bdd.py` | BDD runner para `command_execution.feature`. | tests | 0 | 0 |
| `tests/test_configuration.py` | Tests TDD para el contrato CFG-001 / CFG-002 — Configuración. | tests | 7 | 0 |
| `tests/test_configuration_bdd.py` | BDD runner para `configuration.feature`. | tests | 0 | 0 |
| `tests/test_production.py` | Tests TDD para el contrato SEC-003 — Modo producción del servidor web. | tests | 8 | 0 |
| `tests/test_production_bdd.py` | BDD runner para `production_readiness.feature`. | tests | 0 | 0 |
| `tests/test_secrets_bdd.py` | BDD runner para `secrets.feature`.  pytest-bdd convierte cada Scenario en un test individual. | tests | 0 | 0 |
| `tests/test_security.py` | Tests TDD para el contrato SEC-001 — Manejo seguro de secretos. | tests | 13 | 0 |
