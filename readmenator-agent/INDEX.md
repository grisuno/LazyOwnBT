# Index

| File | Purpose | Subsystem | Symbols |
|------|---------|-----------|---------|
| `app.py` | LazyOwn BlueTeam Framework Una herramienta monolítica de seguridad defensiva par | root | 193 |
| `install.sh` | - | root | 0 |
| `lazyownbt/__init__.py` | LazyOwnBT — Blue Team defensive framework for Linux.  Estructura de paquetes: -  | lazyownbt | 0 |
| `lazyownbt/actions.py` | Registro cerrado de acciones permitidas y parser de parámetros.  Contrato: SEC-0 | lazyownbt | 10 |
| `lazyownbt/audit.py` | Registro de auditoría de acciones.  Contrato: SEC-002.5 — Toda invocación de acc | lazyownbt | 8 |
| `lazyownbt/config.py` | Carga de configuración desde variables de entorno y .env.  Contrato: CFG-001 — C | lazyownbt | 8 |
| `lazyownbt/detection.py` | Detection engine: auditd + Sigma rules for real-time threat detection.  Integrat | lazyownbt | 17 |
| `lazyownbt/handlers.py` | Handlers de acciones: código de aplicación, no shell.  Cada handler es una funci | lazyownbt | 8 |
| `lazyownbt/security.py` | Filtros de seguridad y helpers criptográficos.  Contrato: SEC-001 — Manejo segur | lazyownbt | 6 |
| `lazyownbt/web.py` | Factory de la aplicación Flask (dashboard PurpleTeam).  Reemplaza al `main.py` m | lazyownbt | 15 |
| `main.py` | LazyOwn PurpleTeam Dashboard — entry point.  Versión endurecida (SEC-001, SEC-00 | root | 16 |
| `skills/lazyownbt_mcp.py` | LazyOwnBT MCP Server Exposes LazyOwnBT Blue Team framework capabilities as MCP t | misc | 13 |
| `static/js/auth.js` | LazyOwnBT — helpers comunes de autenticación en el cliente. | js | 1 |
| `static/js/commands.js` | LazyOwnBT — formulario de comandos. | js | 3 |
| `static/js/table-filter.js` | LazyOwnBT — filtro de tabla en cliente (vanilla JS). | js | 2 |
| `tests/conftest.py` | Configuración común para pytest + pytest-bdd.  Combina fixtures tradicionales de | tests | 77 |
| `tests/test_command_execution.py` | Tests TDD para el contrato SEC-002 — Ejecución segura de comandos. | tests | 14 |
| `tests/test_command_execution_bdd.py` | BDD runner para `command_execution.feature`. | tests | 0 |
| `tests/test_configuration.py` | Tests TDD para el contrato CFG-001 / CFG-002 — Configuración. | tests | 7 |
| `tests/test_configuration_bdd.py` | BDD runner para `configuration.feature`. | tests | 0 |
| `tests/test_production.py` | Tests TDD para el contrato SEC-003 — Modo producción del servidor web. | tests | 8 |
| `tests/test_production_bdd.py` | BDD runner para `production_readiness.feature`. | tests | 0 |
| `tests/test_secrets_bdd.py` | BDD runner para `secrets.feature`.  pytest-bdd convierte cada Scenario en un tes | tests | 0 |
| `tests/test_security.py` | Tests TDD para el contrato SEC-001 — Manejo seguro de secretos. | tests | 13 |
