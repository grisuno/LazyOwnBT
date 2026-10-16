# Project Memory

> Cross-session context for agents. Sections 1-6 are regenerated from the source tree with zero LLM tokens: declared rules are quoted verbatim with `file:line`, measured baselines come from the scan. Section 7 is written by agents and humans and is preserved across rebuilds.

Generated from 23 files at commit `fcaae06e5f8f`. Read this first, then `readmenator-wiki/index.md`, then `readmenator . ask "<question>"` for anything specific.

## 1. Purpose and domain

- What it is: │     Archivo      │                    Descripción                     │ (`README.md:8`)
- Domain vocabulary (term, files): `para` (12), `sec` (9), `lazyownbt` (9), `contrato` (9), `una` (8), `app` (8), `env` (8), `debe` (8), `que` (8), `los` (7), `con` (7), `config` (7), `audit` (7), `lazy` (7), `own` (7)
- Subsystem `lazyownbt: web`: 5 files, core `lazyownbt/web.py`: Factory de la aplicación Flask (dashboard PurpleTeam).
- Subsystem `lazyownbt: main`: 4 files, core `main.py`: LazyOwn PurpleTeam Dashboard — entry point.
- Subsystem `lazyownbt: security`: 3 files, core `lazyownbt/security.py`: Filtros de seguridad y helpers criptográficos.
- Business rules that the code cannot show live in section 7: record them there.

## 2. Workflow

Detected commands:
- `python -m pytest -q` (pyproject.toml)
- `CI workflow github-actions-demo.yml` (workflows/github-actions-demo.yml)

Session protocol:
1. Start: read this file, then `readmenator . fresh` (exit 1 means run `readmenator . --rebuild`).
2. Orient: `readmenator-wiki/index.md`; for a question use `readmenator . ask "<question>"` (local = entities + sources, `--global` = community reports).
3. Before editing a file: `grep -n '<file>' readmenator-agent/GOTCHAS.md readmenator-agent/SECURITY.md`.
4. After the change: run the tests above, then `readmenator . --rebuild` so the maps, wiki, and this file stay true.
5. End: record decisions, business rules, and gotchas with `readmenator . remember "<note>" --kind decision`.

## 3. Rules and constraints

Declared:
- **Mover estilos inline a `static/css/`.** Cumple SEC-003.4. (`CLAUDE.md:142`)
- **No re-importar módulos.** Si `import os` ya está, no duplicar. (`CLAUDE.md:144`)
- **No usar `print()` para logs.** Usar `logger.info/warning/error`. (`CLAUDE.md:146`)
- **Magic numbers → constantes nombradas.** (`CLAUDE.md:148`)
- **Funciones de más de 50 líneas → dividir.** (`CLAUDE.md:150`)
- **Bloques `try/except` sin `except Exception` específico → refactor.** (`CLAUDE.md:152`)

Measured baseline:
- Security findings at medium or above: 0 (see `readmenator-agent/SECURITY.md`); do not add new ones.
- Dependency cycles: 0; layer violations: 14 (see `readmenator-agent/GOTCHAS.md`).

## 4. Style norms

Declared:
- none declared in instruction files (add them to AGENTS.md or record them in section 7)

Measured baseline:
- py: 19 files, 396 symbols; docstrings on 52% of symbols; functions snake_case (100%); types PascalCase (100%); median file 127 lines, max 5338.
- js: 3 files, 11 symbols; docstrings on 0% of symbols; functions snake_case (45%); median file 34 lines, max 120.
- sh: 1 files, 0 symbols; median file 4 lines, max 4.
- Tests: 9 files under tests; follow the existing naming (e.g. `conftest.py`).

## 5. Minimum deliverables

Declared:
- 13 TDD en `test_security.py` (`CLAUDE.md:254`)
- 12 TDD en `test_command_execution.py` (`CLAUDE.md:255`)
- 8 TDD en `test_production.py` (`CLAUDE.md:256`)
- 4 TDD en `test_configuration.py` (`CLAUDE.md:257`)
- 7 BDD en `test_secrets_bdd.py` (`CLAUDE.md:258`)
- 8 BDD en `test_command_execution_bdd.py` (`CLAUDE.md:259`)
- 7 BDD en `test_production_bdd.py` (`CLAUDE.md:260`)
- 3 BDD en `test_configuration_bdd.py` (`CLAUDE.md:261`)

Measured baseline:
- Tests pass: `python -m pytest -q`.
- Docstring coverage stays at or above 51%.
- No new security findings at medium or above (current: 0).
- No new dependency cycles (current: 0).
- Files stay under 300 lines where possible (`readmenator . lint`).
- Docs refreshed: `readmenator . --rebuild`, and decisions recorded in section 7.

## 6. Risks to respect

- God nodes (changes ripple widely): `lazyownbt/web.py`, `app.py`, `tests/conftest.py`, `lazyownbt/config.py`, `lazyownbt/actions.py`
- Hotspots (complex and central): `app.py`, `tests/conftest.py`, `lazyownbt/web.py`, `static/js/commands.js`, `skills/lazyownbt_mcp.py`
- Full blast radius: `readmenator-agent/GOTCHAS.md`; findings: `readmenator-agent/SECURITY.md`.

## 7. Session log (preserved across rebuilds)

Append with `readmenator . remember "<note>" --kind <kind>` (kinds: business, decision, rule, workflow, style, deliverable, gotcha, todo, note) or the MCP tool `readmenator.remember`. Record business rules, decisions and their reasons, workflow changes, and anything the next session must not rediscover.

<!-- readmenator:memory:notes:begin -->
<!-- readmenator:memory:notes:end -->
