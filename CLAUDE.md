# CLAUDE.md — Contrato del agente para LazyOwnBT

> Este archivo es un **contrato operativo**. Define lo que el agente
> (Claude, o cualquier LLM que opere sobre el repositorio) puede tocar, lo
> que no, y cómo validar cualquier cambio antes de cerrar una tarea.
>
> **Metodología obligatoria**: SDD + TDD + BDD + Boy Scout.
> 1. **SDD** (Spec Driven Development): las specs en `specs/` son la
>    fuente de verdad. Si una funcionalidad no está especificada, primero
>    se escribe la spec y luego el código.
> 2. **TDD** (Test Driven Development): tests rojos primero, luego
>    implementación mínima, luego refactor.
> 3. **BDD** (Behavior Driven Development): escenarios Gherkin en
>    `tests/features/*.feature` describen el comportamiento desde la
>    perspectiva del operador. Los step definitions viven en `tests/conftest.py`.
> 4. **Boy Scout Rule**: "leave the campground cleaner than you found it".
>    Cualquier commit que toque un archivo debe, como mínimo, no empeorar
>    su calidad. Deuda técnica encontrada y que sea trivialmente
>    corregible **se arregla en el mismo commit**.

## Estructura del repositorio

```
LazyOwnBT/
├── specs/                      # Contratos (SDD) — fuente de verdad
│   ├── README.md
│   ├── security.md             # SEC-001, SEC-002, SEC-003
│   ├── configuration.md        # CFG-001, CFG-002
│   └── operations.md           # OPS-001 (validación, refactor, docs)
├── lazyownbt/                  # Paquete principal (Boy Scout: modular desde SEC-*)
│   ├── __init__.py
│   ├── config.py               # Carga .env, valida secretos (SEC-001)
│   ├── security.py             # SecretsFilter, verify_password (SEC-001)
│   ├── actions.py              # ActionRegistry, ActionSpec (SEC-002)
│   ├── audit.py                # AuditLog en SQLite (SEC-002.5)
│   ├── handlers.py             # Handlers puros, sin subprocess dinámico
│   └── web.py                  # Factory Flask (SEC-001, SEC-002, SEC-003)
├── tests/
│   ├── conftest.py             # Fixtures + step definitions BDD
│   ├── features/               # Escenarios Gherkin (BDD)
│   ├── test_security.py        # TDD: SEC-001
│   ├── test_command_execution.py  # TDD: SEC-002
│   ├── test_production.py      # TDD: SEC-003
│   ├── test_configuration.py   # TDD: CFG-001, CFG-002
│   ├── test_secrets_bdd.py
│   ├── test_command_execution_bdd.py
│   ├── test_production_bdd.py
│   └── test_configuration_bdd.py
├── main.py                     # Entry point (delega a lazyownbt.web)
├── app.py                      # CLI monolítica heredada (en proceso de modularización)
├── pyproject.toml              # Extras, ruff, mypy, pytest
├── .env.example                # Plantilla de variables de entorno
├── README.md
└── CLAUDE.md                   # Este archivo
```

## Comandos canónicos (validación)

Antes de cerrar **cualquier** tarea, ejecutar en orden:

```bash
# 1. Suite completa (TDD + BDD)
python3 -m pytest tests/ -v

# 2. Cobertura mínima 70%
python3 -m pytest tests/ --cov=lazyownbt --cov-report=term-missing

# 3. Linter
ruff check lazyownbt/ tests/

# 4. Type-check (al menos en los modificados)
mypy lazyownbt/

# 5. Comprobación de importabilidad
python3 -c "import lazyownbt; from lazyownbt.web import create_app; print('OK')"
```

Si cualquiera falla, **no** se cierra la tarea.

## Reglas duras (no negociables)

### Seguridad (SEC-001, SEC-002, SEC-003)

1. **Cero secretos hardcodeados.** Buscar antes de commit:
   ```bash
   grep -rn -E "(your-secret-key|password\s*==\s*['\"]password['\"]|api[_-]?key\s*=\s*['\"])" lazyownbt/ main.py app.py
   ```
   Debe retornar vacío.

2. **Cero `subprocess` con código dinámico.** Buscar:
   ```bash
   grep -rn -E "subprocess\.(run|Popen|call)\([^)]*-c\s*['\"]" lazyownbt/ main.py app.py
   ```
   Debe retornar vacío.

3. **Cero `os.system` con interpolación.** Buscar:
   ```bash
   grep -rn -E "os\.system\s*\(\s*[fF]?['\"]" lazyownbt/ main.py app.py
   ```
   Debe retornar vacío.

4. **Cero `eval`/`exec` sobre input del usuario.** Buscar:
   ```bash
   grep -rn -E "(eval|exec)\s*\(\s*(request\.|input\(|data\[)" lazyownbt/ main.py app.py
   ```
   Debe retornar vacío.

5. **CSP sin hashes hardcodeados.** Buscar `sha256-` en `main.py`,
   `lazyownbt/web.py`. Debe retornar vacío.

6. **`debug=True` sólo si `--debug` + `FLASK_ENV=development`.** En otro
   caso, el código debe pasar `debug=False` y el flag CLI debe abortar.

7. **Bind por defecto `127.0.0.1`.** `0.0.0.0` sólo bajo flag explícito
   y emite warning en log.

8. **JWT_SECRET_KEY obligatorio en producción.** Si falta, la app aborta
   con `ConfigError`. En development, se genera uno efímero con warning.

9. **Contraseñas con hash bcrypt.** Nunca comparar en texto plano.
   Usar `verify_password` de `lazyownbt.security`.

10. **Toda acción que ejecuta comandos se audita.** Usar
    `AuditLog.track(...)` en cualquier nuevo endpoint que ejecute
    lógica sensible.

### Configuración (CFG-001, CFG-002)

11. **Toda dependencia usada está en `pyproject.toml`.** El test
    `test_requirements_contains_all_imports` es un contrato vivo: si
    añades un `import`, también lo declaras.

12. **Variables de entorno en `.env.example`.** Si añades una variable
    obligatoria, añádela también a `.env.example` con un valor
    placeholder.

13. **`requirements.txt` no debe contradecir `pyproject.toml`.** Si
    existe, reflejar la lista principal. Preferir `pyproject.toml`.

### Boy Scout (deuda técnica)

14. **Mover estilos inline a `static/css/`.** Cumple SEC-003.4.

15. **No re-importar módulos.** Si `import os` ya está, no duplicar.

16. **No usar `print()` para logs.** Usar `logger.info/warning/error`.

17. **Magic numbers → constantes nombradas.**

18. **Funciones de más de 50 líneas → dividir.**

19. **Bloques `try/except` sin `except Exception` específico → refactor.**

## Workflow por tarea

```
1. Leer specs/ relacionadas con la tarea.
2. Si la spec no existe → escribirla primero (SDD).
3. Escribir tests rojos (TDD): pytest tests/<area>.py::test_<contrato>
4. Escribir escenarios BDD (BDD): tests/features/<area>.feature
5. Implementar hasta verde.
6. Refactor (Boy Scout): sin cambiar comportamiento observable.
7. Validar:
     pytest tests/ → 100% verde
     ruff check    → sin warnings
     mypy          → sin errores
8. Actualizar README.md si la tarea es visible al usuario.
9. Actualizar CLAUDE.md si la tarea añade una regla o cambia el contrato.
10. Commit con mensaje convencional: feat/fix/refactor/test/docs(scope): desc
```

## Convenciones de commit

- `feat(scope):` nueva funcionalidad
- `fix(scope):` corrección de bug
- `refactor(scope):` cambio interno sin cambio de comportamiento
- `test(scope):` solo tests
- `docs(scope):` solo documentación
- `chore(scope):` tareas mecánicas (deps, configs)

Scopes: `security`, `config`, `web`, `cli`, `fim`, `network`, `ai`,
`rag`, `audit`, `actions`, `docs`, `ci`.

## Extras permitidos (instalación)

```bash
# Solo el core (config + secrets)
pip install -e .

# CLI base
pip install -e ".[cli]"

# Dashboard web (Flask)
pip install -e ".[web]"

# Detección IA
pip install -e ".[ai]"

# RAG con ChromaDB + LangChain
pip install -e ".[rag]"

# File Integrity Monitor
pip install -e ".[fim]"

# Todo
pip install -e ".[all]"

# Para desarrollo (tests + linter + type-checker)
pip install -e ".[dev]"
```

## Variables de entorno

Ver `.env.example`. Resumen:

| Variable | Obligatoria | Default | Contrato |
|----------|-------------|---------|----------|
| `FLASK_ENV` | no | `production` | SEC-001, SEC-003 |
| `JWT_SECRET_KEY` | sí en prod | (efímero en dev) | SEC-001.2, SEC-001.3 |
| `ADMIN_PASSWORD` o `ADMIN_PASSWORD_HASH` | sí en prod | (admin/admin en dev) | SEC-001.4 |
| `LAZYOWN_BIND` | no | `127.0.0.1` | SEC-003.2 |
| `LAZYOWN_PORT` | no | `5000` | — |
| `LAZYOWN_DB_PATH` | no | `./lazyown.db` | — |
| `LAZYOWN_COMMAND_TIMEOUT` | no | `30` | SEC-002.4 |

## Cómo añadir un nuevo contrato

1. Crear `specs/<area>.md` con la estructura: ID, secciones numeradas
   (`X.NN`), tests derivados, escenarios BDD.
2. Marcar como `draft` hasta que esté revisado.
3. Pasar a `active` solo cuando tenga al menos un test rojo que falle
   por la ausencia de la implementación.
4. Añadir el test a la suite TDD.
5. Añadir el escenario a `tests/features/`.
6. Implementar.
7. Validar.

## Cómo añadir una nueva acción (SEC-002)

1. Declarar en `lazyownbt/actions.py:DEFAULT_ACTIONS` con `ActionSpec`.
2. Implementar el handler en `lazyownbt/handlers.py`.
3. El handler **no** debe usar `subprocess` con string interpolation. Si
   necesita lanzar procesos, usar argv en lista.
4. El handler es automáticamente registrado en el
   `ActionRegistry` por `lazyownbt/web.py:_register_default_actions`.
5. Añadir test TDD en `tests/test_command_execution.py`.
6. Añadir escenario BDD en `tests/features/command_execution.feature`.
7. El comando queda automáticamente en la lista cerrada de `/commands`
   y se audita vía `AuditLog.track(...)`.

## Estado actual de la base de tests

62 tests, 100% verde:
- 13 TDD en `test_security.py`
- 12 TDD en `test_command_execution.py`
- 8 TDD en `test_production.py`
- 4 TDD en `test_configuration.py`
- 7 BDD en `test_secrets_bdd.py`
- 8 BDD en `test_command_execution_bdd.py`
- 7 BDD en `test_production_bdd.py`
- 3 BDD en `test_configuration_bdd.py`

## Próximos gaps conocidos (backlog)

- Modularizar `app.py` (5.271 líneas) en `lazyownbt/cli/`, `lazyownbt/fim/`,
  `lazyownbt/network/`, etc. (mantener compat con `from app import LazyOwnApp`).
- Mapeo MITRE ATT&CK en cada detección.
- Reglas Sigma/YARA en lugar de regex ad-hoc.
- Integración con auditd / sysmon-for-linux / falco.
- Exportación a SIEM (syslog/CEF/LEEF).
- STIX 2.1 / TAXII para IoC.
- Health/Metrics endpoints (`/healthz` ya existe; falta `/metrics` Prometheus).
- Rate limiting y CSRF.
- CI en GitHub Actions con la suite + ruff + mypy.
