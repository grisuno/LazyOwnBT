# Contratos de Seguridad

> Estado: **active**
> Aplica a: `main.py` (Flask dashboard), `skills/lazyownbt_mcp.py` (MCP),
> cualquier módulo que gestione credenciales, tokens, claves, ejecute
> acciones o levante servidores.

---

## SEC-001 — Manejo seguro de secretos

### SEC-001.1 — Sin secretos hardcodeados
La aplicación **no debe** contener credenciales, tokens JWT, claves de
firmado, contraseñas administrativas ni claves de API en el código fuente
(literales de cadena).

- ❌ `app.config['JWT_SECRET_KEY'] = 'your-secret-key'`
- ❌ `if username == 'admin' and password == 'password':`
- ✅ `app.config['JWT_SECRET_KEY'] = os.environ['JWT_SECRET_KEY']`

Las credenciales por defecto que la app necesite para desarrollo local deben
leerse desde un archivo `.env` (cargado con `python-dotenv`) que **no** se
versiona. Debe existir un `.env.example` con placeholders.

### SEC-001.2 — JWT secret obligatorio al arrancar
Si `JWT_SECRET_KEY` no está definida en el entorno, la aplicación debe
**rechazar arrancar** con un error explícito (`RuntimeError`). Nunca debe
generar un secreto aleatorio silenciosamente en producción.

- `FLASK_ENV=production` → secreto obligatorio, no se acepta fallback.
- `FLASK_ENV=development` → si el secreto no existe, generar uno aleatorio
  (`secrets.token_urlsafe(64)`), imprimir una advertencia y registrar el
  hecho en el log.

### SEC-001.3 — Validación de fortaleza mínima
El secreto de JWT debe tener al menos **32 bytes** de entropía. Si el valor
provisto tiene menos, la app debe abortar.

### SEC-001.4 — Autenticación con hash
Las credenciales de acceso al dashboard deben compararse contra hashes
(`bcrypt` o `argon2`), nunca en texto plano. Para el seed inicial se acepta
un usuario `admin` cuya contraseña se lee de `ADMIN_PASSWORD` (env), se hashea
una vez y se persiste; en el siguiente arranque se compara contra el hash.

### SEC-001.5 — `.env` fuera del repositorio
`.env` debe figurar en `.gitignore`. `.env.example` debe estar versionado y
listar todas las variables requeridas con valores placeholder (`changeme`).

### SEC-001.6 — Cero secretos en logs
El logger debe tener un filtro (`SecretsFilter`) que redacta cualquier valor
que coincida con los nombres de variables de entorno listados en
`SECRETS_ENV_KEYS` antes de escribirlos a disco o a consola.

---

## SEC-002 — Ejecución segura de comandos

### SEC-002.1 — Sin `subprocess` con código dinámico
Queda prohibido construir comandos de shell o de Python por interpolación de
strings con datos del usuario. Esto incluye:

- ❌ `subprocess.run(['python3', '-c', f'... {user_input} ...'])`
- ❌ `os.system(f"python -c '...'")`
- ❌ `eval()` / `exec()` sobre entrada del usuario
- ✅ Llamadas directas a funciones Python en proceso: `app.do_block_ip(ip)`

### SEC-002.2 — Lista cerrada de acciones
La API sólo puede invocar un conjunto cerrado y versionado de acciones,
definido en `ALLOWED_ACTIONS`. Cada acción expone su firma (nombre,
parámetros tipados, descripción, permisos requeridos). Toda acción no listada
debe rechazarse con HTTP 403.

### SEC-002.3 — Validación y sanitización de parámetros
Cada acción debe validar tipos y rangos de sus parámetros con un parser
dedicado (`ActionParser`). La sanitización con `bleach` se mantiene para
campos de texto libre en plantillas, pero **no** se considera protección
frente a inyección de código: la protección real es no usar `subprocess`
dinámico.

### SEC-002.4 — Timeout y captura
Cada acción debe ejecutarse con un timeout (default 30s, configurable) y
capturar `stdout`/`stderr` de forma segura (límite de tamaño para evitar
desbordamiento de memoria).

### SEC-002.5 — Auditoría
Toda invocación de acción debe registrar:
- timestamp (UTC, ISO 8601)
- usuario autenticado
- acción + parámetros (con secrets redactados)
- resultado (`ok` / `error`)
- duración

Los registros van a la tabla `action_audit` y se exponen vía `/api/audit`.

### SEC-002.6 — Autenticación obligatoria
El endpoint `/commands` debe exigir JWT válido (vía `@jwt_required`).
Sin token → 401. Con token pero sin permisos → 403.

---

## SEC-003 — Modo producción del servidor web

### SEC-003.1 — Debug desactivado por defecto
`app.run(debug=True)` queda prohibido en código. El modo debug sólo puede
activarse explícitamente desde CLI con `--debug` y sólo cuando
`FLASK_ENV=development`. En cualquier otro caso, `debug=False`.

### SEC-003.2 — Bind controlado
El host por defecto debe ser `127.0.0.1` (loopback). Exponer en `0.0.0.0`
debe requerir un flag explícito `--host 0.0.0.0` o variable
`LAZYOWN_BIND=0.0.0.0`, y un warning debe aparecer en el log.

### SEC-003.3 — HTTPS obligatorio en producción
Si `FLASK_ENV=production`:
- `Talisman(force_https=True)` debe estar activo.
- `app.run()` debe usar `ssl_context='adhoc'` por defecto si no se provee
  uno, o abortar indicando que se requiere un proxy TLS.

### SEC-003.4 — CSP sin hashes hardcodeados
La política CSP no debe incluir hashes SHA-256 de estilos inline hardcodeados
en el código. Los estilos inline deben moverse a archivos CSS en
`static/css/`, servidos desde el mismo origen.

### SEC-003.5 — Modo producción exige secret de JWT
Ver SEC-001.2.

---

## Tests derivados (TDD)

- `tests/test_security.py::test_no_hardcoded_jwt_secret`
- `tests/test_security.py::test_no_hardcoded_admin_password`
- `tests/test_security.py::test_app_aborts_when_jwt_secret_missing_in_prod`
- `tests/test_security.py::test_app_generates_ephemeral_secret_in_dev`
- `tests/test_security.py::test_jwt_secret_below_minimum_length_aborts`
- `tests/test_security.py::test_password_is_hashed_not_plain`
- `tests/test_security.py::test_env_file_is_gitignored`
- `tests/test_security.py::test_secrets_filter_redacts_values`
- `tests/test_command_execution.py::test_subprocess_dynamic_python_is_gone`
- `tests/test_command_execution.py::test_command_not_in_allowlist_is_rejected`
- `tests/test_command_execution.py::test_command_requires_jwt`
- `tests/test_command_execution.py::test_command_validates_params`
- `tests/test_command_execution.py::test_command_timeout_enforced`
- `tests/test_command_execution.py::test_command_audit_recorded`
- `tests/test_command_execution.py::test_command_executes_via_python_call`
- `tests/test_production.py::test_debug_flag_default_false`
- `tests/test_production.py::test_debug_only_with_explicit_flag`
- `tests/test_production.py::test_bind_default_loopback`
- `tests/test_production.py::test_bind_warns_when_public`
- `tests/test_production.py::test_talisman_https_in_production`
- `tests/test_production.py::test_csp_has_no_hardcoded_inline_hash`

## Escenarios BDD

- `tests/features/secrets.feature`
- `tests/features/command_execution.feature`
- `tests/features/production_readiness.feature`
