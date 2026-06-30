# Contratos de Configuración

> Estado: **active**
> Aplica a: `requirements.txt`, `config.json`, variables de entorno, y el
> cargador de configuración de la aplicación.

---

## CFG-001 — Configuración desde entorno y archivos versionados

### CFG-001.1 — Variables de entorno primero
Toda configuración sensible o específica del despliegue (rutas, credenciales,
URLs, secretos) debe leerse desde variables de entorno. `config.json` sólo
contiene valores por defecto no sensibles y rutas que apunten al sistema
de archivos local.

### CFG-001.2 — `python-dotenv` como cargador
La aplicación debe usar `python-dotenv` para cargar `.env` en desarrollo.
En producción, las variables deben venir del entorno del sistema
(gestor de secretos, systemd `EnvironmentFile`, Kubernetes `Secret`).

### CFG-001.3 — Falla ruidosa
Si una variable obligatoria no existe y la app la necesita, debe lanzar
`ConfigError` con un mensaje accionable, no `KeyError` genérico.

---

## CFG-002 — `requirements.txt` como contrato

### CFG-002.1 — Listado completo y verificable
`requirements.txt` debe contener **todas** las dependencias que el código
importa, con versiones pinneadas (`==X.Y.Z`). Una ejecución de
`pip install -r requirements.txt` en un entorno limpio debe ser suficiente
para que `python -c "import lazyownbt"` funcione.

### CFG-002.2 — `requirements.txt` no debe estar mudo
Está prohibido publicar un `requirements.txt` con menos entradas que las
que el código realmente importa. Un test debe comparar los `import`
descubiertos estáticamente contra el archivo y fallar si faltan.

### CFG-002.3 — Extras opcionales
Dependencias pesadas u opcionales (modelos IA, RAG, dashboard web) se
declaran en extras (`pyproject.toml` → `[project.optional-dependencies]`)
para que un `pip install lazyownbt[web,ai]` instale sólo lo necesario.

---

## Tests derivados (TDD)

- `tests/test_configuration.py::test_config_loads_from_env`
- `tests/test_configuration.py::test_config_fails_loudly_on_missing_var`
- `tests/test_configuration.py::test_requirements_contains_all_imports`
- `tests/test_configuration.py::test_requirements_versions_pinned`
- `tests/test_configuration.py::test_pyproject_extras_declared`

## Escenarios BDD

- `tests/features/configuration.feature`
