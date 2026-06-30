# Contrato OPS-001 — Validación + refactor + documentación

> Estado: **active**
> Aplica a: cualquier cambio de código en el repositorio.

## OPS-001.1 — Boy Scout Rule
> "Leave the campground cleaner than you found it."

Cada commit que toca un archivo debe, como mínimo, no empeorar la calidad
del archivo. Si el archivo tenía deuda técnica (imports duplicados,
`except:`, `print` en vez de `logger`, magic numbers), el commit debe
resolver al menos un item relacionado.

## OPS-001.2 — Validación antes de merge
Antes de cerrar una tarea:

1. `pytest` debe pasar al 100% (sin `--ignore` ni `-k` que excluyan tests).
2. `ruff check` debe pasar sin warnings.
3. `mypy` debe pasar al menos para los archivos modificados.
4. Si se añadieron dependencias: `pip install -r requirements.txt` en
   entorno limpio y `python -c "import <paquete>"` debe funcionar.

## OPS-001.3 — Refactor permitido
El refactor que mantiene o mejora cobertura de tests y no cambia
comportamiento observable no requiere nuevo contrato, pero debe:
- Mantener nombres de funciones públicas o marcar deprecated.
- Actualizar `docs/` si cambia API.
- Añadir un test que proteja la invariante refactorizada.

## OPS-001.4 — Documentación sincronizada
Tras cerrar la tarea, sincronizar:
- `README.md` — cambios visibles al usuario.
- `CLAUDE.md` — contrato para el agente: qué puede tocar, qué no, cómo
  validar, comandos canónicos.
- `docs/` — material de apoyo (guías, tutoriales, decisiones).

Si ninguno cambió, basta con un commit vacío etiquetado `docs:noop` que
lo afirme explícitamente.

## Tests derivados (TDD)

- `tests/test_operations.py::test_requirements_install_clean`
- `tests/test_operations.py::test_ruff_passes`
- `tests/test_operations.py::test_mypy_passes_on_changed_files`
- `tests/test_operations.py::test_readme_has_required_sections`
- `tests/test_operations.py::test_claude_md_is_present`

## Escenarios BDD

- `tests/features/operations.feature`
