# Specs — LazyOwnBT

> Contratos ejecutables. Cada especificación define el comportamiento obligatorio
> de la herramienta. SDD = Spec Driven Development: el código debe satisfacer
> lo que estos archivos declaran. Los tests (TDD) y los escenarios (BDD) se
> derivan directamente de aquí.

## Índice de contratos

| ID       | Contrato                            | Archivo                              |
|----------|-------------------------------------|--------------------------------------|
| SEC-001  | Manejo seguro de secretos           | [security.md](./security.md)         |
| SEC-002  | Ejecución segura de comandos        | [security.md](./security.md)         |
| SEC-003  | Modo producción del servidor web    | [security.md](./security.md)         |
| CFG-001  | Configuración desde entorno         | [configuration.md](./configuration.md)|
| CFG-002  | requirements.txt como contrato      | [configuration.md](./configuration.md)|
| OPS-001  | Validación + refactor + docs        | [operations.md](./operations.md)     |

## Cómo se relacionan con TDD y BDD

- **TDD (tests unitarios)** viven en `tests/` y se escriben **antes** de la
  implementación. Cubren bordes, errores y regresiones de cada contrato.
- **BDD (escenarios Gherkin)** viven en `tests/features/` y describen el
  comportamiento observable desde la perspectiva del operador. Se implementan
  como step definitions en `tests/steps/`.
- **Boy Scout Rule**: cualquier cambio que toque código cubierto por estos
  contratos debe mantener (o ampliar) los tests asociados antes de cerrar la
  tarea.

## Estados de un contrato

- `draft` — en redacción, aún no exigible.
- `active` — vigente. Toda implementación debe cumplirlo y los tests deben
  pasar en CI.
- `deprecated` — sustituido por otro contrato. Indicar el sucesor.
