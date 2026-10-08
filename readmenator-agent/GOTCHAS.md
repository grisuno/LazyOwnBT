# Gotchas

## God Nodes (high connectivity)

These files have the most connections. Changes here have high blast radius.

- `lazyownbt/web.py` (score: 19.50, imported by 4 files)
- `app.py` (score: 19.30)
- `lazyownbt/config.py` (score: 12.80, imported by 6 files)
- `lazyownbt/actions.py` (score: 7.00, imported by 3 files)
- `lazyownbt/security.py` (score: 6.60, imported by 3 files)
- `main.py` (score: 5.60)
- `lazyownbt/handlers.py` (score: 4.80, imported by 1 files)

## Blast Radius (change impact)

Editing these files can break the listed number of dependents. Run their tests after any change.

- `lazyownbt/config.py` -- 6 direct, 7 total dependents
- `lazyownbt/actions.py` -- 3 direct, 6 total dependents
- `lazyownbt/security.py` -- 3 direct, 6 total dependents
- `lazyownbt/audit.py` -- 1 direct, 5 total dependents
- `lazyownbt/handlers.py` -- 1 direct, 5 total dependents
- `lazyownbt/web.py` -- 4 direct, 4 total dependents

## Hotspots (complexity + centrality)

- `app.py` -- complexity: 1.0, centrality: 1.0, combined: 1.0
- `lazyownbt/web.py` -- complexity: 0.1, centrality: 0.6, combined: 0.4
- `static/js/commands.js` -- complexity: 0.0, centrality: 0.5, combined: 0.3
- `skills/lazyownbt_mcp.py` -- complexity: 0.1, centrality: 0.3, combined: 0.2
- `main.py` -- complexity: 0.1, centrality: 0.3, combined: 0.2
- `lazyownbt/config.py` -- complexity: 0.0, centrality: 0.3, combined: 0.2
- `lazyownbt/detection.py` -- complexity: 0.1, centrality: 0.2, combined: 0.2
- `lazyownbt/audit.py` -- complexity: 0.0, centrality: 0.2, combined: 0.1
- `static/js/table-filter.js` -- complexity: 0.0, centrality: 0.2, combined: 0.1
- `static/js/auth.js` -- complexity: 0.0, centrality: 0.2, combined: 0.1

## Layer Violations

- `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation): testing must not import presentation
- `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation): testing must not import presentation
- `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation): testing must not import presentation
- `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation): testing must not import presentation
- `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation): testing must not import presentation
- `tests/conftest.py` (testing) -> `lazyownbt/web.py` (presentation): testing must not import presentation
- `tests/test_command_execution.py` (testing) -> `lazyownbt/actions.py` (presentation): testing must not import presentation
- `tests/test_command_execution.py` (testing) -> `lazyownbt/web.py` (presentation): testing must not import presentation
- `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation): testing must not import presentation
- `tests/test_production.py` (testing) -> `lazyownbt/web.py` (presentation): testing must not import presentation
