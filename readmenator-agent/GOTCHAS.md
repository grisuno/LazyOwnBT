# Gotchas

## God Nodes (high connectivity)

These files have the most connections. Changes here have high blast radius.

- `lazyownbt/web.py` (score: 19.50)
- `app.py` (score: 19.30)
- `tests/conftest.py` (score: 13.70)
- `lazyownbt/config.py` (score: 12.80)
- `lazyownbt/actions.py` (score: 7.00)
- `lazyownbt/security.py` (score: 6.60)
- `main.py` (score: 5.60)
- `tests/test_command_execution.py` (score: 5.40)
- `tests/test_security.py` (score: 5.30)
- `lazyownbt/handlers.py` (score: 4.80)

## Hotspots (complexity + centrality)

- `app.py` -- complexity: 1.0, centrality: 1.0, combined: 1.0
- `tests/conftest.py` -- complexity: 0.4, centrality: 0.5, combined: 0.5
- `lazyownbt/web.py` -- complexity: 0.1, centrality: 0.6, combined: 0.4
- `static/js/commands.js` -- complexity: 0.0, centrality: 0.5, combined: 0.3
- `skills/lazyownbt_mcp.py` -- complexity: 0.1, centrality: 0.3, combined: 0.2
- `main.py` -- complexity: 0.1, centrality: 0.3, combined: 0.2
- `tests/test_production.py` -- complexity: 0.0, centrality: 0.3, combined: 0.2
- `lazyownbt/config.py` -- complexity: 0.0, centrality: 0.3, combined: 0.2
- `lazyownbt/detection.py` -- complexity: 0.1, centrality: 0.2, combined: 0.2
- `lazyownbt/audit.py` -- complexity: 0.0, centrality: 0.2, combined: 0.1

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
