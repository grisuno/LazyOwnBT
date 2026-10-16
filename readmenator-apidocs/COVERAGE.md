# Documentation Coverage

Overall: **69.6%** (160 of 230 public modules, types, and callables). Data members are excluded from the ratio.

[Back to index](index.md)

## By kind

| Kind | Documented | Total | Coverage |
|---|---|---|---|
| class | 20 | 27 | 74.1% |
| constructor | 3 | 19 | 15.8% |
| exception | 2 | 2 | 100.0% |
| function | 11 | 25 | 44.0% |
| method | 107 | 136 | 78.7% |
| module | 13 | 14 | 92.9% |
| property | 0 | 2 | 0.0% |
| staticmethod | 4 | 5 | 80.0% |

## By module (lowest first)

| Module | Documented | Total | Coverage |
|---|---|---|---|
| [`install.sh`](modules/install.sh.md) | 0 | 1 | 0.0% |
| [`static/js/auth.js`](modules/static.js.auth.js.md) | 1 | 7 | 14.3% |
| [`skills.lazyownbt_mcp`](modules/skills.lazyownbt_mcp.py.md) | 1 | 4 | 25.0% |
| [`static/js/commands.js`](modules/static.js.commands.js.md) | 1 | 4 | 25.0% |
| [`static/js/table-filter.js`](modules/static.js.table-filter.js.md) | 1 | 3 | 33.3% |
| [`lazyownbt.handlers`](modules/lazyownbt.handlers.py.md) | 3 | 8 | 37.5% |
| [`main`](modules/main.py.md) | 4 | 10 | 40.0% |
| [`lazyownbt.audit`](modules/lazyownbt.audit.py.md) | 3 | 7 | 42.9% |
| [`lazyownbt.actions`](modules/lazyownbt.actions.py.md) | 5 | 11 | 45.5% |
| [`lazyownbt.config`](modules/lazyownbt.config.py.md) | 4 | 6 | 66.7% |
| [`lazyownbt.security`](modules/lazyownbt.security.py.md) | 4 | 6 | 66.7% |
| [`app`](modules/app.py.md) | 129 | 159 | 81.1% |
| [`lazyownbt`](modules/lazyownbt.__init__.py.md) | 1 | 1 | 100.0% |
| [`lazyownbt.web`](modules/lazyownbt.web.py.md) | 3 | 3 | 100.0% |

## Warnings

DOC001 undocumented public item, DOC002 parameter not documented, DOC003 documented parameter missing from the signature (stale doc), DOC004 return value not documented, DOC005 raised exception not documented.

DOC001: 57

- DOC001 `app.py:228` class FgColor is not documented
- DOC001 `app.py:231` class Cyan is not documented
- DOC001 `app.py:234` class Red is not documented
- DOC001 `app.py:742` staticmethod SystemUtils.get_process_details is not documented
- DOC001 `app.py:2225` method LogAnalyzer.analyze is not documented
- DOC001 `app.py:2438` method SystemHardener.check_system_security is not documented
- DOC001 `app.py:2637` method SystemHardener.apply_hardening is not documented
- DOC001 `app.py:3076` class MemoryScanner is not documented
- DOC001 `app.py:3077` constructor MemoryScanner.__init__ is not documented
- DOC001 `app.py:3088` method MemoryScanner.scan_process_memory is not documented
- DOC001 `app.py:3154` method MemoryScanner.scan_system is not documented
- DOC001 `app.py:3168` class LazySentinelHandler is not documented
- DOC001 `app.py:3169` constructor LazySentinelHandler.__init__ is not documented
- DOC001 `app.py:3183` method LazySentinelHandler.on_created is not documented
- DOC001 `app.py:3195` method LazySentinelHandler.on_modified is not documented
- DOC001 `app.py:3206` class LazySentinel is not documented
- DOC001 `app.py:3207` constructor LazySentinel.__init__ is not documented
- DOC001 `app.py:3228` method LazySentinel.chunk_text is not documented
- DOC001 `app.py:3231` method LazySentinel.select_relevant_chunk is not documented
- DOC001 `app.py:3298` method LazySentinel.process_file is not documented
- DOC001 `app.py:3447` method LazySentinel.stop is not documented
- DOC001 `install.sh:1` module install.sh is not documented
- DOC001 `lazyownbt/actions.py:35` method ActionRegistry.register is not documented
- DOC001 `lazyownbt/actions.py:41` method ActionRegistry.is_allowed is not documented
- DOC001 `lazyownbt/actions.py:44` method ActionRegistry.spec is not documented
- DOC001 `lazyownbt/actions.py:47` method ActionRegistry.handler is not documented
- DOC001 `lazyownbt/actions.py:50` method ActionRegistry.names is not documented
- DOC001 `lazyownbt/audit.py:23` class AuditRecord is not documented
- DOC001 `lazyownbt/audit.py:77` method AuditLog.record is not documented
- DOC001 `lazyownbt/audit.py:133` method AuditLog.fetch is not documented
- DOC001 `lazyownbt/config.py:117` property Settings.is_production is not documented
- DOC001 `lazyownbt/config.py:121` property Settings.is_development is not documented
- DOC001 `lazyownbt/handlers.py:64` function handle_net_scan is not documented
- DOC001 `lazyownbt/handlers.py:68` function handle_fim_scan is not documented
- DOC001 `lazyownbt/handlers.py:72` function handle_lazynmap is not documented
- DOC001 `lazyownbt/handlers.py:78` function handle_ai_playbook is not documented
- DOC001 `lazyownbt/handlers.py:84` function build_default_handlers is not documented
- DOC001 `lazyownbt/security.py:35` method SecretsFilter.filter is not documented
- DOC001 `main.py:60` method Database.connect is not documented
- DOC001 `main.py:106` method Database.fetch_alerts is not documented
- DOC001 `main.py:127` method Database.fetch_events is not documented
- DOC001 `main.py:141` method Database.fetch_network_baseline is not documented
- DOC001 `main.py:148` method Database.fetch_file_hashes is not documented
- DOC001 `skills/lazyownbt_mcp.py:168` function list_tools is not documented
- DOC001 `skills/lazyownbt_mcp.py:864` function call_tool is not documented
- DOC001 `skills/lazyownbt_mcp.py:1431` function main is not documented
- DOC001 `static/js/auth.js:6` function AUTH is not documented
- DOC001 `static/js/auth.js:9` method get is not documented
- DOC001 `static/js/auth.js:10` method set is not documented
- DOC001 `static/js/auth.js:11` method clear is not documented
- DOC001 `static/js/auth.js:12` method requireOrRedirect is not documented
- DOC001 `static/js/auth.js:16` method fetch is not documented
- DOC001 `static/js/commands.js:34` function renderParams is not documented
- DOC001 `static/js/commands.js:67` function collectParams is not documented
- DOC001 `static/js/commands.js:80` function submitCommand is not documented
- DOC001 `static/js/table-filter.js:6` function tableFilter is not documented
- DOC001 `static/js/table-filter.js:15` function apply is not documented
