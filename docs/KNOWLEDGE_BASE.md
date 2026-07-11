# Polyglot Codebase Knowledge Graph

> Generated offline by **readmenator**. Supports C, C++, Python, Go, Rust, JS/TS, Java, C#, Shell, PHP, Dart, GDScript, Nim, ASM.
> No LLMs. No tokens. Pure static analysis.

**Total Files Parsed:** 23 | **Total Symbols Extracted:** 402 | **Total Imports:** 213

## Structural Knowledge Map
```mermaid
graph TD
    classDef mod fill:#1e1e1e,stroke:#ff6666,stroke-width:2px,color:#fff;
    classDef cls fill:#2d2d2d,stroke:#4ec9b0,stroke-width:2px,color:#fff;
    classDef fn fill:#333,stroke:#dcdcaa,stroke-width:1px,color:#dcdcaa;
    classDef ext fill:#111,stroke:#666,stroke-dasharray: 5 5,color:#aaa;
    app_py["app.py (py)"]
    class app_py mod;
    app_py_Fg["Fg"]
    class app_py_Fg cls;
    app_py --> app_py_Fg
    app_py_style["style"]
    class app_py_style fn;
    app_py --> app_py_style
    app_py_replace_command_placeholders["replace_command_placeholders"]
    class app_py_replace_command_placeholders fn;
    app_py --> app_py_replace_command_placeholders
    app_py_FgColor["FgColor"]
    class app_py_FgColor cls;
    app_py --> app_py_FgColor
    app_py_Cyan["Cyan"]
    class app_py_Cyan cls;
    app_py --> app_py_Cyan
    tests_conftest_py["conftest.py (py)"]
    class tests_conftest_py mod;
    tests_conftest_py__make_jwt_secret["_make_jwt_secret"]
    class tests_conftest_py__make_jwt_secret fn;
    tests_conftest_py --> tests_conftest_py__make_jwt_secret
    tests_conftest_py_jwt_secret["jwt_secret"]
    class tests_conftest_py_jwt_secret fn;
    tests_conftest_py --> tests_conftest_py_jwt_secret
    tests_conftest_py_dev_env["dev_env"]
    class tests_conftest_py_dev_env fn;
    tests_conftest_py --> tests_conftest_py_dev_env
    tests_conftest_py_prod_env["prod_env"]
    class tests_conftest_py_prod_env fn;
    tests_conftest_py --> tests_conftest_py_prod_env
    tests_conftest_py_app["app"]
    class tests_conftest_py_app fn;
    tests_conftest_py --> tests_conftest_py_app
    skills_lazyownbt_mcp_py["lazyownbt_mcp.py (py)"]
    class skills_lazyownbt_mcp_py mod;
    skills_lazyownbt_mcp_py__load_config["_load_config"]
    class skills_lazyownbt_mcp_py__load_config fn;
    skills_lazyownbt_mcp_py --> skills_lazyownbt_mcp_py__load_config
    skills_lazyownbt_mcp_py__save_config["_save_config"]
    class skills_lazyownbt_mcp_py__save_config fn;
    skills_lazyownbt_mcp_py --> skills_lazyownbt_mcp_py__save_config
    skills_lazyownbt_mcp_py__db_query["_db_query"]
    class skills_lazyownbt_mcp_py__db_query fn;
    skills_lazyownbt_mcp_py --> skills_lazyownbt_mcp_py__db_query
    skills_lazyownbt_mcp_py__run_lazyownbt_command["_run_lazyownbt_command"]
    class skills_lazyownbt_mcp_py__run_lazyownbt_command fn;
    skills_lazyownbt_mcp_py --> skills_lazyownbt_mcp_py__run_lazyownbt_command
    skills_lazyownbt_mcp_py_list_tools["list_tools"]
    class skills_lazyownbt_mcp_py_list_tools fn;
    skills_lazyownbt_mcp_py --> skills_lazyownbt_mcp_py_list_tools
    lazyownbt_web_py["web.py (py)"]
    class lazyownbt_web_py mod;
    lazyownbt_web_py__build_csp["_build_csp"]
    class lazyownbt_web_py__build_csp fn;
    lazyownbt_web_py --> lazyownbt_web_py__build_csp
    lazyownbt_web_py__register_default_actions["_register_default_actions"]
    class lazyownbt_web_py__register_default_actions fn;
    lazyownbt_web_py --> lazyownbt_web_py__register_default_actions
    lazyownbt_web_py_create_app["create_app"]
    class lazyownbt_web_py_create_app fn;
    lazyownbt_web_py --> lazyownbt_web_py_create_app
    lazyownbt_web_py__register_routes["_register_routes"]
    class lazyownbt_web_py__register_routes fn;
    lazyownbt_web_py --> lazyownbt_web_py__register_routes
    lazyownbt_web_py__handle_command["_handle_command"]
    class lazyownbt_web_py__handle_command fn;
    lazyownbt_web_py --> lazyownbt_web_py__handle_command
    main_py["main.py (py)"]
    class main_py mod;
    main_py_Database["Database"]
    class main_py_Database cls;
    main_py --> main_py_Database
    main_py__register_data_routes["_register_data_routes"]
    class main_py__register_data_routes fn;
    main_py --> main_py__register_data_routes
    main_py__populate_dashboard_metrics["_populate_dashboard_metrics"]
    class main_py__populate_dashboard_metrics fn;
    main_py --> main_py__populate_dashboard_metrics
    main_py_build_app["build_app"]
    class main_py_build_app fn;
    main_py --> main_py_build_app
    main_py___init__["__init__"]
    class main_py___init__ fn;
    main_py --> main_py___init__
    lazyownbt_audit_py["audit.py (py)"]
    class lazyownbt_audit_py mod;
    lazyownbt_audit_py_AuditRecord["AuditRecord"]
    class lazyownbt_audit_py_AuditRecord cls;
    lazyownbt_audit_py --> lazyownbt_audit_py_AuditRecord
    lazyownbt_audit_py_AuditLog["AuditLog"]
    class lazyownbt_audit_py_AuditLog cls;
    lazyownbt_audit_py --> lazyownbt_audit_py_AuditLog
    lazyownbt_audit_py___init__["__init__"]
    class lazyownbt_audit_py___init__ fn;
    lazyownbt_audit_py --> lazyownbt_audit_py___init__
    lazyownbt_audit_py__conn["_conn"]
    class lazyownbt_audit_py__conn fn;
    lazyownbt_audit_py --> lazyownbt_audit_py__conn
    lazyownbt_audit_py__init_db["_init_db"]
    class lazyownbt_audit_py__init_db fn;
    lazyownbt_audit_py --> lazyownbt_audit_py__init_db
    tests_test_production_py["test_production.py (py)"]
    class tests_test_production_py mod;
    tests_test_production_py_test_debug_flag_default_false["test_debug_flag_default_false"]
    class tests_test_production_py_test_debug_flag_default_false fn;
    tests_test_production_py --> tests_test_production_py_test_debug_flag_default_false
    tests_test_production_py_test_debug_only_with_explicit_flag["test_debug_only_with_explicit_flag"]
    class tests_test_production_py_test_debug_only_with_explicit_flag fn;
    tests_test_production_py --> tests_test_production_py_test_debug_only_with_explicit_flag
    tests_test_production_py_test_bind_default_loopback["test_bind_default_loopback"]
    class tests_test_production_py_test_bind_default_loopback fn;
    tests_test_production_py --> tests_test_production_py_test_bind_default_loopback
    tests_test_production_py_test_bind_warns_when_public["test_bind_warns_when_public"]
    class tests_test_production_py_test_bind_warns_when_public fn;
    tests_test_production_py --> tests_test_production_py_test_bind_warns_when_public
    tests_test_production_py_test_talisman_https_in_production["test_talisman_https_in_production"]
    class tests_test_production_py_test_talisman_https_in_production fn;
    tests_test_production_py --> tests_test_production_py_test_talisman_https_in_production
    lazyownbt_config_py["config.py (py)"]
    class lazyownbt_config_py mod;
    lazyownbt_config_py_ConfigError["ConfigError"]
    class lazyownbt_config_py_ConfigError cls;
    lazyownbt_config_py --> lazyownbt_config_py_ConfigError
    lazyownbt_config_py__load_dotenv["_load_dotenv"]
    class lazyownbt_config_py__load_dotenv fn;
    lazyownbt_config_py --> lazyownbt_config_py__load_dotenv
    lazyownbt_config_py__resolve_jwt_secret["_resolve_jwt_secret"]
    class lazyownbt_config_py__resolve_jwt_secret fn;
    lazyownbt_config_py --> lazyownbt_config_py__resolve_jwt_secret
    lazyownbt_config_py__resolve_admin_password_hash["_resolve_admin_password_hash"]
    class lazyownbt_config_py__resolve_admin_password_hash fn;
    lazyownbt_config_py --> lazyownbt_config_py__resolve_admin_password_hash
    lazyownbt_config_py_Settings["Settings"]
    class lazyownbt_config_py_Settings cls;
    lazyownbt_config_py --> lazyownbt_config_py_Settings
    tests_test_configuration_py["test_configuration.py (py)"]
    class tests_test_configuration_py mod;
    tests_test_configuration_py_test_config_loads_from_env["test_config_loads_from_env"]
    class tests_test_configuration_py_test_config_loads_from_env fn;
    tests_test_configuration_py --> tests_test_configuration_py_test_config_loads_from_env
    tests_test_configuration_py_test_config_fails_loudly_on_missing_var["test_config_fails_loudly_on_missing_var"]
    class tests_test_configuration_py_test_config_fails_loudly_on_missing_var fn;
    tests_test_configuration_py --> tests_test_configuration_py_test_config_fails_loudly_on_missing_var
    tests_test_configuration_py__extract_top_level_imports["_extract_top_level_imports"]
    class tests_test_configuration_py__extract_top_level_imports fn;
    tests_test_configuration_py --> tests_test_configuration_py__extract_top_level_imports
    tests_test_configuration_py__declared_deps["_declared_deps"]
    class tests_test_configuration_py__declared_deps fn;
    tests_test_configuration_py --> tests_test_configuration_py__declared_deps
    tests_test_configuration_py__canonical["_canonical"]
    class tests_test_configuration_py__canonical fn;
    tests_test_configuration_py --> tests_test_configuration_py__canonical
    tests_test_command_execution_py["test_command_execution.py (py)"]
    class tests_test_command_execution_py mod;
    tests_test_command_execution_py__read["_read"]
    class tests_test_command_execution_py__read fn;
    tests_test_command_execution_py --> tests_test_command_execution_py__read
    tests_test_command_execution_py_test_subprocess_dynamic_python_is_gone["test_subprocess_dynamic_python_is_gone"]
    class tests_test_command_execution_py_test_subprocess_dynamic_python_is_gone fn;
    tests_test_command_execution_py --> tests_test_command_execution_py_test_subprocess_dynamic_python_is_gone
    tests_test_command_execution_py_test_no_eval_on_user_input["test_no_eval_on_user_input"]
    class tests_test_command_execution_py_test_no_eval_on_user_input fn;
    tests_test_command_execution_py --> tests_test_command_execution_py_test_no_eval_on_user_input
    tests_test_command_execution_py_test_command_not_in_allowlist_is_rejected["test_command_not_in_allowlist_is_rejected"]
    class tests_test_command_execution_py_test_command_not_in_allowlist_is_rejected fn;
    tests_test_command_execution_py --> tests_test_command_execution_py_test_command_not_in_allowlist_is_rejected
    tests_test_command_execution_py_test_command_not_in_allowlist_returns_403["test_command_not_in_allowlist_returns_403"]
    class tests_test_command_execution_py_test_command_not_in_allowlist_returns_403 fn;
    tests_test_command_execution_py --> tests_test_command_execution_py_test_command_not_in_allowlist_returns_403
    tests_test_security_py["test_security.py (py)"]
    class tests_test_security_py mod;
    tests_test_security_py__iter_source_files["_iter_source_files"]
    class tests_test_security_py__iter_source_files fn;
    tests_test_security_py --> tests_test_security_py__iter_source_files
    tests_test_security_py_test_no_hardcoded_jwt_secret["test_no_hardcoded_jwt_secret"]
    class tests_test_security_py_test_no_hardcoded_jwt_secret fn;
    tests_test_security_py --> tests_test_security_py_test_no_hardcoded_jwt_secret
    tests_test_security_py_test_no_hardcoded_admin_password["test_no_hardcoded_admin_password"]
    class tests_test_security_py_test_no_hardcoded_admin_password fn;
    tests_test_security_py --> tests_test_security_py_test_no_hardcoded_admin_password
    tests_test_security_py_test_app_aborts_when_jwt_secret_missing_in_prod["test_app_aborts_when_jwt_secret_missing_in_prod"]
    class tests_test_security_py_test_app_aborts_when_jwt_secret_missing_in_prod fn;
    tests_test_security_py --> tests_test_security_py_test_app_aborts_when_jwt_secret_missing_in_prod
    tests_test_security_py_test_app_generates_ephemeral_secret_in_dev["test_app_generates_ephemeral_secret_in_dev"]
    class tests_test_security_py_test_app_generates_ephemeral_secret_in_dev fn;
    tests_test_security_py --> tests_test_security_py_test_app_generates_ephemeral_secret_in_dev
    lazyownbt_handlers_py["handlers.py (py)"]
    class lazyownbt_handlers_py mod;
    lazyownbt_handlers_py__validate_ip["_validate_ip"]
    class lazyownbt_handlers_py__validate_ip fn;
    lazyownbt_handlers_py --> lazyownbt_handlers_py__validate_ip
    lazyownbt_handlers_py_handle_resp_block_ip["handle_resp_block_ip"]
    class lazyownbt_handlers_py_handle_resp_block_ip fn;
    lazyownbt_handlers_py --> lazyownbt_handlers_py_handle_resp_block_ip
    lazyownbt_handlers_py_handle_resp_kill_proc["handle_resp_kill_proc"]
    class lazyownbt_handlers_py_handle_resp_kill_proc fn;
    lazyownbt_handlers_py --> lazyownbt_handlers_py_handle_resp_kill_proc
    lazyownbt_handlers_py_handle_net_scan["handle_net_scan"]
    class lazyownbt_handlers_py_handle_net_scan fn;
    lazyownbt_handlers_py --> lazyownbt_handlers_py_handle_net_scan
    lazyownbt_handlers_py_handle_fim_scan["handle_fim_scan"]
    class lazyownbt_handlers_py_handle_fim_scan fn;
    lazyownbt_handlers_py --> lazyownbt_handlers_py_handle_fim_scan
    lazyownbt_security_py["security.py (py)"]
    class lazyownbt_security_py mod;
    lazyownbt_security_py_SecretsFilter["SecretsFilter"]
    class lazyownbt_security_py_SecretsFilter cls;
    lazyownbt_security_py --> lazyownbt_security_py_SecretsFilter
    lazyownbt_security_py_install_secrets_filter["install_secrets_filter"]
    class lazyownbt_security_py_install_secrets_filter fn;
    lazyownbt_security_py --> lazyownbt_security_py_install_secrets_filter
    lazyownbt_security_py_verify_password["verify_password"]
    class lazyownbt_security_py_verify_password fn;
    lazyownbt_security_py --> lazyownbt_security_py_verify_password
    lazyownbt_security_py___init__["__init__"]
    class lazyownbt_security_py___init__ fn;
    lazyownbt_security_py --> lazyownbt_security_py___init__
    lazyownbt_security_py__redact["_redact"]
    class lazyownbt_security_py__redact fn;
    lazyownbt_security_py --> lazyownbt_security_py__redact
    lazyownbt_actions_py["actions.py (py)"]
    class lazyownbt_actions_py mod;
    lazyownbt_actions_py_ActionSpec["ActionSpec"]
    class lazyownbt_actions_py_ActionSpec cls;
    lazyownbt_actions_py --> lazyownbt_actions_py_ActionSpec
    lazyownbt_actions_py_ActionParseError["ActionParseError"]
    class lazyownbt_actions_py_ActionParseError cls;
    lazyownbt_actions_py --> lazyownbt_actions_py_ActionParseError
    lazyownbt_actions_py_ActionRegistry["ActionRegistry"]
    class lazyownbt_actions_py_ActionRegistry cls;
    lazyownbt_actions_py --> lazyownbt_actions_py_ActionRegistry
    lazyownbt_actions_py___init__["__init__"]
    class lazyownbt_actions_py___init__ fn;
    lazyownbt_actions_py --> lazyownbt_actions_py___init__
    lazyownbt_actions_py_register["register"]
    class lazyownbt_actions_py_register fn;
    lazyownbt_actions_py --> lazyownbt_actions_py_register
    tests_test_command_execution_bdd_py["test_command_execution_bdd.py (py)"]
    class tests_test_command_execution_bdd_py mod;
    tests_test_configuration_bdd_py["test_configuration_bdd.py (py)"]
    class tests_test_configuration_bdd_py mod;
    tests_test_production_bdd_py["test_production_bdd.py (py)"]
    class tests_test_production_bdd_py mod;
    tests_test_secrets_bdd_py["test_secrets_bdd.py (py)"]
    class tests_test_secrets_bdd_py mod;
    static_js_commands_js["commands.js (js)"]
    class static_js_commands_js mod;
    static_js_commands_js_renderParams["renderParams"]
    class static_js_commands_js_renderParams fn;
    static_js_commands_js --> static_js_commands_js_renderParams
    static_js_commands_js_collectParams["collectParams"]
    class static_js_commands_js_collectParams fn;
    static_js_commands_js --> static_js_commands_js_collectParams
    static_js_commands_js_submitCommand["submitCommand"]
    class static_js_commands_js_submitCommand fn;
    static_js_commands_js --> static_js_commands_js_submitCommand
    static_js_table_filter_js["table-filter.js (js)"]
    class static_js_table_filter_js mod;
    static_js_table_filter_js_tableFilter["tableFilter"]
    class static_js_table_filter_js_tableFilter fn;
    static_js_table_filter_js --> static_js_table_filter_js_tableFilter
    static_js_table_filter_js_apply["apply"]
    class static_js_table_filter_js_apply fn;
    static_js_table_filter_js --> static_js_table_filter_js_apply
    static_js_auth_js["auth.js (js)"]
    class static_js_auth_js mod;
    static_js_auth_js_AUTH["AUTH"]
    class static_js_auth_js_AUTH fn;
    static_js_auth_js --> static_js_auth_js_AUTH
    install_sh["install.sh (sh)"]
    class install_sh mod;
    lazyownbt___init___py["__init__.py (py)"]
    class lazyownbt___init___py mod;
    ext_cmd2["cmd2"]
    class ext_cmd2 ext;
    app_py -.->|imports| ext_cmd2
    ext_json["json"]
    class ext_json ext;
    app_py -.->|imports| ext_json
    ext_psutil["psutil"]
    class ext_psutil ext;
    app_py -.->|imports| ext_psutil
    ext_os["os"]
    class ext_os ext;
    app_py -.->|imports| ext_os
    ext_sys["sys"]
    class ext_sys ext;
    app_py -.->|imports| ext_sys
    ext_re["re"]
    class ext_re ext;
    app_py -.->|imports| ext_re
    ext_yaml["yaml"]
    class ext_yaml ext;
    app_py -.->|imports| ext_yaml
    ext_datetime["datetime"]
    class ext_datetime ext;
    app_py -.->|imports| ext_datetime
    ext_logging["logging"]
    class ext_logging ext;
    app_py -.->|imports| ext_logging
    ext_threading["threading"]
    class ext_threading ext;
    app_py -.->|imports| ext_threading
    ext_sqlite3["sqlite3"]
    class ext_sqlite3 ext;
    app_py -.->|imports| ext_sqlite3
    ext_hashlib["hashlib"]
    class ext_hashlib ext;
    app_py -.->|imports| ext_hashlib
    ext_socket["socket"]
    class ext_socket ext;
    app_py -.->|imports| ext_socket
    ext_subprocess["subprocess"]
    class ext_subprocess ext;
    app_py -.->|imports| ext_subprocess
    ext_platform["platform"]
    class ext_platform ext;
    app_py -.->|imports| ext_platform
    ext_time["time"]
    class ext_time ext;
    app_py -.->|imports| ext_time
    ext_shutil["shutil"]
    class ext_shutil ext;
    app_py -.->|imports| ext_shutil
    ext_joblib["joblib"]
    class ext_joblib ext;
    app_py -.->|imports| ext_joblib
    ext_pandas["pandas"]
    class ext_pandas ext;
    app_py -.->|imports| ext_pandas
    ext_sklearn_feature_extraction_text["sklearn.feature_extraction.text"]
    class ext_sklearn_feature_extraction_text ext;
    app_py -.->|imports| ext_sklearn_feature_extraction_text
    ext_signal["signal"]
    class ext_signal ext;
    app_py -.->|imports| ext_signal
    ext_pwd["pwd"]
    class ext_pwd ext;
    app_py -.->|imports| ext_pwd
    ext_grp["grp"]
    class ext_grp ext;
    app_py -.->|imports| ext_grp
    ext_csv["csv"]
    class ext_csv ext;
    app_py -.->|imports| ext_csv
    ext_argparse["argparse"]
    class ext_argparse ext;
    app_py -.->|imports| ext_argparse
    ext_lupa["lupa"]
    class ext_lupa ext;
    app_py -.->|imports| ext_lupa
    ext_concurrent_futures["concurrent.futures"]
    class ext_concurrent_futures ext;
    app_py -.->|imports| ext_concurrent_futures
    ext_collections["collections"]
    class ext_collections ext;
    app_py -.->|imports| ext_collections
    ext_typing["typing"]
    class ext_typing ext;
    app_py -.->|imports| ext_typing
    ext_tabulate["tabulate"]
    class ext_tabulate ext;
    app_py -.->|imports| ext_tabulate
    ext_pathlib["pathlib"]
    class ext_pathlib ext;
    app_py -.->|imports| ext_pathlib
    app_py -.->|imports| ext_os
    app_py -.->|imports| ext_time
    app_py -.->|imports| ext_cmd2
    app_py -.->|imports| ext_logging
    app_py -.->|imports| ext_json
    ext_requests["requests"]
    class ext_requests ext;
    app_py -.->|imports| ext_requests
    app_py -.->|imports| ext_sqlite3
    app_py -.->|imports| ext_datetime
    app_py -.->|imports| ext_re
    ext_queue["queue"]
    class ext_queue ext;
    app_py -.->|imports| ext_queue
    ext_tempfile["tempfile"]
    class ext_tempfile ext;
    app_py -.->|imports| ext_tempfile
    app_py -.->|imports| ext_hashlib
    ext_watchdog_observers["watchdog.observers"]
    class ext_watchdog_observers ext;
    app_py -.->|imports| ext_watchdog_observers
    ext_watchdog_events["watchdog.events"]
    class ext_watchdog_events ext;
    app_py -.->|imports| ext_watchdog_events
    app_py -.->|imports| ext_pathlib
    app_py -.->|imports| ext_typing
    ext_cachetools["cachetools"]
    class ext_cachetools ext;
    app_py -.->|imports| ext_cachetools
    ext_rich_console["rich.console"]
    class ext_rich_console ext;
    app_py -.->|imports| ext_rich_console
    ext_rich_panel["rich.panel"]
    class ext_rich_panel ext;
    app_py -.->|imports| ext_rich_panel
    ext_rich_markdown["rich.markdown"]
    class ext_rich_markdown ext;
    app_py -.->|imports| ext_rich_markdown
    ext_langchain_community_document_loaders["langchain_community.document_loaders"]
    class ext_langchain_community_document_loaders ext;
    app_py -.->|imports| ext_langchain_community_document_loaders
    ext_langchain_text_splitters["langchain_text_splitters"]
    class ext_langchain_text_splitters ext;
    app_py -.->|imports| ext_langchain_text_splitters
    ext_langchain_chroma["langchain_chroma"]
    class ext_langchain_chroma ext;
    app_py -.->|imports| ext_langchain_chroma
    ext_langchain_ollama["langchain_ollama"]
    class ext_langchain_ollama ext;
    app_py -.->|imports| ext_langchain_ollama
    ext_cmd2_styles["cmd2.styles"]
    class ext_cmd2_styles ext;
    app_py -.->|imports| ext_cmd2_styles
    ext_ollama["ollama"]
    class ext_ollama ext;
    app_py -.->|imports| ext_ollama
    ext_chromadb["chromadb"]
    class ext_chromadb ext;
    app_py -.->|imports| ext_chromadb
    app_py -.->|imports| ext_cachetools
    ext_rich["rich"]
    class ext_rich ext;
    app_py -.->|imports| ext_rich
    app_py -.->|imports| ext_re
    ext___future__["__future__"]
    class ext___future__ ext;
    lazyownbt_actions_py -.->|imports| ext___future__
    ext_dataclasses["dataclasses"]
    class ext_dataclasses ext;
    lazyownbt_actions_py -.->|imports| ext_dataclasses
    lazyownbt_actions_py -.->|imports| ext_typing
    lazyownbt_audit_py -.->|imports| ext___future__
    lazyownbt_audit_py -.->|imports| ext_json
    lazyownbt_audit_py -.->|imports| ext_logging
    lazyownbt_audit_py -.->|imports| ext_sqlite3
    lazyownbt_audit_py -.->|imports| ext_threading
    lazyownbt_audit_py -.->|imports| ext_time
    ext_contextlib["contextlib"]
    class ext_contextlib ext;
    lazyownbt_audit_py -.->|imports| ext_contextlib
    lazyownbt_audit_py -.->|imports| ext_dataclasses
    lazyownbt_audit_py -.->|imports| ext_datetime
    lazyownbt_audit_py -.->|imports| ext_pathlib
    lazyownbt_audit_py -.->|imports| ext_typing
    lazyownbt_config_py -.->|imports| ext___future__
    lazyownbt_config_py -.->|imports| ext_os
    ext_secrets["secrets"]
    class ext_secrets ext;
    lazyownbt_config_py -.->|imports| ext_secrets
    lazyownbt_config_py -.->|imports| ext_sys
    lazyownbt_config_py -.->|imports| ext_dataclasses
    lazyownbt_config_py -.->|imports| ext_pathlib
    lazyownbt_config_py -.->|imports| ext_typing
    ext_dotenv["dotenv"]
    class ext_dotenv ext;
    lazyownbt_config_py -.->|imports| ext_dotenv
    ext_bcrypt["bcrypt"]
    class ext_bcrypt ext;
    lazyownbt_config_py -.->|imports| ext_bcrypt
    lazyownbt_handlers_py -.->|imports| ext___future__
    lazyownbt_handlers_py -.->|imports| ext_os
    lazyownbt_handlers_py -.->|imports| ext_re
    lazyownbt_handlers_py -.->|imports| ext_socket
    lazyownbt_handlers_py -.->|imports| ext_subprocess
    lazyownbt_handlers_py -.->|imports| ext_typing
    ext_lazyownbt_actions["lazyownbt.actions"]
    class ext_lazyownbt_actions ext;
    lazyownbt_handlers_py -.->|imports| ext_lazyownbt_actions
    lazyownbt_security_py -.->|imports| ext___future__
    lazyownbt_security_py -.->|imports| ext_logging
    lazyownbt_security_py -.->|imports| ext_re
    lazyownbt_security_py -.->|imports| ext_typing
    lazyownbt_security_py -.->|imports| ext_bcrypt
    lazyownbt_web_py -.->|imports| ext___future__
    lazyownbt_web_py -.->|imports| ext_logging
    lazyownbt_web_py -.->|imports| ext_os
    lazyownbt_web_py -.->|imports| ext_pathlib
    lazyownbt_web_py -.->|imports| ext_typing
    ext_flask["flask"]
    class ext_flask ext;
    lazyownbt_web_py -.->|imports| ext_flask
    ext_flask_jwt_extended["flask_jwt_extended"]
    class ext_flask_jwt_extended ext;
    lazyownbt_web_py -.->|imports| ext_flask_jwt_extended
    ext_flask_talisman["flask_talisman"]
    class ext_flask_talisman ext;
    lazyownbt_web_py -.->|imports| ext_flask_talisman
    lazyownbt_web_py -.->|imports| ext_lazyownbt_actions
    ext_lazyownbt_audit["lazyownbt.audit"]
    class ext_lazyownbt_audit ext;
    lazyownbt_web_py -.->|imports| ext_lazyownbt_audit
    ext_lazyownbt_config["lazyownbt.config"]
    class ext_lazyownbt_config ext;
    lazyownbt_web_py -.->|imports| ext_lazyownbt_config
    ext_lazyownbt_security["lazyownbt.security"]
    class ext_lazyownbt_security ext;
    lazyownbt_web_py -.->|imports| ext_lazyownbt_security
    ext_lazyownbt_handlers["lazyownbt.handlers"]
    class ext_lazyownbt_handlers ext;
    lazyownbt_web_py -.->|imports| ext_lazyownbt_handlers
    lazyownbt_web_py -.->|imports| ext_flask_jwt_extended
    lazyownbt_web_py -.->|imports| ext_argparse
    main_py -.->|imports| ext___future__
    main_py -.->|imports| ext_json
    main_py -.->|imports| ext_logging
    main_py -.->|imports| ext_sqlite3
    main_py -.->|imports| ext_datetime
    main_py -.->|imports| ext_pathlib
    main_py -.->|imports| ext_typing
    main_py -.->|imports| ext_flask
    main_py -.->|imports| ext_lazyownbt_config
    ext_lazyownbt_web["lazyownbt.web"]
    class ext_lazyownbt_web ext;
    main_py -.->|imports| ext_lazyownbt_web
    main_py -.->|imports| ext_argparse
    main_py -.->|imports| ext_os
    main_py -.->|imports| ext_lazyownbt_config
    main_py -.->|imports| ext_lazyownbt_web
    ext_asyncio["asyncio"]
    class ext_asyncio ext;
    skills_lazyownbt_mcp_py -.->|imports| ext_asyncio
    ext_fcntl["fcntl"]
    class ext_fcntl ext;
    skills_lazyownbt_mcp_py -.->|imports| ext_fcntl
    skills_lazyownbt_mcp_py -.->|imports| ext_json
    skills_lazyownbt_mcp_py -.->|imports| ext_os
    ext_pty["pty"]
    class ext_pty ext;
    skills_lazyownbt_mcp_py -.->|imports| ext_pty
    skills_lazyownbt_mcp_py -.->|imports| ext_re
    ext_select["select"]
    class ext_select ext;
    skills_lazyownbt_mcp_py -.->|imports| ext_select
    skills_lazyownbt_mcp_py -.->|imports| ext_sqlite3
    ext_struct["struct"]
    class ext_struct ext;
    skills_lazyownbt_mcp_py -.->|imports| ext_struct
    skills_lazyownbt_mcp_py -.->|imports| ext_subprocess
    skills_lazyownbt_mcp_py -.->|imports| ext_sys
    ext_termios["termios"]
    class ext_termios ext;
    skills_lazyownbt_mcp_py -.->|imports| ext_termios
    skills_lazyownbt_mcp_py -.->|imports| ext_time
    skills_lazyownbt_mcp_py -.->|imports| ext_datetime
    skills_lazyownbt_mcp_py -.->|imports| ext_pathlib
    skills_lazyownbt_mcp_py -.->|imports| ext_typing
    ext_mcp_server["mcp.server"]
    class ext_mcp_server ext;
    skills_lazyownbt_mcp_py -.->|imports| ext_mcp_server
    ext_mcp_server_stdio["mcp.server.stdio"]
    class ext_mcp_server_stdio ext;
    skills_lazyownbt_mcp_py -.->|imports| ext_mcp_server_stdio
    ext_mcp["mcp"]
    class ext_mcp ext;
    skills_lazyownbt_mcp_py -.->|imports| ext_mcp
    skills_lazyownbt_mcp_py -.->|imports| ext_signal
    tests_conftest_py -.->|imports| ext___future__
    tests_conftest_py -.->|imports| ext_json
    tests_conftest_py -.->|imports| ext_os
    tests_conftest_py -.->|imports| ext_re
    tests_conftest_py -.->|imports| ext_sys
    tests_conftest_py -.->|imports| ext_pathlib
    tests_conftest_py -.->|imports| ext_bcrypt
    ext_pytest["pytest"]
    class ext_pytest ext;
    tests_conftest_py -.->|imports| ext_pytest
    tests_conftest_py -.->|imports| ext_flask_jwt_extended
    ext_pytest_bdd["pytest_bdd"]
    class ext_pytest_bdd ext;
    tests_conftest_py -.->|imports| ext_pytest_bdd
    tests_conftest_py -.->|imports| ext_lazyownbt_config
    tests_conftest_py -.->|imports| ext_lazyownbt_security
    tests_conftest_py -.->|imports| ext_lazyownbt_web
    tests_conftest_py -.->|imports| ext_lazyownbt_web
    tests_conftest_py -.->|imports| ext_bcrypt
    tests_conftest_py -.->|imports| ext_flask_jwt_extended
    tests_conftest_py -.->|imports| ext_logging
    ext_ast["ast"]
    class ext_ast ext;
    tests_conftest_py -.->|imports| ext_ast
    tests_conftest_py -.->|imports| ext_pathlib
    tests_conftest_py -.->|imports| ext_lazyownbt_web
    tests_conftest_py -.->|imports| ext_lazyownbt_web
    tests_conftest_py -.->|imports| ext_lazyownbt_web
    tests_conftest_py -.->|imports| ext_lazyownbt_web
    tests_conftest_py -.->|imports| ext_re
    ext_tomllib["tomllib"]
    class ext_tomllib ext;
    tests_conftest_py -.->|imports| ext_tomllib
    tests_conftest_py -.->|imports| ext_sys
    tests_test_command_execution_py -.->|imports| ext___future__
    tests_test_command_execution_py -.->|imports| ext_json
    tests_test_command_execution_py -.->|imports| ext_re
    tests_test_command_execution_py -.->|imports| ext_pathlib
    tests_test_command_execution_py -.->|imports| ext_pytest
    tests_test_command_execution_py -.->|imports| ext_lazyownbt_actions
    tests_test_command_execution_py -.->|imports| ext_lazyownbt_web
    tests_test_command_execution_bdd_py -.->|imports| ext___future__
    tests_test_command_execution_bdd_py -.->|imports| ext_pytest_bdd
    tests_test_configuration_py -.->|imports| ext___future__
    tests_test_configuration_py -.->|imports| ext_ast
    tests_test_configuration_py -.->|imports| ext_re
    tests_test_configuration_py -.->|imports| ext_sys
    tests_test_configuration_py -.->|imports| ext_pathlib
    tests_test_configuration_py -.->|imports| ext_pytest
    tests_test_configuration_py -.->|imports| ext_lazyownbt_config
    tests_test_configuration_py -.->|imports| ext_tomllib
    tests_test_configuration_py -.->|imports| ext_tomllib
    tests_test_configuration_bdd_py -.->|imports| ext___future__
    tests_test_configuration_bdd_py -.->|imports| ext_pytest_bdd
    tests_test_production_py -.->|imports| ext___future__
    tests_test_production_py -.->|imports| ext_pathlib
    tests_test_production_py -.->|imports| ext_pytest
    tests_test_production_py -.->|imports| ext_lazyownbt_web
    tests_test_production_py -.->|imports| ext_lazyownbt_web
    tests_test_production_py -.->|imports| ext_lazyownbt_config
    tests_test_production_py -.->|imports| ext_lazyownbt_web
    tests_test_production_py -.->|imports| ext_logging
    tests_test_production_py -.->|imports| ext_lazyownbt_web
    tests_test_production_py -.->|imports| ext_lazyownbt_web
    tests_test_production_py -.->|imports| ext_lazyownbt_web
    tests_test_production_bdd_py -.->|imports| ext___future__
    tests_test_production_bdd_py -.->|imports| ext_pytest_bdd
    tests_test_secrets_bdd_py -.->|imports| ext___future__
    tests_test_secrets_bdd_py -.->|imports| ext_pytest_bdd
    tests_test_security_py -.->|imports| ext___future__
    tests_test_security_py -.->|imports| ext_re
    tests_test_security_py -.->|imports| ext_pathlib
    tests_test_security_py -.->|imports| ext_pytest
    tests_test_security_py -.->|imports| ext_lazyownbt_config
    tests_test_security_py -.->|imports| ext_lazyownbt_security
    tests_test_security_py -.->|imports| ext_bcrypt
```

---

## Architecture Reference

### JS (3 files)

#### `auth.js`
**Path:** `static/js/auth.js`

**Functions:**
- `AUTH` (line 6) - *LazyOwnBT — helpers comunes de autenticación en el cliente. Mantiene la convención de usar sessionStorage (mismo nombre de clave que login.html) pa...*

#### `commands.js`
**Path:** `static/js/commands.js`

**Functions:**
- `renderParams` (line 33)
- `collectParams` (line 66)
- `submitCommand` (line 80)

#### `table-filter.js`
**Path:** `static/js/table-filter.js`

**Functions:**
- `tableFilter` (line 5) - *LazyOwnBT — filtro de tabla en cliente (vanilla JS). Reemplaza a DataTables para evitar CDN (CSP estricta). Uso: <script>tableFilter('alertsTable',...*
- `apply` (line 15)

### PY (19 files)

#### `app.py`
**Path:** `app.py`

**Classs:**
- `Fg` (line 48) - *Color foreground (compat). Mapea al enum `cmd2.styles.Color`.*
- `FgColor` (line 228)
- `Cyan` (line 231)
- `Red` (line 234)
- `RAGManager` (line 249) - *Manages RAG functionality with CAG caching for document processing and querying.*
- `Database` (line 455) - *Clase para manejar la base de datos SQLite.*
- `Alert` (line 605) - *Clase para representar y manejar alertas.*
- `SystemUtils` (line 639) - *Utilidades para trabajar con el sistema.*
- `ProcessMonitor` (line 751) - *Monitor de procesos para detección de actividad sospechosa.*
- `NetworkMonitor` (line 849) - *Monitor de red para detección de conexiones sospechosas.*
- `FileIntegrityMonitor` (line 993) - *Monitor de integridad de archivos.*
- `LogAnalyzer` (line 1111) - *Analizador avanzado de logs del sistema para equipos de seguridad azules.*
- `RealTimeLogMonitor` (line 2381) - *Monitor de logs en tiempo real que utiliza LogAnalyzer*
- `SystemHardener` (line 2431) - *Módulo para aplicar y auditar configuraciones de endurecimiento.*
- `IncidentResponder` (line 2910) - *Módulo para acciones de respuesta a incidentes.*
- `ReportGenerator` (line 3006) - *Genera informes basados en los hallazgos.*
- `MemoryScanner` (line 3076)
- `LazySentinelHandler` (line 3168)
- `LazySentinel` (line 3206)
- `LazyOwnApp` (line 3453) - *Interfaz de línea de comandos para LazyOwn BlueTeam Framework.*

**Functions:**
- `style` (line 75) - *Equivalente funcional de la antigua `cmd2.style(text, fg=..., bold=...)`.

Acepta los kwargs que el código de este archivo usa (`fg`, `bold`) y
devuelve el string ya coloreado. Si el runtime no tiene la nueva API
de estilos, devuelve el texto intacto.*
- `replace_command_placeholders` (line 205) - *Replace placeholders in a command string with values from a params dictionary,
handling spaces within placeholders.

The function looks for placeholders in curly braces (e.g., {url} or { url }) within
the command string and replaces them with corresponding values from the params dictionary,
ignoring any spaces inside the curly braces.

Args:
    command (str): The command string containing placeholders.
    params (dict): A dictionary containing key-value pairs for replacement.

Returns:
    str: The command string with placeholders replaced by their corresponding values.*
- `sanitize_content` (line 237) - *Sanitize text to ensure it's safe for Markdown rendering.*
- `replace_match` (line 223)
- `__init__` (line 252)
- `initialize_cache_table` (line 265) - *Initialize SQLite table for persistent cache.*
- `get_cache_key` (line 278) - *Generate a cache key from content using SHA-256.*
- `load_existing_vectorstore` (line 282) - *Load existing vectorstore if available.*
- `ollama_llm` (line 296) - *Query LLM with context using Ollama.*
- `process_file_to_rag` (line 311) - *Process a file, add it to the RAG knowledge base, and cache embeddings.*
- `query_rag` (line 370) - *Query the RAG system with caching.*
- `invalidate_cache` (line 410) - *Invalidate cache entries for a specific file.*
- `get_knowledge_base_stats` (line 429) - *Get statistics about the knowledge base and cache.*
- `__init__` (line 458)
- `initialize` (line 464) - *Inicializa la conexión a la base de datos y crea las tablas si no existen.*
- `execute` (line 550) - *Ejecuta una consulta SQL y devuelve los resultados.*
- `insert` (line 560) - *Inserta datos en la base de datos y devuelve el ID del último registro.*
- `close` (line 571) - *Cierra la conexión a la base de datos.*
- `execute` (line 578) - *Ejecuta una consulta SQL y devuelve los resultados.*
- `insert` (line 588) - *Inserta datos en la base de datos y devuelve el ID del último registro.*
- `close` (line 599) - *Cierra la conexión a la base de datos.*
- `__init__` (line 610)
- `to_dict` (line 616) - *Convierte la alerta a diccionario.*
- `save_to_db` (line 625) - *Guarda la alerta en la base de datos.*
- `run_command` (line 643) - *Ejecuta un comando del sistema y devuelve el código de salida, stdout y stderr.*
- `get_file_hash` (line 673) - *Calcula el hash SHA-256 de un archivo.*
- `get_system_info` (line 690) - *Obtiene información del sistema.*
- `backup_file` (line 721) - *Crea una copia de seguridad de un archivo.*
- `get_process_details` (line 742)
- `__init__` (line 754)
- `scan` (line 761) - *Escanea procesos en busca de actividad sospechosa.*
- `__init__` (line 852)
- `_load_baseline` (line 858) - *Carga la línea base de conexiones de red desde la base de datos.*
- `create_baseline` (line 874) - *Crea una línea base de las conexiones de red actuales (LISTEN y ESTABLISHED).*
- `scan` (line 920) - *Escanea las conexiones de red en busca de anomalías.*
- `__init__` (line 996)
- `initialize_baseline` (line 1001) - *Inicializa o actualiza la línea base de hashes de archivos.*
- `scan` (line 1044) - *Verifica la integridad de los archivos contra la línea base.*
- `__init__` (line 1114) - *Inicializa el analizador con configuración mejorada y validada*
- `_sanitize_config` (line 1167) - *Sanitiza y valida la configuración para prevenir inyecciones y valores maliciosos*
- `_is_safe_path` (line 1191) - *Valida que una ruta sea segura (previene directory traversal)*
- `_initialize_state` (line 1205) - *Inicializa el estado persistente del analizador*
- `_setup_threat_detection_patterns` (line 1235) - *Configura patrones avanzados para detección de amenazas con MITRE ATT&CK mappings*
- `_calculate_file_hash` (line 1403) - *Calcula el hash SHA-256 de un archivo de manera segura*
- `_check_file_integrity` (line 1416) - *Verifica la integridad del archivo de log basado en su hash*
- `_extract_timestamp_from_log` (line 1439) - *Extrae el timestamp de una línea de log usando varios formatos comunes*
- `_extract_ip_from_log` (line 1474) - *Extrae una dirección IP de una línea de log*
- `_extract_username_from_log` (line 1482) - *Extrae un nombre de usuario de una línea de log*
- `_extract_command_from_log` (line 1497) - *Extrae un comando ejecutado de una línea de log*
- `_is_alert_duplicated` (line 1511) - *Verifica si una alerta ya fue generada recientemente para evitar duplicados*
- `analyze_log_file` (line 1533) - *Analiza un único archivo de log con detección avanzada de amenazas.*
- `_enrich_finding_with_context` (line 1753) - *Enriquece un hallazgo con contexto adicional y correlación*
- `_process_specific_event_logic` (line 1790) - *Procesa lógica especializada según el tipo de evento detectado*
- `_get_usual_login_hours` (line 2005) - *Obtiene las horas usuales de login para un usuario basado en la línea base*
- `_get_common_commands_for_user` (line 2012) - *Obtiene los comandos más comunes para un usuario*
- `analyze_all_logs` (line 2021) - *Analiza todos los archivos de log configurados usando procesamiento paralelo.*
- `_correlate_findings` (line 2055) - *Correlaciona hallazgos entre múltiples logs para detectar patrones complejos*
- `get_performance_metrics` (line 2141) - *Devuelve métricas de rendimiento del analizador*
- `reset_trackers` (line 2155) - *Reinicia los contadores y rastreadores de eventos*
- `add_custom_pattern` (line 2163) - *Añade un patrón personalizado para detección*
- `_count_rule_based_alerts` (line 2184) - *Cuenta las alertas generadas por reglas (no por IA)*
- `export_findings_summary` (line 2192) - *Exporta un resumen de hallazgos para informes*
- `create_hunting_report` (line 2210) - *Genera un informe de hunting basado en los hallazgos*
- `analyze` (line 2225)
- `_load_ai_model` (line 2289) - *Carga el modelo de IA y el vectorizador si están disponibles.*
- `_analyze_command_with_ai` (line 2306) - *Usa el modelo de IA para evaluar si un comando es malicioso.
Retorna un dict con score y predicción.*
- `__init__` (line 2384) - *Inicializa el monitor con configuración*
- `start` (line 2391) - *Inicia el monitoreo en tiempo real*
- `stop` (line 2416) - *Detiene el monitoreo en tiempo real*
- `get_status` (line 2421) - *Devuelve el estado actual del monitor*
- `__init__` (line 2433)
- `check_system_security` (line 2438)
- `apply_hardening` (line 2637)
- `audit_ssh_config` (line 2791) - *Audita la configuración de SSHD.*
- `check_suid_sgid_files` (line 2874) - *Encuentra archivos con bits SUID/SGID.*
- `__init__` (line 2912)
- `quarantine_file` (line 2918) - *Mueve un archivo a la carpeta de cuarentena y le quita permisos.*
- `block_ip` (line 2945) - *Bloquea una IP usando iptables (requiere sudo). Esta es una acción peligrosa.*
- `kill_process` (line 2985) - *Termina un proceso por su PID.*
- `__init__` (line 3008)
- `generate_summary_report` (line 3014) - *Genera un informe de resumen en texto plano.*
- `__init__` (line 3077)
- `scan_process_memory` (line 3088)
- `scan_system` (line 3154)
- `__init__` (line 3169)
- `is_text_file` (line 3172) - *Check if a file is a text file by extension or content.*
- `on_created` (line 3183)
- `on_modified` (line 3195)
- `__init__` (line 3207)
- `chunk_text` (line 3228)
- `select_relevant_chunk` (line 3231)
- `parse_deepseek_response` (line 3245) - *Parse DeepSeek's plain text response into a JSON-like dictionary.*
- `show_popup` (line 3275) - *Queue a Rich-based popup to be displayed in the main thread.*
- `process_file` (line 3298)
- `stop` (line 3447)
- `__init__` (line 3467) - *Inicializa el CLI con configuración y componentes necesarios*
- `_load_config` (line 3560) - *Carga la configuración desde un archivo JSON o usa los defaults.*
- `_initialize_database` (line 3586) - *Inicializa la conexión a la base de datos*
- `list_files_in_directory` (line 3591) - *Lista todos los archivos en un directorio dado.*
- `_register_lua_command` (line 3598) - *Registra un comando nuevo desde Lua.*
- `load_plugins` (line 3624) - *Carga todos los plugins Lua desde el directorio 'plugins/'.*
- `load_yaml_plugins` (line 3654) - *Loads all YAML plugins from the 'lazyaddons/' directory.

This method scans the 'lazyaddons/' directory, reads each YAML file,
and registers enabled plugins as new commands.*
- `register_yaml_plugin` (line 3677) - *Registers a YAML plugin as a new command.

This method creates a dynamic command based on the plugin's configuration
and assigns it to the application.*
- `postloop` (line 3740) - *Acciones al salir de la aplicación.*
- `postcmd` (line 3748) - *Check the popup queue after each command and display with Rich Markdown.*
- `do_ai_status` (line 3807) - *Muestra el estado del modelo de IA*
- `do_ai_load` (line 3818) - *Intenta cargar manualmente el modelo de IA*
- `do_ai_test` (line 3830) - *Prueba un comando con el modelo de IA*
- `do_ai_feedback` (line 3857) - *Proporciona feedback sobre una detección de IA para mejorar el modelo*
- `do_ai_retrain` (line 3917) - *Reentrena el modelo de IA con nuevos datos de feedback*
- `do_sysinfo` (line 3964) - *Muestra información detallada del sistema.*
- `do_proc_scan` (line 3991) - *Escanea procesos actuales en busca de actividad sospechosa.*
- `do_proc_details` (line 4014) - *Muestra información detallada de un proceso específico por PID.*
- `do_net_baseline` (line 4043) - *Crea/actualiza la línea base de conexiones de red activas.*
- `do_net_scan` (line 4052) - *Escanea conexiones de red actuales en busca de anomalías respecto a la línea base y puertos sospechosos.*
- `do_net_conns` (line 4081) - *Muestra conexiones de red activas (TCP, UDP, LISTEN, ESTABLISHED, etc.).*
- `do_fim_baseline` (line 4147) - *Inicializa/actualiza la línea base de hashes para los archivos críticos o especificados.*
- `do_fim_scan` (line 4160) - *Verifica la integridad de los archivos críticos contra la línea base.*
- `do_log_analyze` (line 4184) - *Analiza los logs configurados o especificados en busca de patrones sospechosos.*
- `do_harden_audit_ssh` (line 4221) - *Audita la configuración del demonio SSH (sshd_config).*
- `do_resp_quarantine_file` (line 4241) - *Mueve un archivo a cuarentena y le quita permisos (acción irreversible sobre el original).*
- `do_resp_block_ip` (line 4257) - *Bloquea una IP usando iptables (¡ACCIÓN PELIGROSA, REQUIERE SUDO!).*
- `do_resp_kill_proc` (line 4290) - *Termina un proceso enviándole una señal (SIGTERM por defecto).*
- `do_report_summary` (line 4306) - *Genera un informe de resumen de seguridad.*
- `do_show_config` (line 4317) - *Muestra la configuración actual de LazyOwn.*
- `print_रात` (line 4325) - *Método wrapper para poutput, maneja diferentes tipos de datos.*
- `do_system_info` (line 4337) - *Display system information.*
- `do_scan_processes` (line 4342) - *Scan for suspicious processes.*
- `do_scan_network` (line 4354) - *Scan for suspicious network connections.*
- `do_create_network_baseline` (line 4366) - *Create network connections baseline.*
- `do_check_file_integrity` (line 4371) - *Check integrity of critical files.*
- `do_init_file_baseline` (line 4383) - *Initialize file integrity baseline.*
- `do_analyze_logs` (line 4388) - *Analyze system logs for suspicious activity.*
- `do_check_security` (line 4400) - *Check system security configuration.*
- `do_harden_system` (line 4412) - *Apply system hardening measures.*
- `do_scan_memory` (line 4424) - *Scan system memory for suspicious content.*
- `do_block_ip` (line 4438) - *Block an IP address using UFW: block_ip <ip_address>*
- `do_kill_process` (line 4458) - *Kill a process by PID: kill_process <pid>*
- `do_quit` (line 4479) - *Quit the application.*
- `do_debug` (line 4484) - *Display debug information about LazySentinel state.*
- `do_rag_query` (line 4492) - *Query the RAG knowledge base with a question.*
- `do_rag_add` (line 4502) - *Add a specific file to the RAG knowledge base.*
- `do_rag_status` (line 4520) - *Display RAG knowledge base status and statistics.*
- `do_rag_toggle` (line 4529) - *Toggle automatic addition of monitored files to RAG knowledge base.*
- `do_rag_bulk_add` (line 4535) - *Add all files in the monitored directory to RAG knowledge base.*
- `do_rag_search` (line 4558) - *Search for similar content in the RAG knowledge base.*
- `complete_rag_add` (line 4585) - *Tab completion for rag_add command.*
- `complete_rag_bulk_add` (line 4593) - *Tab completion for rag_bulk_add command.*
- `do_quarantine_file` (line 4601) - *Quarantine a suspicious file: quarantine_file <filepath>*
- `do_audit_users` (line 4627) - *Audit system users and their privileges*
- `do_processes` (line 4658) - *Escanear procesos sospechosos*
- `do_network` (line 4669) - *Escanear conexiones de red sospechosas*
- `do_files` (line 4681) - *Verificar integridad de archivos críticos*
- `do_logs` (line 4693) - *Analizar logs del sistema*
- `do_memory` (line 4701) - *Escanear memoria de procesos sospechosos*
- `do_hardening` (line 4710) - *Aplicar medidas de endurecimiento*
- `confirm_action` (line 4727) - *Pide confirmación al usuario para una acción.*
- `_load_config` (line 4740) - *Carga la configuración desde un archivo JSON*
- `do_analyze` (line 4786) - *Analiza archivos de log específicos o todos los configurados.

Uso: analyze [opciones] [archivo1 archivo2 ...]

Opciones:
  -a, --all      Analiza todos los archivos de log configurados
  -n, --no-alert No genera alertas durante el análisis
  -v, --verbose  Muestra información detallada del análisis

Ejemplos:
  analyze -a                        # Analiza todos los logs configurados
  analyze /var/log/auth.log         # Analiza solo auth.log
  analyze -n /var/log/syslog        # Analiza syslog sin generar alertas*
- `_display_findings_summary` (line 4869) - *Muestra un resumen de los hallazgos de un archivo*
- `_get_severity_color` (line 4905) - *Devuelve el código de color ANSI para una severidad dada*
- `do_monitor` (line 4916) - *Inicia o detiene el monitoreo en tiempo real de los logs.

Uso: monitor [opciones]

Opciones:
  start         Inicia el monitoreo (por defecto)
  stop          Detiene el monitoreo activo
  status        Muestra el estado actual del monitoreo
  -i INTERVAL   Intervalo de escaneo en segundos (default: configuración)

Ejemplos:
  monitor start          # Inicia el monitoreo
  monitor start -i 30    # Inicia el monitoreo con intervalo de 30 segundos
  monitor stop           # Detiene el monitoreo
  monitor status         # Muestra el estado del monitoreo*
- `_monitoring_loop` (line 4991) - *Bucle de monitoreo que se ejecuta en un hilo separado*
- `do_patterns` (line 5038) - *Gestiona los patrones de detección para el análisis de logs.

Uso: patterns [opciones] [acción]

Acciones:
  list          Lista todos los patrones disponibles (predeterminado)
  add           Añade un nuevo patrón personalizado
  remove        Elimina un patrón personalizado
  show <name>   Muestra detalles de un patrón específico

Opciones:
  -c, --category CATEGORY   Filtra por categoría (redteam, normal)
  -s, --severity SEVERITY   Filtra por severidad (critical, high, medium, low, info)

Ejemplos:
  patterns list                   # Lista todos los patrones
  patterns list -s critical       # Lista patrones de severidad crítica
  patterns show failed_login      # Muestra detalles del patrón failed_login
  patterns add                    # Inicia asistente para añadir un patrón
  patterns remove                 # Inicia asistente para eliminar un patrón*
- `do_analyze_logs` (line 5209) - *Analiza los archivos de log configurados*
- `do_start_monitor` (line 5229) - *Inicia el monitoreo en tiempo real de logs*
- `do_stop_monitor` (line 5240) - *Detiene el monitoreo en tiempo real*
- `do_monitor_status` (line 5248) - *Muestra el estado actual del monitor*
- `do_add_pattern` (line 5258) - *Añade un patrón personalizado de detección*
- `do_redteam_hunt` (line 5269) - *Realiza una búsqueda específica de actividad del equipo rojo*
- `_process_ai_detection` (line 2332) - *Procesa la detección de comandos maliciosos usando IA*
- `wrapper` (line 3601)
- `wrapper_yaml` (line 3691)

#### `__init__.py`
**Path:** `lazyownbt/__init__.py`

*No symbols extracted*

#### `actions.py`
**Path:** `lazyownbt/actions.py`

**Classs:**
- `ActionSpec` (line 13) - *Especificación declarativa de una acción ejecutable.*
- `ActionParseError` (line 24) - *Error de validación de parámetros.*
- `ActionRegistry` (line 28) - *Registro cerrado de acciones permitidas (SEC-002.2).*

**Functions:**
- `__init__` (line 31)
- `register` (line 35)
- `is_allowed` (line 41)
- `spec` (line 44)
- `handler` (line 47)
- `names` (line 50)
- `validate_params` (line 53) - *Valida y coerciona parámetros (SEC-002.3).*

#### `audit.py`
**Path:** `lazyownbt/audit.py`

**Classs:**
- `AuditRecord` (line 23)
- `AuditLog` (line 33) - *Log de auditoría respaldado por SQLite.*

**Functions:**
- `__init__` (line 38)
- `_conn` (line 43)
- `_init_db` (line 53)
- `record` (line 77)
- `track` (line 113) - *Context manager que mide tiempo y registra resultado/errores.*
- `fetch` (line 133)

#### `config.py`
**Path:** `lazyownbt/config.py`

**Classs:**
- `ConfigError` (line 28) - *Error de configuración. Falla ruidosamente con mensaje accionable.*
- `Settings` (line 104) - *Configuración inmutable de la aplicación.*

**Functions:**
- `_load_dotenv` (line 32) - *Carga .env si existe. No falla si no existe (CFG-001.2).*
- `_resolve_jwt_secret` (line 39) - *Resuelve el secreto de JWT según SEC-001.2 y SEC-001.3.*
- `_resolve_admin_password_hash` (line 73) - *Resuelve el hash de la contraseña admin según SEC-001.4.

Si ADMIN_PASSWORD está definida, se hashea con bcrypt y se retorna.
Si ADMIN_PASSWORD_HASH está definida (ya hasheada), se retorna tal cual.
Si ninguna está definida y estamos en development, se usa 'admin' como
contraseña de desarrollo con un warning.*
- `load_settings` (line 125) - *Carga y valida la configuración. Falla ruidosamente (CFG-001.3).*
- `is_production` (line 117)
- `is_development` (line 121)

#### `handlers.py`
**Path:** `lazyownbt/handlers.py`

**Functions:**
- `_validate_ip` (line 22)
- `handle_resp_block_ip` (line 32) - *Stub seguro. En un despliegue real invocaría iptables con argv.*
- `handle_resp_kill_proc` (line 52) - *Stub seguro. En un despliegue real enviaría la señal al PID.*
- `handle_net_scan` (line 64)
- `handle_fim_scan` (line 68)
- `handle_lazynmap` (line 72)
- `handle_ai_playbook` (line 78)
- `build_default_handlers` (line 84)

#### `security.py`
**Path:** `lazyownbt/security.py`

**Classs:**
- `SecretsFilter` (line 13) - *Filtro de logging que redacta valores de secretos.

Cubre el contrato SEC-001.6.*

**Functions:**
- `install_secrets_filter` (line 51) - *Instala el SecretsFilter en un logger.*
- `verify_password` (line 59) - *Compara una contraseña contra un hash bcrypt (SEC-001.4).*
- `__init__` (line 21)
- `_redact` (line 25)
- `filter` (line 35)

#### `web.py`
**Path:** `lazyownbt/web.py`

**Functions:**
- `_build_csp` (line 38) - *CSP estricta sin hashes hardcodeados (SEC-003.4).*
- `_register_default_actions` (line 55) - *Carga las acciones por defecto. Cada handler es un stub testable.*
- `create_app` (line 66) - *Crea y configura la app Flask.*
- `_register_routes` (line 114)
- `_handle_command` (line 185) - *Ejecuta una acción validada por la lista cerrada (SEC-002.*).*
- `_default_flask_env_if_unset` (line 220) - *UX: si FLASK_ENV no está definida, asume development con warning.

En producción el operador DEBE exportar FLASK_ENV=production. Esto NO
debilita el contrato: ``load_settings`` sigue exigiendo JWT_SECRET_KEY
cuando FLASK_ENV=production (probado en test_security.py).*
- `run` (line 236) - *Punto de entrada CLI: respeta SEC-003.1 y SEC-003.2.*
- `healthz` (line 117)
- `dashboard` (line 121)
- `api_dashboard` (line 126) - *Resumen para el dashboard.

Mantener la lógica de DB en una capa aparte cuando se integre el
módulo de almacenamiento; por ahora retornamos un payload mínimo
que la plantilla pueda renderizar.*
- `commands` (line 145)
- `login` (line 152)
- `api_audit` (line 170)
- `not_found` (line 176)
- `server_error` (line 180)

#### `main.py`
**Path:** `main.py`

**Classs:**
- `Database` (line 42) - *Acceso de solo-lectura a la base de datos SQLite del framework.

Cualquier tabla ausente se trata como "sin datos" en lugar de romper
el dashboard. Esto preserva el comportamiento de la versión anterior
cuando se despliega contra una BD aún no inicializada por ``app.py``.*

**Functions:**
- `_register_data_routes` (line 200) - *Añade las rutas de solo-lectura sobre la BD.

Las rutas sensibles (``/login``, ``/commands``, ``/api/audit``,
``/healthz``) ya las registra :func:`lazyownbt.web.create_app`.*
- `_populate_dashboard_metrics` (line 231) - *Compone el payload que la plantilla ``dashboard.html`` espera.*
- `build_app` (line 260) - *Construye la app final reutilizando :func:`create_app`.*
- `__init__` (line 57)
- `connect` (line 60)
- `_safe_fetch` (line 69) - *Ejecuta un SELECT genérico y tolera tablas inexistentes.

``table`` debe estar en :data:`_ALLOWED_TABLES` (whitelist interna,
defensa en profundidad contra inyección). ``columns`` y ``order``
son validables por el caller; ``where`` solo puede contener
fragmentos pre-fabricados (``"WHERE severity = ?"`` etc.).*
- `fetch_alerts` (line 106)
- `fetch_events` (line 127)
- `fetch_network_baseline` (line 141)
- `fetch_file_hashes` (line 148)
- `correlate_events` (line 155) - *Busca alertas ±5 min relacionadas con un evento.*
- `alerts_view` (line 208)
- `events_view` (line 218)
- `api_correlate` (line 227)
- `_dashboard` (line 272)

#### `lazyownbt_mcp.py`
**Path:** `skills/lazyownbt_mcp.py`

**Functions:**
- `_load_config` (line 49) - *Load config.json, return empty dict on failure.*
- `_save_config` (line 58)
- `_db_query` (line 67) - *Execute a read query against lazyown.db.*
- `_run_lazyownbt_command` (line 82) - *Execute one or more LazyOwnBT CLI commands non-interactively via a PTY.
Sends commands to the app.py interactive shell, drains output, and returns it.*
- `list_tools` (line 168)
- `call_tool` (line 864)
- `_handle_sighup` (line 1423)
- `main` (line 1431)
- `text` (line 866)
- `_query_alerts` (line 1223)
- `_query_events` (line 1257)
- `_stats` (line 1351)
- `_list_reports` (line 1380)

#### `conftest.py`
**Path:** `tests/conftest.py`

**Functions:**
- `_make_jwt_secret` (line 35)
- `jwt_secret` (line 40)
- `dev_env` (line 45)
- `prod_env` (line 52)
- `app` (line 60)
- `client` (line 69)
- `auth_client` (line 74)
- `_iter_source_files` (line 92)
- `_read_text` (line 100)
- `clean_env` (line 112)
- `flask_env` (line 121)
- `flask_env_quoted` (line 127)
- `jwt_no_secret` (line 133)
- `jwt_secret_value` (line 138)
- `jwt_secret_with_length` (line 143)
- `admin_password_with_length` (line 148)
- `admin_hash` (line 153)
- `bdd_app` (line 158)
- `bdd_client` (line 169)
- `bdd_anon` (line 178)
- `fake_failing_handler` (line 183)
- `no_bind` (line 196)
- `bind_value` (line 201)
- `logger_with_filter` (line 206)
- `code_tree` (line 215)
- `extract_imports` (line 220)
- `scan_repo` (line 247)
- `scan_repo_subprocess` (line 252)
- `scan_repo_eval` (line 257)
- `scan_repo_sha` (line 262)
- `assert_no_subprocess_python` (line 271)
- `try_create_app` (line 280)
- `load_config` (line 290)
- `login_ok` (line 298)
- `login_bad` (line 312)
- `invoke_action` (line 323)
- `invoke_action_anon` (line 333)
- `query_audit` (line 342)
- `load_default` (line 347)
- `load_cfg` (line 353)
- `assert_dev_warning` (line 363)
- `cli_with_debug` (line 373)
- `create_the_app` (line 384)
- `get_csp` (line 390)
- `log_msg` (line 396)
- `no_your_secret_key` (line 407)
- `no_admin_password` (line 412)
- `assert_config_error_code` (line 418)
- `assert_ephemeral_secret_loaded` (line 424)
- `assert_dev_warning` (line 429)
- `assert_debug_value` (line 439)
- `assert_cli_abort` (line 444)
- `assert_host` (line 450)
- `assert_bind_warning` (line 455)
- `assert_talisman_https` (line 460)
- `assert_talisman_no_https` (line 465)
- `assert_login_ok` (line 471)
- `assert_status` (line 478)
- `assert_body_contains_quoted` (line 483)
- `assert_body_contains` (line 489)
- `assert_body_mentions_param` (line 495)
- `assert_body_mentions_quoted` (line 501)
- `assert_body_mentions` (line 507)
- `assert_output` (line 513)
- `assert_audit_record` (line 520)
- `assert_audit_list` (line 527)
- `assert_jwt_value` (line 533)
- `assert_config_error` (line 538)
- `assert_gitignore_env` (line 543)
- `assert_env_example` (line 549)
- `assert_redacted_in_message` (line 554)
- `assert_no_sha256` (line 559)
- `assert_not_contains_quoted` (line 565)
- `assert_not_contains` (line 570)
- `assert_imports_covered` (line 575)
- `assert_no_unused_deps` (line 603)
- `failing` (line 187)

#### `test_command_execution.py`
**Path:** `tests/test_command_execution.py`

**Functions:**
- `_read` (line 16)
- `test_subprocess_dynamic_python_is_gone` (line 23) - *SEC-002.1: no debe haber subprocess con 'python3', '-c' o f-string hacia -c.*
- `test_no_eval_on_user_input` (line 39) - *SEC-002.1: no debe haber eval/exec sobre input del usuario.*
- `test_command_not_in_allowlist_is_rejected` (line 55)
- `test_command_not_in_allowlist_returns_403` (line 65)
- `test_command_validates_params` (line 77)
- `test_command_missing_required_param` (line 87)
- `test_command_rejects_unknown_params` (line 97)
- `test_command_requires_jwt` (line 109)
- `test_command_audit_recorded` (line 120)
- `test_command_audit_records_error` (line 133)
- `test_audit_endpoint_returns_records` (line 146)
- `test_command_executes_via_python_call` (line 161) - *Verifica que el handler se llama como función Python, no como shell.*
- `fake_handler` (line 165)

#### `test_command_execution_bdd.py`
**Path:** `tests/test_command_execution_bdd.py`

*No symbols extracted*

#### `test_configuration.py`
**Path:** `tests/test_configuration.py`

**Functions:**
- `test_config_loads_from_env` (line 18)
- `test_config_fails_loudly_on_missing_var` (line 27)
- `_extract_top_level_imports` (line 36) - *Extrae los nombres de paquetes top-level importados en cada archivo.*
- `_declared_deps` (line 58)
- `_canonical` (line 85) - *Devuelve los nombres canónicos posibles para un paquete.*
- `test_requirements_contains_all_imports` (line 94) - *CFG-002.1/CFG-002.2: cada import del código debe estar declarado.*
- `test_pyproject_extras_declared` (line 118) - *Los grupos cli, web, ai, rag, fim, utils, dev deben existir.*

#### `test_configuration_bdd.py`
**Path:** `tests/test_configuration_bdd.py`

*No symbols extracted*

#### `test_production.py`
**Path:** `tests/test_production.py`

**Functions:**
- `test_debug_flag_default_false` (line 13)
- `test_debug_only_with_explicit_flag` (line 23) - *Si debug=True y FLASK_ENV=production, app.config['DEBUG'] debe ser False.*
- `test_bind_default_loopback` (line 34)
- `test_bind_warns_when_public` (line 45)
- `test_talisman_https_in_production` (line 58)
- `test_talisman_no_https_in_development` (line 72)
- `test_csp_has_no_hardcoded_inline_hash` (line 82) - *SEC-003.4: no debe haber 'sha256-' en el código.*
- `test_cli_rejects_debug_in_production` (line 89) - *SEC-003.1: la CLI debe abortar si --debug y FLASK_ENV=production.*

#### `test_production_bdd.py`
**Path:** `tests/test_production_bdd.py`

*No symbols extracted*

#### `test_secrets_bdd.py`
**Path:** `tests/test_secrets_bdd.py`

*No symbols extracted*

#### `test_security.py`
**Path:** `tests/test_security.py`

**Functions:**
- `_iter_source_files` (line 20)
- `test_no_hardcoded_jwt_secret` (line 27) - *SEC-001.1: la cadena literal 'your-secret-key' no debe existir en el código.*
- `test_no_hardcoded_admin_password` (line 40) - *SEC-001.1: la comparación admin/password hardcodeada no debe existir.*
- `test_app_aborts_when_jwt_secret_missing_in_prod` (line 56)
- `test_app_generates_ephemeral_secret_in_dev` (line 66)
- `test_jwt_secret_below_minimum_length_aborts` (line 79)
- `test_empty_jwt_secret_triggers_absence_rule` (line 88) - *Una variable presente pero vacía se trata como ausente (SEC-001.2).*
- `test_password_is_hashed_not_plain` (line 100)
- `test_env_file_is_gitignored` (line 115)
- `test_env_example_exists` (line 125)
- `test_secrets_filter_redacts_values` (line 131)
- `test_secrets_filter_redacts_in_args` (line 140)
- `test_secrets_filter_redacts_in_dict_args` (line 147)

### SH (1 files)

#### `install.sh`
**Path:** `install.sh`

*No symbols extracted*
