# Symbols

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `Alert` | class | `app.py:605` | `class Alert` |
| `Cyan` | class | `app.py:231` | `class Cyan(FgColor)` |
| `Database` | class | `app.py:455` | `class Database` |
| `Fg` | class | `app.py:48` | `class Fg` |
| `FgColor` | class | `app.py:228` | `class FgColor` |
| `FileIntegrityMonitor` | class | `app.py:993` | `class FileIntegrityMonitor` |
| `IncidentResponder` | class | `app.py:2910` | `class IncidentResponder` |
| `LazyOwnApp` | class | `app.py:3453` | `class LazyOwnApp(Cmd)` |
| `LazySentinel` | class | `app.py:3206` | `class LazySentinel` |
| `LazySentinelHandler` | class | `app.py:3168` | `class LazySentinelHandler(FileSystemEventHandler)` |
| `LogAnalyzer` | class | `app.py:1111` | `class LogAnalyzer` |
| `MemoryScanner` | class | `app.py:3076` | `class MemoryScanner` |
| `NetworkMonitor` | class | `app.py:849` | `class NetworkMonitor` |
| `ProcessMonitor` | class | `app.py:751` | `class ProcessMonitor` |
| `RAGManager` | class | `app.py:249` | `class RAGManager` |
| `RealTimeLogMonitor` | class | `app.py:2381` | `class RealTimeLogMonitor` |
| `Red` | class | `app.py:234` | `class Red(FgColor)` |
| `ReportGenerator` | class | `app.py:3006` | `class ReportGenerator` |
| `SystemHardener` | class | `app.py:2431` | `class SystemHardener` |
| `SystemUtils` | class | `app.py:639` | `class SystemUtils` |
| `__init__` | method | `app.py:252` | `def __init__(self, model_name, cache_size)` |
| `__init__` | method | `app.py:458` | `def __init__(self, db_path)` |
| `__init__` | method | `app.py:610` | `def __init__(self, alert_type, details, severity)` |
| `__init__` | method | `app.py:754` | `def __init__(self, config, db)` |
| `__init__` | method | `app.py:852` | `def __init__(self, config, db)` |
| `__init__` | method | `app.py:996` | `def __init__(self, config, db)` |
| `__init__` | method | `app.py:1114` | `def __init__(self, config, db)` |
| `__init__` | method | `app.py:2384` | `def __init__(self, config, db)` |
| `__init__` | method | `app.py:2433` | `def __init__(self, config, db)` |
| `__init__` | method | `app.py:2912` | `def __init__(self, config, db)` |
| `__init__` | method | `app.py:3008` | `def __init__(self, config, db)` |
| `__init__` | method | `app.py:3077` | `def __init__(self, config, db)` |
| `__init__` | method | `app.py:3169` | `def __init__(self, lazysentinel)` |
| `__init__` | method | `app.py:3207` | `def __init__(self, app, popup_queue, watch_dir, excluded_files, min_file_size)` |
| `__init__` | method | `app.py:3467` | `def __init__(self, config_file)` |
| `_analyze_command_with_ai` | method | `app.py:2306` | `def _analyze_command_with_ai(self, command, args)` |
| `_calculate_file_hash` | method | `app.py:1403` | `def _calculate_file_hash(self, filename)` |
| `_check_file_integrity` | method | `app.py:1416` | `def _check_file_integrity(self, log_path)` |
| `_correlate_findings` | method | `app.py:2055` | `def _correlate_findings(self, all_findings)` |
| `_count_rule_based_alerts` | method | `app.py:2184` | `def _count_rule_based_alerts(self)` |
| `_display_findings_summary` | method | `app.py:4869` | `def _display_findings_summary(self, file_path, findings, verbose)` |
| `_enrich_finding_with_context` | method | `app.py:1753` | `def _enrich_finding_with_context(self, event_details)` |
| `_extract_command_from_log` | method | `app.py:1497` | `def _extract_command_from_log(self, line)` |
| `_extract_ip_from_log` | method | `app.py:1474` | `def _extract_ip_from_log(self, line)` |
| `_extract_timestamp_from_log` | method | `app.py:1439` | `def _extract_timestamp_from_log(self, line)` |
| `_extract_username_from_log` | method | `app.py:1482` | `def _extract_username_from_log(self, line)` |
| `_get_common_commands_for_user` | method | `app.py:2012` | `def _get_common_commands_for_user(self, username)` |
| `_get_severity_color` | method | `app.py:4905` | `def _get_severity_color(self, severity)` |
| `_get_usual_login_hours` | method | `app.py:2005` | `def _get_usual_login_hours(self, username)` |
| `_initialize_database` | method | `app.py:3586` | `def _initialize_database(self)` |
| `_initialize_state` | method | `app.py:1205` | `def _initialize_state(self)` |
| `_is_alert_duplicated` | method | `app.py:1511` | `def _is_alert_duplicated(self, alert_type, details_hash)` |
| `_is_safe_path` | method | `app.py:1191` | `def _is_safe_path(self, path)` |
| `_load_ai_model` | method | `app.py:2289` | `def _load_ai_model(self)` |
| `_load_baseline` | method | `app.py:858` | `def _load_baseline(self)` |
| `_load_config` | method | `app.py:3560` | `def _load_config(self, config_file)` |
| `_load_config` | method | `app.py:4740` | `def _load_config(self, config_file)` |
| `_monitoring_loop` | method | `app.py:4991` | `def _monitoring_loop(self, interval)` |
| `_process_ai_detection` | function | `app.py:2332` | `def _process_ai_detection(self, event_details, line_content, log_path, line_num)` |
| `_process_specific_event_logic` | method | `app.py:1790` | `def _process_specific_event_logic(self, pattern_name, pattern_config, event_details, line_content)` |
| `_register_lua_command` | method | `app.py:3598` | `def _register_lua_command(self, command_name, lua_function)` |
| `_sanitize_config` | method | `app.py:1167` | `def _sanitize_config(self, config)` |
| `_setup_threat_detection_patterns` | method | `app.py:1235` | `def _setup_threat_detection_patterns(self)` |
| `add_custom_pattern` | method | `app.py:2163` | `def add_custom_pattern(self, name, pattern, severity, mitre_tactics, mitre_techniques)` |
| `analyze` | method | `app.py:2225` | `def analyze(self)` |
| `analyze_all_logs` | method | `app.py:2021` | `def analyze_all_logs(self, generate_alerts)` |
| `analyze_log_file` | method | `app.py:1533` | `def analyze_log_file(self, log_path, generate_alerts)` |
| `apply_hardening` | method | `app.py:2637` | `def apply_hardening(self, backup)` |
| `audit_ssh_config` | method | `app.py:2791` | `def audit_ssh_config(self, generate_alerts)` |
| `backup_file` | method | `app.py:721` | `def backup_file(filepath, backup_dir)` |
| `block_ip` | method | `app.py:2945` | `def block_ip(self, ip_address, interface)` |
| `check_suid_sgid_files` | method | `app.py:2874` | `def check_suid_sgid_files(self)` |
| `check_system_security` | method | `app.py:2438` | `def check_system_security(self)` |
| `chunk_text` | method | `app.py:3228` | `def chunk_text(self, text, chunk_size)` |
| `close` | method | `app.py:571` | `def close(self)` |
| `close` | method | `app.py:599` | `def close(self)` |
| `complete_rag_add` | method | `app.py:4585` | `def complete_rag_add(self, text, line, begidx, endidx)` |
| `complete_rag_bulk_add` | method | `app.py:4593` | `def complete_rag_bulk_add(self, text, line, begidx, endidx)` |
| `confirm_action` | method | `app.py:4727` | `def confirm_action(self, prompt_message, confirm_keyword)` |
| `create_baseline` | method | `app.py:874` | `def create_baseline(self)` |
| `create_hunting_report` | method | `app.py:2210` | `def create_hunting_report(self)` |
| `do_add_pattern` | method | `app.py:5258` | `def do_add_pattern(self, args)` |
| `do_ai_feedback` | method | `app.py:3857` | `def do_ai_feedback(self, args)` |
| `do_ai_load` | method | `app.py:3818` | `def do_ai_load(self, args)` |
| `do_ai_retrain` | method | `app.py:3917` | `def do_ai_retrain(self, args)` |
| `do_ai_status` | method | `app.py:3807` | `def do_ai_status(self, args)` |
| `do_ai_test` | method | `app.py:3830` | `def do_ai_test(self, args)` |
| `do_analyze` | method | `app.py:4786` | `def do_analyze(self, args)` |
| `do_analyze_logs` | method | `app.py:4388` | `def do_analyze_logs(self, arg)` |
| `do_analyze_logs` | method | `app.py:5209` | `def do_analyze_logs(self, args)` |
| `do_audit_users` | method | `app.py:4627` | `def do_audit_users(self, arg)` |
| `do_block_ip` | method | `app.py:4438` | `def do_block_ip(self, arg)` |
| `do_check_file_integrity` | method | `app.py:4371` | `def do_check_file_integrity(self, arg)` |
| `do_check_security` | method | `app.py:4400` | `def do_check_security(self, arg)` |
| `do_create_network_baseline` | method | `app.py:4366` | `def do_create_network_baseline(self, arg)` |
| `do_debug` | method | `app.py:4484` | `def do_debug(self, arg)` |
| `do_files` | method | `app.py:4681` | `def do_files(self, arg)` |
| `do_fim_baseline` | method | `app.py:4147` | `def do_fim_baseline(self, args)` |
| `do_fim_scan` | method | `app.py:4160` | `def do_fim_scan(self, _)` |
| `do_harden_audit_ssh` | method | `app.py:4221` | `def do_harden_audit_ssh(self, _)` |
| `do_harden_system` | method | `app.py:4412` | `def do_harden_system(self, arg)` |
| `do_hardening` | method | `app.py:4710` | `def do_hardening(self, arg)` |
| `do_init_file_baseline` | method | `app.py:4383` | `def do_init_file_baseline(self, arg)` |
| `do_kill_process` | method | `app.py:4458` | `def do_kill_process(self, arg)` |
| `do_log_analyze` | method | `app.py:4184` | `def do_log_analyze(self, args)` |
| `do_logs` | method | `app.py:4693` | `def do_logs(self, arg)` |
| `do_memory` | method | `app.py:4701` | `def do_memory(self, arg)` |
| `do_monitor` | method | `app.py:4916` | `def do_monitor(self, args)` |
| `do_monitor_status` | method | `app.py:5248` | `def do_monitor_status(self, args)` |
| `do_net_baseline` | method | `app.py:4043` | `def do_net_baseline(self, _)` |
| `do_net_conns` | method | `app.py:4081` | `def do_net_conns(self, args)` |
| `do_net_scan` | method | `app.py:4052` | `def do_net_scan(self, _)` |
| `do_network` | method | `app.py:4669` | `def do_network(self, arg)` |
| `do_patterns` | method | `app.py:5038` | `def do_patterns(self, args)` |
| `do_proc_details` | method | `app.py:4014` | `def do_proc_details(self, args)` |
| `do_proc_scan` | method | `app.py:3991` | `def do_proc_scan(self, _)` |
| `do_processes` | method | `app.py:4658` | `def do_processes(self, arg)` |
| `do_quarantine_file` | method | `app.py:4601` | `def do_quarantine_file(self, arg)` |
| `do_quit` | method | `app.py:4479` | `def do_quit(self, arg)` |
| `do_rag_add` | method | `app.py:4502` | `def do_rag_add(self, arg)` |
| `do_rag_bulk_add` | method | `app.py:4535` | `def do_rag_bulk_add(self, arg)` |
| `do_rag_query` | method | `app.py:4492` | `def do_rag_query(self, arg)` |
| `do_rag_search` | method | `app.py:4558` | `def do_rag_search(self, arg)` |
| `do_rag_status` | method | `app.py:4520` | `def do_rag_status(self, arg)` |
| `do_rag_toggle` | method | `app.py:4529` | `def do_rag_toggle(self, arg)` |
| `do_redteam_hunt` | method | `app.py:5269` | `def do_redteam_hunt(self, args)` |
| `do_report_summary` | method | `app.py:4306` | `def do_report_summary(self, args)` |
| `do_resp_block_ip` | method | `app.py:4257` | `def do_resp_block_ip(self, args)` |
| `do_resp_kill_proc` | method | `app.py:4290` | `def do_resp_kill_proc(self, args)` |
| `do_resp_quarantine_file` | method | `app.py:4241` | `def do_resp_quarantine_file(self, args)` |
| `do_scan_memory` | method | `app.py:4424` | `def do_scan_memory(self, arg)` |
| `do_scan_network` | method | `app.py:4354` | `def do_scan_network(self, arg)` |
| `do_scan_processes` | method | `app.py:4342` | `def do_scan_processes(self, arg)` |
| `do_show_config` | method | `app.py:4317` | `def do_show_config(self, _)` |
| `do_start_monitor` | method | `app.py:5229` | `def do_start_monitor(self, args)` |
| `do_stop_monitor` | method | `app.py:5240` | `def do_stop_monitor(self, args)` |
| `do_sysinfo` | method | `app.py:3964` | `def do_sysinfo(self, _)` |
| `do_system_info` | method | `app.py:4337` | `def do_system_info(self, arg)` |
| `execute` | method | `app.py:550` | `def execute(self, query, params)` |
| `execute` | method | `app.py:578` | `def execute(self, query, params)` |
| `export_findings_summary` | method | `app.py:2192` | `def export_findings_summary(self)` |
| `generate_summary_report` | method | `app.py:3014` | `def generate_summary_report(self, filename)` |
| `get_cache_key` | method | `app.py:278` | `def get_cache_key(self, content)` |
| `get_file_hash` | method | `app.py:673` | `def get_file_hash(filepath)` |
| `get_knowledge_base_stats` | method | `app.py:429` | `def get_knowledge_base_stats(self)` |
| `get_performance_metrics` | method | `app.py:2141` | `def get_performance_metrics(self)` |
| `get_process_details` | method | `app.py:742` | `def get_process_details(pid)` |
| `get_status` | method | `app.py:2421` | `def get_status(self)` |
| `get_system_info` | method | `app.py:690` | `def get_system_info()` |
| `initialize` | method | `app.py:464` | `def initialize(self)` |
| `initialize_baseline` | method | `app.py:1001` | `def initialize_baseline(self, files_to_baseline)` |
| `initialize_cache_table` | method | `app.py:265` | `def initialize_cache_table(self)` |
| `insert` | method | `app.py:560` | `def insert(self, query, params)` |
| `insert` | method | `app.py:588` | `def insert(self, query, params)` |
| `invalidate_cache` | method | `app.py:410` | `def invalidate_cache(self, file_path)` |
| `is_text_file` | method | `app.py:3172` | `def is_text_file(self, file_path)` |
| `kill_process` | method | `app.py:2985` | `def kill_process(self, pid, signal_to_send)` |
| `list_files_in_directory` | method | `app.py:3591` | `def list_files_in_directory(self, directory)` |
| `load_existing_vectorstore` | method | `app.py:282` | `def load_existing_vectorstore(self)` |
| `load_plugins` | method | `app.py:3624` | `def load_plugins(self)` |
| `load_yaml_plugins` | method | `app.py:3654` | `def load_yaml_plugins(self)` |
| `ollama_llm` | method | `app.py:296` | `def ollama_llm(self, question, context)` |
| `on_created` | method | `app.py:3183` | `def on_created(self, event)` |
| `on_modified` | method | `app.py:3195` | `def on_modified(self, event)` |
| `parse_deepseek_response` | method | `app.py:3245` | `def parse_deepseek_response(self, response_text)` |
| `postcmd` | method | `app.py:3748` | `def postcmd(self, stop, line)` |
| `postloop` | method | `app.py:3740` | `def postloop(self)` |
| `print_रात` | method | `app.py:4325` | `def print_रात(self, data_to_print)` |
| `process_file` | method | `app.py:3298` | `def process_file(self, file_path)` |
| `process_file_to_rag` | method | `app.py:311` | `def process_file_to_rag(self, file_path)` |
| `quarantine_file` | method | `app.py:2918` | `def quarantine_file(self, filepath)` |
| `query_rag` | method | `app.py:370` | `def query_rag(self, question)` |
| `register_yaml_plugin` | method | `app.py:3677` | `def register_yaml_plugin(self, plugin_data)` |
| `replace_command_placeholders` | function | `app.py:205` | `def replace_command_placeholders(command, params)` |
| `replace_match` | function | `app.py:223` | `def replace_match(match)` |
| `reset_trackers` | method | `app.py:2155` | `def reset_trackers(self)` |
| `run_command` | method | `app.py:643` | `def run_command(command, shell)` |
| `sanitize_content` | function | `app.py:237` | `def sanitize_content(text)` |
| `save_to_db` | method | `app.py:625` | `def save_to_db(self, db)` |
| `scan` | method | `app.py:761` | `def scan(self, generate_alerts)` |
| `scan` | method | `app.py:920` | `def scan(self, generate_alerts)` |
| `scan` | method | `app.py:1044` | `def scan(self, generate_alerts)` |
| `scan_process_memory` | method | `app.py:3088` | `def scan_process_memory(self, pid)` |
| `scan_system` | method | `app.py:3154` | `def scan_system(self, max_processes)` |
| `select_relevant_chunk` | method | `app.py:3231` | `def select_relevant_chunk(self, file_content, chunks)` |
| `show_popup` | method | `app.py:3275` | `def show_popup(self, file_name, relevant_info, commands, details)` |
| `start` | method | `app.py:2391` | `def start(self)` |
| `stop` | method | `app.py:2416` | `def stop(self)` |
| `stop` | method | `app.py:3447` | `def stop(self)` |
| `style` | function | `app.py:75` | `def style(text, fg, bold)` |
| `to_dict` | method | `app.py:616` | `def to_dict(self)` |
| `wrapper` | function | `app.py:3601` | `def wrapper(arg)` |
| `wrapper_yaml` | function | `app.py:3691` | `def wrapper_yaml(arg)` |
| `ActionParseError` | class | `lazyownbt/actions.py:24` | `class ActionParseError(ValueError)` |
| `ActionRegistry` | class | `lazyownbt/actions.py:28` | `class ActionRegistry` |
| `ActionSpec` | class | `lazyownbt/actions.py:13` | `class ActionSpec` |
| `__init__` | method | `lazyownbt/actions.py:31` | `def __init__(self)` |
| `handler` | method | `lazyownbt/actions.py:47` | `def handler(self, name)` |
| `is_allowed` | method | `lazyownbt/actions.py:41` | `def is_allowed(self, name)` |
| `names` | method | `lazyownbt/actions.py:50` | `def names(self)` |
| `register` | method | `lazyownbt/actions.py:35` | `def register(self, spec, handler)` |
| `spec` | method | `lazyownbt/actions.py:44` | `def spec(self, name)` |
| `validate_params` | method | `lazyownbt/actions.py:53` | `def validate_params(self, name, params)` |
| `AuditLog` | class | `lazyownbt/audit.py:33` | `class AuditLog` |
| `AuditRecord` | class | `lazyownbt/audit.py:23` | `class AuditRecord` |
| `__init__` | method | `lazyownbt/audit.py:38` | `def __init__(self, db_path)` |
| `_conn` | method | `lazyownbt/audit.py:43` | `def _conn(self)` |
| `_init_db` | method | `lazyownbt/audit.py:53` | `def _init_db(self)` |
| `fetch` | method | `lazyownbt/audit.py:133` | `def fetch(self, limit)` |
| `record` | method | `lazyownbt/audit.py:77` | `def record(self, action, user, params, result, duration_ms, error)` |
| `track` | method | `lazyownbt/audit.py:113` | `def track(self, action, user, params)` |
| `ConfigError` | class | `lazyownbt/config.py:28` | `class ConfigError(RuntimeError)` |
| `Settings` | class | `lazyownbt/config.py:104` | `class Settings` |
| `_load_dotenv` | function | `lazyownbt/config.py:32` | `def _load_dotenv()` |
| `_resolve_admin_password_hash` | function | `lazyownbt/config.py:73` | `def _resolve_admin_password_hash()` |
| `_resolve_jwt_secret` | function | `lazyownbt/config.py:39` | `def _resolve_jwt_secret()` |
| `is_development` | method | `lazyownbt/config.py:121` | `def is_development(self)` |
| `is_production` | method | `lazyownbt/config.py:117` | `def is_production(self)` |
| `load_settings` | function | `lazyownbt/config.py:125` | `def load_settings()` |
| `_validate_ip` | function | `lazyownbt/handlers.py:22` | `def _validate_ip(ip)` |
| `build_default_handlers` | function | `lazyownbt/handlers.py:84` | `def build_default_handlers()` |
| `handle_ai_playbook` | function | `lazyownbt/handlers.py:78` | `def handle_ai_playbook(scenario)` |
| `handle_fim_scan` | function | `lazyownbt/handlers.py:68` | `def handle_fim_scan()` |
| `handle_lazynmap` | function | `lazyownbt/handlers.py:72` | `def handle_lazynmap(target)` |
| `handle_net_scan` | function | `lazyownbt/handlers.py:64` | `def handle_net_scan()` |
| `handle_resp_block_ip` | function | `lazyownbt/handlers.py:32` | `def handle_resp_block_ip(ip_address, interface)` |
| `handle_resp_kill_proc` | function | `lazyownbt/handlers.py:52` | `def handle_resp_kill_proc(pid, signal)` |
| `SecretsFilter` | class | `lazyownbt/security.py:13` | `class SecretsFilter(Filter)` |
| `__init__` | method | `lazyownbt/security.py:21` | `def __init__(self, env_keys)` |
| `_redact` | method | `lazyownbt/security.py:25` | `def _redact(self, message)` |
| `filter` | method | `lazyownbt/security.py:35` | `def filter(self, record)` |
| `install_secrets_filter` | function | `lazyownbt/security.py:51` | `def install_secrets_filter(logger, env_keys)` |
| `verify_password` | function | `lazyownbt/security.py:59` | `def verify_password(plain, hashed)` |
| `_build_csp` | function | `lazyownbt/web.py:38` | `def _build_csp(static_csp_hash)` |
| `_default_flask_env_if_unset` | function | `lazyownbt/web.py:220` | `def _default_flask_env_if_unset()` |
| `_handle_command` | function | `lazyownbt/web.py:185` | `def _handle_command(app)` |
| `_register_default_actions` | function | `lazyownbt/web.py:55` | `def _register_default_actions(registry)` |
| `_register_routes` | function | `lazyownbt/web.py:114` | `def _register_routes(app)` |
| `api_audit` | function | `lazyownbt/web.py:170` | `def api_audit()` |
| `api_dashboard` | function | `lazyownbt/web.py:126` | `def api_dashboard()` |
| `commands` | function | `lazyownbt/web.py:145` | `def commands()` |
| `create_app` | function | `lazyownbt/web.py:66` | `def create_app(settings)` |
| `dashboard` | function | `lazyownbt/web.py:121` | `def dashboard()` |
| `healthz` | function | `lazyownbt/web.py:117` | `def healthz()` |
| `login` | function | `lazyownbt/web.py:152` | `def login()` |
| `not_found` | function | `lazyownbt/web.py:176` | `def not_found(_)` |
| `run` | function | `lazyownbt/web.py:236` | `def run()` |
| `server_error` | function | `lazyownbt/web.py:180` | `def server_error(_)` |
| `Database` | class | `main.py:42` | `class Database` |
| `__init__` | method | `main.py:57` | `def __init__(self, db_path)` |
| `_dashboard` | function | `main.py:272` | `def _dashboard()` |
| `_populate_dashboard_metrics` | function | `main.py:231` | `def _populate_dashboard_metrics(db)` |
| `_register_data_routes` | function | `main.py:200` | `def _register_data_routes(app, db)` |
| `_safe_fetch` | method | `main.py:69` | `def _safe_fetch(self, table, columns, where, params, order, limit)` |
| `alerts_view` | function | `main.py:208` | `def alerts_view()` |
| `api_correlate` | function | `main.py:227` | `def api_correlate(event_id)` |
| `build_app` | function | `main.py:260` | `def build_app(settings)` |
| `connect` | method | `main.py:60` | `def connect(self)` |
| `correlate_events` | method | `main.py:155` | `def correlate_events(self, event_id)` |
| `events_view` | function | `main.py:218` | `def events_view()` |
| `fetch_alerts` | method | `main.py:106` | `def fetch_alerts(self, limit, severity)` |
| `fetch_events` | method | `main.py:127` | `def fetch_events(self, limit)` |
| `fetch_file_hashes` | method | `main.py:148` | `def fetch_file_hashes(self, limit)` |
| `fetch_network_baseline` | method | `main.py:141` | `def fetch_network_baseline(self, limit)` |
| `_db_query` | function | `skills/lazyownbt_mcp.py:67` | `def _db_query(sql, params)` |
| `_handle_sighup` | function | `skills/lazyownbt_mcp.py:1423` | `def _handle_sighup(signum, frame)` |
| `_list_reports` | function | `skills/lazyownbt_mcp.py:1380` | `def _list_reports()` |
| `_load_config` | function | `skills/lazyownbt_mcp.py:49` | `def _load_config()` |
| `_query_alerts` | function | `skills/lazyownbt_mcp.py:1223` | `def _query_alerts()` |
| `_query_events` | function | `skills/lazyownbt_mcp.py:1257` | `def _query_events()` |
| `_run_lazyownbt_command` | function | `skills/lazyownbt_mcp.py:82` | `def _run_lazyownbt_command(command, timeout)` |
| `_save_config` | function | `skills/lazyownbt_mcp.py:58` | `def _save_config(data)` |
| `_stats` | function | `skills/lazyownbt_mcp.py:1351` | `def _stats()` |
| `call_tool` | function | `skills/lazyownbt_mcp.py:864` | `def call_tool(name, arguments)` |
| `list_tools` | function | `skills/lazyownbt_mcp.py:168` | `def list_tools()` |
| `main` | function | `skills/lazyownbt_mcp.py:1431` | `def main()` |
| `text` | function | `skills/lazyownbt_mcp.py:866` | `def text(content)` |
| `AUTH` | function | `static/js/auth.js:6` | `` |
| `clear` | method | `static/js/auth.js:11` | `` |
| `fetch` | method | `static/js/auth.js:16` | `` |
| `get` | method | `static/js/auth.js:9` | `` |
| `requireOrRedirect` | method | `static/js/auth.js:12` | `` |
| `set` | method | `static/js/auth.js:10` | `` |
| `collectParams` | function | `static/js/commands.js:67` | `` |
| `renderParams` | function | `static/js/commands.js:34` | `` |
| `submitCommand` | function | `static/js/commands.js:80` | `` |
| `apply` | function | `static/js/table-filter.js:15` | `` |
| `tableFilter` | function | `static/js/table-filter.js:6` | `` |
| `_iter_source_files` | function | `tests/conftest.py:92` | `def _iter_source_files()` |
| `_make_jwt_secret` | function | `tests/conftest.py:35` | `def _make_jwt_secret()` |
| `_read_text` | function | `tests/conftest.py:100` | `def _read_text(path)` |
| `admin_hash` | function | `tests/conftest.py:153` | `def admin_hash(monkeypatch)` |
| `admin_password_with_length` | function | `tests/conftest.py:148` | `def admin_password_with_length(monkeypatch, n)` |
| `app` | function | `tests/conftest.py:60` | `def app(dev_env, tmp_path)` |
| `assert_audit_list` | function | `tests/conftest.py:527` | `def assert_audit_list(response)` |
| `assert_audit_record` | function | `tests/conftest.py:520` | `def assert_audit_record(bdd_app, action, result)` |
| `assert_bind_warning` | function | `tests/conftest.py:455` | `def assert_bind_warning(caplog)` |
| `assert_body_contains` | function | `tests/conftest.py:489` | `def assert_body_contains(response, needle)` |
| `assert_body_contains_quoted` | function | `tests/conftest.py:483` | `def assert_body_contains_quoted(response, needle)` |
| `assert_body_mentions` | function | `tests/conftest.py:507` | `def assert_body_mentions(response, needle)` |
| `assert_body_mentions_param` | function | `tests/conftest.py:495` | `def assert_body_mentions_param(response, param)` |
| `assert_body_mentions_quoted` | function | `tests/conftest.py:501` | `def assert_body_mentions_quoted(response, needle)` |
| `assert_cli_abort` | function | `tests/conftest.py:444` | `def assert_cli_abort(cli_exc)` |
| `assert_config_error` | function | `tests/conftest.py:538` | `def assert_config_error(settings)` |
| `assert_config_error_code` | function | `tests/conftest.py:418` | `def assert_config_error_code(create_exc, code)` |
| `assert_debug_value` | function | `tests/conftest.py:439` | `def assert_debug_value(created_app, expected)` |
| `assert_dev_warning` | function | `tests/conftest.py:363` | `def assert_dev_warning(capsys)` |
| `assert_dev_warning` | function | `tests/conftest.py:429` | `def assert_dev_warning(capsys)` |
| `assert_env_example` | function | `tests/conftest.py:549` | `def assert_env_example()` |
| `assert_ephemeral_secret_loaded` | function | `tests/conftest.py:424` | `def assert_ephemeral_secret_loaded(settings)` |
| `assert_gitignore_env` | function | `tests/conftest.py:543` | `def assert_gitignore_env()` |
| `assert_host` | function | `tests/conftest.py:450` | `def assert_host(settings, expected)` |
| `assert_imports_covered` | function | `tests/conftest.py:575` | `def assert_imports_covered(imports)` |
| `assert_jwt_value` | function | `tests/conftest.py:533` | `def assert_jwt_value(settings)` |
| `assert_login_ok` | function | `tests/conftest.py:471` | `def assert_login_ok(response)` |
| `assert_no_sha256` | function | `tests/conftest.py:559` | `def assert_no_sha256(csp)` |
| `assert_no_subprocess_python` | function | `tests/conftest.py:271` | `def assert_no_subprocess_python(scan_result)` |
| `assert_no_unused_deps` | function | `tests/conftest.py:603` | `def assert_no_unused_deps()` |
| `assert_not_contains` | function | `tests/conftest.py:570` | `def assert_not_contains(logged_msg, needle)` |
| `assert_not_contains_quoted` | function | `tests/conftest.py:565` | `def assert_not_contains_quoted(logged_msg, needle)` |
| `assert_output` | function | `tests/conftest.py:513` | `def assert_output(response)` |
| `assert_redacted_in_message` | function | `tests/conftest.py:554` | `def assert_redacted_in_message(logged_msg)` |
| `assert_status` | function | `tests/conftest.py:478` | `def assert_status(response, code)` |
| `assert_talisman_https` | function | `tests/conftest.py:460` | `def assert_talisman_https(created_app)` |
| `assert_talisman_no_https` | function | `tests/conftest.py:465` | `def assert_talisman_no_https(created_app)` |
| `auth_client` | function | `tests/conftest.py:74` | `def auth_client(client, app)` |
| `bdd_anon` | function | `tests/conftest.py:178` | `def bdd_anon(bdd_app)` |
| `bdd_app` | function | `tests/conftest.py:158` | `def bdd_app(monkeypatch, tmp_path)` |
| `bdd_client` | function | `tests/conftest.py:169` | `def bdd_client(bdd_app)` |
| `bind_value` | function | `tests/conftest.py:201` | `def bind_value(monkeypatch, value)` |
| `clean_env` | function | `tests/conftest.py:112` | `def clean_env(monkeypatch)` |
| `cli_with_debug` | function | `tests/conftest.py:373` | `def cli_with_debug(monkeypatch)` |
| `client` | function | `tests/conftest.py:69` | `def client(app)` |
| `code_tree` | function | `tests/conftest.py:215` | `def code_tree()` |
| `create_the_app` | function | `tests/conftest.py:384` | `def create_the_app(monkeypatch)` |
| `dev_env` | function | `tests/conftest.py:45` | `def dev_env(monkeypatch, jwt_secret)` |
| `extract_imports` | function | `tests/conftest.py:220` | `def extract_imports()` |
| `failing` | function | `tests/conftest.py:187` | `def failing()` |
| `fake_failing_handler` | function | `tests/conftest.py:183` | `def fake_failing_handler(bdd_app, action, what)` |
| `flask_env` | function | `tests/conftest.py:121` | `def flask_env(monkeypatch, env)` |
| `flask_env_quoted` | function | `tests/conftest.py:127` | `def flask_env_quoted(monkeypatch, env)` |
| `get_csp` | function | `tests/conftest.py:390` | `def get_csp()` |
| `invoke_action` | function | `tests/conftest.py:323` | `def invoke_action(bdd_client, action, payload)` |
| `invoke_action_anon` | function | `tests/conftest.py:333` | `def invoke_action_anon(bdd_anon, action, payload)` |
| `jwt_no_secret` | function | `tests/conftest.py:133` | `def jwt_no_secret(monkeypatch)` |
| `jwt_secret` | function | `tests/conftest.py:40` | `def jwt_secret()` |
| `jwt_secret_value` | function | `tests/conftest.py:138` | `def jwt_secret_value(monkeypatch, value)` |
| `jwt_secret_with_length` | function | `tests/conftest.py:143` | `def jwt_secret_with_length(monkeypatch, n)` |
| `load_cfg` | function | `tests/conftest.py:353` | `def load_cfg(monkeypatch, capsys)` |
| `load_config` | function | `tests/conftest.py:290` | `def load_config(monkeypatch)` |
| `load_default` | function | `tests/conftest.py:347` | `def load_default(monkeypatch)` |
| `log_msg` | function | `tests/conftest.py:396` | `def log_msg(logger_with_filter, msg, caplog)` |
| `logger_with_filter` | function | `tests/conftest.py:206` | `def logger_with_filter()` |
| `login_bad` | function | `tests/conftest.py:312` | `def login_bad(bdd_app)` |
| `login_ok` | function | `tests/conftest.py:298` | `def login_ok(bdd_app)` |
| `no_admin_password` | function | `tests/conftest.py:412` | `def no_admin_password(scan_result)` |
| `no_bind` | function | `tests/conftest.py:196` | `def no_bind(monkeypatch)` |
| `no_your_secret_key` | function | `tests/conftest.py:407` | `def no_your_secret_key(scan_result)` |
| `prod_env` | function | `tests/conftest.py:52` | `def prod_env(monkeypatch, jwt_secret)` |
| `query_audit` | function | `tests/conftest.py:342` | `def query_audit(bdd_client)` |
| `scan_repo` | function | `tests/conftest.py:247` | `def scan_repo()` |
| `scan_repo_eval` | function | `tests/conftest.py:257` | `def scan_repo_eval()` |
| `scan_repo_sha` | function | `tests/conftest.py:262` | `def scan_repo_sha()` |
| `scan_repo_subprocess` | function | `tests/conftest.py:252` | `def scan_repo_subprocess()` |
| `try_create_app` | function | `tests/conftest.py:280` | `def try_create_app(monkeypatch)` |
| `_read` | function | `tests/test_command_execution.py:16` | `def _read(path)` |
| `fake_handler` | function | `tests/test_command_execution.py:165` | `def fake_handler()` |
| `test_audit_endpoint_returns_records` | function | `tests/test_command_execution.py:146` | `def test_audit_endpoint_returns_records(auth_client)` |
| `test_command_audit_recorded` | function | `tests/test_command_execution.py:120` | `def test_command_audit_recorded(auth_client, app)` |
| `test_command_audit_records_error` | function | `tests/test_command_execution.py:133` | `def test_command_audit_records_error(auth_client, app)` |
| `test_command_executes_via_python_call` | function | `tests/test_command_execution.py:161` | `def test_command_executes_via_python_call(auth_client, monkeypatch)` |
| `test_command_missing_required_param` | function | `tests/test_command_execution.py:87` | `def test_command_missing_required_param(auth_client)` |
| `test_command_not_in_allowlist_is_rejected` | function | `tests/test_command_execution.py:55` | `def test_command_not_in_allowlist_is_rejected(client)` |
| `test_command_not_in_allowlist_returns_403` | function | `tests/test_command_execution.py:65` | `def test_command_not_in_allowlist_returns_403(auth_client)` |
| `test_command_rejects_unknown_params` | function | `tests/test_command_execution.py:97` | `def test_command_rejects_unknown_params(auth_client)` |
| `test_command_requires_jwt` | function | `tests/test_command_execution.py:109` | `def test_command_requires_jwt(client)` |
| `test_command_validates_params` | function | `tests/test_command_execution.py:77` | `def test_command_validates_params(auth_client)` |
| `test_no_eval_on_user_input` | function | `tests/test_command_execution.py:39` | `def test_no_eval_on_user_input()` |
| `test_subprocess_dynamic_python_is_gone` | function | `tests/test_command_execution.py:23` | `def test_subprocess_dynamic_python_is_gone()` |
| `_canonical` | function | `tests/test_configuration.py:85` | `def _canonical(pkg)` |
| `_declared_deps` | function | `tests/test_configuration.py:58` | `def _declared_deps()` |
| `_extract_top_level_imports` | function | `tests/test_configuration.py:36` | `def _extract_top_level_imports(source_files)` |
| `test_config_fails_loudly_on_missing_var` | function | `tests/test_configuration.py:27` | `def test_config_fails_loudly_on_missing_var(monkeypatch)` |
| `test_config_loads_from_env` | function | `tests/test_configuration.py:18` | `def test_config_loads_from_env(monkeypatch)` |
| `test_pyproject_extras_declared` | function | `tests/test_configuration.py:118` | `def test_pyproject_extras_declared()` |
| `test_requirements_contains_all_imports` | function | `tests/test_configuration.py:94` | `def test_requirements_contains_all_imports()` |
| `test_bind_default_loopback` | function | `tests/test_production.py:34` | `def test_bind_default_loopback(monkeypatch)` |
| `test_bind_warns_when_public` | function | `tests/test_production.py:45` | `def test_bind_warns_when_public(monkeypatch, caplog)` |
| `test_cli_rejects_debug_in_production` | function | `tests/test_production.py:89` | `def test_cli_rejects_debug_in_production(monkeypatch)` |
| `test_csp_has_no_hardcoded_inline_hash` | function | `tests/test_production.py:82` | `def test_csp_has_no_hardcoded_inline_hash()` |
| `test_debug_flag_default_false` | function | `tests/test_production.py:13` | `def test_debug_flag_default_false(monkeypatch)` |
| `test_debug_only_with_explicit_flag` | function | `tests/test_production.py:23` | `def test_debug_only_with_explicit_flag(monkeypatch)` |
| `test_talisman_https_in_production` | function | `tests/test_production.py:58` | `def test_talisman_https_in_production(monkeypatch)` |
| `test_talisman_no_https_in_development` | function | `tests/test_production.py:72` | `def test_talisman_no_https_in_development(monkeypatch)` |
| `_iter_source_files` | function | `tests/test_security.py:20` | `def _iter_source_files()` |
| `test_app_aborts_when_jwt_secret_missing_in_prod` | function | `tests/test_security.py:56` | `def test_app_aborts_when_jwt_secret_missing_in_prod(monkeypatch)` |
| `test_app_generates_ephemeral_secret_in_dev` | function | `tests/test_security.py:66` | `def test_app_generates_ephemeral_secret_in_dev(monkeypatch, capsys)` |
| `test_empty_jwt_secret_triggers_absence_rule` | function | `tests/test_security.py:88` | `def test_empty_jwt_secret_triggers_absence_rule(monkeypatch)` |
| `test_env_example_exists` | function | `tests/test_security.py:125` | `def test_env_example_exists()` |
| `test_env_file_is_gitignored` | function | `tests/test_security.py:115` | `def test_env_file_is_gitignored()` |
| `test_jwt_secret_below_minimum_length_aborts` | function | `tests/test_security.py:79` | `def test_jwt_secret_below_minimum_length_aborts(monkeypatch, bad_secret)` |
| `test_no_hardcoded_admin_password` | function | `tests/test_security.py:40` | `def test_no_hardcoded_admin_password()` |
| `test_no_hardcoded_jwt_secret` | function | `tests/test_security.py:27` | `def test_no_hardcoded_jwt_secret()` |
| `test_password_is_hashed_not_plain` | function | `tests/test_security.py:100` | `def test_password_is_hashed_not_plain(monkeypatch, tmp_path)` |
| `test_secrets_filter_redacts_in_args` | function | `tests/test_security.py:140` | `def test_secrets_filter_redacts_in_args()` |
| `test_secrets_filter_redacts_in_dict_args` | function | `tests/test_security.py:147` | `def test_secrets_filter_redacts_in_dict_args()` |
| `test_secrets_filter_redacts_values` | function | `tests/test_security.py:131` | `def test_secrets_filter_redacts_values()` |
