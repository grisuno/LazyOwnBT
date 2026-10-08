# API

## app.py
- `Fg.style` (method) `app.py:75` `def style(text, fg, bold)` -- Equivalente funcional de la antigua `cmd2.style(text, fg=..., bold=...)`.
- `Fg.replace_command_placeholders` (method) `app.py:209` `def replace_command_placeholders(command, params)` -- Replace placeholders in a command string with values from a params dictionary, handling spaces within placeholders.
- `Fg.replace_match` (method) `app.py:227` `def replace_match(match)`
- `Red.sanitize_content` (method) `app.py:241` `def sanitize_content(text)` -- Sanitize text to ensure it's safe for Markdown rendering.
- `RAGManager.__init__` (method) `app.py:256` `def __init__(self, model_name, cache_size)`
- `RAGManager.initialize_cache_table` (method) `app.py:269` `def initialize_cache_table(self)` -- Initialize SQLite table for persistent cache.
- `RAGManager.get_cache_key` (method) `app.py:282` `def get_cache_key(self, content)` -- Generate a cache key from content using SHA-256.
- `RAGManager.load_existing_vectorstore` (method) `app.py:286` `def load_existing_vectorstore(self)` -- Load existing vectorstore if available.
- `RAGManager.ollama_llm` (method) `app.py:300` `def ollama_llm(self, question, context)` -- Query LLM with context using Ollama.
- `RAGManager.process_file_to_rag` (method) `app.py:315` `def process_file_to_rag(self, file_path)` -- Process a file, add it to the RAG knowledge base, and cache embeddings.
- `RAGManager.query_rag` (method) `app.py:374` `def query_rag(self, question)` -- Query the RAG system with caching.
- `RAGManager.invalidate_cache` (method) `app.py:414` `def invalidate_cache(self, file_path)` -- Invalidate cache entries for a specific file.
- `RAGManager.get_knowledge_base_stats` (method) `app.py:433` `def get_knowledge_base_stats(self)` -- Get statistics about the knowledge base and cache.
- `Database.__init__` (method) `app.py:462` `def __init__(self, db_path)`
- `Database.initialize` (method) `app.py:468` `def initialize(self)` -- Inicializa la conexión a la base de datos y crea las tablas si no existen.
- `Database.execute` (method) `app.py:554` `def execute(self, query, params)` -- Ejecuta una consulta SQL y devuelve los resultados.
- `Database.insert` (method) `app.py:564` `def insert(self, query, params)` -- Inserta datos en la base de datos y devuelve el ID del último registro.
- `Database.close` (method) `app.py:575` `def close(self)` -- Cierra la conexión a la base de datos.
- `Database.execute` (method) `app.py:582` `def execute(self, query, params)` -- Ejecuta una consulta SQL y devuelve los resultados.
- `Database.insert` (method) `app.py:592` `def insert(self, query, params)` -- Inserta datos en la base de datos y devuelve el ID del último registro.
- `Database.close` (method) `app.py:603` `def close(self)` -- Cierra la conexión a la base de datos.
- `Alert.__init__` (method) `app.py:614` `def __init__(self, alert_type, details, severity)`
- `Alert.to_dict` (method) `app.py:620` `def to_dict(self)` -- Convierte la alerta a diccionario.
- `Alert.save_to_db` (method) `app.py:629` `def save_to_db(self, db)` -- Guarda la alerta en la base de datos.
- `SystemUtils.run_command` (method) `app.py:647` `def run_command(command, shell)` -- Ejecuta un comando del sistema y devuelve el código de salida, stdout y stderr.
- `SystemUtils.get_file_hash` (method) `app.py:677` `def get_file_hash(filepath)` -- Calcula el hash SHA-256 de un archivo.
- `SystemUtils.get_system_info` (method) `app.py:694` `def get_system_info()` -- Obtiene información del sistema.
- `SystemUtils.backup_file` (method) `app.py:725` `def backup_file(filepath, backup_dir)` -- Crea una copia de seguridad de un archivo.
- `SystemUtils.get_process_details` (method) `app.py:746` `def get_process_details(pid)`
- `ProcessMonitor.__init__` (method) `app.py:758` `def __init__(self, config, db)`
- `ProcessMonitor.scan` (method) `app.py:765` `def scan(self, generate_alerts)` -- Escanea procesos en busca de actividad sospechosa.
- `NetworkMonitor.__init__` (method) `app.py:856` `def __init__(self, config, db)`
- `NetworkMonitor.create_baseline` (method) `app.py:878` `def create_baseline(self)` -- Crea una línea base de las conexiones de red actuales (LISTEN y ESTABLISHED).
- `NetworkMonitor.scan` (method) `app.py:924` `def scan(self, generate_alerts)` -- Escanea las conexiones de red en busca de anomalías.
- `FileIntegrityMonitor.__init__` (method) `app.py:1000` `def __init__(self, config, db)`
- `FileIntegrityMonitor.initialize_baseline` (method) `app.py:1005` `def initialize_baseline(self, files_to_baseline)` -- Inicializa o actualiza la línea base de hashes de archivos.
- `FileIntegrityMonitor.scan` (method) `app.py:1048` `def scan(self, generate_alerts)` -- Verifica la integridad de los archivos contra la línea base.
- `LogAnalyzer.__init__` (method) `app.py:1118` `def __init__(self, config, db)` -- Inicializa el analizador con configuración mejorada y validada
- `LogAnalyzer.analyze_log_file` (method) `app.py:1537` `def analyze_log_file(self, log_path, generate_alerts)` -- Analiza un único archivo de log con detección avanzada de amenazas.
- `LogAnalyzer.analyze_all_logs` (method) `app.py:2025` `def analyze_all_logs(self, generate_alerts)` -- Analiza todos los archivos de log configurados usando procesamiento paralelo.
- `LogAnalyzer.get_performance_metrics` (method) `app.py:2145` `def get_performance_metrics(self)` -- Devuelve métricas de rendimiento del analizador
- `LogAnalyzer.reset_trackers` (method) `app.py:2159` `def reset_trackers(self)` -- Reinicia los contadores y rastreadores de eventos
- `LogAnalyzer.add_custom_pattern` (method) `app.py:2167` `def add_custom_pattern(self, name, pattern, severity, mitre_tactics, mitre_techniques)` -- Añade un patrón personalizado para detección
- `LogAnalyzer.export_findings_summary` (method) `app.py:2196` `def export_findings_summary(self)` -- Exporta un resumen de hallazgos para informes
- `LogAnalyzer.create_hunting_report` (method) `app.py:2214` `def create_hunting_report(self)` -- Genera un informe de hunting basado en los hallazgos
- `LogAnalyzer.analyze` (method) `app.py:2229` `def analyze(self)`
- `RealTimeLogMonitor.__init__` (method) `app.py:2390` `def __init__(self, config, db)` -- Inicializa el monitor con configuración
- `RealTimeLogMonitor.start` (method) `app.py:2397` `def start(self)` -- Inicia el monitoreo en tiempo real
- `RealTimeLogMonitor.stop` (method) `app.py:2422` `def stop(self)` -- Detiene el monitoreo en tiempo real
- `RealTimeLogMonitor.get_status` (method) `app.py:2427` `def get_status(self)` -- Devuelve el estado actual del monitor
- `SystemHardener.__init__` (method) `app.py:2439` `def __init__(self, config, db)`
- `SystemHardener.check_system_security` (method) `app.py:2444` `def check_system_security(self)`
- `SystemHardener.apply_hardening` (method) `app.py:2643` `def apply_hardening(self, backup)`
- `SystemHardener.audit_ssh_config` (method) `app.py:2797` `def audit_ssh_config(self, generate_alerts)` -- Audita la configuración de SSHD.
- `SystemHardener.check_suid_sgid_files` (method) `app.py:2880` `def check_suid_sgid_files(self)` -- Encuentra archivos con bits SUID/SGID.
- `IncidentResponder.__init__` (method) `app.py:2918` `def __init__(self, config, db)`
- `IncidentResponder.quarantine_file` (method) `app.py:2924` `def quarantine_file(self, filepath)` -- Mueve un archivo a la carpeta de cuarentena y le quita permisos.
- `IncidentResponder.block_ip` (method) `app.py:2951` `def block_ip(self, ip_address, interface)` -- Bloquea una IP usando iptables (requiere sudo).
- `IncidentResponder.kill_process` (method) `app.py:2991` `def kill_process(self, pid, signal_to_send)` -- Termina un proceso por su PID.
- `ReportGenerator.__init__` (method) `app.py:3014` `def __init__(self, config, db)`
- `ReportGenerator.generate_summary_report` (method) `app.py:3020` `def generate_summary_report(self, filename)` -- Genera un informe de resumen en texto plano.
- `MemoryScanner.__init__` (method) `app.py:3083` `def __init__(self, config, db)`
- `MemoryScanner.scan_process_memory` (method) `app.py:3094` `def scan_process_memory(self, pid)`
- `MemoryScanner.scan_system` (method) `app.py:3160` `def scan_system(self, max_processes)`
- `LazySentinelHandler.__init__` (method) `app.py:3175` `def __init__(self, lazysentinel)`
- `LazySentinelHandler.is_text_file` (method) `app.py:3178` `def is_text_file(self, file_path)` -- Check if a file is a text file by extension or content.
- `LazySentinelHandler.on_created` (method) `app.py:3189` `def on_created(self, event)`
- `LazySentinelHandler.on_modified` (method) `app.py:3201` `def on_modified(self, event)`
- `LazySentinel.__init__` (method) `app.py:3213` `def __init__(self, app, popup_queue, watch_dir, excluded_files, min_file_size)`
- `LazySentinel.chunk_text` (method) `app.py:3234` `def chunk_text(self, text, chunk_size)`
- `LazySentinel.select_relevant_chunk` (method) `app.py:3237` `def select_relevant_chunk(self, file_content, chunks)`
- `LazySentinel.parse_deepseek_response` (method) `app.py:3251` `def parse_deepseek_response(self, response_text)` -- Parse DeepSeek's plain text response into a JSON-like dictionary.
- `LazySentinel.show_popup` (method) `app.py:3281` `def show_popup(self, file_name, relevant_info, commands, details)` -- Queue a Rich-based popup to be displayed in the main thread.
- `LazySentinel.process_file` (method) `app.py:3304` `def process_file(self, file_path)`
- `LazySentinel.stop` (method) `app.py:3453` `def stop(self)`
- `LazyOwnApp.__init__` (method) `app.py:3473` `def __init__(self, config_file)` -- Inicializa el CLI con configuración y componentes necesarios
- `LazyOwnApp.list_files_in_directory` (method) `app.py:3597` `def list_files_in_directory(self, directory)` -- Lista todos los archivos en un directorio dado.
- `LazyOwnApp.wrapper` (method) `app.py:3607` `def wrapper(arg)`
- `LazyOwnApp.load_plugins` (method) `app.py:3630` `def load_plugins(self)` -- Carga todos los plugins Lua desde el directorio 'plugins/'.
- `LazyOwnApp.load_yaml_plugins` (method) `app.py:3660` `def load_yaml_plugins(self)` -- Loads all YAML plugins from the 'lazyaddons/' directory.
- `LazyOwnApp.register_yaml_plugin` (method) `app.py:3683` `def register_yaml_plugin(self, plugin_data)` -- Registers a YAML plugin as a new command.
- `LazyOwnApp.wrapper_yaml` (method) `app.py:3697` `def wrapper_yaml(arg)`
- `LazyOwnApp.postloop` (method) `app.py:3746` `def postloop(self)` -- Acciones al salir de la aplicación.
- `LazyOwnApp.postcmd` (method) `app.py:3754` `def postcmd(self, stop, line)` -- Check the popup queue after each command and display with Rich Markdown.
- `LazyOwnApp.do_ai_status` (method) `app.py:3813` `def do_ai_status(self, args)` -- Muestra el estado del modelo de IA
- `LazyOwnApp.do_ai_load` (method) `app.py:3824` `def do_ai_load(self, args)` -- Intenta cargar manualmente el modelo de IA
- `LazyOwnApp.do_ai_test` (method) `app.py:3836` `def do_ai_test(self, args)` -- Prueba un comando con el modelo de IA
- `LazyOwnApp.do_ai_feedback` (method) `app.py:3863` `def do_ai_feedback(self, args)` -- Proporciona feedback sobre una detección de IA para mejorar el modelo
- `LazyOwnApp.do_ai_retrain` (method) `app.py:3923` `def do_ai_retrain(self, args)` -- Reentrena el modelo de IA con nuevos datos de feedback
- `LazyOwnApp.do_sysinfo` (method) `app.py:3970` `def do_sysinfo(self, _)` -- Muestra información detallada del sistema.
- `LazyOwnApp.do_proc_scan` (method) `app.py:3997` `def do_proc_scan(self, _)` -- Escanea procesos actuales en busca de actividad sospechosa.
- `LazyOwnApp.do_proc_details` (method) `app.py:4020` `def do_proc_details(self, args)` -- Muestra información detallada de un proceso específico por PID.
- `LazyOwnApp.do_net_baseline` (method) `app.py:4049` `def do_net_baseline(self, _)` -- Crea/actualiza la línea base de conexiones de red activas.
- `LazyOwnApp.do_net_scan` (method) `app.py:4058` `def do_net_scan(self, _)` -- Escanea conexiones de red actuales en busca de anomalías respecto a la línea base y puertos sospechosos.
- `LazyOwnApp.do_net_conns` (method) `app.py:4087` `def do_net_conns(self, args)` -- Muestra conexiones de red activas (TCP, UDP, LISTEN, ESTABLISHED, etc.).
- `LazyOwnApp.do_fim_baseline` (method) `app.py:4153` `def do_fim_baseline(self, args)` -- Inicializa/actualiza la línea base de hashes para los archivos críticos o especificados.
- `LazyOwnApp.do_fim_scan` (method) `app.py:4166` `def do_fim_scan(self, _)` -- Verifica la integridad de los archivos críticos contra la línea base.
- `LazyOwnApp.do_log_analyze` (method) `app.py:4190` `def do_log_analyze(self, args)` -- Analiza los logs configurados o especificados en busca de patrones sospechosos.
- `LazyOwnApp.do_harden_audit_ssh` (method) `app.py:4227` `def do_harden_audit_ssh(self, _)` -- Audita la configuración del demonio SSH (sshd_config).
- `LazyOwnApp.do_resp_quarantine_file` (method) `app.py:4247` `def do_resp_quarantine_file(self, args)` -- Mueve un archivo a cuarentena y le quita permisos (acción irreversible sobre el original).
- `LazyOwnApp.do_resp_block_ip` (method) `app.py:4263` `def do_resp_block_ip(self, args)` -- Bloquea una IP usando iptables (¡ACCIÓN PELIGROSA, REQUIERE SUDO!).
- `LazyOwnApp.do_resp_kill_proc` (method) `app.py:4296` `def do_resp_kill_proc(self, args)` -- Termina un proceso enviándole una señal (SIGTERM por defecto).
- `LazyOwnApp.do_report_summary` (method) `app.py:4312` `def do_report_summary(self, args)` -- Genera un informe de resumen de seguridad.
- `LazyOwnApp.do_show_config` (method) `app.py:4323` `def do_show_config(self, _)` -- Muestra la configuración actual de LazyOwn.
- `LazyOwnApp.print_रात` (method) `app.py:4331` `def print_रात(self, data_to_print)` -- Método wrapper para poutput, maneja diferentes tipos de datos.
- `LazyOwnApp.do_system_info` (method) `app.py:4343` `def do_system_info(self, arg)` -- Display system information.
- `LazyOwnApp.do_scan_processes` (method) `app.py:4348` `def do_scan_processes(self, arg)` -- Scan for suspicious processes.
- `LazyOwnApp.do_scan_network` (method) `app.py:4360` `def do_scan_network(self, arg)` -- Scan for suspicious network connections.
- `LazyOwnApp.do_create_network_baseline` (method) `app.py:4372` `def do_create_network_baseline(self, arg)` -- Create network connections baseline.
- `LazyOwnApp.do_check_file_integrity` (method) `app.py:4377` `def do_check_file_integrity(self, arg)` -- Check integrity of critical files.
- `LazyOwnApp.do_init_file_baseline` (method) `app.py:4389` `def do_init_file_baseline(self, arg)` -- Initialize file integrity baseline.
- `LazyOwnApp.do_analyze_logs` (method) `app.py:4394` `def do_analyze_logs(self, arg)` -- Analyze system logs for suspicious activity.
- `LazyOwnApp.do_check_security` (method) `app.py:4406` `def do_check_security(self, arg)` -- Check system security configuration.
- `LazyOwnApp.do_harden_system` (method) `app.py:4418` `def do_harden_system(self, arg)` -- Apply system hardening measures.
- `LazyOwnApp.do_scan_memory` (method) `app.py:4430` `def do_scan_memory(self, arg)` -- Scan system memory for suspicious content.
- `LazyOwnApp.do_block_ip` (method) `app.py:4444` `def do_block_ip(self, arg)` -- Block an IP address using UFW: block_ip <ip_address>
- `LazyOwnApp.do_kill_process` (method) `app.py:4464` `def do_kill_process(self, arg)` -- Kill a process by PID: kill_process <pid>
- `LazyOwnApp.do_quit` (method) `app.py:4485` `def do_quit(self, arg)` -- Quit the application.
- `LazyOwnApp.do_debug` (method) `app.py:4490` `def do_debug(self, arg)` -- Display debug information about LazySentinel state.
- `LazyOwnApp.do_rag_query` (method) `app.py:4498` `def do_rag_query(self, arg)` -- Query the RAG knowledge base with a question.
- `LazyOwnApp.do_rag_add` (method) `app.py:4508` `def do_rag_add(self, arg)` -- Add a specific file to the RAG knowledge base.
- `LazyOwnApp.do_rag_status` (method) `app.py:4526` `def do_rag_status(self, arg)` -- Display RAG knowledge base status and statistics.
- `LazyOwnApp.do_rag_toggle` (method) `app.py:4535` `def do_rag_toggle(self, arg)` -- Toggle automatic addition of monitored files to RAG knowledge base.
- `LazyOwnApp.do_rag_bulk_add` (method) `app.py:4541` `def do_rag_bulk_add(self, arg)` -- Add all files in the monitored directory to RAG knowledge base.
- `LazyOwnApp.do_rag_search` (method) `app.py:4564` `def do_rag_search(self, arg)` -- Search for similar content in the RAG knowledge base.
- `LazyOwnApp.complete_rag_add` (method) `app.py:4591` `def complete_rag_add(self, text, line, begidx, endidx)` -- Tab completion for rag_add command.
- `LazyOwnApp.complete_rag_bulk_add` (method) `app.py:4599` `def complete_rag_bulk_add(self, text, line, begidx, endidx)` -- Tab completion for rag_bulk_add command.
- `LazyOwnApp.do_quarantine_file` (method) `app.py:4607` `def do_quarantine_file(self, arg)` -- Quarantine a suspicious file: quarantine_file <filepath>
- `LazyOwnApp.do_audit_users` (method) `app.py:4633` `def do_audit_users(self, arg)` -- Audit system users and their privileges
- `LazyOwnApp.do_processes` (method) `app.py:4664` `def do_processes(self, arg)` -- Escanear procesos sospechosos
- `LazyOwnApp.do_network` (method) `app.py:4675` `def do_network(self, arg)` -- Escanear conexiones de red sospechosas
- `LazyOwnApp.do_files` (method) `app.py:4687` `def do_files(self, arg)` -- Verificar integridad de archivos críticos
- `LazyOwnApp.do_logs` (method) `app.py:4699` `def do_logs(self, arg)` -- Analizar logs del sistema
- `LazyOwnApp.do_memory` (method) `app.py:4707` `def do_memory(self, arg)` -- Escanear memoria de procesos sospechosos
- `LazyOwnApp.do_hardening` (method) `app.py:4716` `def do_hardening(self, arg)` -- Aplicar medidas de endurecimiento
- `LazyOwnApp.confirm_action` (method) `app.py:4733` `def confirm_action(self, prompt_message, confirm_keyword)` -- Pide confirmación al usuario para una acción.
- `LazyOwnApp.do_analyze` (method) `app.py:4792` `def do_analyze(self, args)` -- Analiza archivos de log específicos o todos los configurados.
- `LazyOwnApp.do_monitor` (method) `app.py:4922` `def do_monitor(self, args)` -- Inicia o detiene el monitoreo en tiempo real de los logs.
- `LazyOwnApp.do_patterns` (method) `app.py:5044` `def do_patterns(self, args)` -- Gestiona los patrones de detección para el análisis de logs.
- `LazyOwnApp.do_analyze_logs` (method) `app.py:5215` `def do_analyze_logs(self, args)` -- Analiza los archivos de log configurados
- `LazyOwnApp.do_start_monitor` (method) `app.py:5235` `def do_start_monitor(self, args)` -- Inicia el monitoreo en tiempo real de logs
- `LazyOwnApp.do_stop_monitor` (method) `app.py:5246` `def do_stop_monitor(self, args)` -- Detiene el monitoreo en tiempo real
- `LazyOwnApp.do_monitor_status` (method) `app.py:5254` `def do_monitor_status(self, args)` -- Muestra el estado actual del monitor
- `LazyOwnApp.do_add_pattern` (method) `app.py:5264` `def do_add_pattern(self, args)` -- Añade un patrón personalizado de detección
- `LazyOwnApp.do_redteam_hunt` (method) `app.py:5275` `def do_redteam_hunt(self, args)` -- Realiza una búsqueda específica de actividad del equipo rojo

## lazyownbt/actions.py
Imported by: `lazyownbt/handlers.py`, `lazyownbt/web.py`, `tests/test_command_execution.py`
- `ActionRegistry.__init__` (method) `lazyownbt/actions.py:31` `def __init__(self)`
- `ActionRegistry.register` (method) `lazyownbt/actions.py:35` `def register(self, spec, handler)`
- `ActionRegistry.is_allowed` (method) `lazyownbt/actions.py:41` `def is_allowed(self, name)`
- `ActionRegistry.spec` (method) `lazyownbt/actions.py:44` `def spec(self, name)`
- `ActionRegistry.handler` (method) `lazyownbt/actions.py:47` `def handler(self, name)`
- `ActionRegistry.names` (method) `lazyownbt/actions.py:50` `def names(self)`
- `ActionRegistry.validate_params` (method) `lazyownbt/actions.py:53` `def validate_params(self, name, params)` -- Valida y coerciona parámetros (SEC-002.3).

## lazyownbt/audit.py
Imported by: `lazyownbt/web.py`
- `AuditLog.__init__` (method) `lazyownbt/audit.py:38` `def __init__(self, db_path)`
- `AuditLog.record` (method) `lazyownbt/audit.py:77` `def record(self, action, user, params, result, duration_ms, error)`
- `AuditLog.track` (method) `lazyownbt/audit.py:113` `def track(self, action, user, params)` -- Context manager que mide tiempo y registra resultado/errores.
- `AuditLog.fetch` (method) `lazyownbt/audit.py:133` `def fetch(self, limit)`

## lazyownbt/config.py
Imported by: `lazyownbt/web.py`, `main.py`, `tests/conftest.py`, `tests/test_configuration.py`, `tests/test_production.py`, `tests/test_security.py`
- `Settings.is_production` (method) `lazyownbt/config.py:117` `def is_production(self)`
- `Settings.is_development` (method) `lazyownbt/config.py:121` `def is_development(self)`
- `Settings.load_settings` (method) `lazyownbt/config.py:125` `def load_settings()` -- Carga y valida la configuración.

## lazyownbt/detection.py
- `DetectionEngine.__init__` (method) `lazyownbt/detection.py:154` `def __init__(self, db_path)`
- `DetectionEngine.get_rules` (method) `lazyownbt/detection.py:196` `def get_rules(self)`
- `DetectionEngine.check_command` (method) `lazyownbt/detection.py:199` `def check_command(self, command, args)` -- Check a command against all Sigma rules.
- `DetectionEngine.check_audit_log` (method) `lazyownbt/detection.py:217` `def check_audit_log(self, log_line)` -- Check an auditd log line against all rules.
- `DetectionEngine.get_alerts` (method) `lazyownbt/detection.py:255` `def get_alerts(self, since_minutes, category, level)` -- Get recent alerts, optionally filtered.
- `DetectionEngine.get_stats` (method) `lazyownbt/detection.py:278` `def get_stats(self, since_minutes)` -- Get detection statistics.
- `DetectionEngine.is_auditd_available` (method) `lazyownbt/detection.py:291` `def is_auditd_available(self)` -- Check if auditd is installed and running.
- `DetectionEngine.install_auditd_rule` (method) `lazyownbt/detection.py:301` `def install_auditd_rule(self, key)` -- Install an auditd rule for monitoring.
- `DetectionEngine.get_engine` (method) `lazyownbt/detection.py:316` `def get_engine(db_path)`

## lazyownbt/handlers.py
Depends on: `lazyownbt/actions.py`
Imported by: `lazyownbt/web.py`
- `handle_resp_block_ip` (function) `lazyownbt/handlers.py:32` `def handle_resp_block_ip(ip_address, interface)` -- Stub seguro.
- `handle_resp_kill_proc` (function) `lazyownbt/handlers.py:52` `def handle_resp_kill_proc(pid, signal)` -- Stub seguro.
- `handle_net_scan` (function) `lazyownbt/handlers.py:64` `def handle_net_scan()`
- `handle_fim_scan` (function) `lazyownbt/handlers.py:68` `def handle_fim_scan()`
- `handle_lazynmap` (function) `lazyownbt/handlers.py:72` `def handle_lazynmap(target)`
- `handle_ai_playbook` (function) `lazyownbt/handlers.py:78` `def handle_ai_playbook(scenario)`
- `build_default_handlers` (function) `lazyownbt/handlers.py:84` `def build_default_handlers()`

## lazyownbt/security.py
Imported by: `lazyownbt/web.py`, `tests/conftest.py`, `tests/test_security.py`
- `SecretsFilter.__init__` (method) `lazyownbt/security.py:21` `def __init__(self, env_keys)`
- `SecretsFilter.filter` (method) `lazyownbt/security.py:35` `def filter(self, record)`
- `SecretsFilter.install_secrets_filter` (method) `lazyownbt/security.py:51` `def install_secrets_filter(logger, env_keys)` -- Instala el SecretsFilter en un logger.
- `SecretsFilter.verify_password` (method) `lazyownbt/security.py:59` `def verify_password(plain, hashed)` -- Compara una contraseña contra un hash bcrypt (SEC-001.4).

## lazyownbt/web.py
Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
Imported by: `main.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`
- `create_app` (function) `lazyownbt/web.py:66` `def create_app(settings)` -- Crea y configura la app Flask.
- `healthz` (function) `lazyownbt/web.py:117` `def healthz()`
- `dashboard` (function) `lazyownbt/web.py:121` `def dashboard()`
- `api_dashboard` (function) `lazyownbt/web.py:126` `def api_dashboard()` -- Resumen para el dashboard.
- `commands` (function) `lazyownbt/web.py:145` `def commands()`
- `login` (function) `lazyownbt/web.py:152` `def login()`
- `api_audit` (function) `lazyownbt/web.py:170` `def api_audit()`
- `not_found` (function) `lazyownbt/web.py:176` `def not_found(_)`
- `server_error` (function) `lazyownbt/web.py:180` `def server_error(_)`
- `run` (function) `lazyownbt/web.py:236` `def run()` -- Punto de entrada CLI: respeta SEC-003.1 y SEC-003.2.

## main.py
Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`
- `Database.__init__` (method) `main.py:57` `def __init__(self, db_path)`
- `Database.connect` (method) `main.py:60` `def connect(self)`
- `Database.fetch_alerts` (method) `main.py:106` `def fetch_alerts(self, limit, severity)`
- `Database.fetch_events` (method) `main.py:127` `def fetch_events(self, limit)`
- `Database.fetch_network_baseline` (method) `main.py:141` `def fetch_network_baseline(self, limit)`
- `Database.fetch_file_hashes` (method) `main.py:148` `def fetch_file_hashes(self, limit)`
- `Database.correlate_events` (method) `main.py:155` `def correlate_events(self, event_id)` -- Busca alertas ±5 min relacionadas con un evento.
- `Database.alerts_view` (method) `main.py:208` `def alerts_view()`
- `Database.events_view` (method) `main.py:218` `def events_view()`
- `Database.api_correlate` (method) `main.py:227` `def api_correlate(event_id)`
- `Database.build_app` (method) `main.py:260` `def build_app(settings)` -- Construye la app final reutilizando :func:`create_app`.

## skills/lazyownbt_mcp.py
- `list_tools` (function) `skills/lazyownbt_mcp.py:168` `def list_tools()`
- `call_tool` (function) `skills/lazyownbt_mcp.py:864` `def call_tool(name, arguments)`
- `text` (function) `skills/lazyownbt_mcp.py:866` `def text(content)`
- `main` (function) `skills/lazyownbt_mcp.py:1431` `def main()`

## static/js/auth.js
- `AUTH` (function) `static/js/auth.js:6`

## static/js/commands.js
- `renderParams` (function) `static/js/commands.js:33`
- `collectParams` (function) `static/js/commands.js:66`
- `submitCommand` (function) `static/js/commands.js:80`

## static/js/table-filter.js
- `tableFilter` (function) `static/js/table-filter.js:5` -- LazyOwnBT — filtro de tabla en cliente (vanilla JS).
- `apply` (function) `static/js/table-filter.js:15`
