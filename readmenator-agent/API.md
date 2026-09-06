# API

## app.py

### style `def style(text, fg, bold)`
- Defined: `app.py:75`
- Doc: Equivalente funcional de la antigua `cmd2.style(text, fg=..., bold=...)`.

### replace_command_placeholders `def replace_command_placeholders(command, params)`
- Defined: `app.py:209`
- Doc: Replace placeholders in a command string with values from a params dictionary,

### sanitize_content `def sanitize_content(text)`
- Defined: `app.py:241`
- Doc: Sanitize text to ensure it's safe for Markdown rendering.

### replace_match `def replace_match(match)`
- Defined: `app.py:227`

### __init__ `def __init__(self, model_name, cache_size)`
- Defined: `app.py:256`

### initialize_cache_table `def initialize_cache_table(self)`
- Defined: `app.py:269`
- Doc: Initialize SQLite table for persistent cache.

### get_cache_key `def get_cache_key(self, content)`
- Defined: `app.py:282`
- Doc: Generate a cache key from content using SHA-256.

### load_existing_vectorstore `def load_existing_vectorstore(self)`
- Defined: `app.py:286`
- Doc: Load existing vectorstore if available.

### ollama_llm `def ollama_llm(self, question, context)`
- Defined: `app.py:300`
- Doc: Query LLM with context using Ollama.

### process_file_to_rag `def process_file_to_rag(self, file_path)`
- Defined: `app.py:315`
- Doc: Process a file, add it to the RAG knowledge base, and cache embeddings.

### query_rag `def query_rag(self, question)`
- Defined: `app.py:374`
- Doc: Query the RAG system with caching.

### invalidate_cache `def invalidate_cache(self, file_path)`
- Defined: `app.py:414`
- Doc: Invalidate cache entries for a specific file.

### get_knowledge_base_stats `def get_knowledge_base_stats(self)`
- Defined: `app.py:433`
- Doc: Get statistics about the knowledge base and cache.

### __init__ `def __init__(self, db_path)`
- Defined: `app.py:462`

### initialize `def initialize(self)`
- Defined: `app.py:468`
- Doc: Inicializa la conexión a la base de datos y crea las tablas si no existen.

### execute `def execute(self, query, params)`
- Defined: `app.py:554`
- Doc: Ejecuta una consulta SQL y devuelve los resultados.

### insert `def insert(self, query, params)`
- Defined: `app.py:564`
- Doc: Inserta datos en la base de datos y devuelve el ID del último registro.

### close `def close(self)`
- Defined: `app.py:575`
- Doc: Cierra la conexión a la base de datos.

### execute `def execute(self, query, params)`
- Defined: `app.py:582`
- Doc: Ejecuta una consulta SQL y devuelve los resultados.

### insert `def insert(self, query, params)`
- Defined: `app.py:592`
- Doc: Inserta datos en la base de datos y devuelve el ID del último registro.

### close `def close(self)`
- Defined: `app.py:603`
- Doc: Cierra la conexión a la base de datos.

### __init__ `def __init__(self, alert_type, details, severity)`
- Defined: `app.py:614`

### to_dict `def to_dict(self)`
- Defined: `app.py:620`
- Doc: Convierte la alerta a diccionario.

### save_to_db `def save_to_db(self, db)`
- Defined: `app.py:629`
- Doc: Guarda la alerta en la base de datos.

### run_command `def run_command(command, shell)`
- Defined: `app.py:647`
- Doc: Ejecuta un comando del sistema y devuelve el código de salida, stdout y stderr.

### get_file_hash `def get_file_hash(filepath)`
- Defined: `app.py:677`
- Doc: Calcula el hash SHA-256 de un archivo.

### get_system_info `def get_system_info()`
- Defined: `app.py:694`
- Doc: Obtiene información del sistema.

### backup_file `def backup_file(filepath, backup_dir)`
- Defined: `app.py:725`
- Doc: Crea una copia de seguridad de un archivo.

### get_process_details `def get_process_details(pid)`
- Defined: `app.py:746`

### __init__ `def __init__(self, config, db)`
- Defined: `app.py:758`

### scan `def scan(self, generate_alerts)`
- Defined: `app.py:765`
- Doc: Escanea procesos en busca de actividad sospechosa.

### __init__ `def __init__(self, config, db)`
- Defined: `app.py:856`

### _load_baseline `def _load_baseline(self)`
- Defined: `app.py:862`
- Doc: Carga la línea base de conexiones de red desde la base de datos.

### create_baseline `def create_baseline(self)`
- Defined: `app.py:878`
- Doc: Crea una línea base de las conexiones de red actuales (LISTEN y ESTABLISHED).

### scan `def scan(self, generate_alerts)`
- Defined: `app.py:924`
- Doc: Escanea las conexiones de red en busca de anomalías.

### __init__ `def __init__(self, config, db)`
- Defined: `app.py:1000`

### initialize_baseline `def initialize_baseline(self, files_to_baseline)`
- Defined: `app.py:1005`
- Doc: Inicializa o actualiza la línea base de hashes de archivos.

### scan `def scan(self, generate_alerts)`
- Defined: `app.py:1048`
- Doc: Verifica la integridad de los archivos contra la línea base.

### __init__ `def __init__(self, config, db)`
- Defined: `app.py:1118`
- Doc: Inicializa el analizador con configuración mejorada y validada

### _sanitize_config `def _sanitize_config(self, config)`
- Defined: `app.py:1171`
- Doc: Sanitiza y valida la configuración para prevenir inyecciones y valores maliciosos

### _is_safe_path `def _is_safe_path(self, path)`
- Defined: `app.py:1195`
- Doc: Valida que una ruta sea segura (previene directory traversal)

### _initialize_state `def _initialize_state(self)`
- Defined: `app.py:1209`
- Doc: Inicializa el estado persistente del analizador

### _setup_threat_detection_patterns `def _setup_threat_detection_patterns(self)`
- Defined: `app.py:1239`
- Doc: Configura patrones avanzados para detección de amenazas con MITRE ATT&CK mappings

### _calculate_file_hash `def _calculate_file_hash(self, filename)`
- Defined: `app.py:1407`
- Doc: Calcula el hash SHA-256 de un archivo de manera segura

### _check_file_integrity `def _check_file_integrity(self, log_path)`
- Defined: `app.py:1420`
- Doc: Verifica la integridad del archivo de log basado en su hash

### _extract_timestamp_from_log `def _extract_timestamp_from_log(self, line)`
- Defined: `app.py:1443`
- Doc: Extrae el timestamp de una línea de log usando varios formatos comunes

### _extract_ip_from_log `def _extract_ip_from_log(self, line)`
- Defined: `app.py:1478`
- Doc: Extrae una dirección IP de una línea de log

### _extract_username_from_log `def _extract_username_from_log(self, line)`
- Defined: `app.py:1486`
- Doc: Extrae un nombre de usuario de una línea de log

### _extract_command_from_log `def _extract_command_from_log(self, line)`
- Defined: `app.py:1501`
- Doc: Extrae un comando ejecutado de una línea de log

### _is_alert_duplicated `def _is_alert_duplicated(self, alert_type, details_hash)`
- Defined: `app.py:1515`
- Doc: Verifica si una alerta ya fue generada recientemente para evitar duplicados

### analyze_log_file `def analyze_log_file(self, log_path, generate_alerts)`
- Defined: `app.py:1537`
- Doc: Analiza un único archivo de log con detección avanzada de amenazas.

### _enrich_finding_with_context `def _enrich_finding_with_context(self, event_details)`
- Defined: `app.py:1757`
- Doc: Enriquece un hallazgo con contexto adicional y correlación

### _process_specific_event_logic `def _process_specific_event_logic(self, pattern_name, pattern_config, event_details, line_content)`
- Defined: `app.py:1794`
- Doc: Procesa lógica especializada según el tipo de evento detectado

### _get_usual_login_hours `def _get_usual_login_hours(self, username)`
- Defined: `app.py:2009`
- Doc: Obtiene las horas usuales de login para un usuario basado en la línea base

### _get_common_commands_for_user `def _get_common_commands_for_user(self, username)`
- Defined: `app.py:2016`
- Doc: Obtiene los comandos más comunes para un usuario

### analyze_all_logs `def analyze_all_logs(self, generate_alerts)`
- Defined: `app.py:2025`
- Doc: Analiza todos los archivos de log configurados usando procesamiento paralelo.

### _correlate_findings `def _correlate_findings(self, all_findings)`
- Defined: `app.py:2059`
- Doc: Correlaciona hallazgos entre múltiples logs para detectar patrones complejos

### get_performance_metrics `def get_performance_metrics(self)`
- Defined: `app.py:2145`
- Doc: Devuelve métricas de rendimiento del analizador

### reset_trackers `def reset_trackers(self)`
- Defined: `app.py:2159`
- Doc: Reinicia los contadores y rastreadores de eventos

### add_custom_pattern `def add_custom_pattern(self, name, pattern, severity, mitre_tactics, mitre_techniques)`
- Defined: `app.py:2167`
- Doc: Añade un patrón personalizado para detección

### _count_rule_based_alerts `def _count_rule_based_alerts(self)`
- Defined: `app.py:2188`
- Doc: Cuenta las alertas generadas por reglas (no por IA)

### export_findings_summary `def export_findings_summary(self)`
- Defined: `app.py:2196`
- Doc: Exporta un resumen de hallazgos para informes

### create_hunting_report `def create_hunting_report(self)`
- Defined: `app.py:2214`
- Doc: Genera un informe de hunting basado en los hallazgos

### analyze `def analyze(self)`
- Defined: `app.py:2229`

### _load_ai_model `def _load_ai_model(self)`
- Defined: `app.py:2293`
- Doc: Carga el modelo de IA y el vectorizador si están disponibles.

### _analyze_command_with_ai `def _analyze_command_with_ai(self, command, args)`
- Defined: `app.py:2312`
- Doc: Usa el modelo de IA para evaluar si un comando es malicioso.

### __init__ `def __init__(self, config, db)`
- Defined: `app.py:2390`
- Doc: Inicializa el monitor con configuración

### start `def start(self)`
- Defined: `app.py:2397`
- Doc: Inicia el monitoreo en tiempo real

### stop `def stop(self)`
- Defined: `app.py:2422`
- Doc: Detiene el monitoreo en tiempo real

### get_status `def get_status(self)`
- Defined: `app.py:2427`
- Doc: Devuelve el estado actual del monitor

### __init__ `def __init__(self, config, db)`
- Defined: `app.py:2439`

### check_system_security `def check_system_security(self)`
- Defined: `app.py:2444`

### apply_hardening `def apply_hardening(self, backup)`
- Defined: `app.py:2643`

### audit_ssh_config `def audit_ssh_config(self, generate_alerts)`
- Defined: `app.py:2797`
- Doc: Audita la configuración de SSHD.

### check_suid_sgid_files `def check_suid_sgid_files(self)`
- Defined: `app.py:2880`
- Doc: Encuentra archivos con bits SUID/SGID.

### __init__ `def __init__(self, config, db)`
- Defined: `app.py:2918`

### quarantine_file `def quarantine_file(self, filepath)`
- Defined: `app.py:2924`
- Doc: Mueve un archivo a la carpeta de cuarentena y le quita permisos.

### block_ip `def block_ip(self, ip_address, interface)`
- Defined: `app.py:2951`
- Doc: Bloquea una IP usando iptables (requiere sudo). Esta es una acción peligrosa.

### kill_process `def kill_process(self, pid, signal_to_send)`
- Defined: `app.py:2991`
- Doc: Termina un proceso por su PID.

### __init__ `def __init__(self, config, db)`
- Defined: `app.py:3014`

### generate_summary_report `def generate_summary_report(self, filename)`
- Defined: `app.py:3020`
- Doc: Genera un informe de resumen en texto plano.

### __init__ `def __init__(self, config, db)`
- Defined: `app.py:3083`

### scan_process_memory `def scan_process_memory(self, pid)`
- Defined: `app.py:3094`

### scan_system `def scan_system(self, max_processes)`
- Defined: `app.py:3160`

### __init__ `def __init__(self, lazysentinel)`
- Defined: `app.py:3175`

### is_text_file `def is_text_file(self, file_path)`
- Defined: `app.py:3178`
- Doc: Check if a file is a text file by extension or content.

### on_created `def on_created(self, event)`
- Defined: `app.py:3189`

### on_modified `def on_modified(self, event)`
- Defined: `app.py:3201`

### __init__ `def __init__(self, app, popup_queue, watch_dir, excluded_files, min_file_size)`
- Defined: `app.py:3213`

### chunk_text `def chunk_text(self, text, chunk_size)`
- Defined: `app.py:3234`

### select_relevant_chunk `def select_relevant_chunk(self, file_content, chunks)`
- Defined: `app.py:3237`

### parse_deepseek_response `def parse_deepseek_response(self, response_text)`
- Defined: `app.py:3251`
- Doc: Parse DeepSeek's plain text response into a JSON-like dictionary.

### show_popup `def show_popup(self, file_name, relevant_info, commands, details)`
- Defined: `app.py:3281`
- Doc: Queue a Rich-based popup to be displayed in the main thread.

### process_file `def process_file(self, file_path)`
- Defined: `app.py:3304`

### stop `def stop(self)`
- Defined: `app.py:3453`

### __init__ `def __init__(self, config_file)`
- Defined: `app.py:3473`
- Doc: Inicializa el CLI con configuración y componentes necesarios

### _load_config `def _load_config(self, config_file)`
- Defined: `app.py:3566`
- Doc: Carga la configuración desde un archivo JSON o usa los defaults.

### _initialize_database `def _initialize_database(self)`
- Defined: `app.py:3592`
- Doc: Inicializa la conexión a la base de datos

### list_files_in_directory `def list_files_in_directory(self, directory)`
- Defined: `app.py:3597`
- Doc: Lista todos los archivos en un directorio dado.

### _register_lua_command `def _register_lua_command(self, command_name, lua_function)`
- Defined: `app.py:3604`
- Doc: Registra un comando nuevo desde Lua.

### load_plugins `def load_plugins(self)`
- Defined: `app.py:3630`
- Doc: Carga todos los plugins Lua desde el directorio 'plugins/'.

### load_yaml_plugins `def load_yaml_plugins(self)`
- Defined: `app.py:3660`
- Doc: Loads all YAML plugins from the 'lazyaddons/' directory.

### register_yaml_plugin `def register_yaml_plugin(self, plugin_data)`
- Defined: `app.py:3683`
- Doc: Registers a YAML plugin as a new command.

### postloop `def postloop(self)`
- Defined: `app.py:3746`
- Doc: Acciones al salir de la aplicación.

### postcmd `def postcmd(self, stop, line)`
- Defined: `app.py:3754`
- Doc: Check the popup queue after each command and display with Rich Markdown.

### do_ai_status `def do_ai_status(self, args)`
- Defined: `app.py:3813`
- Doc: Muestra el estado del modelo de IA

### do_ai_load `def do_ai_load(self, args)`
- Defined: `app.py:3824`
- Doc: Intenta cargar manualmente el modelo de IA

### do_ai_test `def do_ai_test(self, args)`
- Defined: `app.py:3836`
- Doc: Prueba un comando con el modelo de IA

### do_ai_feedback `def do_ai_feedback(self, args)`
- Defined: `app.py:3863`
- Doc: Proporciona feedback sobre una detección de IA para mejorar el modelo

### do_ai_retrain `def do_ai_retrain(self, args)`
- Defined: `app.py:3923`
- Doc: Reentrena el modelo de IA con nuevos datos de feedback

### do_sysinfo `def do_sysinfo(self, _)`
- Defined: `app.py:3970`
- Doc: Muestra información detallada del sistema.

### do_proc_scan `def do_proc_scan(self, _)`
- Defined: `app.py:3997`
- Doc: Escanea procesos actuales en busca de actividad sospechosa.

### do_proc_details `def do_proc_details(self, args)`
- Defined: `app.py:4020`
- Doc: Muestra información detallada de un proceso específico por PID.

### do_net_baseline `def do_net_baseline(self, _)`
- Defined: `app.py:4049`
- Doc: Crea/actualiza la línea base de conexiones de red activas.

### do_net_scan `def do_net_scan(self, _)`
- Defined: `app.py:4058`
- Doc: Escanea conexiones de red actuales en busca de anomalías respecto a la línea base y puertos sospechosos.

### do_net_conns `def do_net_conns(self, args)`
- Defined: `app.py:4087`
- Doc: Muestra conexiones de red activas (TCP, UDP, LISTEN, ESTABLISHED, etc.).

### do_fim_baseline `def do_fim_baseline(self, args)`
- Defined: `app.py:4153`
- Doc: Inicializa/actualiza la línea base de hashes para los archivos críticos o especificados.

### do_fim_scan `def do_fim_scan(self, _)`
- Defined: `app.py:4166`
- Doc: Verifica la integridad de los archivos críticos contra la línea base.

### do_log_analyze `def do_log_analyze(self, args)`
- Defined: `app.py:4190`
- Doc: Analiza los logs configurados o especificados en busca de patrones sospechosos.

### do_harden_audit_ssh `def do_harden_audit_ssh(self, _)`
- Defined: `app.py:4227`
- Doc: Audita la configuración del demonio SSH (sshd_config).

### do_resp_quarantine_file `def do_resp_quarantine_file(self, args)`
- Defined: `app.py:4247`
- Doc: Mueve un archivo a cuarentena y le quita permisos (acción irreversible sobre el original).

### do_resp_block_ip `def do_resp_block_ip(self, args)`
- Defined: `app.py:4263`
- Doc: Bloquea una IP usando iptables (¡ACCIÓN PELIGROSA, REQUIERE SUDO!).

### do_resp_kill_proc `def do_resp_kill_proc(self, args)`
- Defined: `app.py:4296`
- Doc: Termina un proceso enviándole una señal (SIGTERM por defecto).

### do_report_summary `def do_report_summary(self, args)`
- Defined: `app.py:4312`
- Doc: Genera un informe de resumen de seguridad.

### do_show_config `def do_show_config(self, _)`
- Defined: `app.py:4323`
- Doc: Muestra la configuración actual de LazyOwn.

### print_रात `def print_रात(self, data_to_print)`
- Defined: `app.py:4331`
- Doc: Método wrapper para poutput, maneja diferentes tipos de datos.

### do_system_info `def do_system_info(self, arg)`
- Defined: `app.py:4343`
- Doc: Display system information.

### do_scan_processes `def do_scan_processes(self, arg)`
- Defined: `app.py:4348`
- Doc: Scan for suspicious processes.

### do_scan_network `def do_scan_network(self, arg)`
- Defined: `app.py:4360`
- Doc: Scan for suspicious network connections.

### do_create_network_baseline `def do_create_network_baseline(self, arg)`
- Defined: `app.py:4372`
- Doc: Create network connections baseline.

### do_check_file_integrity `def do_check_file_integrity(self, arg)`
- Defined: `app.py:4377`
- Doc: Check integrity of critical files.

### do_init_file_baseline `def do_init_file_baseline(self, arg)`
- Defined: `app.py:4389`
- Doc: Initialize file integrity baseline.

### do_analyze_logs `def do_analyze_logs(self, arg)`
- Defined: `app.py:4394`
- Doc: Analyze system logs for suspicious activity.

### do_check_security `def do_check_security(self, arg)`
- Defined: `app.py:4406`
- Doc: Check system security configuration.

### do_harden_system `def do_harden_system(self, arg)`
- Defined: `app.py:4418`
- Doc: Apply system hardening measures.

### do_scan_memory `def do_scan_memory(self, arg)`
- Defined: `app.py:4430`
- Doc: Scan system memory for suspicious content.

### do_block_ip `def do_block_ip(self, arg)`
- Defined: `app.py:4444`
- Doc: Block an IP address using UFW: block_ip <ip_address>

### do_kill_process `def do_kill_process(self, arg)`
- Defined: `app.py:4464`
- Doc: Kill a process by PID: kill_process <pid>

### do_quit `def do_quit(self, arg)`
- Defined: `app.py:4485`
- Doc: Quit the application.

### do_debug `def do_debug(self, arg)`
- Defined: `app.py:4490`
- Doc: Display debug information about LazySentinel state.

### do_rag_query `def do_rag_query(self, arg)`
- Defined: `app.py:4498`
- Doc: Query the RAG knowledge base with a question.

### do_rag_add `def do_rag_add(self, arg)`
- Defined: `app.py:4508`
- Doc: Add a specific file to the RAG knowledge base.

### do_rag_status `def do_rag_status(self, arg)`
- Defined: `app.py:4526`
- Doc: Display RAG knowledge base status and statistics.

### do_rag_toggle `def do_rag_toggle(self, arg)`
- Defined: `app.py:4535`
- Doc: Toggle automatic addition of monitored files to RAG knowledge base.

### do_rag_bulk_add `def do_rag_bulk_add(self, arg)`
- Defined: `app.py:4541`
- Doc: Add all files in the monitored directory to RAG knowledge base.

### do_rag_search `def do_rag_search(self, arg)`
- Defined: `app.py:4564`
- Doc: Search for similar content in the RAG knowledge base.

### complete_rag_add `def complete_rag_add(self, text, line, begidx, endidx)`
- Defined: `app.py:4591`
- Doc: Tab completion for rag_add command.

### complete_rag_bulk_add `def complete_rag_bulk_add(self, text, line, begidx, endidx)`
- Defined: `app.py:4599`
- Doc: Tab completion for rag_bulk_add command.

### do_quarantine_file `def do_quarantine_file(self, arg)`
- Defined: `app.py:4607`
- Doc: Quarantine a suspicious file: quarantine_file <filepath>

### do_audit_users `def do_audit_users(self, arg)`
- Defined: `app.py:4633`
- Doc: Audit system users and their privileges

### do_processes `def do_processes(self, arg)`
- Defined: `app.py:4664`
- Doc: Escanear procesos sospechosos

### do_network `def do_network(self, arg)`
- Defined: `app.py:4675`
- Doc: Escanear conexiones de red sospechosas

### do_files `def do_files(self, arg)`
- Defined: `app.py:4687`
- Doc: Verificar integridad de archivos críticos

### do_logs `def do_logs(self, arg)`
- Defined: `app.py:4699`
- Doc: Analizar logs del sistema

### do_memory `def do_memory(self, arg)`
- Defined: `app.py:4707`
- Doc: Escanear memoria de procesos sospechosos

### do_hardening `def do_hardening(self, arg)`
- Defined: `app.py:4716`
- Doc: Aplicar medidas de endurecimiento

### confirm_action `def confirm_action(self, prompt_message, confirm_keyword)`
- Defined: `app.py:4733`
- Doc: Pide confirmación al usuario para una acción.

### _load_config `def _load_config(self, config_file)`
- Defined: `app.py:4746`
- Doc: Carga la configuración desde un archivo JSON

### do_analyze `def do_analyze(self, args)`
- Defined: `app.py:4792`
- Doc: Analiza archivos de log específicos o todos los configurados.

### _display_findings_summary `def _display_findings_summary(self, file_path, findings, verbose)`
- Defined: `app.py:4875`
- Doc: Muestra un resumen de los hallazgos de un archivo

### _get_severity_color `def _get_severity_color(self, severity)`
- Defined: `app.py:4911`
- Doc: Devuelve el código de color ANSI para una severidad dada

### do_monitor `def do_monitor(self, args)`
- Defined: `app.py:4922`
- Doc: Inicia o detiene el monitoreo en tiempo real de los logs.

### _monitoring_loop `def _monitoring_loop(self, interval)`
- Defined: `app.py:4997`
- Doc: Bucle de monitoreo que se ejecuta en un hilo separado

### do_patterns `def do_patterns(self, args)`
- Defined: `app.py:5044`
- Doc: Gestiona los patrones de detección para el análisis de logs.

### do_analyze_logs `def do_analyze_logs(self, args)`
- Defined: `app.py:5215`
- Doc: Analiza los archivos de log configurados

### do_start_monitor `def do_start_monitor(self, args)`
- Defined: `app.py:5235`
- Doc: Inicia el monitoreo en tiempo real de logs

### do_stop_monitor `def do_stop_monitor(self, args)`
- Defined: `app.py:5246`
- Doc: Detiene el monitoreo en tiempo real

### do_monitor_status `def do_monitor_status(self, args)`
- Defined: `app.py:5254`
- Doc: Muestra el estado actual del monitor

### do_add_pattern `def do_add_pattern(self, args)`
- Defined: `app.py:5264`
- Doc: Añade un patrón personalizado de detección

### do_redteam_hunt `def do_redteam_hunt(self, args)`
- Defined: `app.py:5275`
- Doc: Realiza una búsqueda específica de actividad del equipo rojo

### _process_ai_detection `def _process_ai_detection(self, event_details, line_content, log_path, line_num)`
- Defined: `app.py:2338`
- Doc: Procesa la detección de comandos maliciosos usando IA

### wrapper `def wrapper(arg)`
- Defined: `app.py:3607`

### wrapper_yaml `def wrapper_yaml(arg)`
- Defined: `app.py:3697`

## lazyownbt/actions.py

### __init__ `def __init__(self)`
- Defined: `lazyownbt/actions.py:31`
- Imported by: `lazyownbt/handlers.py`, `lazyownbt/web.py`, `tests/test_command_execution.py`

### register `def register(self, spec, handler)`
- Defined: `lazyownbt/actions.py:35`
- Imported by: `lazyownbt/handlers.py`, `lazyownbt/web.py`, `tests/test_command_execution.py`

### is_allowed `def is_allowed(self, name)`
- Defined: `lazyownbt/actions.py:41`
- Imported by: `lazyownbt/handlers.py`, `lazyownbt/web.py`, `tests/test_command_execution.py`

### spec `def spec(self, name)`
- Defined: `lazyownbt/actions.py:44`
- Imported by: `lazyownbt/handlers.py`, `lazyownbt/web.py`, `tests/test_command_execution.py`

### handler `def handler(self, name)`
- Defined: `lazyownbt/actions.py:47`
- Imported by: `lazyownbt/handlers.py`, `lazyownbt/web.py`, `tests/test_command_execution.py`

### names `def names(self)`
- Defined: `lazyownbt/actions.py:50`
- Imported by: `lazyownbt/handlers.py`, `lazyownbt/web.py`, `tests/test_command_execution.py`

### validate_params `def validate_params(self, name, params)`
- Defined: `lazyownbt/actions.py:53`
- Doc: Valida y coerciona parámetros (SEC-002.3).
- Imported by: `lazyownbt/handlers.py`, `lazyownbt/web.py`, `tests/test_command_execution.py`

## lazyownbt/audit.py

### __init__ `def __init__(self, db_path)`
- Defined: `lazyownbt/audit.py:38`
- Imported by: `lazyownbt/web.py`

### _conn `def _conn(self)`
- Defined: `lazyownbt/audit.py:43`
- Imported by: `lazyownbt/web.py`

### _init_db `def _init_db(self)`
- Defined: `lazyownbt/audit.py:53`
- Imported by: `lazyownbt/web.py`

### record `def record(self, action, user, params, result, duration_ms, error)`
- Defined: `lazyownbt/audit.py:77`
- Imported by: `lazyownbt/web.py`

### track `def track(self, action, user, params)`
- Defined: `lazyownbt/audit.py:113`
- Doc: Context manager que mide tiempo y registra resultado/errores.
- Imported by: `lazyownbt/web.py`

### fetch `def fetch(self, limit)`
- Defined: `lazyownbt/audit.py:133`
- Imported by: `lazyownbt/web.py`

## lazyownbt/config.py

### _load_dotenv `def _load_dotenv()`
- Defined: `lazyownbt/config.py:32`
- Doc: Carga .env si existe. No falla si no existe (CFG-001.2).
- Imported by: `lazyownbt/web.py`, `main.py`, `main.py`, `tests/conftest.py`, `tests/test_configuration.py`, `tests/test_production.py`, `tests/test_security.py`

### _resolve_jwt_secret `def _resolve_jwt_secret()`
- Defined: `lazyownbt/config.py:39`
- Doc: Resuelve el secreto de JWT según SEC-001.2 y SEC-001.3.
- Imported by: `lazyownbt/web.py`, `main.py`, `main.py`, `tests/conftest.py`, `tests/test_configuration.py`, `tests/test_production.py`, `tests/test_security.py`

### _resolve_admin_password_hash `def _resolve_admin_password_hash()`
- Defined: `lazyownbt/config.py:73`
- Doc: Resuelve el hash de la contraseña admin según SEC-001.4.
- Imported by: `lazyownbt/web.py`, `main.py`, `main.py`, `tests/conftest.py`, `tests/test_configuration.py`, `tests/test_production.py`, `tests/test_security.py`

### load_settings `def load_settings()`
- Defined: `lazyownbt/config.py:125`
- Doc: Carga y valida la configuración. Falla ruidosamente (CFG-001.3).
- Imported by: `lazyownbt/web.py`, `main.py`, `main.py`, `tests/conftest.py`, `tests/test_configuration.py`, `tests/test_production.py`, `tests/test_security.py`

### is_production `def is_production(self)`
- Defined: `lazyownbt/config.py:117`
- Imported by: `lazyownbt/web.py`, `main.py`, `main.py`, `tests/conftest.py`, `tests/test_configuration.py`, `tests/test_production.py`, `tests/test_security.py`

### is_development `def is_development(self)`
- Defined: `lazyownbt/config.py:121`
- Imported by: `lazyownbt/web.py`, `main.py`, `main.py`, `tests/conftest.py`, `tests/test_configuration.py`, `tests/test_production.py`, `tests/test_security.py`

## lazyownbt/detection.py

### get_engine `def get_engine(db_path)`
- Defined: `lazyownbt/detection.py:316`

### __init__ `def __init__(self, db_path)`
- Defined: `lazyownbt/detection.py:154`

### _init_db `def _init_db(self)`
- Defined: `lazyownbt/detection.py:160`

### _conn `def _conn(self)`
- Defined: `lazyownbt/detection.py:180`

### _load_custom_rules `def _load_custom_rules(self)`
- Defined: `lazyownbt/detection.py:185`

### get_rules `def get_rules(self)`
- Defined: `lazyownbt/detection.py:196`

### check_command `def check_command(self, command, args)`
- Defined: `lazyownbt/detection.py:199`
- Doc: Check a command against all Sigma rules.

### check_audit_log `def check_audit_log(self, log_line)`
- Defined: `lazyownbt/detection.py:217`
- Doc: Check an auditd log line against all rules.

### _extract_field `def _extract_field(self, log_line, field)`
- Defined: `lazyownbt/detection.py:240`

### _store_alert `def _store_alert(self, alert)`
- Defined: `lazyownbt/detection.py:244`

### get_alerts `def get_alerts(self, since_minutes, category, level)`
- Defined: `lazyownbt/detection.py:255`
- Doc: Get recent alerts, optionally filtered.

### get_stats `def get_stats(self, since_minutes)`
- Defined: `lazyownbt/detection.py:278`
- Doc: Get detection statistics.

### is_auditd_available `def is_auditd_available(self)`
- Defined: `lazyownbt/detection.py:291`
- Doc: Check if auditd is installed and running.

### install_auditd_rule `def install_auditd_rule(self, key)`
- Defined: `lazyownbt/detection.py:301`
- Doc: Install an auditd rule for monitoring.

## lazyownbt/handlers.py

### _validate_ip `def _validate_ip(ip)`
- Defined: `lazyownbt/handlers.py:22`
- Depends on: `lazyownbt/actions.py`
- Imported by: `lazyownbt/web.py`

### handle_resp_block_ip `def handle_resp_block_ip(ip_address, interface)`
- Defined: `lazyownbt/handlers.py:32`
- Doc: Stub seguro. En un despliegue real invocaría iptables con argv.
- Depends on: `lazyownbt/actions.py`
- Imported by: `lazyownbt/web.py`

### handle_resp_kill_proc `def handle_resp_kill_proc(pid, signal)`
- Defined: `lazyownbt/handlers.py:52`
- Doc: Stub seguro. En un despliegue real enviaría la señal al PID.
- Depends on: `lazyownbt/actions.py`
- Imported by: `lazyownbt/web.py`

### handle_net_scan `def handle_net_scan()`
- Defined: `lazyownbt/handlers.py:64`
- Depends on: `lazyownbt/actions.py`
- Imported by: `lazyownbt/web.py`

### handle_fim_scan `def handle_fim_scan()`
- Defined: `lazyownbt/handlers.py:68`
- Depends on: `lazyownbt/actions.py`
- Imported by: `lazyownbt/web.py`

### handle_lazynmap `def handle_lazynmap(target)`
- Defined: `lazyownbt/handlers.py:72`
- Depends on: `lazyownbt/actions.py`
- Imported by: `lazyownbt/web.py`

### handle_ai_playbook `def handle_ai_playbook(scenario)`
- Defined: `lazyownbt/handlers.py:78`
- Depends on: `lazyownbt/actions.py`
- Imported by: `lazyownbt/web.py`

### build_default_handlers `def build_default_handlers()`
- Defined: `lazyownbt/handlers.py:84`
- Depends on: `lazyownbt/actions.py`
- Imported by: `lazyownbt/web.py`

## lazyownbt/security.py

### install_secrets_filter `def install_secrets_filter(logger, env_keys)`
- Defined: `lazyownbt/security.py:51`
- Doc: Instala el SecretsFilter en un logger.
- Imported by: `lazyownbt/web.py`, `tests/conftest.py`, `tests/test_security.py`

### verify_password `def verify_password(plain, hashed)`
- Defined: `lazyownbt/security.py:59`
- Doc: Compara una contraseña contra un hash bcrypt (SEC-001.4).
- Imported by: `lazyownbt/web.py`, `tests/conftest.py`, `tests/test_security.py`

### __init__ `def __init__(self, env_keys)`
- Defined: `lazyownbt/security.py:21`
- Imported by: `lazyownbt/web.py`, `tests/conftest.py`, `tests/test_security.py`

### _redact `def _redact(self, message)`
- Defined: `lazyownbt/security.py:25`
- Imported by: `lazyownbt/web.py`, `tests/conftest.py`, `tests/test_security.py`

### filter `def filter(self, record)`
- Defined: `lazyownbt/security.py:35`
- Imported by: `lazyownbt/web.py`, `tests/conftest.py`, `tests/test_security.py`

## lazyownbt/web.py

### _build_csp `def _build_csp(static_csp_hash)`
- Defined: `lazyownbt/web.py:38`
- Doc: CSP estricta sin hashes hardcodeados (SEC-003.4).
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### _register_default_actions `def _register_default_actions(registry)`
- Defined: `lazyownbt/web.py:55`
- Doc: Carga las acciones por defecto. Cada handler es un stub testable.
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### create_app `def create_app(settings)`
- Defined: `lazyownbt/web.py:66`
- Doc: Crea y configura la app Flask.
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### _register_routes `def _register_routes(app)`
- Defined: `lazyownbt/web.py:114`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### _handle_command `def _handle_command(app)`
- Defined: `lazyownbt/web.py:185`
- Doc: Ejecuta una acción validada por la lista cerrada (SEC-002.*).
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### _default_flask_env_if_unset `def _default_flask_env_if_unset()`
- Defined: `lazyownbt/web.py:220`
- Doc: UX: si FLASK_ENV no está definida, asume development con warning.
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### run `def run()`
- Defined: `lazyownbt/web.py:236`
- Doc: Punto de entrada CLI: respeta SEC-003.1 y SEC-003.2.
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### healthz `def healthz()`
- Defined: `lazyownbt/web.py:117`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### dashboard `def dashboard()`
- Defined: `lazyownbt/web.py:121`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### api_dashboard `def api_dashboard()`
- Defined: `lazyownbt/web.py:126`
- Doc: Resumen para el dashboard.
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### commands `def commands()`
- Defined: `lazyownbt/web.py:145`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### login `def login()`
- Defined: `lazyownbt/web.py:152`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### api_audit `def api_audit()`
- Defined: `lazyownbt/web.py:170`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### not_found `def not_found(_)`
- Defined: `lazyownbt/web.py:176`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

### server_error `def server_error(_)`
- Defined: `lazyownbt/web.py:180`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/audit.py`, `lazyownbt/config.py`, `lazyownbt/handlers.py`, `lazyownbt/security.py`
- Imported by: `main.py`, `main.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/conftest.py`, `tests/test_command_execution.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`, `tests/test_production.py`

## main.py

### _register_data_routes `def _register_data_routes(app, db)`
- Defined: `main.py:200`
- Doc: Añade las rutas de solo-lectura sobre la BD.
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### _populate_dashboard_metrics `def _populate_dashboard_metrics(db)`
- Defined: `main.py:231`
- Doc: Compone el payload que la plantilla ``dashboard.html`` espera.
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### build_app `def build_app(settings)`
- Defined: `main.py:260`
- Doc: Construye la app final reutilizando :func:`create_app`.
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### __init__ `def __init__(self, db_path)`
- Defined: `main.py:57`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### connect `def connect(self)`
- Defined: `main.py:60`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### _safe_fetch `def _safe_fetch(self, table, columns, where, params, order, limit)`
- Defined: `main.py:69`
- Doc: Ejecuta un SELECT genérico y tolera tablas inexistentes.
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### fetch_alerts `def fetch_alerts(self, limit, severity)`
- Defined: `main.py:106`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### fetch_events `def fetch_events(self, limit)`
- Defined: `main.py:127`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### fetch_network_baseline `def fetch_network_baseline(self, limit)`
- Defined: `main.py:141`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### fetch_file_hashes `def fetch_file_hashes(self, limit)`
- Defined: `main.py:148`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### correlate_events `def correlate_events(self, event_id)`
- Defined: `main.py:155`
- Doc: Busca alertas ±5 min relacionadas con un evento.
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### alerts_view `def alerts_view()`
- Defined: `main.py:208`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### events_view `def events_view()`
- Defined: `main.py:218`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### api_correlate `def api_correlate(event_id)`
- Defined: `main.py:227`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### _dashboard `def _dashboard()`
- Defined: `main.py:272`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

## skills/lazyownbt_mcp.py

### _load_config `def _load_config()`
- Defined: `skills/lazyownbt_mcp.py:49`
- Doc: Load config.json, return empty dict on failure.

### _save_config `def _save_config(data)`
- Defined: `skills/lazyownbt_mcp.py:58`

### _db_query `def _db_query(sql, params)`
- Defined: `skills/lazyownbt_mcp.py:67`
- Doc: Execute a read query against lazyown.db.

### _run_lazyownbt_command `def _run_lazyownbt_command(command, timeout)`
- Defined: `skills/lazyownbt_mcp.py:82`
- Doc: Execute one or more LazyOwnBT CLI commands non-interactively via a PTY.

### list_tools `def list_tools()`
- Defined: `skills/lazyownbt_mcp.py:168`

### call_tool `def call_tool(name, arguments)`
- Defined: `skills/lazyownbt_mcp.py:864`

### _handle_sighup `def _handle_sighup(signum, frame)`
- Defined: `skills/lazyownbt_mcp.py:1423`

### main `def main()`
- Defined: `skills/lazyownbt_mcp.py:1431`

### text `def text(content)`
- Defined: `skills/lazyownbt_mcp.py:866`

### _query_alerts `def _query_alerts()`
- Defined: `skills/lazyownbt_mcp.py:1223`

### _query_events `def _query_events()`
- Defined: `skills/lazyownbt_mcp.py:1257`

### _stats `def _stats()`
- Defined: `skills/lazyownbt_mcp.py:1351`

### _list_reports `def _list_reports()`
- Defined: `skills/lazyownbt_mcp.py:1380`

## static/js/auth.js

### AUTH
- Defined: `static/js/auth.js:6`

## static/js/commands.js

### renderParams
- Defined: `static/js/commands.js:33`

### collectParams
- Defined: `static/js/commands.js:66`

### submitCommand
- Defined: `static/js/commands.js:80`

## static/js/table-filter.js

### tableFilter
- Defined: `static/js/table-filter.js:5`
- Doc: LazyOwnBT — filtro de tabla en cliente (vanilla JS). Reemplaza a DataTables para evitar CDN (CSP estricta). Uso: <script

### apply
- Defined: `static/js/table-filter.js:15`

## tests/conftest.py

### _make_jwt_secret `def _make_jwt_secret()`
- Defined: `tests/conftest.py:35`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### jwt_secret `def jwt_secret()`
- Defined: `tests/conftest.py:40`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### dev_env `def dev_env(monkeypatch, jwt_secret)`
- Defined: `tests/conftest.py:45`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### prod_env `def prod_env(monkeypatch, jwt_secret)`
- Defined: `tests/conftest.py:52`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### app `def app(dev_env, tmp_path)`
- Defined: `tests/conftest.py:60`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### client `def client(app)`
- Defined: `tests/conftest.py:69`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### auth_client `def auth_client(client, app)`
- Defined: `tests/conftest.py:74`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### _iter_source_files `def _iter_source_files()`
- Defined: `tests/conftest.py:92`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### _read_text `def _read_text(path)`
- Defined: `tests/conftest.py:100`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### clean_env `def clean_env(monkeypatch)`
- Defined: `tests/conftest.py:112`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### flask_env `def flask_env(monkeypatch, env)`
- Defined: `tests/conftest.py:121`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### flask_env_quoted `def flask_env_quoted(monkeypatch, env)`
- Defined: `tests/conftest.py:127`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### jwt_no_secret `def jwt_no_secret(monkeypatch)`
- Defined: `tests/conftest.py:133`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### jwt_secret_value `def jwt_secret_value(monkeypatch, value)`
- Defined: `tests/conftest.py:138`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### jwt_secret_with_length `def jwt_secret_with_length(monkeypatch, n)`
- Defined: `tests/conftest.py:143`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### admin_password_with_length `def admin_password_with_length(monkeypatch, n)`
- Defined: `tests/conftest.py:148`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### admin_hash `def admin_hash(monkeypatch)`
- Defined: `tests/conftest.py:153`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### bdd_app `def bdd_app(monkeypatch, tmp_path)`
- Defined: `tests/conftest.py:158`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### bdd_client `def bdd_client(bdd_app)`
- Defined: `tests/conftest.py:169`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### bdd_anon `def bdd_anon(bdd_app)`
- Defined: `tests/conftest.py:178`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### fake_failing_handler `def fake_failing_handler(bdd_app, action, what)`
- Defined: `tests/conftest.py:183`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### no_bind `def no_bind(monkeypatch)`
- Defined: `tests/conftest.py:196`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### bind_value `def bind_value(monkeypatch, value)`
- Defined: `tests/conftest.py:201`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### logger_with_filter `def logger_with_filter()`
- Defined: `tests/conftest.py:206`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### code_tree `def code_tree()`
- Defined: `tests/conftest.py:215`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### extract_imports `def extract_imports()`
- Defined: `tests/conftest.py:220`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### scan_repo `def scan_repo()`
- Defined: `tests/conftest.py:247`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### scan_repo_subprocess `def scan_repo_subprocess()`
- Defined: `tests/conftest.py:252`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### scan_repo_eval `def scan_repo_eval()`
- Defined: `tests/conftest.py:257`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### scan_repo_sha `def scan_repo_sha()`
- Defined: `tests/conftest.py:262`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_no_subprocess_python `def assert_no_subprocess_python(scan_result)`
- Defined: `tests/conftest.py:271`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### try_create_app `def try_create_app(monkeypatch)`
- Defined: `tests/conftest.py:280`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### load_config `def load_config(monkeypatch)`
- Defined: `tests/conftest.py:290`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### login_ok `def login_ok(bdd_app)`
- Defined: `tests/conftest.py:298`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### login_bad `def login_bad(bdd_app)`
- Defined: `tests/conftest.py:312`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### invoke_action `def invoke_action(bdd_client, action, payload)`
- Defined: `tests/conftest.py:323`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### invoke_action_anon `def invoke_action_anon(bdd_anon, action, payload)`
- Defined: `tests/conftest.py:333`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### query_audit `def query_audit(bdd_client)`
- Defined: `tests/conftest.py:342`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### load_default `def load_default(monkeypatch)`
- Defined: `tests/conftest.py:347`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### load_cfg `def load_cfg(monkeypatch, capsys)`
- Defined: `tests/conftest.py:353`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_dev_warning `def assert_dev_warning(capsys)`
- Defined: `tests/conftest.py:363`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### cli_with_debug `def cli_with_debug(monkeypatch)`
- Defined: `tests/conftest.py:373`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### create_the_app `def create_the_app(monkeypatch)`
- Defined: `tests/conftest.py:384`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### get_csp `def get_csp()`
- Defined: `tests/conftest.py:390`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### log_msg `def log_msg(logger_with_filter, msg, caplog)`
- Defined: `tests/conftest.py:396`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### no_your_secret_key `def no_your_secret_key(scan_result)`
- Defined: `tests/conftest.py:407`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### no_admin_password `def no_admin_password(scan_result)`
- Defined: `tests/conftest.py:412`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_config_error_code `def assert_config_error_code(create_exc, code)`
- Defined: `tests/conftest.py:418`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_ephemeral_secret_loaded `def assert_ephemeral_secret_loaded(settings)`
- Defined: `tests/conftest.py:424`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_dev_warning `def assert_dev_warning(capsys)`
- Defined: `tests/conftest.py:429`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_debug_value `def assert_debug_value(created_app, expected)`
- Defined: `tests/conftest.py:439`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_cli_abort `def assert_cli_abort(cli_exc)`
- Defined: `tests/conftest.py:444`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_host `def assert_host(settings, expected)`
- Defined: `tests/conftest.py:450`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_bind_warning `def assert_bind_warning(caplog)`
- Defined: `tests/conftest.py:455`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_talisman_https `def assert_talisman_https(created_app)`
- Defined: `tests/conftest.py:460`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_talisman_no_https `def assert_talisman_no_https(created_app)`
- Defined: `tests/conftest.py:465`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_login_ok `def assert_login_ok(response)`
- Defined: `tests/conftest.py:471`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_status `def assert_status(response, code)`
- Defined: `tests/conftest.py:478`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_body_contains_quoted `def assert_body_contains_quoted(response, needle)`
- Defined: `tests/conftest.py:483`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_body_contains `def assert_body_contains(response, needle)`
- Defined: `tests/conftest.py:489`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_body_mentions_param `def assert_body_mentions_param(response, param)`
- Defined: `tests/conftest.py:495`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_body_mentions_quoted `def assert_body_mentions_quoted(response, needle)`
- Defined: `tests/conftest.py:501`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_body_mentions `def assert_body_mentions(response, needle)`
- Defined: `tests/conftest.py:507`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_output `def assert_output(response)`
- Defined: `tests/conftest.py:513`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_audit_record `def assert_audit_record(bdd_app, action, result)`
- Defined: `tests/conftest.py:520`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_audit_list `def assert_audit_list(response)`
- Defined: `tests/conftest.py:527`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_jwt_value `def assert_jwt_value(settings)`
- Defined: `tests/conftest.py:533`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_config_error `def assert_config_error(settings)`
- Defined: `tests/conftest.py:538`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_gitignore_env `def assert_gitignore_env()`
- Defined: `tests/conftest.py:543`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_env_example `def assert_env_example()`
- Defined: `tests/conftest.py:549`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_redacted_in_message `def assert_redacted_in_message(logged_msg)`
- Defined: `tests/conftest.py:554`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_no_sha256 `def assert_no_sha256(csp)`
- Defined: `tests/conftest.py:559`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_not_contains_quoted `def assert_not_contains_quoted(logged_msg, needle)`
- Defined: `tests/conftest.py:565`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_not_contains `def assert_not_contains(logged_msg, needle)`
- Defined: `tests/conftest.py:570`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_imports_covered `def assert_imports_covered(imports)`
- Defined: `tests/conftest.py:575`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### assert_no_unused_deps `def assert_no_unused_deps()`
- Defined: `tests/conftest.py:603`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

### failing `def failing()`
- Defined: `tests/conftest.py:187`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`, `lazyownbt/web.py`

## tests/test_command_execution.py

### _read `def _read(path)`
- Defined: `tests/test_command_execution.py:16`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### test_subprocess_dynamic_python_is_gone `def test_subprocess_dynamic_python_is_gone()`
- Defined: `tests/test_command_execution.py:23`
- Doc: SEC-002.1: no debe haber subprocess con 'python3', '-c' o f-string hacia -c.
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### test_no_eval_on_user_input `def test_no_eval_on_user_input()`
- Defined: `tests/test_command_execution.py:39`
- Doc: SEC-002.1: no debe haber eval/exec sobre input del usuario.
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### test_command_not_in_allowlist_is_rejected `def test_command_not_in_allowlist_is_rejected(client)`
- Defined: `tests/test_command_execution.py:55`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### test_command_not_in_allowlist_returns_403 `def test_command_not_in_allowlist_returns_403(auth_client)`
- Defined: `tests/test_command_execution.py:65`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### test_command_validates_params `def test_command_validates_params(auth_client)`
- Defined: `tests/test_command_execution.py:77`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### test_command_missing_required_param `def test_command_missing_required_param(auth_client)`
- Defined: `tests/test_command_execution.py:87`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### test_command_rejects_unknown_params `def test_command_rejects_unknown_params(auth_client)`
- Defined: `tests/test_command_execution.py:97`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### test_command_requires_jwt `def test_command_requires_jwt(client)`
- Defined: `tests/test_command_execution.py:109`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### test_command_audit_recorded `def test_command_audit_recorded(auth_client, app)`
- Defined: `tests/test_command_execution.py:120`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### test_command_audit_records_error `def test_command_audit_records_error(auth_client, app)`
- Defined: `tests/test_command_execution.py:133`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### test_audit_endpoint_returns_records `def test_audit_endpoint_returns_records(auth_client)`
- Defined: `tests/test_command_execution.py:146`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### test_command_executes_via_python_call `def test_command_executes_via_python_call(auth_client, monkeypatch)`
- Defined: `tests/test_command_execution.py:161`
- Doc: Verifica que el handler se llama como función Python, no como shell.
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

### fake_handler `def fake_handler()`
- Defined: `tests/test_command_execution.py:165`
- Depends on: `lazyownbt/actions.py`, `lazyownbt/web.py`

## tests/test_configuration.py

### test_config_loads_from_env `def test_config_loads_from_env(monkeypatch)`
- Defined: `tests/test_configuration.py:18`
- Depends on: `lazyownbt/config.py`

### test_config_fails_loudly_on_missing_var `def test_config_fails_loudly_on_missing_var(monkeypatch)`
- Defined: `tests/test_configuration.py:27`
- Depends on: `lazyownbt/config.py`

### _extract_top_level_imports `def _extract_top_level_imports(source_files)`
- Defined: `tests/test_configuration.py:36`
- Doc: Extrae los nombres de paquetes top-level importados en cada archivo.
- Depends on: `lazyownbt/config.py`

### _declared_deps `def _declared_deps()`
- Defined: `tests/test_configuration.py:58`
- Depends on: `lazyownbt/config.py`

### _canonical `def _canonical(pkg)`
- Defined: `tests/test_configuration.py:85`
- Doc: Devuelve los nombres canónicos posibles para un paquete.
- Depends on: `lazyownbt/config.py`

### test_requirements_contains_all_imports `def test_requirements_contains_all_imports()`
- Defined: `tests/test_configuration.py:94`
- Doc: CFG-002.1/CFG-002.2: cada import del código debe estar declarado.
- Depends on: `lazyownbt/config.py`

### test_pyproject_extras_declared `def test_pyproject_extras_declared()`
- Defined: `tests/test_configuration.py:118`
- Doc: Los grupos cli, web, ai, rag, fim, utils, dev deben existir.
- Depends on: `lazyownbt/config.py`

## tests/test_production.py

### test_debug_flag_default_false `def test_debug_flag_default_false(monkeypatch)`
- Defined: `tests/test_production.py:13`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### test_debug_only_with_explicit_flag `def test_debug_only_with_explicit_flag(monkeypatch)`
- Defined: `tests/test_production.py:23`
- Doc: Si debug=True y FLASK_ENV=production, app.config['DEBUG'] debe ser False.
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### test_bind_default_loopback `def test_bind_default_loopback(monkeypatch)`
- Defined: `tests/test_production.py:34`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### test_bind_warns_when_public `def test_bind_warns_when_public(monkeypatch, caplog)`
- Defined: `tests/test_production.py:45`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### test_talisman_https_in_production `def test_talisman_https_in_production(monkeypatch)`
- Defined: `tests/test_production.py:58`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### test_talisman_no_https_in_development `def test_talisman_no_https_in_development(monkeypatch)`
- Defined: `tests/test_production.py:72`
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### test_csp_has_no_hardcoded_inline_hash `def test_csp_has_no_hardcoded_inline_hash()`
- Defined: `tests/test_production.py:82`
- Doc: SEC-003.4: no debe haber 'sha256-' en el código.
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

### test_cli_rejects_debug_in_production `def test_cli_rejects_debug_in_production(monkeypatch)`
- Defined: `tests/test_production.py:89`
- Doc: SEC-003.1: la CLI debe abortar si --debug y FLASK_ENV=production.
- Depends on: `lazyownbt/config.py`, `lazyownbt/web.py`

## tests/test_security.py

### _iter_source_files `def _iter_source_files()`
- Defined: `tests/test_security.py:20`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`

### test_no_hardcoded_jwt_secret `def test_no_hardcoded_jwt_secret()`
- Defined: `tests/test_security.py:27`
- Doc: SEC-001.1: la cadena literal 'your-secret-key' no debe existir en el código.
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`

### test_no_hardcoded_admin_password `def test_no_hardcoded_admin_password()`
- Defined: `tests/test_security.py:40`
- Doc: SEC-001.1: la comparación admin/password hardcodeada no debe existir.
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`

### test_app_aborts_when_jwt_secret_missing_in_prod `def test_app_aborts_when_jwt_secret_missing_in_prod(monkeypatch)`
- Defined: `tests/test_security.py:56`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`

### test_app_generates_ephemeral_secret_in_dev `def test_app_generates_ephemeral_secret_in_dev(monkeypatch, capsys)`
- Defined: `tests/test_security.py:66`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`

### test_jwt_secret_below_minimum_length_aborts `def test_jwt_secret_below_minimum_length_aborts(monkeypatch, bad_secret)`
- Defined: `tests/test_security.py:79`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`

### test_empty_jwt_secret_triggers_absence_rule `def test_empty_jwt_secret_triggers_absence_rule(monkeypatch)`
- Defined: `tests/test_security.py:88`
- Doc: Una variable presente pero vacía se trata como ausente (SEC-001.2).
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`

### test_password_is_hashed_not_plain `def test_password_is_hashed_not_plain(monkeypatch, tmp_path)`
- Defined: `tests/test_security.py:100`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`

### test_env_file_is_gitignored `def test_env_file_is_gitignored()`
- Defined: `tests/test_security.py:115`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`

### test_env_example_exists `def test_env_example_exists()`
- Defined: `tests/test_security.py:125`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`

### test_secrets_filter_redacts_values `def test_secrets_filter_redacts_values()`
- Defined: `tests/test_security.py:131`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`

### test_secrets_filter_redacts_in_args `def test_secrets_filter_redacts_in_args()`
- Defined: `tests/test_security.py:140`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`

### test_secrets_filter_redacts_in_dict_args `def test_secrets_filter_redacts_in_dict_args()`
- Defined: `tests/test_security.py:147`
- Depends on: `lazyownbt/config.py`, `lazyownbt/security.py`
