#!/home/grisun0/LazyOwn/env/bin/python3
"""
LazyOwnBT MCP Server
Exposes LazyOwnBT Blue Team framework capabilities as MCP tools for Claude Code.

Usage:
    python3 skills/lazyownbt_mcp.py

Configuration via environment variables:
    LAZYOWNBT_DIR     - Path to LazyOwnBT directory (default: parent of this file)
    LAZYOWNBT_CONFIG  - Path to config.json (default: <LAZYOWNBT_DIR>/config.json)
"""

import asyncio
import fcntl
import json
import os
import pty
import re
import select
import sqlite3
import struct
import subprocess
import sys
import termios
import time
from datetime import datetime
from pathlib import Path
from typing import Any

# ── MCP server import ─────────────────────────────────────────────────────────
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

# ── Paths ─────────────────────────────────────────────────────────────────────
SKILLS_DIR    = Path(__file__).parent
LAZYOWNBT_DIR = Path(os.environ.get("LAZYOWNBT_DIR", str(SKILLS_DIR.parent)))
CONFIG_FILE   = Path(os.environ.get("LAZYOWNBT_CONFIG", str(LAZYOWNBT_DIR / "config.json")))
DB_PATH       = LAZYOWNBT_DIR / "lazyown.db"
REPORTS_DIR   = LAZYOWNBT_DIR / "reports"
QUARANTINE_DIR= LAZYOWNBT_DIR / "quarantine"

# ── MCP server ────────────────────────────────────────────────────────────────
server = Server("lazyownbt")

# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_config() -> dict:
    """Load config.json, return empty dict on failure."""
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception as e:
        return {"_error": str(e)}


def _save_config(data: dict) -> str:
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)
        return "ok"
    except Exception as e:
        return f"error: {e}"


def _db_query(sql: str, params: tuple = ()) -> list[dict]:
    """Execute a read query against lazyown.db."""
    if not DB_PATH.exists():
        return []
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cur = conn.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def _run_lazyownbt_command(command: str, timeout: int = 30) -> str:
    """
    Execute one or more LazyOwnBT CLI commands non-interactively via a PTY.
    Sends commands to the app.py interactive shell, drains output, and returns it.
    """
    cmd_input = (command.strip() + "\nexit\n").encode()

    argv = [sys.executable, "-W", "ignore", str(LAZYOWNBT_DIR / "app.py")]

    env = os.environ.copy()
    env["TERM"] = "xterm-256color"

    master_fd, slave_fd = pty.openpty()
    winsize = struct.pack("HHHH", 50, 220, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)

    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            cwd=str(LAZYOWNBT_DIR),
            start_new_session=True,
        )
        os.close(slave_fd)

        try:
            proc.stdin.write(cmd_input)
            proc.stdin.close()
        except BrokenPipeError:
            pass

        output_chunks: list[str] = []
        deadline = time.monotonic() + timeout

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                os.close(master_fd)
                return f"[timeout] Command exceeded {timeout}s"

            r, _, _ = select.select([master_fd], [], [], min(remaining, 0.5))
            if r:
                try:
                    data = os.read(master_fd, 4096)
                    if data:
                        output_chunks.append(data.decode("utf-8", errors="replace"))
                except OSError:
                    break
            else:
                if proc.poll() is not None:
                    try:
                        while True:
                            r2, _, _ = select.select([master_fd], [], [], 0.1)
                            if not r2:
                                break
                            data = os.read(master_fd, 4096)
                            if not data:
                                break
                            output_chunks.append(data.decode("utf-8", errors="replace"))
                    except OSError:
                        pass
                    break

        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    output = "".join(output_chunks)
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", output).strip()


# ── Tool definitions ──────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        # ── Ejecución de comandos ─────────────────────────────────────────────
        types.Tool(
            name="lazyownbt_run_command",
            description=(
                "Ejecuta uno o más comandos en la shell interactiva de LazyOwnBT. "
                "Separa múltiples comandos con saltos de línea. "
                "Ejemplos: 'proc_scan', 'net_scan', 'log_analyze', 'sysinfo'."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Comando(s) de LazyOwnBT a ejecutar (separados por newline).",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Segundos máximos de espera (default 30).",
                        "default": 30,
                    },
                },
                "required": ["command"],
            },
        ),
        # ── Configuración ─────────────────────────────────────────────────────
        types.Tool(
            name="lazyownbt_get_config",
            description=(
                "Lee la configuración actual de LazyOwnBT (config.json). "
                "Devuelve rutas de logs, umbrales de alerta, archivos críticos, "
                "puertos sospechosos, procesos sospechosos y parámetros de IA."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_set_config",
            description=(
                "Actualiza una clave en config.json de LazyOwnBT. "
                "Claves comunes: alert_threshold, scan_interval, max_failed_logins, "
                "enable_auto_response, output_dir, database_path."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "Clave de config.json a actualizar.",
                    },
                    "value": {
                        "type": "string",
                        "description": "Valor a establecer (se auto-convierte a número/bool).",
                    },
                },
                "required": ["key", "value"],
            },
        ),
        # ── Información del sistema ───────────────────────────────────────────
        types.Tool(
            name="lazyownbt_sysinfo",
            description=(
                "Obtiene información detallada del sistema: CPU, RAM, disco, "
                "OS, hostname, uptime, usuarios activos y resumen de seguridad."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        # ── Detección de procesos ─────────────────────────────────────────────
        types.Tool(
            name="lazyownbt_proc_scan",
            description=(
                "Escanea los procesos en ejecución buscando actividad sospechosa. "
                "Detecta: netcat, msfvenom, meterpreter, socat, kworkerds y otros. "
                "Analiza nombre, PID, uso de CPU/memoria y conexiones de red."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        # ── Detección de red ──────────────────────────────────────────────────
        types.Tool(
            name="lazyownbt_net_scan",
            description=(
                "Escanea conexiones de red activas buscando puertos sospechosos "
                "y conexiones no autorizadas. Detecta puertos: 23, 2323, 4444, "
                "5555, 6666, 31337, 65535 y otros configurados como sospechosos."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_net_baseline",
            description=(
                "Establece o carga la línea base de red normal del sistema. "
                "Útil para detectar nuevas conexiones o servicios no autorizados "
                "comparando con el estado de red esperado."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "'create' para crear baseline, 'show' para mostrar el actual.",
                        "enum": ["create", "show"],
                        "default": "show",
                    },
                },
            },
        ),
        types.Tool(
            name="lazyownbt_net_conns",
            description=(
                "Muestra análisis detallado de conexiones de red activas: "
                "dirección local/remota, estado, PID, nombre de proceso. "
                "Agrupa por estado (ESTABLISHED, LISTEN, TIME_WAIT, etc.)."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        # ── Integridad de archivos (FIM) ───────────────────────────────────────
        types.Tool(
            name="lazyownbt_fim_baseline",
            description=(
                "Crea la línea base de integridad de archivos críticos. "
                "Calcula hashes SHA-256 de archivos configurados como críticos: "
                "/etc/passwd, /etc/shadow, /etc/sudoers, /etc/ssh/sshd_config, etc. "
                "Almacena los hashes en la base de datos SQLite."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_fim_scan",
            description=(
                "Escanea archivos críticos comparando sus hashes actuales contra "
                "la línea base almacenada. Detecta modificaciones no autorizadas, "
                "archivos eliminados o archivos nuevos no esperados. "
                "Genera alertas para cualquier discrepancia encontrada."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_add_critical_file",
            description=(
                "Agrega un archivo a la lista de archivos críticos monitoreados "
                "por el sistema de integridad de archivos (FIM). "
                "El archivo se incluirá en el próximo baseline y escaneo FIM."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Ruta absoluta del archivo a monitorear.",
                    },
                },
                "required": ["filepath"],
            },
        ),
        # ── Análisis de logs ──────────────────────────────────────────────────
        types.Tool(
            name="lazyownbt_log_analyze",
            description=(
                "Analiza logs del sistema buscando patrones de amenazas: "
                "intentos de fuerza bruta, escaladas de privilegios, inyecciones, "
                "accesos no autorizados, anomalías SSH y actividad sospechosa. "
                "Usa IA/ML para detectar amenazas desconocidas. "
                "Rutas de logs configuradas: /var/log/syslog, /var/log/auth.log, etc."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "log_path": {
                        "type": "string",
                        "description": "Ruta de log específica a analizar (opcional, usa config si no se especifica).",
                        "default": "",
                    },
                },
            },
        ),
        types.Tool(
            name="lazyownbt_monitor_start",
            description=(
                "Inicia el monitoreo en tiempo real de logs del sistema. "
                "Vigila archivos de log en busca de patrones sospechosos "
                "y genera alertas inmediatas cuando se detectan amenazas."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "duration": {
                        "type": "integer",
                        "description": "Segundos a monitorear (0 = indefinido, default 60).",
                        "default": 60,
                    },
                },
            },
        ),
        # ── Endurecimiento del sistema ─────────────────────────────────────────
        types.Tool(
            name="lazyownbt_harden_audit_ssh",
            description=(
                "Audita la configuración SSH del sistema buscando debilidades: "
                "root login habilitado, autenticación por password, puerto por defecto, "
                "versión insegura, MaxAuthTries alto, etc. "
                "Devuelve recomendaciones de endurecimiento."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_harden_system",
            description=(
                "Ejecuta una auditoría completa de endurecimiento del sistema: "
                "parámetros de kernel (sysctl), reglas de firewall (iptables/nftables), "
                "permisos de usuarios, servicios innecesarios habilitados, "
                "configuración de PAM y políticas de contraseñas."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_check_security",
            description=(
                "Realiza una revisión rápida de la postura de seguridad del sistema: "
                "usuarios con privilegios, archivos SUID/SGID, puertos abiertos, "
                "servicios en ejecución, actualizaciones pendientes y configuraciones inseguras."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        # ── Respuesta a incidentes ─────────────────────────────────────────────
        types.Tool(
            name="lazyownbt_block_ip",
            description=(
                "Bloquea una dirección IP maliciosa usando iptables. "
                "Agrega una regla DROP en la cadena INPUT para la IP especificada. "
                "Registra la acción en la base de datos de eventos de seguridad."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Dirección IP a bloquear (IPv4 o IPv6).",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Motivo del bloqueo (para registro).",
                        "default": "Actividad sospechosa detectada",
                    },
                },
                "required": ["ip"],
            },
        ),
        types.Tool(
            name="lazyownbt_quarantine_file",
            description=(
                "Mueve un archivo sospechoso al directorio de cuarentena. "
                "Preserva el archivo para análisis posterior mientras lo aísla. "
                "El directorio de cuarentena por defecto es ./quarantine/"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Ruta absoluta del archivo a poner en cuarentena.",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Motivo de la cuarentena.",
                        "default": "Archivo sospechoso detectado",
                    },
                },
                "required": ["filepath"],
            },
        ),
        types.Tool(
            name="lazyownbt_kill_process",
            description=(
                "Termina un proceso sospechoso por su PID o nombre. "
                "Registra la acción en el log de incidentes. "
                "Usa SIGTERM primero, luego SIGKILL si no responde."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "PID del proceso a terminar.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Nombre del proceso (alternativa al PID).",
                        "default": "",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Motivo de la terminación.",
                        "default": "Proceso sospechoso",
                    },
                },
                "required": [],
            },
        ),
        # ── IA y detección inteligente ─────────────────────────────────────────
        types.Tool(
            name="lazyownbt_ai_status",
            description=(
                "Muestra el estado del modelo de IA de detección de amenazas: "
                "si está cargado, versión del modelo, precisión reportada, "
                "umbral de detección configurado y estadísticas de uso."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_ai_test",
            description=(
                "Prueba un comando contra el modelo de IA de detección de amenazas. "
                "El modelo RandomForest con TF-IDF analiza si el comando es malicioso. "
                "Devuelve: predicción (malicious/benign), confianza y características detectadas."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Comando a analizar con el modelo de IA.",
                    },
                },
                "required": ["command"],
            },
        ),
        types.Tool(
            name="lazyownbt_ai_feedback",
            description=(
                "Proporciona retroalimentación al modelo de IA para mejorar su precisión. "
                "Indica si un comando fue correctamente clasificado o no. "
                "Los datos de feedback se acumulan para el reentrenamiento."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Comando evaluado.",
                    },
                    "is_malicious": {
                        "type": "boolean",
                        "description": "True si el comando ES malicioso, False si es benigno.",
                    },
                    "model_was_correct": {
                        "type": "boolean",
                        "description": "True si el modelo acertó, False si falló.",
                    },
                },
                "required": ["command", "is_malicious"],
            },
        ),
        types.Tool(
            name="lazyownbt_ai_retrain",
            description=(
                "Reentrena el modelo de IA usando los datos de feedback acumulados. "
                "Mejora la precisión del detector con casos reales del entorno. "
                "El proceso puede tomar varios minutos dependiendo del dataset."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        # ── RAG / Knowledge Base ──────────────────────────────────────────────
        types.Tool(
            name="lazyownbt_rag_query",
            description=(
                "Consulta la base de conocimiento RAG de LazyOwnBT usando LLM local (Ollama). "
                "Busca en documentos indexados: logs, reportes, guías de seguridad, "
                "playbooks de respuesta a incidentes y documentación técnica. "
                "Usa deepseek-r1:1.5b para generar respuestas contextualizadas."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Pregunta o consulta en lenguaje natural.",
                    },
                },
                "required": ["query"],
            },
        ),
        types.Tool(
            name="lazyownbt_rag_add",
            description=(
                "Agrega un archivo a la base de conocimiento RAG de LazyOwnBT. "
                "Soporta: PDF, TXT, MD, LOG, YAML, CSV, JSON, archivos NMAP. "
                "El documento se divide en chunks y se indexa con embeddings."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Ruta del archivo a indexar.",
                    },
                },
                "required": ["filepath"],
            },
        ),
        types.Tool(
            name="lazyownbt_rag_status",
            description=(
                "Muestra el estado de la base de conocimiento RAG: "
                "número de documentos indexados, tamaño de la base vectorial, "
                "estado de Ollama y métricas de caché."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_rag_search",
            description=(
                "Búsqueda semántica en la base de conocimiento RAG sin generar respuesta LLM. "
                "Devuelve los chunks más relevantes con su puntuación de similitud. "
                "Útil para encontrar documentación específica o logs relacionados."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Término o frase a buscar.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Número máximo de resultados (default 5).",
                        "default": 5,
                    },
                },
                "required": ["query"],
            },
        ),
        # ── Escaneo de memoria ────────────────────────────────────────────────
        types.Tool(
            name="lazyownbt_memory_scan",
            description=(
                "Escanea la memoria de procesos en busca de strings maliciosos: "
                "shellcodes, exploits conocidos, strings de C2, credenciales en texto plano, "
                "firmas de malware y código de inyección. "
                "Analiza el espacio de memoria accesible de los procesos en ejecución."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "PID específico a escanear (0 = todos los procesos).",
                        "default": 0,
                    },
                },
            },
        ),
        # ── Auditoría de usuarios ─────────────────────────────────────────────
        types.Tool(
            name="lazyownbt_audit_users",
            description=(
                "Audita las cuentas de usuario del sistema: "
                "usuarios con UID 0 (root), cuentas sin contraseña, "
                "usuarios con shell válida, grupos privilegiados (sudo, wheel), "
                "últimos accesos y cuentas inactivas sospechosas."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        # ── RedTeam Hunt ──────────────────────────────────────────────────────
        types.Tool(
            name="lazyownbt_redteam_hunt",
            description=(
                "Ejecuta técnicas de threat hunting orientadas a TTPs de red team: "
                "busca indicadores de compromiso (IOCs), técnicas MITRE ATT&CK, "
                "persistencia sospechosa (cron, systemd, rc.local), "
                "herramientas de pentesting instaladas y backdoors conocidos."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        # ── Reportes ──────────────────────────────────────────────────────────
        types.Tool(
            name="lazyownbt_report_summary",
            description=(
                "Genera un reporte resumido de seguridad del estado actual del sistema: "
                "alertas activas, hallazgos de integridad, conexiones sospechosas, "
                "procesos maliciosos detectados y recomendaciones de mitigación."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "description": "Formato de salida: 'text' (default) o 'json'.",
                        "enum": ["text", "json"],
                        "default": "text",
                    },
                },
            },
        ),
        types.Tool(
            name="lazyownbt_report_processes",
            description=(
                "Genera reporte detallado de procesos: todos los procesos activos, "
                "consumo de recursos, conexiones de red por proceso, "
                "árbol de procesos y anomalías detectadas."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_report_network",
            description=(
                "Genera reporte de red: conexiones activas, puertos en escucha, "
                "tráfico sospechoso detectado, desvíos de la línea base "
                "y recomendaciones de segmentación de red."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_report_files",
            description=(
                "Genera reporte de integridad de archivos: archivos modificados, "
                "nuevos archivos en directorios críticos, permisos incorrectos "
                "y archivos en cuarentena."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        # ── Base de datos de alertas ───────────────────────────────────────────
        types.Tool(
            name="lazyownbt_list_alerts",
            description=(
                "Lista las alertas de seguridad almacenadas en la base de datos SQLite. "
                "Filtra por severidad, tipo, estado (activa/resuelta) o rango de fechas. "
                "Devuelve timestamp, tipo, severidad, descripción y estado."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "description": "Filtrar por severidad: 'critical', 'high', 'medium', 'low', 'all'.",
                        "enum": ["critical", "high", "medium", "low", "all"],
                        "default": "all",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Número máximo de alertas a devolver (default 20).",
                        "default": 20,
                    },
                    "status": {
                        "type": "string",
                        "description": "Filtrar por estado: 'active', 'resolved', 'all'.",
                        "enum": ["active", "resolved", "all"],
                        "default": "active",
                    },
                },
            },
        ),
        types.Tool(
            name="lazyownbt_list_events",
            description=(
                "Lista los eventos de seguridad registrados en la base de datos. "
                "Incluye: accesos, cambios de archivo, conexiones bloqueadas, "
                "procesos terminados y acciones de respuesta a incidentes."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "event_type": {
                        "type": "string",
                        "description": "Tipo de evento a filtrar (vacío = todos).",
                        "default": "",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Número máximo de eventos (default 20).",
                        "default": 20,
                    },
                },
            },
        ),
        # ── Descubrimiento de comandos ─────────────────────────────────────────
        types.Tool(
            name="lazyownbt_discover_commands",
            description=(
                "Descubre todos los comandos disponibles en la shell de LazyOwnBT: "
                "comandos integrados, plugins Lua, addons YAML y comandos de auditoría. "
                "Devuelve comandos agrupados por categoría con descripción."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_command_help",
            description=(
                "Obtiene la documentación completa de un comando de LazyOwnBT: "
                "parámetros, descripción, ejemplos de uso y notas de seguridad."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Nombre del comando (ej: 'proc_scan', 'log_analyze', 'fim_scan').",
                    },
                },
                "required": ["command"],
            },
        ),
        # ── Patterns y reglas ──────────────────────────────────────────────────
        types.Tool(
            name="lazyownbt_list_patterns",
            description=(
                "Lista los patrones de detección de amenazas configurados en LazyOwnBT. "
                "Incluye patrones de log, firmas de procesos sospechosos, "
                "strings de malware y reglas de detección de red."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_add_suspicious_process",
            description=(
                "Agrega un nombre de proceso a la lista de procesos sospechosos monitoreados. "
                "LazyOwnBT generará alertas cuando detecte este proceso en ejecución."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "process_name": {
                        "type": "string",
                        "description": "Nombre del proceso a marcar como sospechoso.",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Por qué este proceso es sospechoso.",
                        "default": "",
                    },
                },
                "required": ["process_name"],
            },
        ),
        types.Tool(
            name="lazyownbt_add_suspicious_port",
            description=(
                "Agrega un puerto a la lista de puertos sospechosos monitoreados. "
                "LazyOwnBT generará alertas cuando detecte conexiones en este puerto."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "port": {
                        "type": "integer",
                        "description": "Número de puerto a marcar como sospechoso.",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Por qué este puerto es sospechoso.",
                        "default": "",
                    },
                },
                "required": ["port"],
            },
        ),
        # ── Información de sesión y contexto ───────────────────────────────────
        types.Tool(
            name="lazyownbt_db_stats",
            description=(
                "Muestra estadísticas de la base de datos SQLite de LazyOwnBT: "
                "número de alertas por tipo/severidad, eventos registrados, "
                "hashes de archivos almacenados y baseline de red."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_list_reports",
            description=(
                "Lista los reportes generados en el directorio ./reports/. "
                "Muestra nombre, tamaño y fecha de creación de cada reporte."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="lazyownbt_read_report",
            description=(
                "Lee el contenido de un reporte generado por LazyOwnBT. "
                "Devuelve el contenido del archivo (truncado a 8000 chars si es muy largo)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Nombre del archivo de reporte dentro de ./reports/.",
                    },
                },
                "required": ["filename"],
            },
        ),
    ]


# ── Tool handlers ─────────────────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:

    def text(content: str) -> list[types.TextContent]:
        return [types.TextContent(type="text", text=content)]

    # ── run_command ──────────────────────────────────────────────────────────
    if name == "lazyownbt_run_command":
        command = arguments["command"]
        timeout = int(arguments.get("timeout", 30))
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(command, timeout)
        )
        return text(output)

    # ── get_config ───────────────────────────────────────────────────────────
    elif name == "lazyownbt_get_config":
        cfg = _load_config()
        return text(json.dumps(cfg, indent=2))

    # ── set_config ───────────────────────────────────────────────────────────
    elif name == "lazyownbt_set_config":
        key     = arguments["key"].strip()
        raw_val = arguments["value"]
        value: Any = raw_val
        if isinstance(raw_val, str):
            if raw_val.lower() == "true":
                value = True
            elif raw_val.lower() == "false":
                value = False
            else:
                try:
                    value = int(raw_val)
                except ValueError:
                    try:
                        value = float(raw_val)
                    except ValueError:
                        value = raw_val
        cfg = _load_config()
        if "_error" in cfg:
            return text(f"No se puede cargar config.json: {cfg['_error']}")
        # Handle nested keys via dot notation: "ai_detection.threshold"
        if "." in key:
            parts = key.split(".", 1)
            if isinstance(cfg.get(parts[0]), dict):
                cfg[parts[0]][parts[1]] = value
            else:
                cfg[key] = value
        else:
            cfg[key] = value
        result = _save_config(cfg)
        if result == "ok":
            return text(f"Configurado: {key} = {value!r}")
        return text(result)

    # ── sysinfo ──────────────────────────────────────────────────────────────
    elif name == "lazyownbt_sysinfo":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("sysinfo", timeout=20)
        )
        return text(output)

    # ── proc_scan ────────────────────────────────────────────────────────────
    elif name == "lazyownbt_proc_scan":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("proc_scan", timeout=30)
        )
        return text(output)

    # ── net_scan ─────────────────────────────────────────────────────────────
    elif name == "lazyownbt_net_scan":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("net_scan", timeout=30)
        )
        return text(output)

    # ── net_baseline ─────────────────────────────────────────────────────────
    elif name == "lazyownbt_net_baseline":
        action = arguments.get("action", "show")
        cmd = "net_baseline" if action == "create" else "net_conns"
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(cmd, timeout=30)
        )
        return text(output)

    # ── net_conns ────────────────────────────────────────────────────────────
    elif name == "lazyownbt_net_conns":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("net_conns", timeout=20)
        )
        return text(output)

    # ── fim_baseline ─────────────────────────────────────────────────────────
    elif name == "lazyownbt_fim_baseline":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("fim_baseline", timeout=30)
        )
        return text(output)

    # ── fim_scan ─────────────────────────────────────────────────────────────
    elif name == "lazyownbt_fim_scan":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("fim_scan", timeout=30)
        )
        return text(output)

    # ── add_critical_file ─────────────────────────────────────────────────────
    elif name == "lazyownbt_add_critical_file":
        filepath = arguments["filepath"].strip()
        cfg = _load_config()
        if "_error" in cfg:
            return text(f"Error al cargar config.json: {cfg['_error']}")
        critical = cfg.get("critical_files", [])
        if filepath in critical:
            return text(f"El archivo ya está en la lista de archivos críticos: {filepath}")
        critical.append(filepath)
        cfg["critical_files"] = critical
        _save_config(cfg)
        return text(f"Archivo agregado a monitoreo FIM: {filepath}\nTotal archivos críticos: {len(critical)}")

    # ── log_analyze ──────────────────────────────────────────────────────────
    elif name == "lazyownbt_log_analyze":
        log_path = arguments.get("log_path", "").strip()
        if log_path:
            cmd = f"log_analyze {log_path}"
        else:
            cmd = "log_analyze"
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(cmd, timeout=60)
        )
        return text(output)

    # ── monitor_start ────────────────────────────────────────────────────────
    elif name == "lazyownbt_monitor_start":
        duration = int(arguments.get("duration", 60))
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("monitor", timeout=duration + 5)
        )
        return text(output)

    # ── harden_audit_ssh ─────────────────────────────────────────────────────
    elif name == "lazyownbt_harden_audit_ssh":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("harden_audit_ssh", timeout=20)
        )
        return text(output)

    # ── harden_system ────────────────────────────────────────────────────────
    elif name == "lazyownbt_harden_system":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("harden_system", timeout=30)
        )
        return text(output)

    # ── check_security ───────────────────────────────────────────────────────
    elif name == "lazyownbt_check_security":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("check_security", timeout=30)
        )
        return text(output)

    # ── block_ip ─────────────────────────────────────────────────────────────
    elif name == "lazyownbt_block_ip":
        ip     = arguments["ip"].strip()
        reason = arguments.get("reason", "Actividad sospechosa detectada")
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(f"block_ip {ip}", timeout=15)
        )
        # Also write to events DB directly for audit trail
        try:
            if DB_PATH.exists():
                conn = sqlite3.connect(str(DB_PATH))
                conn.execute(
                    "INSERT OR IGNORE INTO security_events (timestamp, event_type, description, severity) "
                    "VALUES (?, 'IP_BLOCKED', ?, 'high')",
                    (datetime.now().isoformat(), f"Blocked IP {ip}: {reason}")
                )
                conn.commit()
                conn.close()
        except Exception:
            pass
        return text(f"Comando ejecutado: block_ip {ip}\nMotivo: {reason}\n\n{output}")

    # ── quarantine_file ──────────────────────────────────────────────────────
    elif name == "lazyownbt_quarantine_file":
        filepath = arguments["filepath"].strip()
        reason   = arguments.get("reason", "Archivo sospechoso detectado")
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(f"quarantine_file {filepath}", timeout=15)
        )
        return text(f"Cuarentena solicitada: {filepath}\nMotivo: {reason}\n\n{output}")

    # ── kill_process ─────────────────────────────────────────────────────────
    elif name == "lazyownbt_kill_process":
        pid          = arguments.get("pid")
        process_name = arguments.get("process_name", "").strip()
        reason       = arguments.get("reason", "Proceso sospechoso")
        if pid:
            cmd = f"kill_process {pid}"
        elif process_name:
            cmd = f"kill_process {process_name}"
        else:
            return text("[kill_process] Se requiere 'pid' o 'process_name'.")
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(cmd, timeout=15)
        )
        return text(f"Terminación solicitada — Motivo: {reason}\n\n{output}")

    # ── ai_status ────────────────────────────────────────────────────────────
    elif name == "lazyownbt_ai_status":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("ai_status", timeout=15)
        )
        # Supplement with model file info
        model_dir = LAZYOWNBT_DIR / "sessions" / "ai_model"
        model_info = []
        for f in model_dir.glob("*.pkl"):
            size_kb = f.stat().st_size // 1024
            model_info.append(f"  {f.name} ({size_kb} KB)")
        if model_info:
            output += "\n\nArchivos de modelo:\n" + "\n".join(model_info)
        cfg = _load_config()
        ai_cfg = cfg.get("ai_detection", {})
        output += f"\n\nConfiguración IA:\n{json.dumps(ai_cfg, indent=2)}"
        return text(output)

    # ── ai_test ──────────────────────────────────────────────────────────────
    elif name == "lazyownbt_ai_test":
        command = arguments["command"]
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(f"ai_test {command}", timeout=15)
        )
        return text(output)

    # ── ai_feedback ──────────────────────────────────────────────────────────
    elif name == "lazyownbt_ai_feedback":
        command    = arguments["command"]
        is_mal     = arguments["is_malicious"]
        was_correct= arguments.get("model_was_correct", True)
        label = "malicious" if is_mal else "benign"
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(f"ai_feedback {command}", timeout=15)
        )
        return text(
            f"Feedback registrado:\n"
            f"  Comando: {command}\n"
            f"  Etiqueta: {label}\n"
            f"  Modelo correcto: {was_correct}\n\n"
            f"{output}"
        )

    # ── ai_retrain ───────────────────────────────────────────────────────────
    elif name == "lazyownbt_ai_retrain":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("ai_retrain", timeout=120)
        )
        return text(output)

    # ── rag_query ────────────────────────────────────────────────────────────
    elif name == "lazyownbt_rag_query":
        query = arguments["query"]
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(f"rag_query {query}", timeout=60)
        )
        return text(output)

    # ── rag_add ──────────────────────────────────────────────────────────────
    elif name == "lazyownbt_rag_add":
        filepath = arguments["filepath"].strip()
        if not Path(filepath).exists():
            return text(f"[rag_add] Archivo no encontrado: {filepath}")
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(f"rag_add {filepath}", timeout=60)
        )
        return text(output)

    # ── rag_status ───────────────────────────────────────────────────────────
    elif name == "lazyownbt_rag_status":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("rag_status", timeout=20)
        )
        return text(output)

    # ── rag_search ───────────────────────────────────────────────────────────
    elif name == "lazyownbt_rag_search":
        query = arguments["query"]
        limit = int(arguments.get("limit", 5))
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(f"rag_search {query}", timeout=30)
        )
        return text(output)

    # ── memory_scan ──────────────────────────────────────────────────────────
    elif name == "lazyownbt_memory_scan":
        pid = int(arguments.get("pid", 0))
        if pid:
            cmd = f"scan_memory {pid}"
        else:
            cmd = "scan_memory"
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(cmd, timeout=60)
        )
        return text(output)

    # ── audit_users ──────────────────────────────────────────────────────────
    elif name == "lazyownbt_audit_users":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("audit_users", timeout=20)
        )
        return text(output)

    # ── redteam_hunt ─────────────────────────────────────────────────────────
    elif name == "lazyownbt_redteam_hunt":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("redteam_hunt", timeout=60)
        )
        return text(output)

    # ── report_summary ───────────────────────────────────────────────────────
    elif name == "lazyownbt_report_summary":
        fmt = arguments.get("format", "text")
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("report_summary", timeout=30)
        )
        if fmt == "json":
            # Wrap in JSON structure for programmatic consumption
            return text(json.dumps({
                "timestamp": datetime.now().isoformat(),
                "source":    "lazyownbt_report_summary",
                "output":    output,
            }, indent=2))
        return text(output)

    # ── report_processes ─────────────────────────────────────────────────────
    elif name == "lazyownbt_report_processes":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("process", timeout=30)
        )
        return text(output)

    # ── report_network ───────────────────────────────────────────────────────
    elif name == "lazyownbt_report_network":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("network", timeout=30)
        )
        return text(output)

    # ── report_files ─────────────────────────────────────────────────────────
    elif name == "lazyownbt_report_files":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("files", timeout=30)
        )
        return text(output)

    # ── list_alerts ──────────────────────────────────────────────────────────
    elif name == "lazyownbt_list_alerts":
        severity = arguments.get("severity", "all")
        limit    = int(arguments.get("limit", 20))
        status   = arguments.get("status", "active")

        def _query_alerts() -> str:
            conditions = []
            params: list = []
            if severity != "all":
                conditions.append("severity = ?")
                params.append(severity)
            if status != "all":
                conditions.append("status = ?")
                params.append(status)
            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
            sql = f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            rows = _db_query(sql, tuple(params))
            if not rows:
                return f"No hay alertas{' con severidad=' + severity if severity != 'all' else ''} en la base de datos."
            lines = [f"Alertas ({len(rows)}):\n"]
            sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
            for r in rows:
                icon = sev_icon.get(str(r.get("severity", "")).lower(), "⚪")
                ts   = str(r.get("timestamp", ""))[:19]
                lines.append(
                    f"{icon} [{ts}] [{r.get('severity','?'):8s}] {r.get('type', r.get('alert_type','?'))}"
                )
                lines.append(f"   {r.get('description', r.get('message', ''))[:100]}")
            return "\n".join(lines)

        result = await asyncio.get_event_loop().run_in_executor(None, _query_alerts)
        return text(result)

    # ── list_events ──────────────────────────────────────────────────────────
    elif name == "lazyownbt_list_events":
        event_type = arguments.get("event_type", "").strip()
        limit      = int(arguments.get("limit", 20))

        def _query_events() -> str:
            if event_type:
                rows = _db_query(
                    "SELECT * FROM security_events WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
                    (event_type, limit)
                )
            else:
                rows = _db_query(
                    "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                )
            if not rows:
                return "No hay eventos de seguridad registrados."
            lines = [f"Eventos de seguridad ({len(rows)}):\n"]
            for r in rows:
                ts = str(r.get("timestamp", ""))[:19]
                lines.append(
                    f"[{ts}] [{r.get('event_type','?'):20s}] [{r.get('severity','info'):8s}]"
                )
                lines.append(f"   {r.get('description', '')[:120]}")
            return "\n".join(lines)

        result = await asyncio.get_event_loop().run_in_executor(None, _query_events)
        return text(result)

    # ── discover_commands ────────────────────────────────────────────────────
    elif name == "lazyownbt_discover_commands":
        raw = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("help", timeout=20)
        )
        return text(raw[:6000] if raw else "No se pudo obtener la lista de comandos.")

    # ── command_help ─────────────────────────────────────────────────────────
    elif name == "lazyownbt_command_help":
        cmd = arguments["command"].strip()
        raw = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command(f"help {cmd}", timeout=15)
        )
        return text(raw[:4000] if raw else f"No se encontró ayuda para '{cmd}'.")

    # ── list_patterns ────────────────────────────────────────────────────────
    elif name == "lazyownbt_list_patterns":
        output = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _run_lazyownbt_command("patterns", timeout=15)
        )
        cfg = _load_config()
        supplement = (
            f"\n\nProcesos sospechosos configurados:\n"
            + "\n".join(f"  - {p}" for p in cfg.get("suspicious_processes", []))
            + f"\n\nPuertos sospechosos configurados:\n"
            + "\n".join(f"  - {p}" for p in cfg.get("suspicious_ports", []))
        )
        return text(output + supplement)

    # ── add_suspicious_process ────────────────────────────────────────────────
    elif name == "lazyownbt_add_suspicious_process":
        process_name = arguments["process_name"].strip()
        reason       = arguments.get("reason", "")
        cfg = _load_config()
        if "_error" in cfg:
            return text(f"Error al cargar config.json: {cfg['_error']}")
        procs = cfg.get("suspicious_processes", [])
        if process_name in procs:
            return text(f"El proceso '{process_name}' ya está en la lista sospechosa.")
        procs.append(process_name)
        cfg["suspicious_processes"] = procs
        _save_config(cfg)
        note = f" — Motivo: {reason}" if reason else ""
        return text(
            f"Proceso '{process_name}' agregado a la lista sospechosa{note}.\n"
            f"Total procesos monitoreados: {len(procs)}"
        )

    # ── add_suspicious_port ──────────────────────────────────────────────────
    elif name == "lazyownbt_add_suspicious_port":
        port   = int(arguments["port"])
        reason = arguments.get("reason", "")
        cfg = _load_config()
        if "_error" in cfg:
            return text(f"Error al cargar config.json: {cfg['_error']}")
        ports = cfg.get("suspicious_ports", [])
        if port in ports:
            return text(f"El puerto {port} ya está en la lista sospechosa.")
        ports.append(port)
        cfg["suspicious_ports"] = sorted(ports)
        _save_config(cfg)
        note = f" — Motivo: {reason}" if reason else ""
        return text(
            f"Puerto {port} agregado a la lista sospechosa{note}.\n"
            f"Total puertos monitoreados: {len(ports)}"
        )

    # ── db_stats ─────────────────────────────────────────────────────────────
    elif name == "lazyownbt_db_stats":
        def _stats() -> str:
            if not DB_PATH.exists():
                return f"Base de datos no encontrada: {DB_PATH}"
            lines = [f"Base de datos: {DB_PATH}\n"]
            # Get table names
            tables = _db_query("SELECT name FROM sqlite_master WHERE type='table'")
            for t in tables:
                tname = t["name"]
                count_rows = _db_query(f"SELECT COUNT(*) as c FROM {tname}")
                count = count_rows[0]["c"] if count_rows else 0
                lines.append(f"  {tname:<30} {count:>6} registros")
            # Alert breakdown by severity
            sev_rows = _db_query(
                "SELECT severity, COUNT(*) as c FROM alerts GROUP BY severity"
            )
            if sev_rows:
                lines.append("\nAlertas por severidad:")
                for r in sev_rows:
                    lines.append(f"  {r.get('severity','?'):10s} {r['c']}")
            # DB file size
            size_kb = DB_PATH.stat().st_size // 1024
            lines.append(f"\nTamaño de la BD: {size_kb} KB")
            return "\n".join(lines)

        result = await asyncio.get_event_loop().run_in_executor(None, _stats)
        return text(result)

    # ── list_reports ─────────────────────────────────────────────────────────
    elif name == "lazyownbt_list_reports":
        def _list_reports() -> str:
            reports_dir = LAZYOWNBT_DIR / "reports"
            if not reports_dir.exists():
                return "Directorio de reportes no encontrado: ./reports/"
            files = sorted(reports_dir.iterdir(), key=lambda f: f.stat().st_mtime, reverse=True)
            if not files:
                return "No hay reportes generados aún. Use lazyownbt_report_summary para crear uno."
            lines = [f"Reportes en {reports_dir} ({len(files)} archivos):\n"]
            for f in files:
                if f.is_file():
                    size_kb = f.stat().st_size // 1024
                    mtime   = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                    lines.append(f"  {f.name:<40} {size_kb:>5} KB  {mtime}")
            return "\n".join(lines)

        result = await asyncio.get_event_loop().run_in_executor(None, _list_reports)
        return text(result)

    # ── read_report ──────────────────────────────────────────────────────────
    elif name == "lazyownbt_read_report":
        filename = arguments["filename"].lstrip("/")
        target   = LAZYOWNBT_DIR / "reports" / filename
        # Safety: prevent path traversal
        try:
            target.resolve().relative_to((LAZYOWNBT_DIR / "reports").resolve())
        except ValueError:
            return text("Error: path traversal no permitido.")
        try:
            content = target.read_text(errors="replace")
            if len(content) > 8000:
                content = content[:8000] + "\n... [truncado — archivo muy largo]"
            return text(content)
        except FileNotFoundError:
            return text(f"Reporte no encontrado: {filename}")
        except Exception as e:
            return text(f"Error al leer reporte: {e}")

    return [types.TextContent(type="text", text=f"Herramienta desconocida: {name}")]


# ── Hot-reload via SIGHUP ─────────────────────────────────────────────────────
import signal

def _handle_sighup(signum, frame):
    sys.exit(0)

signal.signal(signal.SIGHUP, _handle_sighup)


# ── Entry point ───────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
