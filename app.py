#!/usr/bin/env python3
"""
LazyOwn BlueTeam Framework
Una herramienta monolítica de seguridad defensiva para detección de amenazas,
respuesta a incidentes y endurecimiento de sistemas Linux.
"""

import cmd2
import json
import psutil
import os
import sys
import re
import datetime # Usar directamente, no from datetime import datetime
import logging
import sqlite3
import hashlib
import socket
import subprocess
import platform
import time
import shutil
import tempfile
import signal # No usado directamente aún, pero puede ser útil para manejo de procesos
import pwd
import grp
from typing import List, Dict, Optional, Tuple, Any, Union # Mantener para type hints
from tabulate import tabulate
from pathlib import Path
# from datetime import datetime # Ya importado como 'datetime'

# Versión del framework
__version__ = "1.0.0"

# Configuración de logging
logging.basicConfig(
    filename='lazyown_blueteam.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger("LazyOwn")

# Configurar también la salida a consola para los mensajes de debug
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG) # Mostrar DEBUG en consola
formatter = logging.Formatter('%(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


# Constantes
DEFAULT_CONFIG = {
    "log_paths": [
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/secure", # Común en RHEL/CentOS
        "/var/log/messages" # Común en algunas distros
    ],
    "alert_threshold": 3,
    "output_dir": "./reports",
    "database_path": "./lazyown.db",
    "critical_files": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/bin/login", # Agregado
        "/usr/sbin/sshd" # Agregado
    ],
    "scan_interval": 60,  # segundos
    "network_baseline": {}, # Se cargará desde la DB
    "suspicious_ports": [23, 2323, 4444, 5555, 6666, 31337, 65535], # Telnet y comunes de backdoor
    "suspicious_processes": ["nc", "netcat", "ncat", "msfvenom", "meterpreter", "socat", "kworkerds"], # Agregados
    "max_failed_logins": 5,
    "quarantine_dir": "./quarantine",
    "backup_dir": "./backups",
    "enable_auto_response": False,
    "threat_intel_ips_url": None # Placeholder para una URL de lista de IPs maliciosas
}
class FgColor:
    pass

class Cyan(FgColor):
    pass

class Red(FgColor):
    pass
class Database:
    """Clase para manejar la base de datos SQLite."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self.initialize()

    def initialize(self) -> None:
        """Inicializa la conexión a la base de datos y crea las tablas si no existen."""
        try:
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir)

            self.conn = sqlite3.connect(self.db_path)
            self.cursor = self.conn.cursor()

            # Tabla de alertas
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY,
                    type TEXT NOT NULL,
                    details TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    timestamp DATETIME NOT NULL
                )
            ''')

            # Tabla de hashes de archivos para verificación de integridad
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_hashes (
                    id INTEGER PRIMARY KEY,
                    filepath TEXT NOT NULL UNIQUE,
                    hash TEXT NOT NULL,
                    last_checked DATETIME NOT NULL
                )
            ''')

            # Tabla de línea base de conexiones de red
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_baseline (
                    id INTEGER PRIMARY KEY,
                    local_address TEXT NOT NULL,
                    local_port INTEGER NOT NULL,
                    remote_address TEXT,
                    remote_port INTEGER,
                    protocol TEXT NOT NULL, /* TCP, UDP, etc. */
                    process_name TEXT,
                    pid INTEGER,
                    timestamp DATETIME NOT NULL,
                    UNIQUE(local_address, local_port, remote_address, remote_port, protocol, pid)
                )
            ''')

            # Tabla de eventos de seguridad
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY,
                    event_type TEXT NOT NULL, /* ej: 'failed_login', 'sudo_usage' */
                    source TEXT NOT NULL, /* ej: '/var/log/auth.log', 'ProcessMonitor' */
                    description TEXT NOT NULL,
                    raw_data TEXT, /* ej: la línea de log completa */
                    timestamp DATETIME NOT NULL
                )
            ''')
            
            # Tabla de configuración del sistema auditada (para hardening)
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_config_audit (
                    id INTEGER PRIMARY KEY,
                    component TEXT NOT NULL, /* ej: 'sshd', 'kernel_param' */
                    setting TEXT NOT NULL, /* ej: 'PermitRootLogin', 'net.ipv4.ip_forward' */
                    current_value TEXT,
                    recommended_value TEXT,
                    status TEXT NOT NULL, /* ej: 'compliant', 'non-compliant', 'check_manually' */
                    notes TEXT,
                    timestamp DATETIME NOT NULL,
                    UNIQUE(component, setting)
                )
            ''')

            self.conn.commit()
            logger.info(f"Base de datos inicializada correctamente en {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Error al inicializar la base de datos: {e}")
            sys.exit(1)
        except OSError as e:
            logger.error(f"Error de OS al crear directorio para la base de datos {self.db_path}: {e}")
            sys.exit(1)


    def execute(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        """Ejecuta una consulta SQL y devuelve los resultados."""
        try:
            self.cursor.execute(query, params)
            self.conn.commit() # Asegurar commit para DML que no sea INSERT
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Error en consulta SQL: {e}, Query: {query}, Params: {params}")
            return []

    def insert(self, query: str, params: tuple = ()) -> Optional[int]:
        """Inserta datos en la base de datos y devuelve el ID del último registro."""
        try:
            self.cursor.execute(query, params)
            self.conn.commit()
            return self.cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error al insertar datos: {e}, Query: {query}, Params: {params}")
            self.conn.rollback()
            return None

    def close(self) -> None:
        """Cierra la conexión a la base de datos."""
        if self.conn:
            self.conn.close()
            logger.info("Conexión a la base de datos cerrada.")

class Alert:
    """Clase para representar y manejar alertas."""

    SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]

    def __init__(self, alert_type: str, details: Dict, severity: str = "medium"):
        self.alert_type = alert_type
        self.details = details
        self.severity = severity if severity in self.SEVERITY_LEVELS else "medium"
        self.timestamp = datetime.datetime.now().isoformat() # Usar datetime.datetime

    def to_dict(self) -> Dict:
        """Convierte la alerta a diccionario."""
        return {
            "type": self.alert_type,
            "details": self.details,
            "severity": self.severity,
            "timestamp": self.timestamp
        }

    def save_to_db(self, db: Database) -> Optional[int]:
        """Guarda la alerta en la base de datos."""
        details_json = json.dumps(self.details)
        query = """
            INSERT INTO alerts (type, details, severity, timestamp)
            VALUES (?, ?, ?, ?)
        """
        alert_id = db.insert(query, (self.alert_type, details_json, self.severity, self.timestamp))
        if alert_id:
            logger.info(f"Alerta '{self.alert_type}' (Severidad: {self.severity}) guardada en DB con ID: {alert_id}")
        else:
            logger.error(f"No se pudo guardar la alerta '{self.alert_type}' en la DB.")
        return alert_id

class SystemUtils:
    """Utilidades para trabajar con el sistema."""

    @staticmethod
    def run_command(command: Union[str, List[str]], shell: bool = False) -> Tuple[int, str, str]:
        """Ejecuta un comando del sistema y devuelve el código de salida, stdout y stderr."""
        try:
            # Preferir lista de argumentos para evitar shell=True cuando sea posible
            if isinstance(command, str) and not shell:
                # Intentar dividir comandos simples, pero ser cauteloso
                # Para mayor seguridad, el llamador debería pasar una lista
                effective_command = command.split()
            else:
                effective_command = command

            process = subprocess.Popen(
                effective_command,
                shell=shell, # Usar con precaución si command es una cadena construida por el usuario
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, # Decodifica stdout/stderr como texto
                # universal_newlines=True # Deprecado en favor de text=True
            )
            stdout, stderr = process.communicate()
            return process.returncode, stdout.strip(), stderr.strip()
        except subprocess.SubprocessError as e:
            logger.error(f"Error al ejecutar comando '{command}': {e}")
            return -1, "", str(e)
        except FileNotFoundError:
            logger.error(f"Comando no encontrado: {command[0] if isinstance(command, list) else command.split()[0]}")
            return -1, "", f"Comando no encontrado: {command[0] if isinstance(command, list) else command.split()[0]}"


    @staticmethod
    def get_file_hash(filepath: str) -> str:
        """Calcula el hash SHA-256 de un archivo."""
        if not os.path.isfile(filepath):
            logger.warning(f"get_file_hash: Archivo no encontrado en {filepath}")
            return ""

        try:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256()
                while chunk := f.read(8192): # Walrus operator (Python 3.8+)
                    file_hash.update(chunk)
            return file_hash.hexdigest()
        except (IOError, OSError) as e:
            logger.error(f"Error al calcular hash del archivo {filepath}: {e}")
            return ""

    @staticmethod
    def get_system_info() -> Dict:
        """Obtiene información del sistema."""
        info = {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "boot_time": datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "python_version": platform.python_version(),
            "ip_addresses": []
        }

        try:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        info["ip_addresses"].append({
                            "interface": interface,
                            "address": addr.address,
                            "netmask": addr.netmask
                        })
        except Exception as e:
            logger.error(f"Error al obtener direcciones IP: {e}")
        return info

    @staticmethod
    def backup_file(filepath: str, backup_dir: str) -> str:
        """Crea una copia de seguridad de un archivo."""
        if not os.path.isfile(filepath):
            logger.warning(f"backup_file: Archivo no encontrado en {filepath}")
            return ""

        try:
            os.makedirs(backup_dir, exist_ok=True)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.basename(filepath)
            # Sanitizar nombre de archivo para el backup (reemplazar '/' si es parte del nombre, aunque basename lo evita)
            safe_filename = filename.replace(os.sep, "_")
            backup_path = os.path.join(backup_dir, f"{safe_filename}_{timestamp}.bak")
            shutil.copy2(filepath, backup_path)
            logger.info(f"Backup de {filepath} creado en {backup_path}")
            return backup_path
        except (IOError, OSError) as e:
            logger.error(f"Error al hacer backup del archivo {filepath}: {e}")
            return ""
            
    @staticmethod
    def get_process_details(pid: int) -> Optional[Dict]:
        try:
            proc = psutil.Process(pid)
            return proc.as_dict(attrs=['pid', 'name', 'cmdline', 'username', 'status', 
                                       'create_time', 'cpu_percent', 'memory_percent', 
                                       'ppid', 'cwd', 'exe', 'open_files', 'connections'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None


class ProcessMonitor:
    """Monitor de procesos para detección de actividad sospechosa."""

    def __init__(self, config: Dict, db: Database):
        self.config = config
        self.db = db
        self.suspicious_processes_names = config.get("suspicious_processes", []) # Renombrado para claridad
        self.suspicious_ports = config.get("suspicious_ports", [])


    def scan(self, generate_alerts: bool = True) -> List[Dict]:
        """Escanea procesos en busca de actividad sospechosa."""
        suspicious_found = []
        logger.info("Iniciando escaneo de procesos...")

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'status', 'create_time', 'connections', 'cpu_percent', 'memory_percent']):
            try:
                proc_info = proc.as_dict(attrs=['pid', 'name', 'cmdline', 'username',
                                                'cpu_percent', 'memory_percent', 'create_time',
                                                'status']) # 'connections' se manejará por separado para evitar errores
                
                proc_info['cmdline'] = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
                proc_info['create_time'] = datetime.datetime.fromtimestamp(proc_info['create_time']).isoformat()

                is_suspicious = False
                reasons = []

                # 1. Procesos con nombres conocidos como maliciosos
                if any(s.lower() in proc_info['name'].lower() for s in self.suspicious_processes_names):
                    is_suspicious = True
                    reasons.append(f"Nombre sospechoso ('{proc_info['name']}')")

                # 2. Procesos con alto uso de CPU (ajustable)
                if proc_info['cpu_percent'] is not None and proc_info['cpu_percent'] > self.config.get("high_cpu_threshold", 85.0):
                    is_suspicious = True
                    reasons.append(f"Alto uso de CPU ({proc_info['cpu_percent']}%)")
                
                # 3. Procesos escuchando en puertos sospechosos o conectándose a ellos
                try:
                    connections = proc.connections(kind='inet')
                    for conn in connections:
                        if conn.laddr and conn.laddr.port in self.suspicious_ports and conn.status == 'LISTEN':
                            is_suspicious = True
                            reasons.append(f"Escuchando en puerto sospechoso {conn.laddr.port}")
                        if conn.raddr and conn.raddr.port in self.suspicious_ports:
                             is_suspicious = True
                             reasons.append(f"Conectado a puerto remoto sospechoso {conn.raddr.port}")
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass # Ignorar si no se pueden obtener conexiones

                # 4. Procesos con nombres ocultados o rutas sospechosas
                if proc_info['name'].startswith('.') or '/tmp/' in proc_info.get('exe', '') or '/dev/shm' in proc_info.get('exe', ''):
                    is_suspicious = True
                    reasons.append("Nombre/ruta de ejecutable sospechosa")
                
                # 5. Procesos sin ejecutable en disco (podría indicar fileless malware)
                try:
                    if proc.exe() == "" and proc_info['status'] not in [psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD]: # Verificar que no sea zombie
                        # Esto puede tener falsos positivos (ej: kernel threads)
                        # Una verificación más robusta sería ver si /proc/<pid>/exe es un enlace roto
                        exe_path = f"/proc/{proc.pid}/exe"
                        if os.path.exists(exe_path) and os.path.islink(exe_path) and not os.path.exists(os.readlink(exe_path)):
                            is_suspicious = True
                            reasons.append("Proceso sin ejecutable en disco (enlace roto en /proc)")
                except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
                    pass


                if is_suspicious:
                    proc_info['reasons'] = list(set(reasons)) # Eliminar duplicados
                    suspicious_found.append(proc_info)
                    
                    if generate_alerts:
                        # Simplificar detalles para la alerta
                        alert_details = {
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': proc_info['cmdline'][:200], # Truncar cmdline largo
                            'username': proc_info['username'],
                            'reasons': proc_info['reasons']
                        }
                        alert = Alert(
                            alert_type="suspicious_process_detected",
                            details=alert_details,
                            severity="high" if "puerto sospechoso" in ' '.join(reasons) else "medium"
                        )
                        alert.save_to_db(self.db)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logger.debug(f"Error al analizar proceso (PID puede haber terminado): {e}")
                continue
            except Exception as e:
                logger.error(f"Error inesperado al analizar proceso {proc.info.get('pid', 'N/A')}: {e}")
                continue
        
        logger.info(f"Escaneo de procesos completado. {len(suspicious_found)} procesos sospechosos encontrados.")
        return suspicious_found

class NetworkMonitor:
    """Monitor de red para detección de conexiones sospechosas."""

    def __init__(self, config: Dict, db: Database):
        self.config = config
        self.db = db
        self.suspicious_ports = config.get("suspicious_ports", [])
        # self.baseline = self._load_baseline() # Cargar al inicio si es necesario o bajo demanda

    def _load_baseline(self) -> Dict[str, Dict]:
        """Carga la línea base de conexiones de red desde la base de datos."""
        baseline = {}
        rows = self.db.execute("SELECT local_address, local_port, remote_address, remote_port, protocol, process_name, pid FROM network_baseline")
        for row in rows:
            # Crear una clave única para cada entrada de la línea base
            key_parts = [str(row[field]) if row[field] is not None else '' for field in ['local_address', 'local_port', 'remote_address', 'remote_port', 'protocol']]
            key = ":".join(key_parts)
            baseline[key] = {
                "local_address": row['local_address'], "local_port": row['local_port'],
                "remote_address": row['remote_address'], "remote_port": row['remote_port'],
                "protocol": row['protocol'], "process_name": row['process_name'], "pid": row['pid']
            }
        logger.info(f"Línea base de red cargada con {len(baseline)} entradas.")
        return baseline

    def create_baseline(self) -> None:
        """Crea una línea base de las conexiones de red actuales (LISTEN y ESTABLISHED)."""
        logger.info("Creando línea base de red...")
        self.db.execute("DELETE FROM network_baseline") # Limpiar línea base anterior
        
        count = 0
        # Usar net_connections() para obtener información más rica, incluyendo PID
        for conn in psutil.net_connections(kind='inet'): # inet para IPv4/IPv6
            try:
                if conn.status in ['LISTEN', 'ESTABLISHED']:
                    process_name = ""
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            process_name = "N/A"
                    
                    laddr_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
                    laddr_port = conn.laddr.port if conn.laddr else 0
                    raddr_ip = conn.raddr.ip if conn.raddr and conn.raddr.ip else None
                    raddr_port = conn.raddr.port if conn.raddr and conn.raddr.port else None
                    
                    # Determinar protocolo (TCP/UDP)
                    proto = ""
                    if conn.type == socket.SOCK_STREAM: proto = "TCP"
                    elif conn.type == socket.SOCK_DGRAM: proto = "UDP"
                    else: proto = str(conn.type) # Otros tipos

                    query = """
                        INSERT OR IGNORE INTO network_baseline 
                        (local_address, local_port, remote_address, remote_port, protocol, process_name, pid, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """
                    self.db.insert(query, (
                        laddr_ip, laddr_port, raddr_ip, raddr_port,
                        proto, process_name, conn.pid, datetime.datetime.now().isoformat()
                    ))
                    count += 1
            except (AttributeError, psutil.Error, OSError) as e: # OSError puede ocurrir con algunas conexiones raras
                logger.debug(f"Error al procesar conexión para línea base: {e} - Conn: {conn}")
        
        logger.info(f"Línea base de red creada/actualizada con {count} conexiones activas (LISTEN/ESTABLISHED).")
        # self.baseline = self._load_baseline() # Recargar la línea base en memoria


    def scan(self, generate_alerts: bool = True) -> List[Dict]:
        """Escanea las conexiones de red en busca de anomalías."""
        logger.info("Iniciando escaneo de red...")
        suspicious_connections = []
        current_baseline = self._load_baseline() # Cargar baseline actual para comparación

        active_connections = {}
        for conn in psutil.net_connections(kind='inet'):
            try:
                laddr_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
                laddr_port = conn.laddr.port if conn.laddr else 0
                raddr_ip = conn.raddr.ip if conn.raddr and conn.raddr.ip else None
                raddr_port = conn.raddr.port if conn.raddr and conn.raddr.port else None
                
                proto = ""
                if conn.type == socket.SOCK_STREAM: proto = "TCP"
                elif conn.type == socket.SOCK_DGRAM: proto = "UDP"
                else: proto = str(conn.type)

                conn_key_parts = [str(laddr_ip), str(laddr_port), str(raddr_ip or ''), str(raddr_port or ''), proto]
                conn_key = ":".join(conn_key_parts)

                process_name = "N/A"
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        process_name = p.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                conn_info = {
                    "local_address": laddr_ip, "local_port": laddr_port,
                    "remote_address": raddr_ip, "remote_port": raddr_port,
                    "protocol": proto, "status": conn.status,
                    "process_name": process_name, "pid": conn.pid,
                    "reasons": []
                }

                is_suspicious = False

                # 1. Conexiones a/desde puertos sospechosos
                if (laddr_port in self.suspicious_ports and conn.status == 'LISTEN') or \
                   (raddr_port in self.suspicious_ports):
                    is_suspicious = True
                    conn_info["reasons"].append(f"Puerto sospechoso involucrado ({laddr_port if conn.status == 'LISTEN' else raddr_port})")

                # 2. Conexiones ESTABLISHED no en línea base (si la línea base existe)
                #    Esto es más útil si la línea base se considera "de confianza"
                if conn.status == 'ESTABLISHED' and current_baseline and conn_key not in current_baseline:
                     # Podría ser una nueva conexión legítima, así que la severidad debe ser considerada
                    is_suspicious = True
                    conn_info["reasons"].append("Conexión ESTABLISHED no en línea base")
                
                # 3. TODO: Añadir detección de IPs maliciosas (requiere feed de threat intelligence)

                if is_suspicious:
                    suspicious_connections.append(conn_info)
                    if generate_alerts:
                        alert = Alert(
                            alert_type="suspicious_network_activity",
                            details=conn_info, # Guardar toda la info de la conexión
                            severity="high" if "puerto sospechoso" in ' '.join(conn_info["reasons"]) else "medium"
                        )
                        alert.save_to_db(self.db)

            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError, OSError) as e:
                logger.debug(f"Error al analizar conexión de red: {e}")
                continue
        
        logger.info(f"Escaneo de red completado. {len(suspicious_connections)} actividades sospechosas encontradas.")
        return suspicious_connections


class FileIntegrityMonitor:
    """Monitor de integridad de archivos."""

    def __init__(self, config: Dict, db: Database):
        self.config = config
        self.db = db
        self.critical_files = list(set(config.get("critical_files", []))) # Asegurar unicidad

    def initialize_baseline(self, files_to_baseline: Optional[List[str]] = None) -> None:
        """Inicializa o actualiza la línea base de hashes de archivos."""
        target_files = files_to_baseline if files_to_baseline else self.critical_files
        logger.info(f"Inicializando línea base de integridad para {len(target_files)} archivos.")
        
        updated_count = 0
        new_count = 0
        error_count = 0

        for filepath_str in target_files:
            filepath = Path(filepath_str) # Usar Path para mejor manejo de rutas
            if filepath.is_file():
                file_hash = SystemUtils.get_file_hash(str(filepath))
                if file_hash:
                    timestamp = datetime.datetime.now().isoformat()
                    # Verificar si ya existe en la base de datos
                    rows = self.db.execute(
                        "SELECT id FROM file_hashes WHERE filepath = ?",
                        (str(filepath),)
                    )
                    if rows: # Actualizar hash existente
                        self.db.execute(
                            "UPDATE file_hashes SET hash = ?, last_checked = ? WHERE filepath = ?",
                            (file_hash, timestamp, str(filepath))
                        )
                        updated_count +=1
                    else: # Insertar nuevo hash
                        self.db.insert(
                            "INSERT INTO file_hashes (filepath, hash, last_checked) VALUES (?, ?, ?)",
                            (str(filepath), file_hash, timestamp)
                        )
                        new_count +=1
                    logger.debug(f"Línea base establecida/actualizada para {filepath}")
                else:
                    logger.warning(f"No se pudo calcular hash para {filepath}, no se añadió a la línea base.")
                    error_count +=1
            else:
                logger.warning(f"Archivo para línea base no encontrado o no es un archivo: {filepath}")
                # Considerar si se deben eliminar de la DB los archivos que ya no existen.
                # self.db.execute("DELETE FROM file_hashes WHERE filepath = ?", (str(filepath),))
                error_count +=1
        logger.info(f"Línea base de integridad: {new_count} nuevos, {updated_count} actualizados, {error_count} errores.")

    def scan(self, generate_alerts: bool = True) -> List[Dict]:
        """Verifica la integridad de los archivos contra la línea base."""
        logger.info("Iniciando escaneo de integridad de archivos...")
        violations = []
        
        baseline_hashes_rows = self.db.execute("SELECT filepath, hash FROM file_hashes")
        if not baseline_hashes_rows:
            logger.warning("No hay línea base de integridad de archivos definida. Ejecute 'fim_baseline'.")
            return []

        for row in baseline_hashes_rows:
            filepath_str, baseline_hash = row['filepath'], row['hash']
            filepath = Path(filepath_str)

            if not filepath.is_file():
                violation_info = {
                    "filepath": str(filepath),
                    "status": "missing",
                    "message": "Archivo crítico falta o no es accesible.",
                    "expected_hash": baseline_hash
                }
                violations.append(violation_info)
                if generate_alerts:
                    Alert("file_integrity_violation", violation_info, "critical").save_to_db(self.db)
                logger.critical(f"VIOLACIÓN DE INTEGRIDAD: Archivo crítico {filepath} NO ENCONTRADO.")
                continue

            current_hash = SystemUtils.get_file_hash(str(filepath))
            if not current_hash:
                logger.warning(f"No se pudo calcular hash para {filepath} durante el escaneo.")
                # Podría ser una alerta si se espera que el archivo sea legible
                violation_info = {
                    "filepath": str(filepath),
                    "status": "error_hashing",
                    "message": "No se pudo calcular el hash del archivo durante el escaneo.",
                }
                violations.append(violation_info)
                if generate_alerts:
                     Alert("file_integrity_error", violation_info, "medium").save_to_db(self.db)
                continue

            if current_hash != baseline_hash:
                try:
                    mtime = datetime.datetime.fromtimestamp(filepath.stat().st_mtime).isoformat()
                except OSError:
                    mtime = "N/A"
                
                violation_info = {
                    "filepath": str(filepath),
                    "status": "modified",
                    "current_hash": current_hash,
                    "baseline_hash": baseline_hash,
                    "modified_time": mtime,
                    "message": "Hash del archivo no coincide con la línea base."
                }
                violations.append(violation_info)
                if generate_alerts:
                    Alert("file_integrity_violation", violation_info, "critical").save_to_db(self.db)
                logger.critical(f"VIOLACIÓN DE INTEGRIDAD: Archivo {filepath} modificado. Actual: {current_hash}, Baseline: {baseline_hash}")
            else:
                 # Actualizar last_checked incluso si no hay violación
                 self.db.execute("UPDATE file_hashes SET last_checked = ? WHERE filepath = ?", (datetime.datetime.now().isoformat(), str(filepath)))


        logger.info(f"Escaneo de integridad de archivos completado. {len(violations)} violaciones encontradas.")
        return violations

class LogAnalyzer:
    """Analizador de logs del sistema."""

    def __init__(self, config: Dict, db: Database):
        self.config = config
        self.db = db
        self.log_paths = list(set(config.get("log_paths", []))) # Asegurar unicidad
        self.max_failed_logins_threshold = config.get("max_failed_logins", 5)
        
        # Patrones mejorados y adicionales
        self.patterns = {
            "failed_login": re.compile(r"(?:failed\s+password|authentication\s+failure|invalid\s+user|failed\s+login)", re.IGNORECASE),
            "successful_login": re.compile(r"(?:accepted\s+password|session\s+opened\s+for\s+user)", re.IGNORECASE),
            "sudo_command": re.compile(r"sudo:\s*\S+\s*:\s*USER=\S+\s*;\s*COMMAND=(.+)", re.IGNORECASE),
            "user_added": re.compile(r"(?:new\s+user|useradd|adduser).*name=(\S+)", re.IGNORECASE),
            "user_deleted": re.compile(r"(?:delete\s+user|userdel).*name=(\S+)", re.IGNORECASE),
            "group_added": re.compile(r"(?:new\s+group|groupadd).*name=(\S+)", re.IGNORECASE),
            "ssh_key_added": re.compile(r"AuthorizedKeysFile\s+\S+\s+added\s+key\s+", re.IGNORECASE), # Más específico si los logs lo permiten
            "permission_denied": re.compile(r"permission\s+denied", re.IGNORECASE),
            "kernel_error": re.compile(r"kernel:.*(?:error|critical|panic)", re.IGNORECASE),
            "segmentation_fault": re.compile(r"segmentation\s+fault", re.IGNORECASE),
        }
        # Para rastrear logins fallidos por IP o usuario
        self.failed_login_tracker = {} # key: 'ip_address' or 'username', value: count

    def analyze_log_file(self, log_path: str, generate_alerts: bool = True) -> List[Dict]:
        """Analiza un único archivo de log."""
        findings = []
        if not os.path.isfile(log_path):
            logger.warning(f"Archivo de log no encontrado o no es un archivo: {log_path}")
            return findings
        
        logger.info(f"Analizando log: {log_path}")
        try:
            with open(log_path, 'r', errors='ignore') as f:
                # Considerar leer solo las N últimas líneas o desde la última posición leída (más complejo)
                # Para este ejemplo, leemos las últimas N líneas para evitar procesar logs enormes cada vez.
                # Esto es una simplificación; un HIDS real tendría un manejo de estado más sofisticado.
                lines = f.readlines()[-self.config.get("log_analyzer_max_lines", 5000):] 
                
                for line_num, line_content in enumerate(lines):
                    line_content = line_content.strip()
                    if not line_content:
                        continue

                    timestamp_str = datetime.datetime.now().isoformat() # Usar timestamp actual si no se puede extraer del log

                    for pattern_name, pattern_re in self.patterns.items():
                        match = pattern_re.search(line_content)
                        if match:
                            event_details = {
                                "log_file": log_path,
                                "line_number": line_num + 1, # aproximado si se leen últimas N
                                "line_content": line_content,
                                "pattern_name": pattern_name,
                                "match_groups": match.groups() if match.groups() else None,
                                "timestamp": timestamp_str # Idealmente, extraer del log
                            }
                            findings.append(event_details)
                            
                            # Guardar evento en DB
                            event_id = self.db.insert(
                                """INSERT INTO security_events 
                                   (event_type, source, description, raw_data, timestamp) 
                                   VALUES (?, ?, ?, ?, ?)""",
                                (pattern_name, log_path, f"Detectado evento '{pattern_name}'", line_content, timestamp_str)
                            )
                            if not event_id: logger.error(f"No se pudo guardar evento de log {pattern_name} en DB.")


                            # Lógica de Alerta específica
                            if generate_alerts:
                                severity = "medium" # Default
                                if pattern_name == "failed_login":
                                    severity = "medium"
                                    # Intentar extraer IP o usuario para alerta de fuerza bruta
                                    # Esta parte es muy dependiente del formato del log
                                    ip_match = re.search(r"from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line_content)
                                    user_match = re.search(r"user\s+(\S+)", line_content, re.IGNORECASE)
                                    target_key = None
                                    if ip_match: target_key = ip_match.group(1)
                                    elif user_match: target_key = user_match.group(1)

                                    if target_key:
                                        self.failed_login_tracker[target_key] = self.failed_login_tracker.get(target_key, 0) + 1
                                        if self.failed_login_tracker[target_key] >= self.max_failed_logins_threshold:
                                            Alert(
                                                "potential_brute_force",
                                                {"target": target_key, "count": self.failed_login_tracker[target_key], "log_line": line_content, "log_file": log_path},
                                                "high"
                                            ).save_to_db(self.db)
                                            self.failed_login_tracker[target_key] = 0 # Resetear contador tras alerta
                                elif pattern_name in ["user_added", "user_deleted", "kernel_error", "segmentation_fault"]:
                                    severity = "high"
                                elif pattern_name == "sudo_command":
                                    severity = "low" # O 'info' dependiendo de la política

                                Alert(
                                    f"log_event_{pattern_name}",
                                    event_details,
                                    severity
                                ).save_to_db(self.db)
        except IOError as e:
            logger.error(f"Error al leer archivo de log {log_path}: {e}")
        except Exception as e:
            logger.error(f"Error inesperado analizando {log_path}: {e}")
            
        logger.info(f"Análisis de {log_path} completado. {len(findings)} hallazgos.")
        return findings

    def analyze(self) -> Dict[str, List]:
        findings = {pattern: [] for pattern in self.patterns}
        failed_logins = {}
        for log_path in self.log_paths:
            if not os.path.isfile(log_path):
                logger.warning(f"Log file not found: {log_path}")
                continue
            try:
                with open(log_path, 'r', errors='ignore') as f:
                    lines = f.readlines()[-5000:]
                    for line in lines:
                        for pattern_name, pattern in self.patterns.items():
                            if pattern.search(line):
                                findings[pattern_name].append({
                                    "log": log_path,
                                    "line": line.strip(),
                                    "timestamp": datetime.now().isoformat()
                                })
                                self.db.insert(
                                    """
                                    INSERT INTO security_events 
                                    (event_type, source, description, raw_data, timestamp)
                                    VALUES (?, ?, ?, ?, ?)
                                    """,
                                    (
                                        pattern_name,
                                        log_path,
                                        f"Detected {pattern_name} event",
                                        line.strip(),
                                        datetime.now().isoformat()
                                    )
                                )
                                if pattern_name == "failed_login":
                                    user_match = re.search(r"user\s+(\w+)", line, re.IGNORECASE)
                                    if user_match:
                                        username = user_match.group(1)
                                        failed_logins[username] = failed_logins.get(username, 0) + 1
                                        if failed_logins[username] >= self.max_failed_logins:
                                            alert = Alert(
                                                alert_type="brute_force_attempt",
                                                details={
                                                    "username": username,
                                                    "attempts": failed_logins[username],
                                                    "log": log_path
                                                },
                                                severity="high"
                                            )
                                            alert.save_to_db(self.db)
            except Exception as e:
                logger.error(f"Log analysis error {log_path}: {e}")
        for pattern_name, entries in findings.items():
            if entries and pattern_name in ["user_added", "sudo_usage"]:
                severity = "medium" if pattern_name == "sudo_usage" else "high"
                alert = Alert(
                    alert_type=f"log_{pattern_name}",
                    details={
                        "count": len(entries),
                        "sample": entries[:5]
                    },
                    severity=severity
                )
                alert.save_to_db(self.db)
        return findings

    def analyze_all_logs(self, generate_alerts: bool = True) -> Dict[str, List[Dict]]:
        """Analiza todos los archivos de log configurados."""
        logger.info("Iniciando análisis de todos los logs configurados...")
        all_findings = {}
        self.failed_login_tracker.clear() # Resetear para cada escaneo completo
        
        for log_path in self.log_paths:
            all_findings[log_path] = self.analyze_log_file(log_path, generate_alerts)
        
        logger.info("Análisis de todos los logs completado.")
        return all_findings

# --- Nuevos Módulos (Esqueletos) ---
class SystemHardener:
    """Módulo para aplicar y auditar configuraciones de endurecimiento."""
    def __init__(self, config: Dict, db: Database):
        self.config = config
        self.db = db
        self.backup_dir = config.get("backup_dir", "./backups")

    def check_system_security(self) -> Dict[str, List]:
        results = {
            "firewall": [],
            "services": [],
            "permissions": [],
            "users": [],
            "software": []
        }
        returncode, stdout, stderr = SystemUtils.run_command("ufw status")
        if returncode == 0:
            if "inactive" in stdout:
                results["firewall"].append({
                    "check": "ufw_status",
                    "status": "fail",
                    "message": "Firewall is inactive",
                    "recommendation": "Activate firewall with 'sudo ufw enable'"
                })
                self.db.insert(
                    """
                    INSERT INTO system_config 
                    (component, setting, value, recommended, status, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "firewall",
                        "ufw_status",
                        "inactive",
                        "active",
                        "fail",
                        datetime.now().isoformat()
                    )
                )
            else:
                results["firewall"].append({
                    "check": "ufw_status",
                    "status": "pass",
                    "message": "Firewall is active",
                    "details": stdout.strip()
                })
                self.db.insert(
                    """
                    INSERT INTO system_config 
                    (component, setting, value, recommended, status, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "firewall",
                        "ufw_status",
                        "active",
                        "active",
                        "pass",
                        datetime.now().isoformat()
                    )
                )
        services_to_check = ["ssh", "apache2", "nginx", "mysql", "postgresql"]
        for service in services_to_check:
            returncode, stdout, stderr = SystemUtils.run_command(f"systemctl is-active {service}")
            if returncode == 0 and "active" in stdout:
                if service == "ssh":
                    returncode, stdout, stderr = SystemUtils.run_command("grep -i '^PermitRootLogin' /etc/ssh/sshd_config")
                    if returncode == 0 and "yes" in stdout.lower():
                        results["services"].append({
                            "check": "ssh_root_login",
                            "status": "fail",
                            "message": "SSH allows root login",
                            "recommendation": "Change PermitRootLogin to 'no' in /etc/ssh/sshd_config"
                        })
                        self.db.insert(
                            """
                            INSERT INTO system_config 
                            (component, setting, value, recommended, status, timestamp)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                "ssh",
                                "PermitRootLogin",
                                "yes",
                                "no",
                                "fail",
                                datetime.now().isoformat()
                            )
                        )
                    else:
                        results["services"].append({
                            "check": "ssh_root_login",
                            "status": "pass",
                            "message": "SSH does not allow root login"
                        })
                        self.db.insert(
                            """
                            INSERT INTO system_config 
                            (component, setting, value, recommended, status, timestamp)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                "ssh",
                                "PermitRootLogin",
                                "no",
                                "no",
                                "pass",
                                datetime.now().isoformat()
                            )
                        )
                results["services"].append({
                    "check": f"{service}_status",
                    "status": "info",
                    "message": f"Service {service} is active"
                })
        files_to_check = [
            {
                "path": "/etc/passwd",
                "expected_perms": "644",
                "expected_owner": "root"
            },
            {
                "path": "/etc/shadow",
                "expected_perms": "640",
                "expected_owner": "root"
            },
            {
                "path": "/etc/sudoers",
                "expected_perms": "440",
                "expected_owner": "root"
            }
        ]
        for file_info in files_to_check:
            path = file_info["path"]
            if os.path.isfile(path):
                try:
                    stat_info = os.stat(path)
                    owner = pwd.getpwuid(stat_info.st_uid).pw_name
                    if owner != file_info["expected_owner"]:
                        results["permissions"].append({
                            "check": f"{path}_owner",
                            "status": "fail",
                            "message": f"Incorrect owner for {path}: {owner}",
                            "recommendation": f"Change owner to {file_info['expected_owner']} with 'chown {file_info['expected_owner']} {path}'"
                        })
                    perms = oct(stat_info.st_mode)[-3:]
                    if perms != file_info["expected_perms"]:
                        results["permissions"].append({
                            "check": f"{path}_permissions",
                            "status": "fail",
                            "message": f"Incorrect permissions for {path}: {perms}",
                            "recommendation": f"Change permissions to {file_info['expected_perms']} with 'chmod {file_info['expected_perms']} {path}'"
                        })
                    else:
                        results["permissions"].append({
                            "check": f"{path}_permissions",
                            "status": "pass",
                            "message": f"Correct permissions for {path}: {perms}"
                        })
                except Exception as e:
                    logger.error(f"Permission check error {path}: {e}")
        returncode, stdout, stderr = SystemUtils.run_command("awk -F: '($3 == 0) {print}' /etc/passwd")
        if returncode == 0:
            root_users = stdout.strip().split("\n")
            if len(root_users) > 1:
                results["users"].append({
                    "check": "uid_0_users",
                    "status": "fail",
                    "message": f"There are {len(root_users)} users with UID 0",
                    "details": root_users,
                    "recommendation": "Only one user with UID 0 (root) should exist"
                })
                alert = Alert(
                    alert_type="multiple_root_users",
                    details={
                        "count": len(root_users),
                        "users": root_users
                    },
                    severity="critical"
                )
                alert.save_to_db(self.db)
            else:
                results["users"].append({
                    "check": "uid_0_users",
                    "status": "pass",
                    "message": "Only one user with UID 0 (root) exists"
                })
        if os.path.isfile("/usr/bin/apt"):
            returncode, stdout, stderr = SystemUtils.run_command("apt list --upgradable")
            if returncode == 0:
                upgradable_packages = [line for line in stdout.strip().split("\n") if "upgradable" in line]
                if upgradable_packages:
                    results["software"].append({
                        "check": "software_updates",
                        "status": "fail",
                        "message": f"There are {len(upgradable_packages)} packages pending update",
                        "recommendation": "Update packages with 'sudo apt update && sudo apt upgrade'"
                    })
                else:
                    results["software"].append({
                        "check": "software_updates",
                        "status": "pass",
                        "message": "System is up to date"
                    })
        return results

    def apply_hardening(self, backup: bool = True) -> Dict[str, Any]:
        results = {
            "success": [],
            "failure": [],
            "skipped": []
        }
        if os.geteuid() != 0:
            results["skipped"].append({
                "hardening": "all",
                "reason": "Root privileges required for hardening"
            })
            return results
        if backup and not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
        try:
            if backup:
                SystemUtils.run_command(f"cp /etc/ufw/user.rules {self.backup_dir}/ufw_user.rules_backup")
            SystemUtils.run_command("ufw --force reset")
            SystemUtils.run_command("ufw default deny incoming")
            SystemUtils.run_command("ufw default allow outgoing")
            SystemUtils.run_command("ufw allow ssh")
            returncode, stdout, stderr = SystemUtils.run_command("ufw --force enable")
            if returncode == 0:
                results["success"].append({
                    "hardening": "firewall",
                    "details": "Firewall configured and enabled"
                })
            else:
                results["failure"].append({
                    "hardening": "firewall",
                    "details": f"Error enabling firewall: {stderr}"
                })
        except Exception as e:
            results["failure"].append({
                "hardening": "firewall",
                "details": f"Firewall configuration error: {str(e)}"
            })
        try:
            ssh_config_path = "/etc/ssh/sshd_config"
            if backup:
                SystemUtils.run_command(f"cp {ssh_config_path} {self.backup_dir}/sshd_config_backup")
            modifications = [
                "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' {}",
                "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' {}",
                "sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' {}",
                "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' {}",
                "sed -i 's/^#*AllowTcpForwarding.*/AllowTcpForwarding no/' {}"
            ]
            for mod in modifications:
                SystemUtils.run_command(mod.format(ssh_config_path))
            returncode, stdout, stderr = SystemUtils.run_command("systemctl restart sshd")
            if returncode == 0:
                results["success"].append({
                    "hardening": "ssh",
                    "details": "SSH configuration hardened"
                })
            else:
                results["failure"].append({
                    "hardening": "ssh",
                    "details": f"Error restarting SSH: {stderr}"
                })
        except Exception as e:
            results["failure"].append({
                "hardening": "ssh",
                "details": f"SSH configuration error: {str(e)}"
            })
        try:
            file_permissions = [
                {"path": "/etc/passwd", "perms": "644", "owner": "root", "group": "root"},
                {"path": "/etc/shadow", "perms": "640", "owner": "root", "group": "shadow"},
                {"path": "/etc/group", "perms": "644", "owner": "root", "group": "root"},
                {"path": "/etc/gshadow", "perms": "640", "owner": "root", "group": "shadow"},
                {"path": "/etc/sudoers", "perms": "440", "owner": "root", "group": "root"}
            ]
            for file_info in file_permissions:
                path = file_info["path"]
                if backup and os.path.isfile(path):
                    backup_path = os.path.join(self.backup_dir, os.path.basename(path) + "_backup")
                    SystemUtils.run_command(f"cp {path} {backup_path}")
                SystemUtils.run_command(f"chmod {file_info['perms']} {path}")
                SystemUtils.run_command(f"chown {file_info['owner']}:{file_info['group']} {path}")
            results["success"].append({
                "hardening": "file_permissions",
                "details": "Critical file permissions configured"
            })
        except Exception as e:
            results["failure"].append({
                "hardening": "file_permissions",
                "details": f"Permission configuration error: {str(e)}"
            })
        try:
            sysctl_conf = "/etc/sysctl.conf"
            if backup:
                SystemUtils.run_command(f"cp {sysctl_conf} {self.backup_dir}/sysctl.conf_backup")
            sysctl_settings = [
                "net.ipv4.conf.all.accept_redirects = 0",
                "net.ipv4.conf.default.accept_redirects = 0",
                "net.ipv4.conf.all.secure_redirects = 0",
                "net.ipv4.conf.default.secure_redirects = 0",
                "net.ipv4.conf.all.accept_source_route = 0",
                "net.ipv4.conf.default.accept_source_route = 0",
                "net.ipv4.conf.all.send_redirects = 0",
                "net.ipv4.conf.default.send_redirects = 0",
                "net.ipv4.icmp_echo_ignore_broadcasts = 1",
                "net.ipv4.icmp_ignore_bogus_error_responses = 1",
                "net.ipv4.tcp_syncookies = 1",
                "net.ipv4.tcp_max_syn_backlog = 2048",
                "net.ipv4.tcp_synack_retries = 2",
                "net.ipv4.tcp_syn_retries = 5",
                "kernel.randomize_va_space = 2"
            ]
            with open(sysctl_conf, "a") as f:
                f.write("\n# Security configurations added by LazyOwn\n")
                for setting in sysctl_settings:
                    f.write(setting + "\n")
            returncode, stdout, stderr = SystemUtils.run_command("sysctl -p")
            if returncode == 0:
                results["success"].append({
                    "hardening": "kernel_parameters",
                    "details": "Kernel parameters configured"
                })
            else:
                results["failure"].append({
                    "hardening": "kernel_parameters",
                    "details": f"Error applying kernel parameters: {stderr}"
                })
        except Exception as e:
            results["failure"].append({
                "hardening": "kernel_parameters",
                "details": f"Kernel parameter configuration error: {str(e)}"
            })
        try:
            unnecessary_services = ["avahi-daemon", "cups", "bluetooth", "nfs-server", "rpcbind"]
            for service in unnecessary_services:
                returncode, stdout, stderr = SystemUtils.run_command(f"systemctl stop {service}")
                if returncode == 0:
                    SystemUtils.run_command(f"systemctl disable {service}")
                    results["success"].append({
                        "hardening": f"service_{service}",
                        "details": f"Service {service} disabled"
                    })
                else:
                    results["skipped"].append({
                        "hardening": f"service_{service}",
                        "details": f"Could not disable {service}: {stderr}"
                    })
        except Exception as e:
            results["failure"].append({
                "hardening": "services",
                "details": f"Service disable error: {str(e)}"
            })
        return results


    def audit_ssh_config(self, generate_alerts: bool = True) -> List[Dict]:
        """Audita la configuración de SSHD."""
        ssh_config_path = "/etc/ssh/sshd_config"
        recommendations = {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "PubkeyAuthentication": "yes",
            "ChallengeResponseAuthentication": "no",
            "UsePAM": "yes", # Depende del setup
            "X11Forwarding": "no",
            "Protocol": "2",
            "LogLevel": "VERBOSE" # O INFO
        }
        audit_results = []
        logger.info(f"Auditando {ssh_config_path}...")

        if not os.path.isfile(ssh_config_path):
            logger.error(f"{ssh_config_path} no encontrado.")
            if generate_alerts:
                Alert("hardening_check_failed", {"component": "sshd", "error": "sshd_config not found"}, "high").save_to_db(self.db)
            return [{"component": "sshd", "setting": "file_check", "current_value": "Not Found", "status": "error", "notes": "sshd_config not found"}]

        current_config = {}
        try:
            with open(ssh_config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(maxsplit=1)
                    if len(parts) == 2:
                        current_config[parts[0]] = parts[1]
        except IOError as e:
            logger.error(f"Error leyendo {ssh_config_path}: {e}")
            if generate_alerts:
                 Alert("hardening_check_failed", {"component": "sshd", "error": f"Error reading sshd_config: {e}"}, "medium").save_to_db(self.db)
            return [{"component": "sshd", "setting": "file_read", "current_value": "Error", "status": "error", "notes": str(e)}]


        for setting, rec_value in recommendations.items():
            curr_value = current_config.get(setting)
            status = "compliant"
            notes = ""

            if curr_value is None:
                status = "missing_setting"
                notes = f"Configuración recomendada '{setting} {rec_value}' no encontrada."
            elif isinstance(rec_value, str) and curr_value.lower() != rec_value.lower():
                status = "non-compliant"
                notes = f"Se recomienda '{rec_value}', actual es '{curr_value}'."
            # Aquí se pueden añadir más lógicas para valores numéricos, listas, etc.
            
            result_entry = {
                "component": "sshd", "setting": setting, 
                "current_value": curr_value, "recommended_value": rec_value,
                "status": status, "notes": notes,
                "timestamp": datetime.datetime.now().isoformat()
            }
            audit_results.append(result_entry)
            
            # Guardar/Actualizar en DB
            db_entry = self.db.execute("SELECT id FROM system_config_audit WHERE component = 'sshd' AND setting = ?", (setting,))
            if db_entry:
                self.db.execute(
                    "UPDATE system_config_audit SET current_value=?, recommended_value=?, status=?, notes=?, timestamp=? WHERE component='sshd' AND setting=?",
                    (curr_value, rec_value, status, notes, result_entry["timestamp"], setting)
                )
            else:
                self.db.insert(
                    "INSERT INTO system_config_audit (component, setting, current_value, recommended_value, status, notes, timestamp) VALUES ('sshd', ?, ?, ?, ?, ?, ?)",
                    (setting, curr_value, rec_value, status, notes, result_entry["timestamp"])
                )

            if status != "compliant" and generate_alerts:
                Alert(
                    "hardening_violation",
                    {"component": "sshd", "setting": setting, "current": curr_value, "recommended": rec_value, "status": status},
                    "medium" if status == "non-compliant" else "low" # 'missing_setting' podría ser 'low'
                ).save_to_db(self.db)
        
        logger.info(f"Auditoría de SSHD completada. {len(audit_results)} configuraciones revisadas.")
        return audit_results
        
    def check_suid_sgid_files(self) -> List[Dict]:
        """Encuentra archivos con bits SUID/SGID."""
        logger.info("Buscando archivos SUID/SGID...")
        # Comandos más robustos para buscar, excluyendo directorios comunes de /proc y /sys
        # find / \( -path /proc -o -path /sys \) -prune -o \( -perm -4000 -o -perm -2000 \) -type f -print0
        cmd = "find / \\( -path /proc -o -path /sys -o -path /dev -o -path /run \\) -prune -o \\( -perm -4000 -o -perm -2000 \\) -type f -ls"
        # OJO: Este comando puede tardar mucho y ser intensivo en I/O
        # Para una herramienta real, se necesitarían optimizaciones o hacerlo opcional / programado
        
        # Simplificado para el ejemplo:
        # cmd = ["find", "/", "-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print0"]
        # code, stdout, stderr = SystemUtils.run_command(cmd)
        # files = []
        # if code == 0 and stdout:
        #     files = [f for f in stdout.split('\0') if f] # Split por NUL byte
        # elif stderr:
        #     logger.error(f"Error buscando archivos SUID/SGID: {stderr}")

        # Alternativa con psutil para evitar `find` que puede ser lento, pero es más limitado:
        # Esta alternativa es conceptual, psutil no tiene un find directo con permisos.
        # Se mantiene el `find` como el método más directo para esto en shell.
        # Por ahora, un placeholder:
        logger.warning("La búsqueda de SUID/SGID con 'find' puede ser lenta. Implementación simplificada.")
        
        suid_sgid_files = []
        # Este es un ejemplo muy básico, en un sistema real, `find` es más apropiado pero más lento.
        # Una implementación más segura de `find` requiere cuidado con `shell=True`.
        # Para este ejemplo, dejaremos un mensaje y un resultado vacío.
        # Si decides usar `find`, usa `shell=False` y la lista de argumentos.
        # ej: SystemUtils.run_command(['find', '/', '-perm', '/6000', '-type', 'f'])
        
        logger.info("Revisar manualmente con: find / \\( -path /proc -o -path /sys \\) -prune -o \\( -perm -4000 -o -perm -2000 \\) -type f -ls")
        # Aquí se podrían añadir hashes conocidos de SUID/SGID "buenos" vs "malos".
        return [] # Placeholder


class IncidentResponder:
    """Módulo para acciones de respuesta a incidentes."""
    def __init__(self, config: Dict, db: Database):
        self.config = config
        self.db = db
        self.quarantine_dir = config.get("quarantine_dir", "./quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def quarantine_file(self, filepath: str) -> bool:
        """Mueve un archivo a la carpeta de cuarentena y le quita permisos."""
        if not os.path.isfile(filepath):
            logger.error(f"No se puede poner en cuarentena: {filepath} no es un archivo o no existe.")
            return False
        
        try:
            filename = os.path.basename(filepath)
            quarantine_path = os.path.join(self.quarantine_dir, filename + "_" + datetime.datetime.now().strftime("%Y%m%d%H%M%S"))
            
            # Primero, backup si está configurado
            SystemUtils.backup_file(filepath, self.config.get("backup_dir_before_quarantine", os.path.join(self.quarantine_dir, "backups")))

            shutil.move(filepath, quarantine_path)
            os.chmod(quarantine_path, 0o000) # Sin permisos
            
            logger.info(f"Archivo {filepath} movido a cuarentena en {quarantine_path} y permisos eliminados.")
            Alert(
                "file_quarantined",
                {"original_path": filepath, "quarantine_path": quarantine_path},
                "medium"
            ).save_to_db(self.db)
            return True
        except Exception as e:
            logger.error(f"Error al poner en cuarentena {filepath}: {e}")
            return False

    def block_ip(self, ip_address: str, interface: str = "INPUT") -> bool:
        """Bloquea una IP usando iptables (requiere sudo). Esta es una acción peligrosa."""
        # ¡ADVERTENCIA! Esto requiere privilegios de root y puede bloquear el acceso al sistema si se usa incorrectamente.
        # En una herramienta real, esto necesitaría una confirmación MUY explícita.
        logger.warning(f"Intentando bloquear IP {ip_address}. ESTO REQUIERE SUDO y es potencialmente peligroso.")
        
        # Comprobar si el usuario es root
        if os.geteuid() != 0:
            logger.error("Se requieren privilegios de root para bloquear IP con iptables.")
            self.db.insert(
                "INSERT INTO security_events (event_type, source, description, raw_data, timestamp) VALUES (?, ?, ?, ?, ?)",
                ("ip_block_failed", "IncidentResponder", f"Intento de bloquear {ip_address} falló: sin privilegios root", ip_address, datetime.datetime.now().isoformat())
            )
            return False

        # Comando para iptables
        # Usar -I para insertar al principio de la cadena, para que tenga prioridad
        cmd = ["iptables", "-I", interface.upper(), "-s", ip_address, "-j", "DROP"]
        
        # Verificar si la regla ya existe para evitar duplicados (opcional, pero buena práctica)
        check_cmd = ["iptables", "-C", interface.upper(), "-s", ip_address, "-j", "DROP"]
        code_check, _, _ = SystemUtils.run_command(check_cmd, shell=False)
        if code_check == 0:
            logger.info(f"La regla para bloquear {ip_address} ya existe.")
            return True # Considerar éxito si ya está bloqueada

        code, stdout, stderr = SystemUtils.run_command(cmd, shell=False)

        if code == 0:
            logger.info(f"IP {ip_address} bloqueada exitosamente en la cadena {interface}.")
            Alert("ip_blocked", {"ip_address": ip_address, "interface": interface, "rule": " ".join(cmd)}, "high").save_to_db(self.db)
            return True
        else:
            logger.error(f"Error al bloquear IP {ip_address}: {stderr} (stdout: {stdout})")
            self.db.insert(
                "INSERT INTO security_events (event_type, source, description, raw_data, timestamp) VALUES (?, ?, ?, ?, ?)",
                ("ip_block_failed", "IncidentResponder", f"Error iptables: {stderr}", ip_address, datetime.datetime.now().isoformat())
            )
            return False

    def kill_process(self, pid: int, signal_to_send=signal.SIGTERM) -> bool:
        """Termina un proceso por su PID."""
        logger.warning(f"Intentando terminar proceso PID: {pid} con señal {signal_to_send}")
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.send_signal(signal_to_send) # SIGTERM (15) es más amigable, SIGKILL (9) es forzado
            logger.info(f"Señal {signal_to_send} enviada al proceso PID {pid} ({proc_name}). Verificar si terminó.")
            Alert("process_kill_attempted", {"pid": pid, "name": proc_name, "signal": signal_to_send}, "medium").save_to_db(self.db)
            # No se puede garantizar que el proceso termine inmediatamente, solo que se envió la señal.
            return True
        except psutil.NoSuchProcess:
            logger.error(f"No se puede terminar: Proceso PID {pid} no encontrado.")
            return False
        except psutil.AccessDenied:
            logger.error(f"No se puede terminar: Acceso denegado para terminar PID {pid}. ¿Se necesitan privilegios?")
            return False
        except Exception as e:
            logger.error(f"Error al intentar terminar proceso PID {pid}: {e}")
            return False

class ReportGenerator:
    """Genera informes basados en los hallazgos."""
    def __init__(self, config: Dict, db: Database):
        self.config = config
        self.db = db
        self.output_dir = config.get("output_dir", "./reports")
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_summary_report(self, filename: Optional[str] = None) -> str:
        """Genera un informe de resumen en texto plano."""
        report_path = os.path.join(self.output_dir, filename or f"summary_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        logger.info(f"Generando informe de resumen en {report_path}...")
        
        content = []
        content.append(f"LazyOwn BlueTeam Framework - Informe de Seguridad")
        content.append(f"Generado el: {datetime.datetime.now().isoformat()}")
        content.append("=" * 40)

        # 1. Alertas recientes (últimas 24h, top 10)
        content.append("\n[+] Alertas Recientes (últimas 24h, máx 10 de alta/crítica severidad):")
        cutoff_time = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
        alerts = self.db.execute(
            "SELECT timestamp, type, severity, details FROM alerts WHERE severity IN ('high', 'critical') AND timestamp >= ? ORDER BY timestamp DESC LIMIT 10",
            (cutoff_time,)
        )
        if alerts:
            for alert_row in alerts:
                details_dict = json.loads(alert_row['details']) # Convertir JSON string a dict
                content.append(f"  - {alert_row['timestamp']} [{alert_row['severity'].upper()}] {alert_row['type']}: {details_dict.get('name', details_dict.get('filepath', next(iter(details_dict.values()))))}") # Mostrar un detalle relevante
        else:
            content.append("  No hay alertas críticas/altas recientes.")

        # 2. Violaciones de Integridad de Archivos (activas)
        content.append("\n[+] Violaciones de Integridad de Archivos (activas):")
        fim_violations = FileIntegrityMonitor(self.config, self.db).scan(generate_alerts=False) # No generar nuevas alertas aquí
        if fim_violations:
            for v in fim_violations:
                content.append(f"  - {v['filepath']} ({v['status']})")
        else:
            content.append("  No se encontraron violaciones de integridad de archivos.")
            
        # 3. Procesos Sospechosos (del último escaneo, si hubiera un log de eso, o un escaneo rápido)
        #    Para este ejemplo, no tenemos un "último escaneo" guardado, así que es conceptual.
        content.append("\n[+] Procesos Sospechosos (ejecutar 'proc_scan' para detalles):")
        content.append("  (Información de procesos requiere escaneo activo)")

        # 4. Endurecimiento del sistema (basado en system_config_audit)
        content.append("\n[+] Estado de Endurecimiento (no conformidades):")
        hardening_issues = self.db.execute(
            "SELECT component, setting, current_value, recommended_value FROM system_config_audit WHERE status != 'compliant' AND status != 'check_manually' LIMIT 10"
        )
        if hardening_issues:
            for issue in hardening_issues:
                content.append(f"  - {issue['component']}/{issue['setting']}: Actual='{issue['current_value']}', Recomendado='{issue['recommended_value']}'")
        else:
            content.append("  No hay problemas de endurecimiento no conformes registrados (o ninguno auditado).")

        content.append("\n" + "=" * 40)
        content.append("Fin del informe.")
        
        report_str = "\n".join(content)
        try:
            with open(report_path, 'w') as f:
                f.write(report_str)
            logger.info(f"Informe de resumen guardado en {report_path}")
            return report_path
        except IOError as e:
            logger.error(f"Error al guardar el informe: {e}")
            return ""

class MemoryScanner:
    def __init__(self, config: Dict, db: Database):
        self.config = config
        self.db = db
        self.suspicious_strings = [
            "backdoor", "exploit", "rootkit", "malware", "virus", "trojan",
            "reverse shell", "connect back", "netcat", "meterpreter", "payload",
            "/bin/sh", "/bin/bash", "/dev/tcp", "wget http", "curl http",
            "base64 -d", "eval(", "exec(", "system(", "passthru(", "shell_exec(",
            "msfvenom", "metasploit"
        ]

    def scan_process_memory(self, pid: int) -> Dict:
        results = {
            "pid": pid,
            "suspicious_strings": [],
            "scanned": False
        }
        try:
            process = psutil.Process(pid)
            results["process_name"] = process.name()
            results["process_cmdline"] = process.cmdline()
            results["process_username"] = process.username()
            maps_path = f"/proc/{pid}/maps"
            mem_path = f"/proc/{pid}/mem"
            if not os.path.exists(maps_path) or not os.path.exists(mem_path):
                results["error"] = "Memory files not accessible"
                return results
            if os.geteuid() != 0:
                results["error"] = "Root privileges required to scan memory"
                return results
            with open(maps_path, 'r') as maps_file:
                try:
                    with open(mem_path, 'rb', 0) as mem_file:
                        for line in maps_file:
                            region = line.split()
                            if len(region) < 6:
                                continue
                            if 'r' not in region[1]:
                                continue
                            region_start, region_end = map(lambda x: int(x, 16), region[0].split('-'))
                            region_size = region_end - region_start
                            if region_size > 100 * 1024 * 1024:
                                continue
                            try:
                                mem_file.seek(region_start)
                                content = mem_file.read(region_size)
                                for suspicious_string in self.suspicious_strings:
                                    if suspicious_string.encode() in content:
                                        results["suspicious_strings"].append({
                                            "string": suspicious_string,
                                            "region_start": hex(region_start),
                                            "region_end": hex(region_end)
                                        })
                            except Exception as e:
                                logger.debug(f"Memory region read error {region[0]}: {e}")
                except Exception as e:
                    results["error"] = f"Process memory access error: {e}"
                    return results
            results["scanned"] = True
            results["suspicious_count"] = len(results["suspicious_strings"])
            if results["suspicious_strings"]:
                alert = Alert(
                    alert_type="suspicious_memory_content",
                    details={
                        "pid": pid,
                        "process_name": results["process_name"],
                        "suspicious_count": len(results["suspicious_strings"]),
                        "suspicious_strings": [s["string"] for s in results["suspicious_strings"]]
                    },
                    severity="high"
                )
                alert.save_to_db(self.db)
            return results
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            results["error"] = f"Process access error: {e}"
            return results

    def scan_system(self, max_processes: int = 50) -> List[Dict]:
        results = []
        process_monitor = ProcessMonitor(self.config, self.db)
        suspicious_processes = process_monitor.scan()
        suspicious_processes.sort(key=lambda p: len(p.get("reasons", [])), reverse=True)
        processes_to_scan = suspicious_processes[:max_processes]
        for process in processes_to_scan:
            try:
                scan_result = self.scan_process_memory(process["pid"])
                results.append(scan_result)
            except Exception as e:
                logger.error(f"Process scan error {process['pid']}: {e}")
        return results

# --- Aplicación Principal CMD2 ---
class LazyOwnApp(cmd2.Cmd):
    """Interfaz de línea de comandos para LazyOwn BlueTeam Framework."""

    prompt = '(LazyOwn@BlueTeam) %  '
    intro = cmd2.style("Bienvenido a LazyOwn BlueTeam Framework v" + __version__ + ". Escriba 'help' para ver los comandos.", bold=True)

    def __init__(self, config_path: Optional[str] = None):
        super().__init__(allow_cli_args=False) # Deshabilitar argumentos de CLI para cmd2 por ahora

        # Eliminar comandos integrados no deseados
        del cmd2.Cmd.do_alias
        del cmd2.Cmd.do_macro
        del cmd2.Cmd.do_run_script # o `del cmd2.Cmd.do__relative_run_script`
        del cmd2.Cmd.do_run_pyscript
        del cmd2.Cmd.do_shell # Proporcionaremos uno propio más controlado si es necesario
        del cmd2.Cmd.do_edit
        del cmd2.Cmd.do_set
        del cmd2.Cmd.do_shortcuts
        del cmd2.Cmd.do_history


        self.config = self._load_config(config_path)
        self.db = Database(self.config["database_path"])

        # Inicializar módulos principales
        self.process_monitor = ProcessMonitor(self.config, self.db)
        self.network_monitor = NetworkMonitor(self.config, self.db)
        self.fim = FileIntegrityMonitor(self.config, self.db)
        self.log_analyzer = LogAnalyzer(self.config, self.db)
        self.hardener = SystemHardener(self.config, self.db)
        self.responder = IncidentResponder(self.config, self.db)
        self.reporter = ReportGenerator(self.config, self.db)
        self.file_monitor = FileIntegrityMonitor(self.config, self.db)
        self.system_hardener = SystemHardener(self.config, self.db)
        self.memory_scanner = MemoryScanner(self.config, self.db)
        logger.info("LazyOwnApp inicializada.")

    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Carga la configuración desde un archivo JSON o usa los defaults."""
        config = DEFAULT_CONFIG.copy()
        if config_file and os.path.isfile(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    config.update(user_config)
                logger.info(f"Configuración cargada desde {config_file}")
            except json.JSONDecodeError:
                logger.error(f"Error al decodificar JSON en {config_file}. Usando defaults.")
            except Exception as e:
                logger.error(f"Error al cargar {config_file}: {e}. Usando defaults.")
        else:
            if config_file: # Si se especificó pero no se encontró
                 logger.warning(f"Archivo de configuración {config_file} no encontrado. Usando defaults.")
            else: # Ningún archivo especificado, usar defaults silenciosamente
                 logger.info("Usando configuración por defecto.")
        
        # Asegurar que los directorios existen
        os.makedirs(config.get("output_dir", "./reports"), exist_ok=True)
        os.makedirs(config.get("quarantine_dir", "./quarantine"), exist_ok=True)
        os.makedirs(config.get("backup_dir", "./backups"), exist_ok=True)
        
        return config

    def postloop(self) -> None:
        """Acciones al salir de la aplicación."""
        self.poutput("Cerrando LazyOwn BlueTeam Framework...")
        if self.db:
            self.db.close()
        logger.info("LazyOwnApp cerrada.")

    # --- Comandos CMD2 ---
    sysinfo_category = "1. Información del Sistema"
    detection_category = "2. Detección de Amenazas"
    integrity_category = "3. Integridad del Sistema"
    logging_category = "4. Análisis de Logs"
    hardening_category = "5. Endurecimiento del Sistema"
    response_category = "6. Respuesta a Incidentes"
    reporting_category = "7. Reportes"
    config_category = "8. Configuración"


    @cmd2.with_category(sysinfo_category)
    def do_sysinfo(self, _: cmd2.Statement):
        """Muestra información detallada del sistema."""
        self.poutput(cmd2.style("Obteniendo información del sistema..."))
        info = SystemUtils.get_system_info()
        
        # Formatear un poco la salida
        output_lines = [
            f"[+] Hostname: {info['hostname']}",
            f"[+] OS: {info['os']} {info['os_release']} ({info['os_version']})",
            f"[+] Arquitectura: {info['architecture']}",
            f"[+] Procesador: {info['processor']}",
            f"[+] CPUs Lógicas: {info['cpu_count_logical']}, Físicas: {info['cpu_count_physical']}",
            f"[+] Memoria Total: {info['memory_total_gb']} GB",
            f"[+] Tiempo de Arranque: {info['boot_time']}",
            f"[+] Versión Python: {info['python_version']}"
        ]
        if info["ip_addresses"]:
             output_lines.append("[+] Direcciones IP:")
             for ip_info in info["ip_addresses"]:
                 output_lines.append(f"  - {ip_info['interface']}: {ip_info['address']} (Mask: {ip_info['netmask']})")
        else:
            output_lines.append("[+] Direcciones IP: No encontradas o no accesibles.")

        self.print_रात(output_lines) # Usar un método de impresión consistente

    # --- Comandos de Detección ---
    @cmd2.with_category(detection_category)
    def do_proc_scan(self, _: cmd2.Statement):
        """Escanea procesos actuales en busca de actividad sospechosa."""
        self.poutput(cmd2.style("Escaneando procesos..."))
        suspicious = self.process_monitor.scan()
        if suspicious:
            headers = ["PID", "Nombre", "Usuario", "CPU%", "Mem%", "Cmdline", "Razones"]
            table_data = [
                [
                    s.get('pid'), s.get('name'), s.get('username'), 
                    f"{s.get('cpu_percent', 0.0):.2f}", f"{s.get('memory_percent', 0.0):.2f}",
                    s.get('cmdline', '')[:50] + ('...' if len(s.get('cmdline', '')) > 50 else ''), # Acortar cmdline
                    ', '.join(s.get('reasons', []))
                ] for s in suspicious
            ]
            self.print_रात(tabulate(table_data, headers=headers, tablefmt="grid"))
            self.poutput(cmd2.style(f"{len(suspicious)} procesos sospechosos encontrados. Ver 'lazyown_blueteam.log' y alertas en DB para detalles."))
        else:
            self.poutput(cmd2.style("No se encontraron procesos sospechosos según los criterios actuales."))

    proc_details_parser = cmd2.Cmd2ArgumentParser(description="Muestra detalles de un proceso específico.")
    proc_details_parser.add_argument('pid', type=int, help="PID del proceso a detallar.")
    @cmd2.with_category(detection_category)
    @cmd2.with_argparser(proc_details_parser)
    def do_proc_details(self, args: cmd2.Statement):
        """Muestra información detallada de un proceso específico por PID."""
        self.poutput(cmd2.style(f"Obteniendo detalles del PID {args.pid}..."))
        details = SystemUtils.get_process_details(args.pid)
        if details:
            # Preparar tabla de detalles
            table_data = []
            for key, value in details.items():
                if key == 'open_files' and value:
                    value_str = f"{len(value)} archivos abiertos (ej: {value[0].path[:50]}{'...' if len(value[0].path) > 50 else ''})"
                elif key == 'connections' and value:
                     value_str = f"{len(value)} conexiones (ver detalles con 'net_conns -p {args.pid}')"
                elif isinstance(value, list) and value and isinstance(value[0], dict) and len(value) > 1: # Para conexiones o archivos
                    value_str = f"{len(value)} elementos (primeros mostrados)"
                elif isinstance(value, list):
                    value_str = ", ".join(map(str,value[:3])) + ('...' if len(value) > 3 else '') if value else "N/A"
                elif isinstance(value, (int, float, str)) or value is None:
                    value_str = str(value) if value is not None else "N/A"
                else:
                    value_str = str(type(value)) # Tipo si es un objeto complejo no manejado

                table_data.append([cmd2.style(key, bold=True), value_str])
            
            self.print_रात(tabulate(table_data, headers=["Atributo", "Valor"], tablefmt="grid"))
        else:
            self.poutput(cmd2.style(f"No se pudo obtener información para el PID {args.pid}. Puede que no exista o no tengas permisos."))


    @cmd2.with_category(detection_category)
    def do_net_baseline(self, _: cmd2.Statement):
        """Crea/actualiza la línea base de conexiones de red activas."""
        if self.confirm_action("Esto sobrescribirá la línea base de red existente. ¿Continuar? (s/N)"):
            self.network_monitor.create_baseline()
            self.poutput(cmd2.style("Línea base de red actualizada. Los datos están en la base de datos."))
        else:
            self.poutput(cmd2.style("Creación de línea base de red cancelada."))

    @cmd2.with_category(detection_category)
    def do_net_scan(self, _: cmd2.Statement):
        """Escanea conexiones de red actuales en busca de anomalías respecto a la línea base y puertos sospechosos."""
        self.poutput(cmd2.style("Escaneando conexiones de red..."))
        suspicious = self.network_monitor.scan()
        if suspicious:
            headers = ["PID", "Proceso", "Proto", "L-Addr", "L-Port", "R-Addr", "R-Port", "Estado", "Razones"]
            table_data = [
                [
                    s.get('pid', 'N/A'), s.get('process_name', 'N/A')[:20], s.get('protocol'),
                    s.get('local_address'), s.get('local_port'),
                    s.get('remote_address', ''), s.get('remote_port', ''),
                    s.get('status'),
                    ', '.join(s.get('reasons', []))
                ] for s in suspicious
            ]
            self.print_रात(tabulate(table_data, headers=headers, tablefmt="grid"))
            self.poutput(cmd2.style(f"{len(suspicious)} conexiones/actividades de red sospechosas encontradas. Ver log y alertas DB."))
        else:
            self.poutput(cmd2.style("No se encontraron conexiones de red sospechosas."))

    net_conns_parser = cmd2.Cmd2ArgumentParser(description="Muestra conexiones de red activas, similar a netstat/ss.")
    net_conns_parser.add_argument('-p', '--pid', type=int, help="Filtrar por PID del proceso propietario.")
    net_conns_parser.add_argument('-l', '--listening', action='store_true', help="Mostrar solo sockets en escucha (LISTEN).")
    net_conns_parser.add_argument('-P', '--port', type=int, help="Filtrar por puerto local o remoto.")
    net_conns_parser.add_argument('-t', '--tcp', action='store_true', help="Mostrar solo conexiones TCP.")
    net_conns_parser.add_argument('-u', '--udp', action='store_true', help="Mostrar solo conexiones UDP.")

    @cmd2.with_category(detection_category)
    @cmd2.with_argparser(net_conns_parser)
    def do_net_conns(self, args: cmd2.Statement):
        """Muestra conexiones de red activas (TCP, UDP, LISTEN, ESTABLISHED, etc.)."""
        self.poutput(cmd2.style("Listando conexiones de red..."))
        connections_data = []
        try:
            # kind='inet' cubre TCP y UDP para IPv4/v6. Se puede especificar 'tcp', 'udp'.
            kind_filter = 'inet'
            if args.tcp and not args.udp: kind_filter = 'tcp'
            if args.udp and not args.tcp: kind_filter = 'udp'

            for conn in psutil.net_connections(kind=kind_filter):
                display_conn = True
                
                # Filtrar por PID
                if args.pid and conn.pid != args.pid:
                    display_conn = False
                
                # Filtrar por estado LISTEN
                if args.listening and conn.status != 'LISTEN':
                    display_conn = False
                
                # Filtrar por puerto
                if args.port:
                    lport = conn.laddr.port if conn.laddr else -1
                    rport = conn.raddr.port if conn.raddr and conn.raddr else -1
                    if args.port not in [lport, rport]:
                        display_conn = False

                if display_conn:
                    proc_name = "N/A"
                    if conn.pid:
                        try:
                            p = psutil.Process(conn.pid)
                            proc_name = p.name()[:20] # Acortar nombre de proceso
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass # Mantener N/A
                    
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP" if conn.type == socket.SOCK_DGRAM else str(conn.type)
                    
                    connections_data.append([
                        conn.pid or "N/A",
                        proc_name,
                        proto,
                        f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        conn.status or "N/A"
                    ])
            
            if connections_data:
                headers = ["PID", "Proceso", "Proto", "Local Address", "Remote Address", "Estado"]
                self.print_रात(tabulate(connections_data, headers=headers, tablefmt="psql")) # psql es más compacto
            else:
                self.poutput(cmd2.style("No se encontraron conexiones que coincidan con los filtros."))

        except psutil.AccessDenied:
            self.poutput(cmd2.style("Acceso denegado. Algunos datos de conexión pueden no estar disponibles sin privilegios."))
        except Exception as e:
            self.poutput(cmd2.style(f"Error obteniendo conexiones de red: {e}"))
            logger.error(f"Error en do_net_conns: {e}")


    # --- Comandos de Integridad ---
    fim_baseline_parser = cmd2.Cmd2ArgumentParser(description="Inicializa o actualiza la línea base de integridad para archivos críticos o especificados.")
    fim_baseline_parser.add_argument('files', nargs='*', help="Archivos específicos para añadir/actualizar en la línea base (opcional, usa críticos por defecto).")
    @cmd2.with_category(integrity_category)
    @cmd2.with_argparser(fim_baseline_parser)
    def do_fim_baseline(self, args: cmd2.Statement):
        """Inicializa/actualiza la línea base de hashes para los archivos críticos o especificados."""
        target_files = args.files if args.files else None # None para usar los críticos por defecto
        
        action_msg = "los archivos críticos configurados" if not target_files else f"{len(target_files)} archivos especificados"
        if self.confirm_action(f"Esto (re)calculará y almacenará los hashes para {action_msg}. ¿Continuar? (s/N)"):
            self.fim.initialize_baseline(files_to_baseline=target_files)
            self.poutput(cmd2.style("Línea base de integridad de archivos actualizada."))
        else:
            self.poutput(cmd2.style("Actualización de línea base cancelada."))


    @cmd2.with_category(integrity_category)
    def do_fim_scan(self, _: cmd2.Statement):
        """Verifica la integridad de los archivos críticos contra la línea base."""
        self.poutput(cmd2.style("Escaneando integridad de archivos..."))
        violations = self.fim.scan()
        if violations:
            headers = ["Archivo", "Estado", "Hash Actual / Mensaje", "Hash Baseline", "Modificado"]
            table_data = [
                [
                    v.get('filepath'), v.get('status'),
                    v.get('current_hash') or v.get('message', ''),
                    v.get('baseline_hash', 'N/A'),
                    v.get('modified_time', 'N/A')
                ] for v in violations
            ]
            self.print_रात(tabulate(table_data, headers=headers, tablefmt="grid"))
            self.poutput(cmd2.style(f"{len(violations)} violaciones de integridad encontradas. Ver log y alertas DB."))
        else:
            self.poutput(cmd2.style("No se encontraron violaciones de integridad en los archivos monitorizados."))

    # --- Comandos de Logs ---
    log_analyze_parser = cmd2.Cmd2ArgumentParser(description="Analiza archivos de log específicos o todos los configurados.")
    log_analyze_parser.add_argument('log_files', nargs='*', help="Rutas a archivos de log específicos para analizar (opcional, usa configurados por defecto).")
    @cmd2.with_category(logging_category)
    @cmd2.with_argparser(log_analyze_parser)
    def do_log_analyze(self, args: cmd2.Statement):
        """Analiza los logs configurados o especificados en busca de patrones sospechosos."""
        self.poutput(cmd2.style("Analizando logs..."))
        
        if args.log_files:
            self.poutput(f"Analizando archivos de log especificados: {', '.join(args.log_files)}")
            results = {}
            for log_file_path in args.log_files:
                results[log_file_path] = self.log_analyzer.analyze_log_file(log_file_path)
        else:
            self.poutput(f"Analizando todos los logs configurados: {', '.join(self.config.get('log_paths',[]))}")
            results = self.log_analyzer.analyze_all_logs()

        total_findings = sum(len(f) for f in results.values())
        
        if total_findings > 0:
            self.poutput(cmd2.style(f"Se encontraron {total_findings} eventos de interés en los logs."))
            # Mostrar un resumen (ej. los 5 primeros o los más recientes)
            display_count = 0
            for log_file, findings_in_file in results.items():
                if not findings_in_file: continue
                self.poutput(cmd2.style(f"\n--- Hallazgos en {log_file} ---", bold=True))
                for finding in findings_in_file[:5]: # Mostrar hasta 5 por archivo
                    if display_count >= 10: break # No más de 10 en total
                    self.poutput(f"  [{finding['pattern_name']}] {finding['line_content'][:100]}{'...' if len(finding['line_content'])>100 else ''}")
                    display_count+=1
                if display_count >= 10:
                    self.poutput("... y más (ver log y alertas DB para todos los detalles).")
                    break
            if display_count == 0 and total_findings > 0: # Si los primeros archivos no tenían nada pero otros sí
                 self.poutput("Hallazgos encontrados. Ver log y alertas DB para todos los detalles.")

        else:
            self.poutput(cmd2.style("No se encontraron eventos de interés en los logs analizados según los patrones actuales."))

    # --- Comandos de Endurecimiento ---
    @cmd2.with_category(hardening_category)
    def do_harden_audit_ssh(self, _: cmd2.Statement):
        """Audita la configuración del demonio SSH (sshd_config)."""
        results = self.hardener.audit_ssh_config()
        if results:
            headers = ["Componente", "Configuración", "Actual", "Recomendado", "Estado", "Notas"]
            table_data = [[r['component'], r['setting'], r['current_value'], r['recommended_value'], r['status'], r['notes']] for r in results]
            self.print_रात(tabulate(table_data, headers=headers, tablefmt="grid"))
            non_compliant = [r for r in results if r['status'] != 'compliant' and r['status'] != 'check_manually']
            if non_compliant:
                self.poutput(cmd2.style(f"{len(non_compliant)} configuraciones de SSHD no cumplen las recomendaciones."))
            else:
                self.poutput(cmd2.style("Configuración de SSHD parece cumplir con las recomendaciones básicas auditadas."))
        else:
            self.poutput(cmd2.style("No se pudo realizar la auditoría de SSHD o no se encontraron configuraciones."))

    # --- Comandos de Respuesta ---
    quarantine_parser = cmd2.Cmd2ArgumentParser(description="Mueve un archivo a la carpeta de cuarentena y le quita permisos.")
    quarantine_parser.add_argument('filepath', help="Ruta completa al archivo a poner en cuarentena.")
    @cmd2.with_category(response_category)
    @cmd2.with_argparser(quarantine_parser)
    def do_resp_quarantine_file(self, args: cmd2.Statement):
        """Mueve un archivo a cuarentena y le quita permisos (acción irreversible sobre el original)."""
        filepath = args.filepath
        if self.confirm_action(f"ADVERTENCIA: Esto moverá '{filepath}' a la cuarentena ({self.responder.quarantine_dir}) y eliminará sus permisos. Esta acción es difícil de revertir. ¿Está seguro? (s/N)"):
            if self.responder.quarantine_file(filepath):
                self.poutput(cmd2.style(f"Archivo {filepath} puesto en cuarentena."))
            else:
                self.poutput(cmd2.style(f"Falló la puesta en cuarentena de {filepath}. Ver logs."))
        else:
            self.poutput(cmd2.style("Acción de cuarentena cancelada."))

    blockip_parser = cmd2.Cmd2ArgumentParser(description="Bloquea una dirección IP usando iptables (requiere sudo).")
    blockip_parser.add_argument('ip_address', help="Dirección IP a bloquear.")
    blockip_parser.add_argument('-i', '--interface', default="INPUT", help="Cadena de iptables (ej: INPUT, FORWARD). Default: INPUT.")
    @cmd2.with_category(response_category)
    @cmd2.with_argparser(blockip_parser)
    def do_resp_block_ip(self, args: cmd2.Statement):
        """Bloquea una IP usando iptables (¡ACCIÓN PELIGROSA, REQUIERE SUDO!)."""
        # Doble confirmación por la peligrosidad
        if not self.confirm_action(f"ADVERTENCIA EXTREMA: Está a punto de intentar bloquear la IP {args.ip_address} usando iptables. "
                                   "Esto requiere privilegios de root y una regla incorrecta puede CORTAR SU ACCESO AL SERVIDOR. "
                                   "¿Está ABSOLUTAMENTE SEGURO de que sabe lo que está haciendo? (escriba 'si,estoyseguro' para continuar)"):
            self.poutput(cmd2.style("Bloqueo de IP cancelado."))
            return

        # Validar formato de IP simple
        try:
            socket.inet_aton(args.ip_address)
        except socket.error:
            self.poutput(cmd2.style(f"Formato de IP inválido: {args.ip_address}"))
            return
            
        if os.geteuid() != 0:
            self.poutput(cmd2.style("Error: Esta acción requiere privilegios de root (sudo). Ejecute LazyOwn con sudo."))
            Alert("action_failed_privileges", {"action": "block_ip", "ip": args.ip_address}, "critical").save_to_db(self.db)
            return

        if self.responder.block_ip(args.ip_address, args.interface):
            self.poutput(cmd2.style(f"IP {args.ip_address} bloqueada (o ya estaba bloqueada) en la cadena {args.interface}."))
        else:
            self.poutput(cmd2.style(f"Falló el bloqueo de la IP {args.ip_address}. Ver logs."))


    killproc_parser = cmd2.Cmd2ArgumentParser(description="Termina un proceso por su PID (envía SIGTERM por defecto).")
    killproc_parser.add_argument('pid', type=int, help="PID del proceso a terminar.")
    killproc_parser.add_argument('-s', '--signal', type=int, default=signal.SIGTERM, help=f"Señal a enviar (ej: {signal.SIGTERM} para TERM, {signal.SIGKILL} para KILL). Default: {signal.SIGTERM} (TERM).")
    
    @cmd2.with_category(response_category)
    @cmd2.with_argparser(killproc_parser)
    def do_resp_kill_proc(self, args: cmd2.Statement):
        """Termina un proceso enviándole una señal (SIGTERM por defecto)."""
        if self.confirm_action(f"ADVERTENCIA: Intentará enviar la señal {args.signal} al proceso PID {args.pid}. Esto podría causar pérdida de datos o inestabilidad. ¿Continuar? (s/N)"):
            if self.responder.kill_process(args.pid, args.signal):
                self.poutput(cmd2.style(f"Señal {args.signal} enviada al PID {args.pid}. Verifique su estado."))
            else:
                self.poutput(cmd2.style(f"No se pudo enviar la señal al PID {args.pid}. Ver logs."))
        else:
            self.poutput(cmd2.style("Envío de señal cancelado."))


    # --- Comandos de Reporte ---
    report_parser = cmd2.Cmd2ArgumentParser(description="Genera un informe de seguridad resumen.")
    report_parser.add_argument('-o', '--output', help="Nombre del archivo de salida para el informe (opcional).")
    @cmd2.with_category(reporting_category)
    @cmd2.with_argparser(report_parser)
    def do_report_summary(self, args: cmd2.Statement):
        """Genera un informe de resumen de seguridad."""
        report_file = self.reporter.generate_summary_report(filename=args.output)
        if report_file:
            self.poutput(cmd2.style(f"Informe de resumen generado: {report_file}"))
        else:
            self.poutput(cmd2.style("No se pudo generar el informe de resumen."))


    # --- Comandos de Configuración ---
    @cmd2.with_category(config_category)
    def do_show_config(self, _: cmd2.Statement):
        """Muestra la configuración actual de LazyOwn."""
        self.poutput(cmd2.style("Configuración Actual:", bold=True))
        # Usar json.dumps para una visualización bonita de diccionarios/listas
        config_str = json.dumps(self.config, indent=4, sort_keys=True, default=str) # default=str para manejar Path, etc.
        self.print_रात(config_str)

    # --- Utilidades ---
    def print_रात(self, data_to_print: Union[str, List[str], Dict]):
        """Método wrapper para poutput, maneja diferentes tipos de datos."""
        if isinstance(data_to_print, str):
            self.poutput(data_to_print)
        elif isinstance(data_to_print, list):
            for line in data_to_print:
                self.poutput(str(line)) # Asegurar que sea string
        elif isinstance(data_to_print, dict):
             self.poutput(json.dumps(data_to_print, indent=4, default=str))
        else: # Para tabulate u otros objetos que se convierten bien a str
            self.poutput(str(data_to_print))
    
    def do_system_info(self, arg):
        """Display system information."""
        info = SystemUtils.get_system_info()
        self.poutput(f"System Information:\n{json.dumps(info, indent=2)}")

    def do_scan_processes(self, arg):
        """Scan for suspicious processes."""
        results = self.process_monitor.scan()
        if results:
            self.poutput(tabulate(
                [[p["pid"], p["name"], p["username"], ", ".join(p["reasons"])] for p in results],
                headers=["PID", "Name", "User", "Reasons"],
                tablefmt="grid"
            ))
        else:
            self.poutput("No suspicious processes found.")

    def do_scan_network(self, arg):
        """Scan for suspicious network connections."""
        results = self.network_monitor.scan()
        if results:
            self.poutput(tabulate(
                [[c["pid"], c["local_address"], c["local_port"], c["remote_address"], c["remote_port"], ", ".join(c["reasons"])] for c in results],
                headers=["PID", "Local Address", "Local Port", "Remote Address", "Remote Port", "Reasons"],
                tablefmt="grid"
            ))
        else:
            self.poutput("No suspicious network connections found.")

    def do_create_network_baseline(self, arg):
        """Create network connections baseline."""
        self.network_monitor.create_baseline()
        self.poutput("Network baseline created successfully.")

    def do_check_file_integrity(self, arg):
        """Check integrity of critical files."""
        results = self.file_monitor.scan()
        if results:
            self.poutput(tabulate(
                [[f["filepath"], f.get("current_hash", ""), f.get("baseline_hash", ""), f.get("error", "")] for f in results],
                headers=["File", "Current Hash", "Baseline Hash", "Error"],
                tablefmt="grid"
            ))
        else:
            self.poutput("No file integrity issues found.")

    def do_init_file_baseline(self, arg):
        """Initialize file integrity baseline."""
        self.file_monitor.initialize_baseline()
        self.poutput("File integrity baseline initialized.")

    def do_analyze_logs(self, arg):
        """Analyze system logs for suspicious activity."""
        results = self.log_analyzer.analyze()
        for pattern, findings in results.items():
            if findings:
                self.poutput(f"\n{pattern.replace('_', ' ').title()}:")
                self.poutput(tabulate(
                    [[f["timestamp"], f["line"]] for f in findings[:5]],
                    headers=["Timestamp", "Log Entry"],
                    tablefmt="grid"
                ))

    def do_check_security(self, arg):
        """Check system security configuration."""
        results = self.system_hardener.check_system_security()
        for category, checks in results.items():
            if checks:
                self.poutput(f"\n{category.title()}:")
                self.poutput(tabulate(
                    [[c["check"], c["status"], c["message"], c.get("recommendation", "")] for c in checks],
                    headers=["Check", "Status", "Message", "Recommendation"],
                    tablefmt="grid"
                ))

    def do_harden_system(self, arg):
        """Apply system hardening measures."""
        results = self.system_hardener.apply_hardening()
        for status, actions in results.items():
            if actions:
                self.poutput(f"\n{status.title()}:")
                self.poutput(tabulate(
                    [[a["hardening"], a["details"]] for a in actions],
                    headers=["Hardening", "Details"],
                    tablefmt="grid"
                ))

    def do_scan_memory(self, arg):
        """Scan system memory for suspicious content."""
        results = self.memory_scanner.scan_system()
        suspicious = [r for r in results if r["suspicious_strings"]]
        if suspicious:
            self.poutput(tabulate(
                [[r["pid"], r["process_name"], len(r["suspicious_strings"]), ", ".join(s["string"] for s in r["suspicious_strings"])] for r in suspicious],
                headers=["PID", "Process", "Count", "Suspicious Strings"],
                tablefmt="grid"
            ))
        else:
            self.poutput("No suspicious memory content found.")

    # Defensive Commands
    def do_block_ip(self, arg):
        """Block an IP address using UFW: block_ip <ip_address>"""
        if not arg:
            self.poutput("Usage: block_ip <ip_address>")
            return
        if os.geteuid() != 0:
            self.poutput("Root privileges required")
            return
        returncode, stdout, stderr = SystemUtils.run_command(f"ufw deny from {arg}")
        if returncode == 0:
            self.poutput(f"IP {arg} blocked successfully")
            alert = Alert(
                alert_type="ip_blocked",
                details={"ip_address": arg},
                severity="medium"
            )
            alert.save_to_db(self.db)
        else:
            self.poutput(f"Error blocking IP: {stderr}")

    def do_kill_process(self, arg):
        """Kill a process by PID: kill_process <pid>"""
        if not arg:
            self.poutput("Usage: kill_process <pid>")
            return
        if os.geteuid() != 0:
            self.poutput("Root privileges required")
            return
        try:
            pid = int(arg)
            os.kill(pid, signal.SIGTERM)
            self.poutput(f"Process {pid} terminated")
            alert = Alert(
                alert_type="process_killed",
                details={"pid": pid},
                severity="medium"
            )
            alert.save_to_db(self.db)
        except (ValueError, OSError) as e:
            self.poutput(f"Error killing process: {e}")

    def do_quarantine_file(self, arg):
        """Quarantine a suspicious file: quarantine_file <filepath>"""
        if not arg:
            self.poutput("Usage: quarantine_file <filepath>")
            return
        if os.geteuid() != 0:
            self.poutput("Root privileges required")
            return
        try:
            quarantine_dir = self.config["quarantine_dir"]
            os.makedirs(quarantine_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.basename(arg)
            dest_path = os.path.join(quarantine_dir, f"{filename}_{timestamp}")
            shutil.move(arg, dest_path)
            os.chmod(dest_path, 0o400)
            self.poutput(f"File {arg} quarantined to {dest_path}")
            alert = Alert(
                alert_type="file_quarantined",
                details={"filepath": arg, "quarantine_path": dest_path},
                severity="high"
            )
            alert.save_to_db(self.db)
        except Exception as e:
            self.poutput(f"Error quarantining file: {e}")

    def do_audit_users(self, arg):
        """Audit system users and their privileges"""
        if os.geteuid() != 0:
            self.poutput("Root privileges required")
            return
        users = []
        with open('/etc/passwd', 'r') as f:
            for line in f:
                fields = line.strip().split(':')
                if int(fields[3]) < 1000 and fields[0] not in ['root', 'nobody']:
                    users.append({
                        "username": fields[0],
                        "uid": fields[3],
                        "home": fields[5],
                        "shell": fields[6]
                    })
        if users:
            self.poutput(tabulate(
                [[u["username"], u["uid"], u["home"], u["shell"]] for u in users],
                headers=["Username", "UID", "Home", "Shell"],
                tablefmt="grid"
            ))
            alert = Alert(
                alert_type="suspicious_users",
                details={"users": users},
                severity="medium"
            )
            alert.save_to_db(self.db)
        else:
            self.poutput("No suspicious users found.")

    def do_processes(self, arg):
        """Escanear procesos sospechosos"""
        print("Escaneando procesos...")
        results = self.process_monitor.scan()
        if results:
            for proc in results:
                print(f"[!] Proceso sospechoso encontrado: {proc['name']} (PID: {proc['pid']})")
                print(f"    Razones: {', '.join(proc['reasons'])}")
        else:
            print("[*] No se encontraron procesos sospechosos.")

    def do_network(self, arg):
        """Escanear conexiones de red sospechosas"""
        print("Escaneando conexiones de red...")
        results = self.network_monitor.scan()
        if results:
            for conn in results:
                print(f"[!] Conexión sospechosa detectada: {conn['remote_address']}:{conn['remote_port']}")
                print(f"    Proceso: {conn['process_name']} (PID: {conn['pid']})")
                print(f"    Razones: {', '.join(conn['reasons'])}")
        else:
            print("[*] No se encontraron conexiones sospechosas.")

    def do_files(self, arg):
        """Verificar integridad de archivos críticos"""
        print("Verificando archivos críticos...")
        results = self.file_integrity_monitor.scan()
        if results:
            for file_info in results:
                print(f"[!] Archivo modificado: {file_info['filepath']}")
                print(f"    Hash actual: {file_info['current_hash']}")
                print(f"    Hash baseline: {file_info['baseline_hash']}")
        else:
            print("[*] Todos los archivos críticos están intactos.")

    def do_logs(self, arg):
        """Analizar logs del sistema"""
        print("Analizando logs del sistema...")
        findings = self.log_analyzer.analyze()
        for pattern, entries in findings.items():
            if entries:
                print(f"[!] Se encontraron {len(entries)} coincidencias para '{pattern}'")

    def do_memory(self, arg):
        """Escanear memoria de procesos sospechosos"""
        print("Escaneando memoria de procesos...")
        results = self.memory_scanner.scan_system()
        for result in results:
            if result.get('suspicious_count', 0) > 0:
                print(f"[!] Memoria sospechosa en proceso PID={result['pid']} ({result['process_name']})")
                print(f"    Cadenas sospechosas encontradas: {result['suspicious_count']}")

    def do_hardening(self, arg):
        """Aplicar medidas de endurecimiento"""
        print("Aplicando medidas de endurecimiento...")
        results = self.system_hardener.apply_hardening()
        if results["success"]:
            print("[+] Éxito en las siguientes medidas:")
            for item in results["success"]:
                print(f"    - {item['hardening']}")
        if results["failure"]:
            print("[!] Fallos al aplicar endurecimiento:")
            for item in results["failure"]:
                print(f"    - {item['hardening']}: {item['details']}")
        if results["skipped"]:
            print("[*] Omitidos:")
            for item in results["skipped"]:
                print(f"    - {item['hardening']}: {item['reason']}")

    def confirm_action(self, prompt_message: str, confirm_keyword: str = 's') -> bool:
        """Pide confirmación al usuario para una acción."""
        response = self.read_input(cmd2.style(f"{prompt_message} [{confirm_keyword}/N]: ")).lower()
        return response == confirm_keyword.lower() or (confirm_keyword == "si,estoyseguro" and response == "si,estoyseguro")


if __name__ == '__main__':
    # Para pruebas, se puede pasar una ruta de config
    # config_file_path = "config.json" 
    # app = LazyOwnApp(config_file_path)
    
    # Verificar si se ejecuta como root para advertir sobre comandos que lo necesiten
    if os.geteuid() != 0:
        print(cmd2.style("ADVERTENCIA: LazyOwn no se está ejecutando como root. "
                         "Algunos comandos (ej. bloqueo de IP, acceso a ciertos archivos/procesos) "
                         "pueden fallar o no funcionar completamente.", bold=True))
    else:
        print(cmd2.style("LazyOwn se está ejecutando como root. Tenga extrema precaución con los comandos de respuesta.", bold=True))

    app = LazyOwnApp()
    sys.exit(app.cmdloop())
