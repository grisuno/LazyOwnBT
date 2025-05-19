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
import yaml
import datetime # Usar directamente, no from datetime import datetime
import logging
import threading
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
import argparse
from lupa import LuaRuntime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import List, Dict, Optional, Tuple, Any, Union # Mantener para type hints
from tabulate import tabulate
from pathlib import Path
import os
import time
import cmd2
import logging
import json
import requests
import sqlite3
import datetime
import re
import queue
import tempfile
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from cachetools import LRUCache
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

# RAG imports
from langchain_community.document_loaders import PyMuPDFLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings
try:
    import ollama
    import chromadb
    import cachetools
    import rich
except ImportError as e:
    print(f"Error: Missing required library: {e}")
    print("Please install with: pip install langchain langchain-community chromadb ollama cachetools rich")
    exit(1)


DEEPSEEK_API_URL = "http://localhost:11434/api/generate"
DEEPSEEK_MODEL = "deepseek-r1:1.5b"
KNOWLEDGE_BASE_DIR = "./persistent_chroma_db"

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
# --- Comandos CMD2 ---
sysinfo_category = "1. Información del Sistema"
detection_category = "2. Detección de Amenazas"
integrity_category = "3. Integridad del Sistema"
logging_category = "4. Análisis de Logs"
hardening_category = "5. Endurecimiento del Sistema"
response_category = "6. Respuesta a Incidentes"
reporting_category = "7. Reportes"
config_category = "8. Configuración"

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
def replace_command_placeholders(command, params):
    """
    Replace placeholders in a command string with values from a params dictionary,
    handling spaces within placeholders.

    The function looks for placeholders in curly braces (e.g., {url} or { url }) within
    the command string and replaces them with corresponding values from the params dictionary,
    ignoring any spaces inside the curly braces.

    Args:
        command (str): The command string containing placeholders.
        params (dict): A dictionary containing key-value pairs for replacement.

    Returns:
        str: The command string with placeholders replaced by their corresponding values.
    """
    import re
    
    def replace_match(match):
        key = match.group(1).strip()  # Remove any spaces from the captured key
        return str(params.get(key, match.group(0)))  # Return replacement or original if not found
    
    return re.sub(r'\{([^}]+)\}', replace_match, command)
class FgColor:
    pass

class Cyan(FgColor):
    pass

class Red(FgColor):
    pass

def sanitize_content(text: str) -> str:
    """Sanitize text to ensure it's safe for Markdown rendering."""
    # Preserve Markdown-compatible characters but remove problematic ones
    text = text.replace('\r', '')  # Remove carriage returns
    text = re.sub(r'```.*?```', lambda m: m.group(0), text, flags=re.DOTALL)  # Preserve code blocks
    text = re.sub(r'`.*?`', lambda m: m.group(0), text)  # Preserve inline code
    text = re.sub(r'(\[.*?\]\(.*?\))', lambda m: m.group(0), text)  # Preserve links
    # Remove invalid control characters and excessive whitespace
    text = re.sub(r'[^\x20-\x7E\n\t#*+-_`[]()|]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

class RAGManager:
    """Manages RAG functionality with CAG caching for document processing and querying."""
    
    def __init__(self, model_name: str = DEEPSEEK_MODEL, cache_size: int = 1000):
        self.model_name = model_name
        self.embeddings = OllamaEmbeddings(model=model_name)
        self.persist_dir = KNOWLEDGE_BASE_DIR
        self.vectorstore = None
        self.retriever = None
        # Initialize caches
        self.embedding_cache = LRUCache(maxsize=cache_size)  # Cache document embeddings
        self.query_cache = LRUCache(maxsize=cache_size)      # Cache query results
        self.db = Database("lazysentinel.db")                # For persistent cache
        self.load_existing_vectorstore()
        self.initialize_cache_table()
    
    def initialize_cache_table(self):
        """Initialize SQLite table for persistent cache."""
        query = """
            CREATE TABLE IF NOT EXISTS rag_cache (
                cache_key TEXT PRIMARY KEY,
                cache_type TEXT NOT NULL,
                value TEXT NOT NULL,
                timestamp DATETIME NOT NULL
            )
        """
        self.db.execute(query)
        logging.info("Initialized RAG cache table")
    
    def get_cache_key(self, content: str) -> str:
        """Generate a cache key from content using SHA-256."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def load_existing_vectorstore(self):
        """Load existing vectorstore if available."""
        try:
            if os.path.exists(self.persist_dir):
                self.vectorstore = Chroma(persist_directory=self.persist_dir, embedding_function=self.embeddings)
                self.retriever = self.vectorstore.as_retriever()
                logging.info("Loaded existing RAG knowledge base")
            else:
                logging.info("No existing RAG knowledge base found")
        except Exception as e:
            logging.error(f"Error loading vectorstore: {e}")
            self.vectorstore = None
            self.retriever = None
    
    def ollama_llm(self, question: str, context: str) -> str:
        """Query LLM with context using Ollama."""
        formatted_prompt = f"Question: {question}\n\nContext: {context}"
        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[{"role": "user", "content": formatted_prompt}],
            )
            response_content = response["message"]["content"]
            final_answer = re.sub(r"<think>.*?</think>", "", response_content, flags=re.DOTALL).strip()
            return final_answer
        except Exception as e:
            logging.error(f"Error querying Ollama: {e}")
            return f"Error querying LLM: {str(e)}"
    
    def process_file_to_rag(self, file_path: Path) -> bool:
        """Process a file, add it to the RAG knowledge base, and cache embeddings."""
        try:
            file_extension = file_path.suffix.lower()
            text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=500, chunk_overlap=100
            )
            
            # Handle different file types
            if file_extension == '.pdf':
                loader = PyMuPDFLoader(str(file_path))
            elif file_extension in ['.txt', '.md', '.log', '', '.yaml', '.csv', '.json', '.nmap']:
                loader = TextLoader(str(file_path))
            else:
                logging.warning(f"Unsupported file type for RAG: {file_extension}")
                return False
            
            # Load and split documents
            data = loader.load()
            chunks = text_splitter.split_documents(data)
            
            # Cache embeddings for each chunk
            for chunk in chunks:
                chunk_content = chunk.page_content
                cache_key = self.get_cache_key(chunk_content)
                if cache_key not in self.embedding_cache:
                    embedding = self.embeddings.embed_documents([chunk_content])[0]
                    self.embedding_cache[cache_key] = embedding
                    # Persist to SQLite
                    query = """
                        INSERT OR REPLACE INTO rag_cache (cache_key, cache_type, value, timestamp)
                        VALUES (?, ?, ?, ?)
                    """
                    self.db.execute(query, (
                        cache_key,
                        "embedding",
                        json.dumps(embedding),
                        datetime.datetime.now().isoformat()
                    ))
            
            # Add to vectorstore
            if self.vectorstore is None:
                self.vectorstore = Chroma.from_documents(
                    documents=chunks, 
                    embedding=self.embeddings, 
                    persist_directory=self.persist_dir
                )
                self.retriever = self.vectorstore.as_retriever()
            else:
                self.vectorstore.add_documents(documents=chunks)
                self.vectorstore.persist()
            
            logging.info(f"Added {file_path} to RAG knowledge base with {len(chunks)} chunks")
            return True
            
        except Exception as e:
            logging.error(f"Error processing file for RAG: {e}")
            return False
    
    def query_rag(self, question: str) -> str:
        """Query the RAG system with caching."""
        if self.retriever is None:
            return "No knowledge base available. Please process some files first."
        
        # Check query cache
        query_key = self.get_cache_key(question)
        if query_key in self.query_cache:
            logging.info(f"Query cache hit for: {question}")
            return self.query_cache[query_key]
        
        try:
            # Retrieve relevant documents
            retrieved_docs = self.retriever.invoke(question)
            
            # Combine documents into context
            context = "\n\n".join(doc.page_content for doc in retrieved_docs)
            
            # Query LLM with context
            response = self.ollama_llm(question, context)
            
            # Cache the response
            self.query_cache[query_key] = response
            query = """
                INSERT OR REPLACE INTO rag_cache (cache_key, cache_type, value, timestamp)
                VALUES (?, ?, ?, ?)
            """
            self.db.execute(query, (
                query_key,
                "query",
                response,
                datetime.datetime.now().isoformat()
            ))
            
            return response
            
        except Exception as e:
            logging.error(f"Error querying RAG: {e}")
            return f"Error querying knowledge base: {str(e)}"
    
    def invalidate_cache(self, file_path: Path):
        """Invalidate cache entries for a specific file."""
        try:
            with file_path.open('r', encoding='utf-8') as f:
                content = f.read()
            chunks = RecursiveCharacterTextSplitter(
                chunk_size=500, chunk_overlap=100
            ).split_text(content)
            
            for chunk in chunks:
                cache_key = self.get_cache_key(chunk)
                if cache_key in self.embedding_cache:
                    del self.embedding_cache[cache_key]
                self.db.execute("DELETE FROM rag_cache WHERE cache_key = ?", (cache_key,))
            
            logging.info(f"Invalidated cache for {file_path}")
        except Exception as e:
            logging.error(f"Error invalidating cache for {file_path}: {e}")
    
    def get_knowledge_base_stats(self) -> Dict:
        """Get statistics about the knowledge base and cache."""
        if self.vectorstore is None:
            return {
                "status": "No knowledge base",
                "document_count": 0,
                "embedding_cache_size": len(self.embedding_cache),
                "query_cache_size": len(self.query_cache)
            }
        
        try:
            collection = self.vectorstore._collection
            count = collection.count() if hasattr(collection, 'count') else 0
            
            return {
                "status": "Active",
                "document_count": count,
                "persist_dir": self.persist_dir,
                "embedding_cache_size": len(self.embedding_cache),
                "query_cache_size": len(self.query_cache)
            }
        except Exception as e:
            logging.error(f"Error getting knowledge base stats: {e}")
            return {"status": "Error", "error": str(e)}

    
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
            # Añade esta línea para que las filas se puedan acceder por nombre
            self.conn.row_factory = sqlite3.Row
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
        self.timestamp = datetime.datetime.now().isoformat()

    def to_dict(self) -> Dict:
        """Convierte la alerta a diccionario."""
        return {
            "type": self.alert_type,
            "details": self.details,
            "severity": self.severity,
            "timestamp": self.timestamp
        }

    def save_to_db(self, db: 'Database') -> Optional[int]:
        """Guarda la alerta en la base de datos."""
        details_json = json.dumps(self.details)
        query = """
            INSERT INTO alerts (type, details, severity, timestamp)
            VALUES (?, ?, ?, ?)
        """
        alert_id = db.insert(query, (self.alert_type, details_json, self.severity, self.timestamp))
        if alert_id:
            logging.info(f"Alerta '{self.alert_type}' (Severidad: {self.severity}) guardada en DB con ID: {alert_id}")
        else:
            logging.error(f"No se pudo guardar la alerta '{self.alert_type}' en la DB.")
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
                                       'ppid', 'cwd', 'exe', 'open_files']) # Elimina 'connections' de la lista
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

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'status', 'create_time', 'cpu_percent', 'memory_percent']):
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
    """Analizador avanzado de logs del sistema para equipos de seguridad azules."""

    def __init__(self, config: Dict, db: Database):
        """Inicializa el analizador con configuración mejorada y validada"""
        # Validar configuración mínima necesaria
        if not isinstance(config, dict):
            raise TypeError("La configuración debe ser un diccionario")
        if not isinstance(db, Database):
            raise TypeError("Se requiere una instancia válida de Database")
        
        self.config = self._sanitize_config(config)
        self.db = db
        
        # Valores predeterminados seguros si no se proporcionan en config
        self.log_paths = list(set(self.config.get("log_paths", [])))
        self.max_failed_logins_threshold = max(3, self.config.get("max_failed_logins", 5))
        self.scan_interval = max(10, self.config.get("scan_interval_seconds", 60))
        self.max_log_lines = max(100, self.config.get("log_analyzer_max_lines", 5000))
        self.max_threads = min(10, self.config.get("max_analyzer_threads", 4))
        
        # Estado del analizador para seguimiento persistente
        self._initialize_state()
        
        # Configuración del detector de amenazas
        self._setup_threat_detection_patterns()
        
        # Inicializar métricas de rendimiento
        self.performance_metrics = {
            "last_scan_duration": 0,
            "total_events_processed": 0,
            "alerts_generated": 0,
        }
        
        logger.info(f"LogAnalyzer inicializado con {len(self.log_paths)} archivos de log configurados")

    def _sanitize_config(self, config: Dict) -> Dict:
        """Sanitiza y valida la configuración para prevenir inyecciones y valores maliciosos"""
        sanitized = {}
        
        # Validar rutas de log
        if "log_paths" in config and isinstance(config["log_paths"], list):
            sanitized["log_paths"] = [
                path for path in config["log_paths"] 
                if isinstance(path, str) and self._is_safe_path(path)
            ]
        
        # Copiar otros valores de configuración con valores predeterminados seguros
        sanitized["max_failed_logins"] = max(3, config.get("max_failed_logins", 5))
        sanitized["log_analyzer_max_lines"] = max(100, config.get("log_analyzer_max_lines", 5000))
        sanitized["scan_interval_seconds"] = max(10, config.get("scan_interval_seconds", 60))
        sanitized["max_analyzer_threads"] = min(10, config.get("max_analyzer_threads", 4))
        
        # Parámetros adicionales de seguridad
        sanitized["alert_deduplication_window"] = config.get("alert_deduplication_window", 300)  # 5 min
        sanitized["baseline_period_days"] = config.get("baseline_period_days", 7)
        sanitized["enable_file_integrity_monitoring"] = config.get("enable_file_integrity_monitoring", True)
        
        return sanitized
    
    def _is_safe_path(self, path: str) -> bool:
        """Valida que una ruta sea segura (previene directory traversal)"""
        # Evitar rutas con caracteres sospechosos
        if '..' in path or path.startswith('~') or '$(' in path or '`' in path:
            logger.warning(f"Ruta de log potencialmente insegura rechazada: {path}")
            return False
            
        # Verificar que la ruta existe y es un archivo regular
        if os.path.exists(path) and not os.path.isfile(path):
            logger.warning(f"Ruta de log no es un archivo regular: {path}")
            return False
            
        return True

    def _initialize_state(self) -> None:
        """Inicializa el estado persistente del analizador"""
        # Para rastrear la última posición leída en cada archivo
        self.file_positions = {}
        
        # Para detectar ataques de fuerza bruta
        self.failed_login_tracker = defaultdict(lambda: {"count": 0, "timestamps": []})
        
        # Para detectar anomalías y comportamientos sospechosos
        self.baseline_metrics = {
            "logins_per_hour": defaultdict(int),
            "commands_per_user": defaultdict(lambda: defaultdict(int)),
            "last_login_ip_by_user": {},
        }
        
        # Para detección de anomalías en comportamiento del sistema
        self.system_behavior_baseline = {
            "service_restarts": defaultdict(int),
            "kernel_events": defaultdict(int),
        }
        
        # Para deduplicación de alertas
        self.recent_alerts = {}
        
        # Para seguimiento de indicadores de compromiso (IOCs)
        self.observed_iocs = set()
        
        # Hash de archivos monitoreados para integridad
        self.file_hashes = {}

    def _setup_threat_detection_patterns(self) -> None:
        """Configura patrones avanzados para detección de amenazas con MITRE ATT&CK mappings"""
        # Patrones básicos mejorados
        self.patterns = {
            # T1078 - Valid Accounts
            "failed_login": {
                "pattern": re.compile(r"(?:failed\s+password|authentication\s+failure|invalid\s+user|failed\s+login)", re.IGNORECASE),
                "severity": "medium",
                "mitre_tactics": ["Initial Access", "Persistence", "Privilege Escalation"],
                "mitre_techniques": ["T1078"],
            },
            "successful_login": {
                "pattern": re.compile(r"(?:accepted\s+password|session\s+opened\s+for\s+user)", re.IGNORECASE),
                "severity": "info",
                "mitre_tactics": ["Initial Access"],
                "mitre_techniques": ["T1078"],
            },
            # T1169 - Sudo / T1548.003 - Sudo and Sudo Caching
            "sudo_command": {
                "pattern": re.compile(r"sudo:\s*\S+\s*:\s*USER=\S+\s*;\s*COMMAND=(.+)", re.IGNORECASE),
                "severity": "medium",
                "mitre_tactics": ["Privilege Escalation", "Defense Evasion"],
                "mitre_techniques": ["T1548.003"],
            },
            # T1136 - Create Account
            "user_added": {
                "pattern": re.compile(r"(?:new\s+user|useradd|adduser).*name=(\S+)", re.IGNORECASE),
                "severity": "high",
                "mitre_tactics": ["Persistence", "Privilege Escalation"],
                "mitre_techniques": ["T1136"],
            },
            # T1531 - Account Access Removal
            "user_deleted": {
                "pattern": re.compile(r"(?:delete\s+user|userdel).*name=(\S+)", re.IGNORECASE),
                "severity": "high",
                "mitre_tactics": ["Impact"],
                "mitre_techniques": ["T1531"],
            },
            # T1136.001 - Create Account: Local Account
            "group_added": {
                "pattern": re.compile(r"(?:new\s+group|groupadd).*name=(\S+)", re.IGNORECASE),
                "severity": "medium",
                "mitre_tactics": ["Persistence"],
                "mitre_techniques": ["T1136.001"],
            },
            # T1098 - Account Manipulation
            "ssh_key_added": {
                "pattern": re.compile(r"(?:authorized_keys|ssh-keygen|ssh-add|AuthorizedKeysFile).*(?:added|created|new)", re.IGNORECASE),
                "severity": "high", 
                "mitre_tactics": ["Persistence"],
                "mitre_techniques": ["T1098"],
            },
            # T1222 - File and Directory Permissions Modification
            "permission_denied": {
                "pattern": re.compile(r"permission\s+denied", re.IGNORECASE),
                "severity": "low",
                "mitre_tactics": ["Defense Evasion"],
                "mitre_techniques": ["T1222"],
            },
            # T1562 - Impair Defenses
            "service_stopped": {
                "pattern": re.compile(r"(?:systemctl\s+stop|service\s+\S+\s+stop|stopped|Stopping)", re.IGNORECASE),
                "severity": "high",
                "mitre_tactics": ["Defense Evasion"],
                "mitre_techniques": ["T1562"],
            },
            # T1070 - Indicator Removal on Host
            "log_cleared": {
                "pattern": re.compile(r"(?:logrotate|truncate|>\s*/var/log|erased\s+logs)", re.IGNORECASE),
                "severity": "critical",
                "mitre_tactics": ["Defense Evasion"],
                "mitre_techniques": ["T1070"],
            },
            # T1059 - Command and Scripting Interpreter
            "suspicious_command": {
                "pattern": re.compile(r"(?:nc\s+-|netcat|wget\s+http|curl\s+-o|python\s+-c|bash\s+-i|nmap|masscan|base64\s+[^-])", re.IGNORECASE),
                "severity": "high",
                "mitre_tactics": ["Execution"],
                "mitre_techniques": ["T1059"],
            },
            # T1082 - System Information Discovery
            "system_discovery": {
                "pattern": re.compile(r"(?:uname\s+-a|hostname|ifconfig|ip\s+a|ip\s+addr|whoami)", re.IGNORECASE),
                "severity": "medium",
                "mitre_tactics": ["Discovery"],
                "mitre_techniques": ["T1082"],
            },
            # T1105 - Ingress Tool Transfer
            "file_download": {
                "pattern": re.compile(r"(?:wget|curl)\s+(?:https?|ftp)://", re.IGNORECASE),
                "severity": "high",
                "mitre_tactics": ["Command and Control"],
                "mitre_techniques": ["T1105"],
            },
            # T1046 - Network Service Scanning
            "port_scan": {
                "pattern": re.compile(r"(?:scan|nmap|masscan|portscan)", re.IGNORECASE),
                "severity": "high",
                "mitre_tactics": ["Discovery"],
                "mitre_techniques": ["T1046"],
            },
            # Sistema y kernel
            "kernel_error": {
                "pattern": re.compile(r"kernel:.*(?:error|critical|panic)", re.IGNORECASE),
                "severity": "high",
                "mitre_tactics": ["Impact"],
                "mitre_techniques": ["T1499"],
            },
            "segmentation_fault": {
                "pattern": re.compile(r"segmentation\s+fault", re.IGNORECASE),
                "severity": "medium",
                "mitre_tactics": ["Impact"],
                "mitre_techniques": ["T1499"],
            },
        }
        
        # Patrones avanzados para detección de equipos rojos en CTFs y juegos de emulación
        self.redteam_patterns = {
            # Herramientas comunes de Red Team
            "offensive_tools": {
                "pattern": re.compile(r"(?:metasploit|meterpreter|mimikatz|bloodhound|empire|powershell\s+empire|cobalt\s+strike|cobaltstrike|beacon|reverse\s+shell)", re.IGNORECASE),
                "severity": "critical",
                "mitre_tactics": ["Command and Control", "Execution"],
                "mitre_techniques": ["T1219", "T1059"],
            },
            # Comandos de exfiltración 
            "data_exfiltration": {
                "pattern": re.compile(r"(?:scp\s+\S+@|\S+\.gz\s+|tar\s+cvf|zip\s+-r|7z\s+a|wget\s+--post-data|curl\s+--data)", re.IGNORECASE),
                "severity": "critical",
                "mitre_tactics": ["Exfiltration"],
                "mitre_techniques": ["T1048"],
            },
            # Puertos de escucha inhabituales
            "unusual_listening": {
                "pattern": re.compile(r"(?:LISTEN|listening).*:(?:4444|443\d|666\d|8080|31337)", re.IGNORECASE),
                "severity": "high",
                "mitre_tactics": ["Command and Control"],
                "mitre_techniques": ["T1571"],
            },
            # Webshells
            "webshell": {
                "pattern": re.compile(r"(?:eval\s*\(|system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\(|phpinfo\s*\(|base64_decode\s*\()", re.IGNORECASE),
                "severity": "critical",
                "mitre_tactics": ["Persistence", "Execution"],
                "mitre_techniques": ["T1505.003"],
            },
            # Escalada de privilegios
            "privilege_escalation": {
                "pattern": re.compile(r"(?:chmod\s+[+]s|chown\s+root|setuid|setgid|privileged|CVE-\d+-\d+)", re.IGNORECASE),
                "severity": "critical",
                "mitre_tactics": ["Privilege Escalation"],
                "mitre_techniques": ["T1548"],
            },
            # Limpieza de huellas (antiforensics)
            "antiforensics": {
                "pattern": re.compile(r"(?:shred\s+-z|wipe\s+|secure-delete|history\s+-c|unset\s+HISTFILE|export\s+HISTFILESIZE=0)", re.IGNORECASE),
                "severity": "critical", 
                "mitre_tactics": ["Defense Evasion"],
                "mitre_techniques": ["T1070"],
            },
        }
        
        # Fusionar todos los patrones
        self.all_patterns = {**self.patterns, **self.redteam_patterns}

    def _calculate_file_hash(self, filename: str) -> str:
        """Calcula el hash SHA-256 de un archivo de manera segura"""
        try:
            with open(filename, "rb") as f:
                file_hash = hashlib.sha256()
                # Leer en bloques para archivos grandes
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
            return file_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error al calcular el hash del archivo {filename}: {e}")
            return ""

    def _check_file_integrity(self, log_path: str) -> bool:
        """Verifica la integridad del archivo de log basado en su hash"""
        if not self.config.get("enable_file_integrity_monitoring", True):
            return True
            
        current_hash = self._calculate_file_hash(log_path)
        if not current_hash:
            return False
            
        if log_path not in self.file_hashes:
            # Primera vez que vemos este archivo
            self.file_hashes[log_path] = current_hash
            return True
            
        if self.file_hashes[log_path] != current_hash:
            # El archivo ha cambiado
            self.file_hashes[log_path] = current_hash
            # Para logs, cambiar es normal, pero podríamos alertar ante cambios sospechosos
            # Si fuera un binario del sistema, aquí alertaríamos
            return True
            
        return True

    def _extract_timestamp_from_log(self, line: str) -> Optional[datetime.datetime]:
        """Extrae el timestamp de una línea de log usando varios formatos comunes"""
        # Patrones de timestamp comunes en logs
        timestamp_patterns = [
            # May 15 23:48:37
            r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
            # 2023-05-15T23:48:37
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2})?)",
            # 2023-05-15 23:48:37
            r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
            # 15/May/2023:23:48:37 +0000
            r"(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})",
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group(1)
                try:
                    # Intentar varios formatos de fecha
                    for fmt in [
                        "%b %d %H:%M:%S",
                        "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%d %H:%M:%S",
                        "%d/%b/%Y:%H:%M:%S %z",
                    ]:
                        try:
                            return datetime.datetime.strptime(timestamp_str, fmt)
                        except ValueError:
                            continue
                except Exception:
                    pass
        
        return None

    def _extract_ip_from_log(self, line: str) -> Optional[str]:
        """Extrae una dirección IP de una línea de log"""
        ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        match = ip_pattern.search(line)
        if match:
            return match.group(1)
        return None

    def _extract_username_from_log(self, line: str) -> Optional[str]:
        """Extrae un nombre de usuario de una línea de log"""
        username_patterns = [
            r"user[=:\s]+(\S+)",
            r"USER[=:\s]+(\S+)",
            r"username[=:\s]+(\S+)",
            r"login[=:\s]+(\S+)",
        ]
        
        for pattern in username_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _extract_command_from_log(self, line: str) -> Optional[str]:
        """Extrae un comando ejecutado de una línea de log"""
        command_patterns = [
            r"COMMAND=(.+?)(?:$|;)",
            r"executing\s+command[=:\s]+(.+?)(?:$|;)",
            r"RUN\s+(.+?)(?:$|;)",
        ]
        
        for pattern in command_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    def _is_alert_duplicated(self, alert_type: str, details_hash: str) -> bool:
        """Verifica si una alerta ya fue generada recientemente para evitar duplicados"""
        dedup_window = self.config.get("alert_deduplication_window", 300)  # 5 min por defecto
        current_time = time.time()
        
        # Clave única basada en tipo de alerta y detalles
        key = f"{alert_type}:{details_hash}"
        
        if key in self.recent_alerts:
            last_time = self.recent_alerts[key]
            if current_time - last_time < dedup_window:
                return True
        
        # Actualizar timestamp para esta alerta
        self.recent_alerts[key] = current_time
        
        # Limpiar alertas antiguas para evitar crecimiento de memoria
        self.recent_alerts = {k: v for k, v in self.recent_alerts.items() 
                             if current_time - v < dedup_window}
        
        return False

    def analyze_log_file(self, log_path: str, generate_alerts: bool = True) -> List[Dict]:
        """Analiza un único archivo de log con detección avanzada de amenazas."""
        findings = []
        
        if not os.path.isfile(log_path):
            logger.warning(f"Archivo de log no encontrado o no es un archivo regular: {log_path}")
            return findings
        
        # Verificar integridad del archivo
        if not self._check_file_integrity(log_path):
            logger.error(f"Verificación de integridad fallida para {log_path}")
            # Generar alerta de seguridad por posible manipulación
            if generate_alerts:
                Alert(
                    alert_type="file_integrity_failure",
                    details={"log_file": log_path, "reason": "Hash verification failed"},
                    severity="critical",
                    mitre_tactics=["Defense Evasion"],
                    mitre_techniques=["T1070"]
                ).save_to_db(self.db)
            return findings
        
        logger.info(f"Analizando log: {log_path}")
        start_time = time.time()
        
        try:
            # Determinar desde qué posición comenzar a leer
            start_position = self.file_positions.get(log_path, 0)
            current_position = 0
            
            with open(log_path, 'r', errors='ignore') as f:
                # Moverse a la última posición conocida si el archivo existe
                if start_position > 0:
                    try:
                        f.seek(start_position)
                    except:
                        # Si hay error al posicionar, empezar desde el inicio
                        f.seek(0)
                        logger.warning(f"No se pudo posicionar en {start_position} para {log_path}, comenzando desde el inicio")
                
                # Si no hay nuevos datos desde la última lectura
                if f.tell() == os.path.getsize(log_path):
                    logger.debug(f"No hay nuevos datos en {log_path} desde la última lectura")
                    return []
                
                # Leer líneas nuevas
                new_lines = f.readlines()
                current_position = f.tell()
                
                # Si hay demasiadas líneas nuevas, limitar procesamiento
                if len(new_lines) > self.max_log_lines:
                    logger.warning(f"Demasiadas líneas nuevas en {log_path}, limitando a las últimas {self.max_log_lines}")
                    new_lines = new_lines[-self.max_log_lines:]
                
                # Actualizar la posición para la próxima lectura
                self.file_positions[log_path] = current_position
                
                for line_num, line_content in enumerate(new_lines):
                    line_content = line_content.strip()
                    if not line_content:
                        continue
                    
                    # Extraer metadata de la línea para enriquecer los hallazgos
                    timestamp = self._extract_timestamp_from_log(line_content)
                    timestamp_str = timestamp.isoformat() if timestamp else datetime.datetime.now().isoformat()
                    ip_address = self._extract_ip_from_log(line_content)
                    username = self._extract_username_from_log(line_content)
                    command = self._extract_command_from_log(line_content)
                    
                    # Aplicar todos los patrones de detección
                    for pattern_name, pattern_config in self.all_patterns.items():
                        pattern_re = pattern_config["pattern"]
                        match = pattern_re.search(line_content)
                        
                        if match:
                            # Base de datos mínimos para el evento
                            event_details = {
                                "log_file": log_path,
                                "line_number": line_num + 1, 
                                "line_content": line_content,
                                "pattern_name": pattern_name,
                                "match_groups": match.groups() if match.groups() else None,
                                "timestamp": timestamp_str,
                                "ip_address": ip_address,
                                "username": username,
                                "command": command
                            }
                            
                            # Enriquecer hallazgo con contexto
                            self._enrich_finding_with_context(event_details)
                            findings.append(event_details)
                            
                            # Registrar el evento en la base de datos
                            event_id = self.db.insert(
                                """INSERT INTO security_events 
                                   (event_type, source, description, raw_data, timestamp, 
                                    ip_address, username, command) 
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                (pattern_name, 
                                 log_path, 
                                 f"Detectado evento '{pattern_name}'", 
                                 line_content, 
                                 timestamp_str,
                                 ip_address or "",
                                 username or "",
                                 command or "")
                            )
                            
                            if not event_id: 
                                logger.error(f"No se pudo guardar evento de log {pattern_name} en DB.")
                            
                            # Generar alertas según la configuración
                            if generate_alerts:
                                # Procesar lógica específica según el tipo de evento
                                self._process_specific_event_logic(
                                    pattern_name, 
                                    pattern_config, 
                                    event_details, 
                                    line_content
                                )
                
                # Actualizar métricas
                self.performance_metrics["total_events_processed"] += len(findings)
                
        except IOError as e:
            logger.error(f"Error al leer archivo de log {log_path}: {e}")
        except Exception as e:
            logger.error(f"Error inesperado analizando {log_path}: {e}")
            
        duration = time.time() - start_time
        self.performance_metrics["last_scan_duration"] = duration
        logger.info(f"Análisis de {log_path} completado en {duration:.2f}s. {len(findings)} hallazgos.")
        
        return findings

    def _enrich_finding_with_context(self, event_details: Dict) -> None:
        """Enriquece un hallazgo con contexto adicional y correlación"""
        # Añadir contexto temporal (hora del día, día de la semana)
        if "timestamp" in event_details:
            try:
                ts = datetime.datetime.fromisoformat(event_details["timestamp"])
                event_details["hour_of_day"] = ts.hour
                event_details["day_of_week"] = ts.strftime("%A")
                event_details["is_weekend"] = ts.weekday() >= 5
                event_details["is_after_hours"] = ts.hour < 7 or ts.hour > 19
            except:
                pass
        
                    # Enriquecer con contexto de usuario si existe
        if event_details.get("username"):
            username = event_details["username"]
            # Añadir información sobre actividad previa del usuario
            event_details["previous_logins"] = self.baseline_metrics["logins_per_hour"].get(username, 0)
            event_details["common_commands"] = list(self.baseline_metrics["commands_per_user"].get(username, {}).keys())[:5]
            event_details["last_login_ip"] = self.baseline_metrics["last_login_ip_by_user"].get(username)
            
            # Detectar si es un nuevo usuario (no visto antes)
            if username not in self.baseline_metrics["last_login_ip_by_user"]:
                event_details["new_user"] = True
            
            # Detectar cambio de IP para este usuario
            if (event_details.get("ip_address") and 
                username in self.baseline_metrics["last_login_ip_by_user"] and
                event_details["ip_address"] != self.baseline_metrics["last_login_ip_by_user"][username]):
                event_details["ip_changed"] = True
                event_details["previous_ip"] = self.baseline_metrics["last_login_ip_by_user"][username]
        
        # Verificar si la IP está en listas de IOCs conocidos
        if event_details.get("ip_address") and event_details["ip_address"] in self.observed_iocs:
            event_details["known_ioc"] = True
            event_details["ioc_first_seen"] = self.observed_iocs[event_details["ip_address"]]
            
    def _process_specific_event_logic(self, pattern_name: str, pattern_config: Dict, 
                                     event_details: Dict, line_content: str) -> None:
        """Procesa lógica especializada según el tipo de evento detectado"""
        severity = pattern_config.get("severity", "medium")
        mitre_tactics = pattern_config.get("mitre_tactics", [])
        mitre_techniques = pattern_config.get("mitre_techniques", [])
        username = event_details.get("username")
        ip_address = event_details.get("ip_address")
        
        # Calcular un hash de los detalles para deduplicación
        details_hash = hashlib.md5(str(event_details).encode()).hexdigest()
        
        # Verificar deduplicación de alertas
        if self._is_alert_duplicated(pattern_name, details_hash):
            logger.debug(f"Alerta duplicada suprimida: {pattern_name}")
            return
            
        # Lógica específica según el patrón detectado
        if pattern_name == "failed_login":
            # Identificar posibles ataques de fuerza bruta
            target_key = username or ip_address
            if not target_key:
                return
                
            # Añadir evento a la lista de timestamps para este objetivo
            now = datetime.datetime.now()
            self.failed_login_tracker[target_key]["count"] += 1
            self.failed_login_tracker[target_key]["timestamps"].append(now)
            
            # Conservar solo los últimos N minutos de intentos
            recent_window = datetime.timedelta(minutes=15)
            self.failed_login_tracker[target_key]["timestamps"] = [
                ts for ts in self.failed_login_tracker[target_key]["timestamps"]
                if now - ts < recent_window
            ]
            
            recent_attempts = len(self.failed_login_tracker[target_key]["timestamps"])
            
            # Generar alerta si supera el umbral
            if recent_attempts >= self.max_failed_logins_threshold:
                alert = Alert(
                    alert_type="brute_force_login_attempt",
                    details={
                        "target": target_key,
                        "count": recent_attempts,
                        "time_window_minutes": 15,
                        "source_ips": list(set(self._extract_ip_from_log(line) for line in line_content if self._extract_ip_from_log(line)))
                    },
                    severity="high",
                    mitre_tactics=["Credential Access", "Initial Access"],
                    mitre_techniques=["T1110"],
                    remediation_steps=[
                        "Bloquear la IP de origen temporalmente",
                        "Verificar la cuenta de usuario para cambios no autorizados",
                        "Considerar implementar autenticación de dos factores"
                    ]
                )
                alert.save_to_db(self.db)
                self.performance_metrics["alerts_generated"] += 1
                
                # Resetear contador tras generar la alerta
                self.failed_login_tracker[target_key]["count"] = 0
                
        elif pattern_name == "successful_login":
            # Verificar si hubo intentos fallidos previos
            if username and username in self.failed_login_tracker and self.failed_login_tracker[username]["count"] > 2:
                # Posible caso de acceso después de varios intentos (password spray)
                alert = Alert(
                    alert_type="successful_login_after_failures",
                    details={
                        "username": username,
                        "ip_address": ip_address,
                        "previous_failures": self.failed_login_tracker[username]["count"]
                    },
                    severity="high",
                    mitre_tactics=["Initial Access", "Credential Access"],
                    mitre_techniques=["T1110.003", "T1078"]
                )
                alert.save_to_db(self.db)
                self.performance_metrics["alerts_generated"] += 1
            
            # Actualizar línea base
            if username:
                hour = datetime.datetime.now().hour
                self.baseline_metrics["logins_per_hour"][username] += 1
                if ip_address:
                    self.baseline_metrics["last_login_ip_by_user"][username] = ip_address
                    
                # Detectar logins fuera de horas habituales
                user_usual_login_hours = self._get_usual_login_hours(username)
                if user_usual_login_hours and hour not in user_usual_login_hours:
                    alert = Alert(
                        alert_type="unusual_login_time",
                        details={
                            "username": username,
                            "login_hour": hour,
                            "usual_hours": user_usual_login_hours
                        },
                        severity="medium",
                        mitre_tactics=["Initial Access"],
                        mitre_techniques=["T1078"]
                    )
                    alert.save_to_db(self.db)
                    self.performance_metrics["alerts_generated"] += 1
                    
        elif pattern_name == "sudo_command" or pattern_name == "suspicious_command":
            command = event_details.get("command", "")
            if not command:
                command = self._extract_command_from_log(line_content) or ""
                
            if username and command:
                # Actualizar comandos usuales por usuario
                self.baseline_metrics["commands_per_user"][username][command] += 1
                
                # Detectar comandos inusuales para este usuario
                common_commands = self._get_common_commands_for_user(username)
                if common_commands and command not in common_commands:
                    alert = Alert(
                        alert_type="unusual_command",
                        details={
                            "username": username,
                            "command": command,
                            "common_commands": common_commands
                        },
                        severity="medium",
                        mitre_tactics=["Execution", "Discovery"],
                        mitre_techniques=["T1059"]
                    )
                    alert.save_to_db(self.db)
                    self.performance_metrics["alerts_generated"] += 1
                    
            # Detectar comandos de alto riesgo o relacionados con compromiso
            high_risk_commands = [
                "chmod +s", "nc -e", "bash -i", 
                "wget http", "curl -o", 
                "python -c", "perl -e", "ruby -e",
                "eval", "base64 -d", "openssl enc -d"
            ]
            
            for risky_cmd in high_risk_commands:
                if risky_cmd in command.lower():
                    alert = Alert(
                        alert_type="high_risk_command",
                        details={
                            "username": username,
                            "command": command,
                            "matched_pattern": risky_cmd
                        },
                        severity="critical",
                        mitre_tactics=["Execution", "Defense Evasion"],
                        mitre_techniques=["T1059", "T1027"]
                    )
                    alert.save_to_db(self.db)
                    self.performance_metrics["alerts_generated"] += 1
                    break
                    
        elif pattern_name == "user_added":
            # Alta severidad para nuevos usuarios
            alert = Alert(
                alert_type="new_user_created",
                details={
                    "username": self._extract_username_from_log(line_content) or "unknown",
                    "creator": username or "unknown",
                    "ip_address": ip_address
                },
                severity="high",
                mitre_tactics=["Persistence", "Privilege Escalation"],
                mitre_techniques=["T1136"],
                remediation_steps=[
                    "Verificar si la creación del usuario fue autorizada",
                    "Revisar los permisos asignados al nuevo usuario",
                    "Verificar el grupo al que fue añadido"
                ]
            )
            alert.save_to_db(self.db)
            self.performance_metrics["alerts_generated"] += 1
            
        elif pattern_name in self.redteam_patterns:
            # Alertas específicas para patrones de equipo rojo
            redteam_alert = Alert(
                alert_type=f"redteam_activity_{pattern_name}",
                details={
                    "evidence": line_content,
                    "username": username,
                    "ip_address": ip_address,
                    "command": event_details.get("command")
                },
                severity="critical",  # Equipos rojos siempre generan alerta crítica
                mitre_tactics=mitre_tactics,
                mitre_techniques=mitre_techniques,
                remediation_steps=[
                    "¡ALERTA! Posible presencia de equipo rojo detectada",
                    "Aislar el sistema comprometido",
                    "Documentar actividad para análisis posterior",
                    "Iniciar contención si es un ejercicio real"
                ]
            )
            redteam_alert.save_to_db(self.db)
            self.performance_metrics["alerts_generated"] += 1
            
            # Registrar IOC para correlación futura
            if ip_address:
                self.observed_iocs[ip_address] = datetime.datetime.now().isoformat()
        else:
            # Alerta general para otros patrones
            alert = Alert(
                alert_type=f"security_event_{pattern_name}",
                details=event_details,
                severity=severity,
                mitre_tactics=mitre_tactics,
                mitre_techniques=mitre_techniques
            )
            alert.save_to_db(self.db)
            self.performance_metrics["alerts_generated"] += 1

    def _get_usual_login_hours(self, username: str) -> List[int]:
        """Obtiene las horas usuales de login para un usuario basado en la línea base"""
        # Esta función podría implementarse consultando la base de datos
        # o manteniendo estadísticas en memoria
        # Para simplificar, devolvemos un rango ficticio de 9-18 (horario laboral)
        return list(range(9, 18))

    def _get_common_commands_for_user(self, username: str) -> List[str]:
        """Obtiene los comandos más comunes para un usuario"""
        if username not in self.baseline_metrics["commands_per_user"]:
            return []
            
        commands = self.baseline_metrics["commands_per_user"][username]
        # Ordenar por frecuencia y tomar los 10 más comunes
        return [cmd for cmd, _ in sorted(commands.items(), key=lambda x: x[1], reverse=True)[:10]]

    def analyze_all_logs(self, generate_alerts: bool = True) -> Dict[str, List[Dict]]:
        """Analiza todos los archivos de log configurados usando procesamiento paralelo."""
        logger.info("Iniciando análisis de todos los logs configurados...")
        start_time = time.time()
        all_findings = {}
        
        # Usar ThreadPoolExecutor para procesamiento paralelo
        with ThreadPoolExecutor(max_workers=min(len(self.log_paths), self.max_threads)) as executor:
            # Preparar las tareas
            future_to_log = {
                executor.submit(self.analyze_log_file, log_path, generate_alerts): log_path
                for log_path in self.log_paths if os.path.isfile(log_path)
            }
            
            # Recoger resultados a medida que se completan
            for future in as_completed(future_to_log):
                log_path = future_to_log[future]
                try:
                    findings = future.result()
                    all_findings[log_path] = findings
                except Exception as e:
                    logger.error(f"Error procesando {log_path}: {e}")
                    all_findings[log_path] = []
        
        # Post-procesamiento: Correlación entre logs
        if generate_alerts:
            self._correlate_findings(all_findings)
        
        duration = time.time() - start_time
        logger.info(f"Análisis de todos los logs completado en {duration:.2f}s. "
                   f"Total hallazgos: {sum(len(findings) for findings in all_findings.values())}")
        
        return all_findings

    def _correlate_findings(self, all_findings: Dict[str, List[Dict]]) -> None:
        """Correlaciona hallazgos entre múltiples logs para detectar patrones complejos"""
        # Extraer eventos por tipo para correlación
        events_by_type = defaultdict(list)
        events_by_user = defaultdict(list)
        events_by_ip = defaultdict(list)
        
        # Agrupar eventos para correlación
        for log_path, findings in all_findings.items():
            for finding in findings:
                event_type = finding.get("pattern_name", "unknown")
                events_by_type[event_type].append(finding)
                
                if "username" in finding and finding["username"]:
                    events_by_user[finding["username"]].append(finding)
                    
                if "ip_address" in finding and finding["ip_address"]:
                    events_by_ip[finding["ip_address"]].append(finding)
        
        # Correlación 1: Detección de Privilege Escalation y Lateral Movement
        # Buscar usuarios con login exitoso + comando sudo + nuevos usuarios creados
        for username, events in events_by_user.items():
            event_types = [e.get("pattern_name") for e in events]
            
            if ("successful_login" in event_types and 
                ("sudo_command" in event_types or "user_added" in event_types)):
                
                alert = Alert(
                    alert_type="privilege_escalation_sequence",
                    details={
                        "username": username,
                        "event_sequence": event_types,
                        "evidence": [e.get("line_content", "")[:100] for e in events][:5]
                    },
                    severity="high",
                    mitre_tactics=["Privilege Escalation", "Persistence"],
                    mitre_techniques=["T1078", "T1548"]
                )
                alert.save_to_db(self.db)
        
        # Correlación 2: Detección de Command and Control
        # Buscar actividad inusual de red después de ejecución de comandos sospechosos
        suspicious_ips = set()
        for event in events_by_type.get("suspicious_command", []):
            if "ip_address" in event:
                suspicious_ips.add(event["ip_address"])
                
        for event in events_by_type.get("file_download", []):
            if "ip_address" in event and event["ip_address"] in suspicious_ips:
                alert = Alert(
                    alert_type="potential_c2_activity",
                    details={
                        "ip_address": event["ip_address"],
                        "commands": [e.get("command", "") for e in events_by_ip[event["ip_address"]] 
                                    if "command" in e][:5],
                        "evidence": event.get("line_content", "")
                    },
                    severity="critical",
                    mitre_tactics=["Command and Control"],
                    mitre_techniques=["T1105", "T1571"]
                )
                alert.save_to_db(self.db)
        
        # Correlación 3: Detección de actividad de reconocimiento seguida de explotación
        recon_ips = set()
        for event in events_by_type.get("system_discovery", []):
            if "ip_address" in event:
                recon_ips.add(event["ip_address"])
                
        for event in events_by_type.get("permission_denied", []):
            if "ip_address" in event and event["ip_address"] in recon_ips:
                alert = Alert(
                    alert_type="reconnaissance_to_exploit",
                    details={
                        "ip_address": event["ip_address"],
                        "recon_evidence": [e.get("line_content", "")[:100] 
                                          for e in events_by_ip[event["ip_address"]] 
                                          if e.get("pattern_name") == "system_discovery"][:3],
                        "exploit_attempt": event.get("line_content", "")
                    },
                    severity="high",
                    mitre_tactics=["Discovery", "Initial Access"],
                    mitre_techniques=["T1082", "T1190"]
                )
                alert.save_to_db(self.db)

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Devuelve métricas de rendimiento del analizador"""
        return {
            "last_scan_duration": f"{self.performance_metrics['last_scan_duration']:.2f}s",
            "total_events_processed": self.performance_metrics["total_events_processed"],
            "alerts_generated": self.performance_metrics["alerts_generated"],
            "logs_analyzed": len(self.log_paths),
            "patterns_monitored": len(self.all_patterns)
        }

    def reset_trackers(self) -> None:
        """Reinicia los contadores y rastreadores de eventos"""
        self.failed_login_tracker.clear()
        # Mantener las líneas base pero limpiar los IOCs temporales
        self.observed_iocs.clear()
        # Reiniciar las alertas recientes para evitar supresión indebida
        self.recent_alerts.clear()

    def add_custom_pattern(self, name: str, pattern: str, severity: str = "medium", 
                          mitre_tactics: List[str] = None, 
                          mitre_techniques: List[str] = None) -> bool:
        """Añade un patrón personalizado para detección"""
        if not name or not pattern:
            return False
            
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            self.all_patterns[name] = {
                "pattern": compiled_pattern,
                "severity": severity,
                "mitre_tactics": mitre_tactics or [],
                "mitre_techniques": mitre_techniques or []
            }
            logger.info(f"Patrón personalizado añadido: {name}")
            return True
        except re.error:
            logger.error(f"Error compilando patrón personalizado: {pattern}")
            return False

    def export_findings_summary(self) -> Dict[str, Any]:
        """Exporta un resumen de hallazgos para informes"""
        # Esta función podría implementarse para generar informes
        return {
            "total_events": self.performance_metrics["total_events_processed"],
            "total_alerts": self.performance_metrics["alerts_generated"],
            "top_patterns": {},  # Podría poblarse consultando la BD
            "redteam_indicators": len(self.observed_iocs),
            "timestamp": datetime.datetime.now().isoformat()
        }

    def create_hunting_report(self) -> Dict[str, Any]:
        """Genera un informe de hunting basado en los hallazgos"""
        # Implementación base - podría expandirse con consultas a la BD
        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "suspicious_ips": list(self.observed_iocs.keys()),
            "compromised_users": [],  # Requiere lógica adicional
            "potential_redteam_activity": bool(self.observed_iocs),
            "recommendations": [
                "Revisar los logs originales de los sistemas con alertas críticas",
                "Verificar la legitimidad de nuevos usuarios creados",
                "Monitorear actividad de red hacia IPs sospechosas"
            ]
        }
    
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
    
# Clase auxiliar para implementar un monitor en tiempo real
class RealTimeLogMonitor:
    """Monitor de logs en tiempo real que utiliza LogAnalyzer"""
    
    def __init__(self, config: Dict, db: Database):
        """Inicializa el monitor con configuración"""
        self.log_analyzer = LogAnalyzer(config, db)
        self.scan_interval = max(5, config.get("scan_interval_seconds", 60))
        self.running = False
        self.last_scan_time = 0
        
    def start(self):
        """Inicia el monitoreo en tiempo real"""
        if self.running:
            logger.warning("El monitor ya está en ejecución")
            return
            
        self.running = True
        logger.info(f"Iniciando monitoreo en tiempo real cada {self.scan_interval} segundos")
        
        try:
            while self.running:
                current_time = time.time()
                if current_time - self.last_scan_time >= self.scan_interval:
                    self.log_analyzer.analyze_all_logs()
                    self.last_scan_time = current_time
                    
                # Dormir un tiempo corto para no consumir CPU innecesariamente
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Monitoreo detenido por el usuario")
        except Exception as e:
            logger.error(f"Error en el monitor de tiempo real: {e}")
        finally:
            self.running = False
    
    def stop(self):
        """Detiene el monitoreo en tiempo real"""
        self.running = False
        logger.info("Solicitando detención del monitoreo en tiempo real")

    def get_status(self) -> Dict[str, Any]:
        """Devuelve el estado actual del monitor"""
        return {
            "running": self.running,
            "last_scan": datetime.datetime.fromtimestamp(self.last_scan_time).isoformat() if self.last_scan_time else "Nunca",
            "scan_interval": f"{self.scan_interval} segundos",
            "metrics": self.log_analyzer.get_performance_metrics()
        }

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

class LazySentinelHandler(FileSystemEventHandler):
    def __init__(self, lazysentinel):
        self.lazysentinel = lazysentinel

    def is_text_file(self, file_path: Path) -> bool:
        """Check if a file is a text file by extension or content."""
        text_extensions = ['.txt', '.md', '.log', '.py', '.c', '.asm', '.go', '.pdf', '']
        if file_path.suffix.lower() in text_extensions:
            return True
        try:
            with file_path.open('rb') as f:
                return b'\x00' not in f.read(1024)
        except:
            return False

    def on_created(self, event):
        if event.is_directory:
            return
        file_path = Path(event.src_path)
        if file_path.name in self.lazysentinel.excluded_files:
            logging.info(f"Excluded file created: {file_path}")
            return
        if self.is_text_file(file_path):
            logging.info(f"File created: {file_path}, scheduling processing")
            time.sleep(1)
            self.lazysentinel.process_file(file_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        file_path = Path(event.src_path)
        if file_path.name in self.lazysentinel.excluded_files:
            logging.info(f"Excluded file modified: {file_path}")
            return
        if self.is_text_file(file_path):
            logging.info(f"File modified: {file_path}, scheduling processing")
            self.lazysentinel.process_file(file_path)

class LazySentinel:
    def __init__(self, app, popup_queue, watch_dir="sessions", excluded_files=None, min_file_size=10):
        self.app = app
        self.popup_queue = popup_queue
        self.watch_dir = Path(watch_dir)
        self.excluded_files = excluded_files or ['COMMANDS.md']
        self.min_file_size = min_file_size
        self.observer = Observer()
        self.handler = LazySentinelHandler(self)
        self.commands_md = Path("COMMANDS.md")
        self.model = DEEPSEEK_MODEL
        self.max_tokens = 64000
        self.chunk_size = 40000
        self.processed_files = {}
        self.db = Database("lazysentinel.db")
        self.rag_manager = RAGManager(self.model)
        self.auto_rag_enabled = True
        
        self.watch_dir.mkdir(exist_ok=True)
        self.observer.schedule(self.handler, str(self.watch_dir), recursive=False)
        self.observer.start()

    def chunk_text(self, text, chunk_size):
        return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]

    def select_relevant_chunk(self, file_content, chunks):
        if not chunks:
            return ""
        file_words = set(re.findall(r'\w+', file_content.lower()))
        best_chunk = chunks[0]
        max_overlap = 0
        for chunk in chunks:
            chunk_words = set(re.findall(r'\w+', chunk.lower()))
            overlap = len(file_words & chunk_words)
            if overlap > max_overlap:
                max_overlap = overlap
                best_chunk = chunk
        return best_chunk

    def parse_deepseek_response(self, response_text: str) -> Dict:
        """Parse DeepSeek's plain text response into a JSON-like dictionary."""
        result = {
            "relevant_info": "No info extracted.",
            "commands": [],
            "details": "No additional details."
        }
        if not response_text.strip():
            logging.warning("Empty DeepSeek response")
            return result

        relevant_info_match = re.search(r'(?:Relevant Information|Summary|Info):?\s*(.*?)(?=\n(?:Suggested Commands|Commands|Details|$))', response_text, re.DOTALL | re.IGNORECASE)
        commands_match = re.search(r'(?:Suggested Commands|Commands):?\s*(.*?)(?=\n(?:Details|$))', response_text, re.DOTALL | re.IGNORECASE)
        details_match = re.search(r'(?:Details|Additional Context):?\s*(.*)', response_text, re.DOTALL | re.IGNORECASE)

        if relevant_info_match:
            result["relevant_info"] = relevant_info_match.group(1).strip()
        elif response_text.strip():
            result["relevant_info"] = response_text.strip()

        if commands_match:
            commands_text = commands_match.group(1).strip()
            if commands_text.lower() != "none":
                result["commands"] = [cmd.strip() for cmd in commands_text.replace('\n', ',').split(',') if cmd.strip()]
        
        if details_match:
            result["details"] = details_match.group(1).strip()

        return result

    def show_popup(self, file_name: str, relevant_info: str, commands: List[str], details: str):
        """Queue a Rich-based popup to be displayed in the main thread."""
        try:
            # Sanitize content to prevent invalid characters or code snippets
            file_name = sanitize_content(file_name)
            relevant_info = sanitize_content(relevant_info)
            commands_str = sanitize_content(", ".join(commands) or "None")
            details = sanitize_content(details)
            
            self.popup_queue.put((file_name, relevant_info, commands_str, details, time.time()))
            logging.info(f"Queued popup for {file_name} at {time.time()}")
        except Exception as e:
            logging.error(f"Error queuing popup: {e}")
            content = (
                f"File: {file_name}\n"
                f"Relevant Information:\n{relevant_info}\n"
                f"Suggested Commands:\n{', '.join(commands) or 'None'}\n"
                f"Details:\n{details}\n"
                f"Press any key to continue..."
            )
            self.app.poutput(content)
            self.app.read_input("")

    def process_file(self, file_path):
        logging.info(f"Attempting to process file: {file_path}")
        try:
            mtime = file_path.stat().st_mtime
            current_time = time.time()
            file_info = self.processed_files.get(str(file_path), {'mtime': 0, 'last_processed': 0})
            if file_info['mtime'] >= mtime and current_time - file_info['last_processed'] < 2:
                logging.info(f"File {file_path} recently processed, skipping")
                return
            self.processed_files[str(file_path)] = {'mtime': mtime, 'last_processed': current_time}
            
            # Invalidate cache for modified file
            self.rag_manager.invalidate_cache(file_path)
        except FileNotFoundError:
            logging.warning(f"File {file_path} not found, possibly deleted")
            return

        for _ in range(5):
            try:
                if file_path.stat().st_size >= self.min_file_size:
                    break
            except FileNotFoundError:
                logging.warning(f"File {file_path} not found, possibly deleted")
                return
            time.sleep(1)
        else:
            logging.info(f"File {file_path} too small or inaccessible, skipping.")
            return

        try:
            with file_path.open('r', encoding='utf-8') as f:
                content = f.read()
            logging.info(f"Processing file: {file_path}, size: {file_path.stat().st_size} bytes")

            if self.auto_rag_enabled:
                self.rag_manager.process_file_to_rag(file_path)

            knowledge_base = ""
            if self.commands_md.exists():
                with self.commands_md.open('r', encoding='utf-8') as f:
                    commands_content = f.read()
                chunks = self.chunk_text(commands_content, self.chunk_size)
                knowledge_base = self.select_relevant_chunk(content, chunks)

            prompt = (
                f"""
                You are a helpful assistant. Analyze the provided file content and extract relevant information like passwords or usernames.
                Use the COMMANDS.md knowledge base to suggest relevant cmd2 commands.
                Respond with plain text in this format:
                Relevant Information: A brief summary of the file's key information.
                Suggested Commands: A comma-separated list of cmd2 commands or "none".
                Details: Additional context or observations.

                File content:
                {content[:10000]}

                COMMANDS.md knowledge base (partial):
                {knowledge_base}
                """
            )

            if len(prompt) > self.max_tokens * 4:
                prompt = prompt[:self.max_tokens * 4 - 100] + "..."
                logging.warning(f"Prompt truncated for {file_path} to fit token limit.")

            response = requests.post(
                DEEPSEEK_API_URL,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=600
            )

            if response.status_code == 200:
                try:
                    json_response = response.json()
                    logging.info(f"Full DeepSeek API response for {file_path}: {json_response}")
                    full_response = json_response.get("response", "")
                    
                    final_answer = re.sub(r"<think>.*?</think>", "", full_response, flags=re.DOTALL).strip()
                    if not final_answer:
                        logging.warning(f"Empty DeepSeek response for {file_path}")
                        full_response = "No response from DeepSeek."

                    result = self.parse_deepseek_response(final_answer)
                    relevant_info = result.get('relevant_info', 'No info extracted.')
                    commands = result.get('commands', [])
                    details = result.get('details', 'No additional details.')

                    self.show_popup(file_path.name, relevant_info, commands, details)
                    logging.info(f"Processed {file_path}: {result}")

                    alert = Alert(
                        alert_type="file_processed",
                        details={
                            "file_path": str(file_path),
                            "relevant_info": relevant_info,
                            "commands": commands,
                            "details": details
                        },
                        severity="info"
                    )
                    alert.save_to_db(self.db)

                except (KeyError, ValueError) as e:
                    logging.error(f"Error processing DeepSeek response for {file_path}: {e}, Raw response: {json_response}")
                    relevant_info = "Failed to process DeepSeek response."
                    commands = []
                    details = f"Error: {str(e)}. Raw response: {json_response.get('response', 'No response')}"
                    self.show_popup(file_path.name, relevant_info, commands, details)
                    alert = Alert(
                        alert_type="processing_error",
                        details={
                            "file_path": str(file_path),
                            "error": str(e),
                            "raw_response": str(json_response)
                        },
                        severity="medium"
                    )
                    alert.save_to_db(self.db)
            else:
                logging.error(f"DeepSeek API error for {file_path}: {response.status_code}, Response: {response.text}")
                self.app.poutput(f"Error: DeepSeek API returned {response.status_code}")
                alert = Alert(
                    alert_type="api_error",
                    details={
                        "file_path": str(file_path),
                        "status_code": response.status_code,
                        "response_text": response.text
                    },
                    severity="high"
                )
                alert.save_to_db(self.db)

        except Exception as e:
            logging.error(f"Error processing {file_path}: {e}")
            self.app.poutput(f"Error processing {file_path}: {str(e)}")
            alert = Alert(
                alert_type="general_error",
                details={
                    "file_path": str(file_path),
                    "error": str(e)
                },
                severity="medium"
            )
            alert.save_to_db(self.db)

    def stop(self):
        self.observer.stop()
        self.observer.join()
        logging.info("LazySentinel stopped.")

# --- Aplicación Principal CMD2 ---
class LazyOwnApp(cmd2.Cmd):
    """Interfaz de línea de comandos para LazyOwn BlueTeam Framework."""

    intro = """
    ╔══════════════════════════════════════════════════════════╗
    ║              LazyOwn BLUE TEAM FRAMEWORK CLI             ║
    ║              Análisis Forense y Monitoreo                ║
    ╚══════════════════════════════════════════════════════════╝
    
    Escriba 'help' o '?' para ver la lista de comandos disponibles.
    Escriba 'exit' para salir del programa.
    """
    prompt = "\033[1;34mBlueTeam>\033[0m "  # Azul para equipos azules

    def __init__(self, config_file: str = "config.json"):
        """Inicializa el CLI con configuración y componentes necesarios"""
        super().__init__(allow_cli_args=False)
        
        self.debug = False
        self.config = self._load_config(config_file)
        self.plugins_dir = 'plugins'
        self.lazyaddons_dir = 'lazyaddons'
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.plugins = {}
        self.register_lua_command = self._register_lua_command
        self.lua.globals().register_command = self.register_lua_command
        self.lua.globals().app = self
        self.lua.globals().list_files_in_directory = self.list_files_in_directory
        self.load_plugins()
        self.popup_queue = queue.Queue()
        self.last_popup_time = {}
        self.console = Console()  # Initialize Rich Console
        self.sentinel = LazySentinel(
            app=self,
            popup_queue=self.popup_queue,
            watch_dir="sessions",
            excluded_files=['COMMANDS.md', '.gitignore'],
            min_file_size=10
        )
        # Inicializar la base de datos
        self.db = Database(self.config.get("database", {}).get("path", "blue_team.db"))
        
        # Inicializar el analizador de logs
        self.log_analyzer = LogAnalyzer(self.config.get("log_analyzer", {}), self.db)
        
        # Estado del CLI
        self.monitoring_active = False
        self.monitor_thread = None
        self.last_analyzed_files = []
        self.current_context = None  # Para guardar contexto de comandos
        
        # Configurar historial de comandos persistente
        self.history_file = os.path.expanduser("~/.blue_team_history")
        
        # Añadir espacios de categorías para comandos
        self.categories = {
            'Análisis de Logs': ['analyze', 'monitor', 'patterns', 'correlate'],
            'Investigación': ['search', 'timeline', 'ioc', 'users', 'hosts'],
            'Alertas': ['alerts', 'respond', 'triage', 'escalate'],
            'Reportes': ['report', 'export', 'statistics'],
            'Sistema': ['config', 'status', 'debug', 'help', 'exit']
        }
        
        # Inicializar el filtro de alertas
        self.alert_filters = {
            'severity': None,
            'from_date': None,
            'to_date': None,
            'username': None,
            'ip': None,
            'pattern': None
        }
        

        # Eliminar comandos integrados no deseados
        del cmd2.Cmd.do_alias
        del cmd2.Cmd.do_macro
        del cmd2.Cmd.do_run_script # o `del cmd2.Cmd.do__relative_run_script`
        del cmd2.Cmd.do_run_pyscript
        del cmd2.Cmd.do_shell # Proporcionaremos uno propio más controlado si es necesario
        del cmd2.Cmd.do_edit

        del cmd2.Cmd.do_shortcuts
        del cmd2.Cmd.do_history


        self.config = self._load_config(config_file)
        self.db = Database(self.config["database_path"])

        # Inicializar módulos principales
        self.process_monitor = ProcessMonitor(self.config, self.db)
        self.network_monitor = NetworkMonitor(self.config, self.db)
        self.fim = FileIntegrityMonitor(self.config, self.db)
        self.file_monitor = FileIntegrityMonitor(self.config, self.db)
        self.hardener = SystemHardener(self.config, self.db)
        self.responder = IncidentResponder(self.config, self.db)
        self.reporter = ReportGenerator(self.config, self.db)
        self.file_integrity_monitor = FileIntegrityMonitor(self.config, self.db)
        self.system_hardener = SystemHardener(self.config, self.db)
        self.memory_scanner = MemoryScanner(self.config, self.db)
        logger.info("LazyOwnApp inicializada.")
        self.app = self
  
        self.db = self._initialize_database()
        self.log_analyzer = LogAnalyzer(self.config, self.db)
        self.monitor = RealTimeLogMonitor(self.config, self.db)

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

    def _initialize_database(self):
        """Inicializa la conexión a la base de datos"""
        # Esta es una implementación simulada
        return Database("./lazyown.db")

    def list_files_in_directory(self, directory):
        """Lista todos los archivos en un directorio dado."""
        if not os.path.exists(directory):
            return []  # Devuelve una lista vacía si el directorio no existe
        return [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]


    def _register_lua_command(self, command_name, lua_function):
        """Registra un comando nuevo desde Lua."""
        @cmd2.with_category("13. Lua Plugin")
        def wrapper(arg):
            try:
                # Llama a la función Lua y obtén el resultado
                result = lua_function(arg)
                if result is not None:
                    print(result)  # Imprime el resultado si no es None
            except Exception as e:
                print(f"Error en el comando Lua {command_name}: {e}")
        yaml_file = os.path.join(self.plugins_dir, f"{command_name}.yaml")
        description = ""
        
        if os.path.exists(yaml_file):
            try:
                with open(yaml_file, 'r') as file:
                    yaml_data = yaml.safe_load(file)
                    description = yaml_data.get('description', "")
            except Exception as e:
                print(f"Error al leer YAML para {command_name}: {e}")

        wrapper.__doc__ = description if description else f"Ejecuta el comando Lua '{command_name}'."
        setattr(self, f'do_{command_name}', wrapper)
        print(f"Command '{command_name}' register from Lua.")

    def load_plugins(self):
        """Carga todos los plugins Lua desde el directorio 'plugins/'."""
        plugins_dir = self.plugins_dir
        if not os.path.exists(plugins_dir):
            os.makedirs(plugins_dir)
            print("Directorio de plugins creado.")
            return

        for filename in os.listdir(plugins_dir):
            if filename.endswith('.lua'):
                filepath = os.path.join(plugins_dir, filename)
                yaml_ = filename.replace(".lua", ".yaml")
                filepathyaml = os.path.join(plugins_dir, yaml_)
                if filepathyaml == 'plugins/init_plugins.yaml':
                    pass
                else:
                    try:
                        with open(filepathyaml, 'r') as file:
                            file_yaml = yaml.safe_load(file)
                            enabled = file_yaml.get('enabled')
                            if enabled:
                                try:
                                    with open(filepath, 'r') as file:
                                        script = file.read()
                                        self.lua.execute(script)
                                except Exception as e:
                                    print(f"Error al cargar el plugin '{filename}': {e}")
                    except Exception as e:
                        print(f"Error al cargar el yaml '{filepathyaml}': {e}")

    def load_yaml_plugins(self):
        """
        Loads all YAML plugins from the 'lazyaddons/' directory.

        This method scans the 'lazyaddons/' directory, reads each YAML file,
        and registers enabled plugins as new commands.
        """
        if not os.path.exists(self.lazyaddons_dir):
            os.makedirs(self.lazyaddons_dir)
            print("Lazyaddons directory created.")
            return

        for filename in os.listdir(self.lazyaddons_dir):
            if filename.endswith('.yaml'):
                filepath = os.path.join(self.lazyaddons_dir, filename)
                try:
                    with open(filepath, 'r') as file:
                        plugin_data = yaml.safe_load(file)
                        if plugin_data.get('enabled', False):
                            self.register_yaml_plugin(plugin_data)
                except Exception as e:
                    print(f"Error loading YAML plugin '{filename}': {e}")

    def register_yaml_plugin(self, plugin_data):
        """
        Registers a YAML plugin as a new command.

        This method creates a dynamic command based on the plugin's configuration
        and assigns it to the application.
        """
        tool = plugin_data.get('tool', {})
        name = plugin_data['name']
        params = plugin_data.get('params', [])
        description = plugin_data.get('description', [])
        execute_command = tool.get('execute_command', '')
      
        @cmd2.with_category("14. Yaml Addon.")
        def wrapper_yaml(arg):
            try:

                args = arg.split()
                param_values = {}
                
                for param in params:
                    param_name = param['name']

                    if param.get('required', False) and param_name not in self.params:
                        print(f"Error: Parameter '{param_name}' is required but not found in self.params.")
                        return

                    if param_name in self.params:
                        param_values[param_name] = self.params[param_name]
                    elif 'default' in param:
                        param_values[param_name] = param['default']
                    else:
                        print(f"Error: Parameter '{param_name}' is missing and no default value is provided.")
                        return

                install_path = os.path.join(os.getcwd(), tool['install_path'])

                if not os.path.exists(install_path):
                    print(f"{tool['name']} is not installed. Installing...")
                    self.cmd(f"git clone {tool['repo_url']} {install_path}")
                    if 'install_command' in tool:
                        cmd = f"cd {install_path} && {tool['install_command']}"
                        self.cmd(cmd)

                try:

                    command = execute_command.format(**param_values)
                    command_replaced = replace_command_placeholders(command, self.params)
               
                    final_command = f"cd {install_path} && {command_replaced}"
                except KeyError as e:
                    print(f"Error: Missing parameter '{e}' in the plugin configuration.")
                    return

  
                self.cmd(final_command)

            except Exception as e:
                print(f"Error in plugin '{name}': {e}")
        wrapper_yaml.__doc__  = description
        setattr(self, f'do_{name}', wrapper_yaml)
        print(f"Command '{name}' registered from YAML.")

    def postloop(self) -> None:
        """Acciones al salir de la aplicación."""
        self.poutput("Cerrando LazyOwn BlueTeam Framework...")
        if self.db:
            self.db.close()
        logger.info("LazyOwnApp cerrada.")


    def postcmd(self, stop, line):
        """Check the popup queue after each command and display with Rich Markdown."""
        while not self.popup_queue.empty():
            try:
                file_name, relevant_info, commands, details, queue_time = self.popup_queue.get_nowait()
                last_time = self.last_popup_time.get(file_name, 0)
                if time.time() - last_time < 2:
                    logging.info(f"Skipped duplicate popup for {file_name} at {time.time()}")
                    continue
                self.last_popup_time[file_name] = time.time()
                
                # Create a Markdown-formatted string
                content = f"""# LazySentinel Alert

**File:** {file_name}

## Relevant Information
{relevant_info}

## Suggested Commands
{commands}

## Details
{details}

*Press any key to continue...*
"""
                # Render the content as Markdown
                markdown_content = Markdown(content)
                
                # Create a panel with the Markdown content
                panel = Panel(markdown_content, title="LazySentinel Alert", border_style="red", padding=(1, 2))
                
                # Clear the console and display the panel
                self.console.clear()
                self.console.print(panel)
                
                # Wait for user input to continue
                self.console.input("")
                logging.info(f"Displayed popup for {file_name} at {time.time()}")
                
                # Clear the console after input
                self.console.clear()
                
            except Exception as e:
                logging.error(f"Error displaying popup: {e}")
                content = (
                    f"File: {file_name}\n"
                    f"Relevant Information:\n{relevant_info}\n"
                    f"Suggested Commands:\n{commands}\n"
                    f"Details:\n{details}\n"
                    f"Press any key to continue..."
                )
                self.poutput(content)
                self.read_input("")
        return stop


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
    @cmd2.with_category(reporting_category)
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

    def do_quit(self, arg):
        """Quit the application."""
        self.sentinel.stop()
        return True

    def do_debug(self, arg):
        """Display debug information about LazySentinel state."""
        self.poutput(f"Monitoring directory: {self.sentinel.watch_dir}")
        self.poutput(f"Processed files: {list(self.sentinel.processed_files.keys())}")
        alerts = self.sentinel.db.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5")
        for alert in alerts:
            self.poutput(f"Alert: {alert['type']}, Severity: {alert['severity']}, Details: {json.loads(alert['details'])}")

    def do_rag_query(self, arg):
        """Query the RAG knowledge base with a question."""
        if not arg.strip():
            self.poutput("Usage: rag_query <your question>")
            return
        
        self.poutput("Querying RAG knowledge base...")
        response = self.sentinel.rag_manager.query_rag(arg)
        self.poutput(f"\nRAG Response:\n{response}\n")

    def do_rag_add(self, arg):
        """Add a specific file to the RAG knowledge base."""
        if not arg.strip():
            self.poutput("Usage: rag_add <file_path>")
            return
        
        file_path = Path(arg.strip())
        if not file_path.exists():
            self.poutput(f"File not found: {file_path}")
            return
        
        self.poutput(f"Adding {file_path} to RAG knowledge base...")
        success = self.sentinel.rag_manager.process_file_to_rag(file_path)
        if success:
            self.poutput(f"Successfully added {file_path} to knowledge base")
        else:
            self.poutput(f"Failed to add {file_path} to knowledge base")

    def do_rag_status(self, arg):
        """Display RAG knowledge base status and statistics."""
        stats = self.sentinel.rag_manager.get_knowledge_base_stats()
        self.poutput("RAG Knowledge Base Status:")
        for key, value in stats.items():
            self.poutput(f"  {key}: {value}")
        
        self.poutput(f"\nAuto-RAG enabled: {self.sentinel.auto_rag_enabled}")

    def do_rag_toggle(self, arg):
        """Toggle automatic addition of monitored files to RAG knowledge base."""
        self.sentinel.auto_rag_enabled = not self.sentinel.auto_rag_enabled
        status = "enabled" if self.sentinel.auto_rag_enabled else "disabled"
        self.poutput(f"Auto-RAG is now {status}")

    def do_rag_bulk_add(self, arg):
        """Add all files in the monitored directory to RAG knowledge base."""
        if not arg.strip():
            directory = self.sentinel.watch_dir
        else:
            directory = Path(arg.strip())
        
        if not directory.exists() or not directory.is_dir():
            self.poutput(f"Directory not found: {directory}")
            return
        
        self.poutput(f"Adding all files from {directory} to RAG knowledge base...")
        
        added_count = 0
        for file_path in directory.iterdir():
            if file_path.is_file() and file_path.name not in self.sentinel.excluded_files:
                success = self.sentinel.rag_manager.process_file_to_rag(file_path)
                if success:
                    added_count += 1
                    self.poutput(f"  Added: {file_path.name}")
        
        self.poutput(f"Successfully added {added_count} files to knowledge base")

    def do_rag_search(self, arg):
        """Search for similar content in the RAG knowledge base."""
        if not arg.strip():
            self.poutput("Usage: rag_search <search terms>")
            return
        
        if self.sentinel.rag_manager.retriever is None:
            self.poutput("No knowledge base available. Add some files first.")
            return
        
        try:
            docs = self.sentinel.rag_manager.retriever.invoke(arg)
            
            if not docs:
                self.poutput("No similar documents found.")
                return
            
            self.poutput(f"Found {len(docs)} similar documents:")
            for i, doc in enumerate(docs[:5], 1):
                self.poutput(f"\n{i}. Content preview:")
                self.poutput(f"   {doc.page_content[:200]}...")
                if hasattr(doc, 'metadata') and doc.metadata:
                    self.poutput(f"   Source: {doc.metadata.get('source', 'Unknown')}")
                    
        except Exception as e:
            self.poutput(f"Error searching knowledge base: {e}")

    def complete_rag_add(self, text, line, begidx, endidx):
        """Tab completion for rag_add command."""
        files = []
        for path in [Path("."), self.sentinel.watch_dir]:
            if path.exists():
                files.extend([str(f) for f in path.iterdir() if f.is_file()])
        return [f for f in files if f.startswith(text)]

    def complete_rag_bulk_add(self, text, line, begidx, endidx):
        """Tab completion for rag_bulk_add command."""
        dirs = []
        for path in Path(".").iterdir():
            if path.is_dir():
                dirs.append(str(path))
        return [d for d in dirs if d.startswith(text)]

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



    

    
 

    
    def _load_config(self, config_file: str) -> Dict:
        """Carga la configuración desde un archivo JSON"""
        default_config = {
            "database": {"path": "blue_team.db"},
            "log_analyzer": {
                "log_paths": ["/var/log/auth.log", "/var/log/syslog"],
                "scan_interval_seconds": 60,
                "max_failed_logins": 5,
                "log_analyzer_max_lines": 5000,
                "max_analyzer_threads": 4
            },
            "reporting": {
                "output_dir": "./reports",
                "formats": ["json", "html", "pdf"]
            },
            "integration": {
                "enable_slack": False,
                "enable_email": False
            }
        }
        
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Fusionar con valores predeterminados
                    for key, value in default_config.items():
                        if key not in loaded_config:
                            loaded_config[key] = value
                        elif isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                if sub_key not in loaded_config[key]:
                                    loaded_config[key][sub_key] = sub_value
                    return loaded_config
            else:
                print(f"Archivo de configuración {config_file} no encontrado. Usando valores predeterminados.")
                return default_config
        except Exception as e:
            print(f"Error cargando configuración: {e}")
            return default_config
    

    ########################
    # Comandos de análisis de logs
    ########################
    
    def do_analyze(self, args):
        """
        Analiza archivos de log específicos o todos los configurados.
        
        Uso: analyze [opciones] [archivo1 archivo2 ...]
        
        Opciones:
          -a, --all      Analiza todos los archivos de log configurados
          -n, --no-alert No genera alertas durante el análisis
          -v, --verbose  Muestra información detallada del análisis
        
        Ejemplos:
          analyze -a                        # Analiza todos los logs configurados
          analyze /var/log/auth.log         # Analiza solo auth.log
          analyze -n /var/log/syslog        # Analiza syslog sin generar alertas
        """
        parser = argparse.ArgumentParser(prog="analyze")
        parser.add_argument('-a', '--all', action='store_true', help='Analiza todos los archivos de log')
        parser.add_argument('-n', '--no-alert', action='store_true', help='No genera alertas')
        parser.add_argument('-v', '--verbose', action='store_true', help='Muestra información detallada')
        parser.add_argument('files', nargs='*', help='Archivos de log a analizar')
        
        try:
            parsed_args = parser.parse_args(args.arg_list)
            
            # Determinar qué archivos analizar
            files_to_analyze = []
            if parsed_args.all:
                files_to_analyze = self.log_analyzer.log_paths
                print(f"Analizando todos los logs configurados ({len(files_to_analyze)} archivos)")
            elif parsed_args.files:
                files_to_analyze = parsed_args.files
                print(f"Analizando logs especificados ({len(files_to_analyze)} archivos)")
            else:
                print("Error: Debe especificar archivos o usar la opción --all")
                return
            
            # Verificar que los archivos existen
            valid_files = [f for f in files_to_analyze if os.path.isfile(f)]
            if len(valid_files) < len(files_to_analyze):
                print(f"Advertencia: {len(files_to_analyze) - len(valid_files)} archivos no encontrados")
            
            if not valid_files:
                print("Error: No hay archivos válidos para analizar")
                return
            
            # Realizar el análisis
            start_time = time.time()
            generate_alerts = not parsed_args.no_alert
            
            if len(valid_files) == 1:
                # Analizar un solo archivo
                findings = self.log_analyzer.analyze_log_file(valid_files[0], generate_alerts)
                self._display_findings_summary(valid_files[0], findings, parsed_args.verbose)
            else:
                # Analizar múltiples archivos
                all_findings = {}
                for file in valid_files:
                    findings = self.log_analyzer.analyze_log_file(file, generate_alerts)
                    all_findings[file] = findings
                    if parsed_args.verbose:
                        self._display_findings_summary(file, findings, verbose=True)
                
                # Mostrar resumen general
                total_findings = sum(len(findings) for findings in all_findings.values())
                print(f"\nResumen del análisis:")
                print(f"- Archivos analizados: {len(valid_files)}")
                print(f"- Total de hallazgos: {total_findings}")
                print(f"- Tiempo de análisis: {time.time() - start_time:.2f} segundos")
                
                if generate_alerts:
                    alert_count = self.log_analyzer.performance_metrics["alerts_generated"]
                    print(f"- Alertas generadas: {alert_count}")
            
            # Guardar los archivos analizados en el estado
            self.last_analyzed_files = valid_files
            
        except SystemExit:
            # Capturar la salida de argparse cuando hay error en parámetros
            return
        except Exception as e:
            print(f"Error durante el análisis: {e}")
    
    def _display_findings_summary(self, file_path: str, findings: List[Dict], verbose: bool = False):
        """Muestra un resumen de los hallazgos de un archivo"""
        print(f"\nArchivo: {file_path}")
        print(f"Hallazgos: {len(findings)}")
        
        if not findings:
            print("No se encontraron eventos de interés")
            return
        
        # Agrupar por tipo de patrón
        patterns = defaultdict(int)
        for finding in findings:
            pattern = finding.get("pattern_name", "desconocido")
            patterns[pattern] += 1
        
        # Mostrar resumen por patrón
        print("\nResumen por patrón:")
        for pattern, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True):
            severity = next((p["severity"] for p in self.log_analyzer.all_patterns.values() 
                            if p.get("pattern_name") == pattern), "medium")
            severity_color = self._get_severity_color(severity)
            print(f"- {pattern}: {count} eventos ({severity_color}{severity}\033[0m)")
        
        # Si es verbose, mostrar algunos ejemplos de los hallazgos más importantes
        if verbose and findings:
            critical_findings = [f for f in findings 
                               if f.get("pattern_name") in self.log_analyzer.all_patterns and 
                               self.log_analyzer.all_patterns[f.get("pattern_name")].get("severity") in ["high", "critical"]]
            
            if critical_findings:
                print("\nEjemplos de hallazgos importantes:")
                for i, finding in enumerate(critical_findings[:5]):  # Mostrar hasta 5 ejemplos
                    pattern = finding.get("pattern_name", "desconocido")
                    line = finding.get("line_content", "")[:100] + "..." if len(finding.get("line_content", "")) > 100 else finding.get("line_content", "")
                    print(f"{i+1}. [{pattern}] {line}")
    
    def _get_severity_color(self, severity: str) -> str:
        """Devuelve el código de color ANSI para una severidad dada"""
        colors = {
            "critical": "\033[1;31m",  # Rojo brillante
            "high": "\033[31m",        # Rojo
            "medium": "\033[33m",      # Amarillo
            "low": "\033[32m",         # Verde
            "info": "\033[36m"         # Cian
        }
        return colors.get(severity.lower(), "\033[0m")  # Por defecto sin color
    
    def do_monitor(self, args):
        """
        Inicia o detiene el monitoreo en tiempo real de los logs.
        
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
          monitor status         # Muestra el estado del monitoreo
        """
        parser = argparse.ArgumentParser(prog="monitor")
        parser.add_argument('action', nargs='?', choices=['start', 'stop', 'status'], default='start',
                           help='Acción a realizar con el monitoreo')
        parser.add_argument('-i', '--interval', type=int, help='Intervalo de escaneo en segundos')
        
        try:
            parsed_args = parser.parse_args(args.arg_list)
            
            if parsed_args.action == 'start':
                if self.monitoring_active:
                    print("El monitoreo ya está activo. Deténgalo primero con 'monitor stop'.")
                    return
                
                # Configurar intervalo
                interval = parsed_args.interval or self.log_analyzer.scan_interval
                
                # Iniciar monitoreo en un hilo separado
                self.monitoring_active = True
                self.monitor_thread = threading.Thread(
                    target=self._monitoring_loop,
                    args=(interval,),
                    daemon=True
                )
                self.monitor_thread.start()
                
                print(f"Monitoreo iniciado con intervalo de {interval} segundos")
                print("Los hallazgos y alertas se mostrarán en tiempo real")
                print("Utilice 'monitor stop' para detener el monitoreo")
                
            elif parsed_args.action == 'stop':
                if not self.monitoring_active:
                    print("El monitoreo no está activo.")
                    return
                
                self.monitoring_active = False
                if self.monitor_thread:
                    self.monitor_thread.join(timeout=2)
                    self.monitor_thread = None
                
                print("Monitoreo detenido")
                
            elif parsed_args.action == 'status':
                if self.monitoring_active:
                    interval = parsed_args.interval or self.log_analyzer.scan_interval
                    print(f"Monitoreo ACTIVO con intervalo de {interval} segundos")
                    print(f"Archivos monitoreados: {len(self.log_analyzer.log_paths)}")
                    metrics = self.log_analyzer.get_performance_metrics()
                    print(f"Eventos procesados: {metrics['total_events_processed']}")
                    print(f"Alertas generadas: {metrics['alerts_generated']}")
                else:
                    print("Monitoreo INACTIVO")
        
        except SystemExit:
            return
        except Exception as e:
            print(f"Error en el comando de monitoreo: {e}")
    
    def _monitoring_loop(self, interval: int):
        """Bucle de monitoreo que se ejecuta en un hilo separado"""
        try:
            while self.monitoring_active:
                # Mostrar hora de escaneo
                scan_time = datetime.datetime.now().strftime("%H:%M:%S")
                print(f"\n[{scan_time}] Escaneando logs...")
                
                # Analizar todos los logs configurados
                all_findings = self.log_analyzer.analyze_all_logs(generate_alerts=True)
                
                # Mostrar resumen de hallazgos
                total_findings = sum(len(findings) for findings in all_findings.values())
                if total_findings > 0:
                    print(f"[{scan_time}] Nuevos hallazgos: {total_findings}")
                    
                    # Mostrar hallazgos críticos en tiempo real
                    critical_findings = []
                    for file_path, findings in all_findings.items():
                        for finding in findings:
                            pattern_name = finding.get("pattern_name")
                            if pattern_name in self.log_analyzer.all_patterns:
                                severity = self.log_analyzer.all_patterns[pattern_name].get("severity")
                                if severity in ["critical", "high"]:
                                    critical_findings.append((file_path, finding))
                    
                    if critical_findings:
                        print("\n¡ALERTAS CRÍTICAS DETECTADAS!")
                        for file_path, finding in critical_findings[:5]:  # Limitar a 5 para no saturar
                            pattern = finding.get("pattern_name", "desconocido")
                            severity = self.log_analyzer.all_patterns[pattern].get("severity", "medium")
                            severity_color = self._get_severity_color(severity)
                            print(f"- [{severity_color}{severity}\033[0m] {pattern}: {finding.get('line_content', '')[:80]}...")
                        
                        if len(critical_findings) > 5:
                            print(f"... y {len(critical_findings) - 5} más. Use 'alerts list' para ver todas.")
                
                # Esperar hasta el próximo escaneo
                for _ in range(interval):
                    if not self.monitoring_active:
                        break
                    time.sleep(1)
                    
        except Exception as e:
            print(f"Error en el bucle de monitoreo: {e}")
            self.monitoring_active = False
    
    def do_patterns(self, args):
        """
        Gestiona los patrones de detección para el análisis de logs.
        
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
          patterns remove                 # Inicia asistente para eliminar un patrón
        """
        parser = argparse.ArgumentParser(prog="patterns")
        parser.add_argument('action', nargs='?', choices=['list', 'add', 'remove', 'show'], default='list',
                           help='Acción a realizar con los patrones')
        parser.add_argument('name', nargs='?', help='Nombre del patrón para mostrar/eliminar')
        parser.add_argument('-c', '--category', choices=['redteam', 'normal'], help='Filtrar por categoría')
        parser.add_argument('-s', '--severity', choices=['critical', 'high', 'medium', 'low', 'info'], 
                           help='Filtrar por severidad')
        
        try:
            parsed_args = parser.parse_args(args.arg_list)
            
            if parsed_args.action == 'list':
                # Filtrar patrones según parámetros
                filtered_patterns = {}
                
                if parsed_args.category == 'redteam':
                    patterns_to_filter = self.log_analyzer.redteam_patterns
                elif parsed_args.category == 'normal':
                    patterns_to_filter = self.log_analyzer.patterns
                else:
                    patterns_to_filter = self.log_analyzer.all_patterns
                
                # Aplicar filtro de severidad si existe
                if parsed_args.severity:
                    filtered_patterns = {name: config for name, config in patterns_to_filter.items()
                                      if config.get('severity') == parsed_args.severity}
                else:
                    filtered_patterns = patterns_to_filter
                
                # Mostrar patrones en formato tabular
                pattern_data = []
                for name, config in sorted(filtered_patterns.items()):
                    severity = config.get('severity', 'medium')
                    techniques = ', '.join(config.get('mitre_techniques', ['N/A']))
                    tactics = ', '.join(config.get('mitre_tactics', ['N/A']))
                    pattern_type = 'RedTeam' if name in self.log_analyzer.redteam_patterns else 'Normal'
                    
                    # Colorear severidad
                    severity_colored = f"{self._get_severity_color(severity)}{severity}\033[0m"
                    
                    pattern_data.append([name, severity_colored, pattern_type, techniques, tactics])
                
                if pattern_data:
                    headers = ['Nombre', 'Severidad', 'Tipo', 'Técnicas MITRE', 'Tácticas MITRE']
                    print("\nPatrones de detección configurados:")
                    print(tabulate(pattern_data, headers=headers, tablefmt='pretty'))
                    print(f"Total: {len(pattern_data)} patrones")
                else:
                    print("No se encontraron patrones con los filtros especificados")
            
            elif parsed_args.action == 'show':
                if not parsed_args.name:
                    print("Error: Debe especificar el nombre del patrón a mostrar")
                    return
                
                pattern_name = parsed_args.name
                if pattern_name in self.log_analyzer.all_patterns:
                    config = self.log_analyzer.all_patterns[pattern_name]
                    pattern_type = 'RedTeam' if pattern_name in self.log_analyzer.redteam_patterns else 'Normal'
                    
                    print(f"\nDetalles del patrón: {pattern_name}")
                    print(f"Tipo: {pattern_type}")
                    print(f"Severidad: {self._get_severity_color(config.get('severity', 'medium'))}{config.get('severity', 'medium')}\033[0m")
                    print(f"Expresión regular: {config['pattern'].pattern}")
                    print(f"Tácticas MITRE: {', '.join(config.get('mitre_tactics', ['N/A']))}")
                    print(f"Técnicas MITRE: {', '.join(config.get('mitre_techniques', ['N/A']))}")
                else:
                    print(f"Error: El patrón '{pattern_name}' no existe")
            
            elif parsed_args.action == 'add':
                # Asistente para añadir patrón
                print("\nAsistente para añadir un nuevo patrón de detección")
                name = input("Nombre del patrón: ")
                
                if name in self.log_analyzer.all_patterns:
                    print(f"Error: Ya existe un patrón con el nombre '{name}'")
                    return
                
                pattern_regex = input("Expresión regular: ")
                severity = input("Severidad (critical/high/medium/low/info) [medium]: ") or "medium"
                
                # Validar severidad
                if severity.lower() not in ['critical', 'high', 'medium', 'low', 'info']:
                    print(f"Severidad '{severity}' no válida. Usando 'medium' por defecto.")
                    severity = "medium"
                
                mitre_tactics = input("Tácticas MITRE (separadas por comas): ").split(',')
                mitre_tactics = [t.strip() for t in mitre_tactics if t.strip()]
                
                mitre_techniques = input("Técnicas MITRE (separadas por comas): ").split(',')
                mitre_techniques = [t.strip() for t in mitre_techniques if t.strip()]
                
                # Añadir patrón
                result = self.log_analyzer.add_custom_pattern(
                    name, pattern_regex, severity, mitre_tactics, mitre_techniques
                )
                
                if result:
                    print(f"Patrón '{name}' añadido correctamente")
                else:
                    print(f"Error al añadir el patrón '{name}'")
            
            elif parsed_args.action == 'remove':
                if parsed_args.name:
                    pattern_name = parsed_args.name
                else:
                    # Mostrar lista para seleccionar
                    pattern_names = list(self.log_analyzer.all_patterns.keys())
                    for i, name in enumerate(pattern_names):
                        print(f"{i+1}. {name}")
                    
                    selection = input("\nSeleccione el número del patrón a eliminar: ")
                    try:
                        index = int(selection) - 1
                        if 0 <= index < len(pattern_names):
                            pattern_name = pattern_names[index]
                        else:
                            print("Selección fuera de rango")
                            return
                    except ValueError:
                        print("Entrada no válida")
                        return
                
                # Verificar si es un patrón predefinido o personalizado
                if pattern_name in self.log_analyzer.patterns or pattern_name in self.log_analyzer.redteam_patterns:
                    confirm = input(f"'{pattern_name}' es un patrón predefinido. ¿Realmente desea eliminarlo? [s/N]: ").lower()
                    if confirm != 's':
                        print("Operación cancelada")
                        return
                
                # Eliminar patrón
                if pattern_name in self.log_analyzer.all_patterns:
                    del self.log_analyzer.all_patterns[pattern_name]
                    if pattern_name in self.log_analyzer.patterns:
                        del self.log_analyzer.patterns[pattern_name]
                    if pattern_name in self.log_analyzer.redteam_patterns:
                        del self.log_analyzer.redteam_patterns[pattern_name]
                    
                    print(f"Patrón '{pattern_name}' eliminado correctamente")
                else:
                    print(f"Error: El patrón '{pattern_name}' no existe")
        
        except SystemExit:
            return
        except Exception as e:
            print(f"Error en el comando de patrones: {e}")

    
    def do_analyze_logs(self, args):
        """Analiza los archivos de log configurados"""
        self.poutput("Analizando logs del sistema...")
        findings = self.log_analyzer.analyze_all_logs()
        
        total = sum(len(f) for f in findings.values())
        self.poutput(f"Análisis completado. {total} hallazgos encontrados.")
        
        # Mostrar resumen por tipo de patrón
        summary = defaultdict(int)
        for log_findings in findings.values():
            for finding in log_findings:
                pattern = finding.get("pattern_name", "unknown")
                summary[pattern] += 1
                
        self.poutput("\nResumen por tipo de patrón:")
        for pattern, count in sorted(summary.items(), key=lambda x: x[1], reverse=True):
            severity = self.log_analyzer.all_patterns.get(pattern, {}).get("severity", "unknown")
            self.poutput(f"  {pattern}: {count} eventos [{severity}]")
    
    def do_start_monitor(self, args):
        """Inicia el monitoreo en tiempo real de logs"""
        if not self.monitor.running:
            # Iniciar en un thread separado
            
            monitor_thread = threading.Thread(target=self.monitor.start, daemon=True)
            monitor_thread.start()
            self.poutput(f"Monitor iniciado con intervalo de {self.monitor.scan_interval}s")
        else:
            self.poutput("El monitor ya está en ejecución")
    
    def do_stop_monitor(self, args):
        """Detiene el monitoreo en tiempo real"""
        if self.monitor.running:
            self.monitor.stop()
            self.poutput("Solicitando detención del monitor...")
        else:
            self.poutput("El monitor no está en ejecución")
    
    def do_monitor_status(self, args):
        """Muestra el estado actual del monitor"""
        status = self.monitor.get_status()
        self.poutput(f"Estado: {'Activo' if status['running'] else 'Detenido'}")
        self.poutput(f"Último escaneo: {status['last_scan']}")
        self.poutput(f"Intervalo: {status['scan_interval']}")
        self.poutput("\nMétricas de rendimiento:")
        for key, value in status['metrics'].items():
            self.poutput(f"  {key}: {value}")
    
    def do_add_pattern(self, args):
        """Añade un patrón personalizado de detección"""
        pattern_name = self.app.read_input("Nombre del patrón: ")
        pattern_regex = self.app.read_input("Expresión regular: ")
        severity = self.app.read_input("Severidad (low/medium/high/critical) [medium]: ") or "medium"
        
        if self.log_analyzer.add_custom_pattern(pattern_name, pattern_regex, severity):
            self.poutput(f"Patrón '{pattern_name}' añadido correctamente")
        else:
            self.poutput("Error al añadir el patrón")
    
    def do_redteam_hunt(self, args):
        """Realiza una búsqueda específica de actividad del equipo rojo"""
        self.poutput("Iniciando búsqueda de actividad de equipo rojo...")
        
        # Analizar logs con los patrones específicos de equipo rojo
        findings = self.log_analyzer.analyze_all_logs()
        
        # Filtrar solo hallazgos relacionados con equipo rojo
        redteam_findings = []
        for log_path, log_findings in findings.items():
            for finding in log_findings:
                pattern = finding.get("pattern_name", "")
                if pattern in self.log_analyzer.redteam_patterns:
                    redteam_findings.append(finding)
        
        if redteam_findings:
            self.poutput(f"\n¡ALERTA! Se encontraron {len(redteam_findings)} indicios de actividad del equipo rojo:")
            for i, finding in enumerate(redteam_findings[:10], 1):  # Mostrar los primeros 10
                self.poutput(f"\n--- Hallazgo #{i} ---")
                self.poutput(f"Tipo: {finding.get('pattern_name', 'desconocido')}")
                self.poutput(f"Log: {finding.get('log_file', 'desconocido')}")
                self.poutput(f"Línea: {finding.get('line_content', 'N/A')[:150]}...")
                
                if finding.get("ip_address"):
                    self.poutput(f"IP: {finding['ip_address']}")
                if finding.get("username"):
                    self.poutput(f"Usuario: {finding['username']}")
                
            if len(redteam_findings) > 10:
                self.poutput(f"\n... y {len(redteam_findings) - 10} hallazgos más.")
                
            # Generar reporte
            report = self.log_analyzer.create_hunting_report()
            self.poutput("\n=== REPORTE DE HUNTING ===")
            self.poutput(f"Timestamp: {report['timestamp']}")
            self.poutput(f"IPs Sospechosas: {', '.join(report['suspicious_ips']) if report['suspicious_ips'] else 'Ninguna'}")
            self.poutput("\nRecomendaciones:")
            for rec in report['recommendations']:
                self.poutput(f"  - {rec}")
        else:
            self.poutput("No se encontraron indicios de actividad del equipo rojo.")
    


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
    app.poutput("LazySentinel with RAG and CAG capabilities initialized.")
    app.poutput("New RAG commands available:")
    app.poutput("  - rag_query <question>     : Ask questions about your knowledge base")
    app.poutput("  - rag_add <file>          : Add a specific file to knowledge base")
    app.poutput("  - rag_bulk_add [dir]      : Add all files from directory")
    app.poutput("  - rag_status              : Show knowledge base statistics")
    app.poutput("  - rag_toggle              : Toggle auto-RAG for monitored files")
    app.poutput("  - rag_search <terms>      : Search for similar content")
    app.poutput("  - debug                   : Show debug information")
    app.poutput("  - quit                    : Exit application")    
    sys.exit(app.cmdloop())
