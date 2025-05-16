#!/usr/bin/env python3
"""
LazyOwn PurpleTeam Dashboard
Panel web para unificar y visualizar operaciones RedTeam y BlueTeam.
"""

import sqlite3
import json
import subprocess
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_talisman import Talisman
import bleach
from pathlib import Path
from typing import Dict, List, Optional
import os

# Configuración de logging
logging.basicConfig(
    filename='lazyown_purpleteam.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("LazyOwnPurpleTeam")

# Inicializar Flask
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Cambiar por una clave segura
app.config['DATABASE_PATH'] = './lazyown.db'
jwt = JWTManager(app)

# Configuración de Talisman con CSP personalizado
csp = {
    'default-src': "'self'",
    'style-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
        # Agrega el hash para los inline styles en commands.html
        "'sha256-lKxzDHhV4lbpglq4Lo9Kwok3OXo6kSv/8AX6AnVNzxA='"
    ],
    'script-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
        'https://code.jquery.com',  # Para DataTables
        'https://cdn.datatables.net'
    ]
}
Talisman(app, force_https=False, content_security_policy=csp)

# Constantes
ALLOWED_COMMANDS = [
    'do_resp_block_ip', 'do_resp_kill_proc', 'do_net_scan', 'do_fim_scan',
    'lazynmap', 'ai_playbook'  # Comandos RedTeam/BlueTeam permitidos
]

# Clase para manejar la base de datos
class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def connect(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            logger.error(f"Error connecting to database: {e}")
            return None

    def fetch_alerts(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict]:
        conn = self.connect()
        if not conn:
            return []
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            alerts = [
                {
                    'id': row['id'], 'type': row['type'], 'details': json.loads(row['details']),
                    'severity': row['severity'], 'timestamp': row['timestamp']
                } for row in rows
            ]
            return alerts
        except sqlite3.Error as e:
            logger.error(f"Error fetching alerts: {e}")
            return []
        finally:
            conn.close()

    def fetch_events(self, limit: int = 100) -> List[Dict]:
        conn = self.connect()
        if not conn:
            return []
        query = "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?"
        try:
            cursor = conn.cursor()
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            events = [
                {
                    'id': row['id'], 'event_type': row['event_type'], 'source': row['source'],
                    'description': row['description'], 'raw_data': row['raw_data'],
                    'timestamp': row['timestamp']
                } for row in rows
            ]
            return events
        except sqlite3.Error as e:
            logger.error(f"Error fetching events: {e}")
            return []
        finally:
            conn.close()

    def correlate_events(self, event_id: int) -> Dict:
        # Ejemplo de correlación: buscar alertas relacionadas con un evento
        conn = self.connect()
        if not conn:
            return {}
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT raw_data, timestamp FROM security_events WHERE id = ?", (event_id,))
            event = cursor.fetchone()
            if not event:
                return {}
            # Buscar alertas en un rango de tiempo cercano (±5 minutos)
            event_time = datetime.fromisoformat(event['timestamp'])
            start_time = (event_time - datetime.timedelta(minutes=5)).isoformat()
            end_time = (event_time + datetime.timedelta(minutes=5)).isoformat()
            cursor.execute(
                "SELECT * FROM alerts WHERE timestamp BETWEEN ? AND ? AND details LIKE ?",
                (start_time, end_time, f'%{event["raw_data"]}%')
            )
            related_alerts = [
                {'id': row['id'], 'type': row['type'], 'details': json.loads(row['details'])}
                for row in cursor.fetchall()
            ]
            return {'event_id': event_id, 'related_alerts': related_alerts}
        except sqlite3.Error as e:
            logger.error(f"Error correlating events: {e}")
            return {}
        finally:
            conn.close()
    def fetch_network_baseline(self, limit: int = 100) -> List[Dict]:
        conn = self.connect()
        if not conn:
            return []
        query = "SELECT * FROM network_baseline ORDER BY timestamp DESC LIMIT ?"
        try:
            cursor = conn.cursor()
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            return [
                {
                    'id': row['id'], 'ip': row['ip'], 'port': row['port'],
                    'protocol': row['protocol'], 'timestamp': row['timestamp']
                } for row in rows
            ]
        except sqlite3.Error as e:
            logger.error(f"Error fetching network baseline: {e}")
            return []
        finally:
            conn.close()

    def fetch_file_hashes(self, limit: int = 100) -> List[Dict]:
        conn = self.connect()
        if not conn:
            return []
        query = "SELECT * FROM file_hashes ORDER BY timestamp DESC LIMIT ?"
        try:
            cursor = conn.cursor()
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            return [
                {
                    'id': row['id'], 'file_path': row['file_path'], 'hash': row['hash'],
                    'timestamp': row['timestamp']
                } for row in rows
            ]
        except sqlite3.Error as e:
            logger.error(f"Error fetching file hashes: {e}")
            return []
        finally:
            conn.close()
# Inicializar base de datos
db = Database(app.config['DATABASE_PATH'])

# Rutas
@app.route('/')

def dashboard():
    alerts = db.fetch_alerts(limit=10)
    events = db.fetch_events(limit=10)
    metrics = {
        'total_alerts': len(db.fetch_alerts()),
        'critical_alerts': len(db.fetch_alerts(severity='critical')),
        'total_events': len(db.fetch_events()),
        'last_scan': datetime.now().isoformat()
    }
    return render_template('dashboard.html', alerts=alerts, events=events, metrics=metrics)

@app.route('/alerts', methods=['GET'])

def alerts():
    severity = request.args.get('severity')
    limit = int(request.args.get('limit', 100))
    alerts = db.fetch_alerts(limit=limit, severity=severity)
    return render_template('alerts.html', alerts=alerts)

@app.route('/events', methods=['GET'])

def events():
    limit = int(request.args.get('limit', 100))
    events = db.fetch_events(limit=limit)
    return render_template('events.html', events=events)

@app.route('/commands', methods=['GET', 'POST'])

def commands():
    if request.method == 'POST':
        command = bleach.clean(request.form.get('command'))
        params = bleach.clean(request.form.get('params', ''))
        if command not in ALLOWED_COMMANDS:
            return jsonify({'error': 'Comando no permitido'}), 403
        try:
            # Ejecutar comando (simulación, ajustar según integración real)
            result = subprocess.run(
                ['python3', '-c', f'from lazyown import LazyOwnApp; app = LazyOwnApp(); app.onecmd("{command} {params}")'],
                capture_output=True, text=True, timeout=30
            )
            return jsonify({'output': result.stdout, 'error': result.stderr})
        except subprocess.SubprocessError as e:
            logger.error(f"Error ejecutando comando {command}: {e}")
            return jsonify({'error': str(e)}), 500
    return render_template('commands.html', allowed_commands=ALLOWED_COMMANDS)

@app.route('/api/correlate/<int:event_id>', methods=['GET'])

def correlate_event(event_id):
    correlation = db.correlate_events(event_id)
    return jsonify(correlation)

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    # Autenticación simple (reemplazar con un sistema real)
    if username == 'admin' and password == 'password':  # Cambiar por autenticación segura
        access_token = create_access_token(identity=username)
        return jsonify({'access_token': access_token})
    return jsonify({'error': 'Credenciales inválidas'}), 401

# Plantillas HTML (guardar en templates/)
# dashboard.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>LazyOwn PurpleTeam Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
</head>
<body>
    <div class="container">
        <h1>LazyOwn PurpleTeam Dashboard</h1>
        <div class="row">
            <div class="col-md-4">
                <h3>Métricas</h3>
                <ul>
                    <li>Total Alertas: {{ metrics.total_alerts }}</li>
                    <li>Alertas Críticas: {{ metrics.critical_alerts }}</li>
                    <li>Total Eventos: {{ metrics.total_events }}</li>
                    <li>Último Escaneo: {{ metrics.last_scan }}</li>
                </ul>
            </div>
            <div class="col-md-8">
                <h3>Últimas Alertas</h3>
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>ID</th><th>Tipo</th><th>Detalles</th><th>Severidad</th><th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for alert in alerts %}
                        <tr>
                            <td>{{ alert.id }}</td>
                            <td>{{ alert.type }}</td>
                            <td>{{ alert.details | tojson }}</td>
                            <td>{{ alert.severity }}</td>
                            <td>{{ alert.timestamp }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""

# alerts.html, events.html, commands.html similares, con tablas y formularios según necesidad

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
