"""Detection engine: auditd + Sigma rules for real-time threat detection.

Integrates with Linux auditd for system call monitoring and applies
Sigma rules to detect malicious patterns. Stores alerts in SQLite
for querying by purple team and other consumers.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("lazyownbt.detection")

_DEFAULT_DB = Path(__file__).resolve().parent.parent / "lazyown.db"
_RULES_DIR = Path(__file__).resolve().parent.parent / "sigma_rules"


@dataclass(frozen=True)
class SigmaRule:
    """A single detection rule."""
    id: str
    title: str
    description: str
    category: str
    level: str
    pattern: str
    mitre: str = ""


@dataclass
class Alert:
    """A detection alert."""
    rule_id: str
    rule_title: str
    category: str
    level: str
    message: str
    command: str = ""
    process_name: str = ""
    pid: int = 0
    uid: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_log: str = ""


_DEFAULT_RULES: list[SigmaRule] = [
    SigmaRule(
        id="LAZYOWN-001",
        title="Mimikatz Credential Dump",
        description="Detects mimikatz or sekurlsa credential extraction",
        category="credential_access",
        level="critical",
        pattern=r"(mimikatz|sekurlsa|logonpasswords|kerberos::list|lsadump)",
        mitre="T1003",
    ),
    SigmaRule(
        id="LAZYOWN-002",
        title="Reverse Shell",
        description="Detects reverse shell payloads",
        category="execution",
        level="critical",
        pattern=r"(bash\s+-i\s+>/dev/tcp|nc\s+-e|python.*socket.*connect|msfvenom.*reverse)",
        mitre="T1059",
    ),
    SigmaRule(
        id="LAZYOWN-003",
        title="Privilege Escalation",
        description="Detects common privesc techniques",
        category="privilege_escalation",
        level="high",
        pattern=r"(chmod\s+[0-7]*777|chown\s+root|/etc/passwd.*write|sudo\s+-l|find\s+/-perm\s+-4000)",
        mitre="T1548",
    ),
    SigmaRule(
        id="LAZYOWN-004",
        title="Suspicious Network Scan",
        description="Detects aggressive nmap scans",
        category="reconnaissance",
        level="medium",
        pattern=r"(nmap\s+.*-[sS][VA]|masscan|zmap|unicornscan)",
        mitre="T1046",
    ),
    SigmaRule(
        id="LAZYOWN-005",
        title="Web Shell Detected",
        description="Detects web shell access patterns",
        category="persistence",
        level="critical",
        pattern=r"(cmd\.php|c99\.php|r57\.php|shell\.php.*exec|eval\(\$_(GET|POST|REQUEST))",
        mitre="T1505",
    ),
    SigmaRule(
        id="LAZYOWN-006",
        title="Suspicious Process Injection",
        description="Detects process injection attempts",
        category="defense_evasion",
        level="high",
        pattern=r"(ptrace\s+PTRACE_ATTACH|/proc/.*/mem|process_vm_writev|CreateRemoteThread)",
        mitre="T1055",
    ),
    SigmaRule(
        id="LAZYOWN-007",
        title="Credential Access - /etc/shadow",
        description="Attempts to read shadow password file",
        category="credential_access",
        level="critical",
        pattern=r"(cat\s+/etc/shadow|less\s+/etc/shadow|grep\s+.*\s+/etc/shadow)",
        mitre="T1003",
    ),
    SigmaRule(
        id="LAZYOWN-008",
        title="Suspicious Cron Persistence",
        description="Detects cron job manipulation",
        category="persistence",
        level="high",
        pattern=r"(crontab\s+-e|echo\s+.*>\s+/etc/cron|chmod\s+.*\s+/etc/cron)",
        mitre="T1053",
    ),
    SigmaRule(
        id="LAZYOWN-009",
        title="Lateral Movement - SMB",
        description="Detects SMB-based lateral movement",
        category="lateral_movement",
        level="high",
        pattern=r"(smbclient.*-c|psexec|wmic.*process.*call|evil-winrm)",
        mitre="T1021",
    ),
    SigmaRule(
        id="LAZYOWN-010",
        title="Data Exfiltration",
        description="Detects data exfiltration patterns",
        category="exfiltration",
        level="high",
        pattern=r"(curl\s+.*-F\s+file=|wget\s+.*--post-file|scp\s+.*@.*:|rsync\s+.*@.*)",
        mitre="T1041",
    ),
]


class DetectionEngine:
    """auditd + Sigma detection engine."""

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or str(_DEFAULT_DB)
        self._rules: list[SigmaRule] = list(_DEFAULT_RULES)
        self._load_custom_rules()
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sigma_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    rule_title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    command TEXT DEFAULT '',
                    process_name TEXT DEFAULT '',
                    pid INTEGER DEFAULT 0,
                    uid INTEGER DEFAULT 0,
                    timestamp TEXT NOT NULL,
                    raw_log TEXT DEFAULT '',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _load_custom_rules(self) -> None:
        if not _RULES_DIR.exists():
            _RULES_DIR.mkdir(parents=True, exist_ok=True)
            return
        for rule_file in _RULES_DIR.glob("*.json"):
            try:
                data = json.loads(rule_file.read_text())
                self._rules.append(SigmaRule(**data))
            except Exception as e:
                logger.warning("Failed to load rule %s: %s", rule_file, e)

    def get_rules(self) -> list[SigmaRule]:
        return list(self._rules)

    def check_command(self, command: str, args: str = "") -> list[Alert]:
        """Check a command against all Sigma rules."""
        full_cmd = f"{command} {args}".strip()
        alerts = []
        for rule in self._rules:
            if re.search(rule.pattern, full_cmd, re.IGNORECASE):
                alert = Alert(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    category=rule.category,
                    level=rule.level,
                    message=f"Detected: {rule.title} - {full_cmd}",
                    command=full_cmd,
                )
                alerts.append(alert)
                self._store_alert(alert)
        return alerts

    def check_audit_log(self, log_line: str) -> list[Alert]:
        """Check an auditd log line against all rules."""
        alerts = []
        for rule in self._rules:
            if re.search(rule.pattern, log_line, re.IGNORECASE):
                pid = self._extract_field(log_line, "pid")
                uid = self._extract_field(log_line, "uid")
                comm = self._extract_field(log_line, "comm")
                alert = Alert(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    category=rule.category,
                    level=rule.level,
                    message=f"Audit alert: {rule.title}",
                    process_name=comm,
                    pid=pid,
                    uid=uid,
                    raw_log=log_line,
                )
                alerts.append(alert)
                self._store_alert(alert)
        return alerts

    def _extract_field(self, log_line: str, field: str) -> int:
        match = re.search(rf'{field}=(\d+)', log_line)
        return int(match.group(1)) if match else 0

    def _store_alert(self, alert: Alert) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO sigma_alerts (rule_id, rule_title, category, level, message,
                   command, process_name, pid, uid, timestamp, raw_log)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert.rule_id, alert.rule_title, alert.category, alert.level,
                 alert.message, alert.command, alert.process_name, alert.pid,
                 alert.uid, alert.timestamp, alert.raw_log),
            )

    def get_alerts(
        self,
        since_minutes: int = 5,
        category: str | None = None,
        level: str | None = None,
    ) -> list[dict]:
        """Get recent alerts, optionally filtered."""
        query = "SELECT * FROM sigma_alerts WHERE timestamp > datetime('now', ?)"
        params: list[Any] = [f"-{since_minutes} minutes"]

        if category:
            query += " AND category = ?"
            params.append(category)
        if level:
            query += " AND level = ?"
            params.append(level)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def get_stats(self, since_minutes: int = 60) -> dict:
        """Get detection statistics."""
        with self._conn() as conn:
            row = conn.execute(
                """SELECT COUNT(*) as total,
                          SUM(CASE WHEN level='critical' THEN 1 ELSE 0 END) as critical,
                          SUM(CASE WHEN level='high' THEN 1 ELSE 0 END) as high,
                          SUM(CASE WHEN level='medium' THEN 1 ELSE 0 END) as medium
                   FROM sigma_alerts WHERE timestamp > datetime('now', ?)""",
                [f"-{since_minutes} minutes"],
            ).fetchone()
            return dict(row) if row else {"total": 0, "critical": 0, "high": 0, "medium": 0}

    def is_auditd_available(self) -> bool:
        """Check if auditd is installed and running."""
        try:
            result = subprocess.run(
                ["auditctl", "-l"], capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def install_auditd_rule(self, key: str = "lazyownbt") -> bool:
        """Install an auditd rule for monitoring."""
        try:
            rule = f"-w /etc/passwd -p wa -k {key}"
            subprocess.run(
                ["auditctl", rule], capture_output=True, text=True, timeout=5,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False


_engine: DetectionEngine | None = None


def get_engine(db_path: str | None = None) -> DetectionEngine:
    global _engine
    if _engine is None:
        _engine = DetectionEngine(db_path)
    return _engine
