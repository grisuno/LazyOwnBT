"""Handlers de acciones: código de aplicación, no shell.

Cada handler es una función Python pura que recibe los parámetros validados
por el ActionRegistry. Si necesita lanzar subprocesos, debe hacerlo de forma
segura (lista cerrada de binarios + argumentos en array, nunca string).
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
from typing import Any, Callable, Dict

from lazyownbt.actions import ActionSpec


_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _validate_ip(ip: str) -> str:
    if not _IP_RE.match(ip):
        raise ValueError(f"IP inválida: {ip!r}")
    try:
        socket.inet_aton(ip)
    except OSError as exc:
        raise ValueError(f"IP inválida: {ip!r}") from exc
    return ip


def handle_resp_block_ip(ip_address: str = "", interface: str = "INPUT", **_extra: Any) -> str:
    """Stub seguro. En un despliegue real invocaría iptables con argv."""
    _validate_ip(ip_address)
    if not interface.replace("_", "").isalnum():
        raise ValueError("interface inválido")
    if os.geteuid() != 0:
        return f"DRY-RUN: bloquearía {ip_address} en cadena {interface} (no root)"
    # Lista cerrada de binarios + argv (nunca string).
    proc = subprocess.run(  # noqa: S603 — argv validado
        ["/sbin/iptables", "-I", interface, "-s", ip_address, "-j", "DROP"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"iptables falló: {proc.stderr.strip()}")
    return f"OK: {ip_address} bloqueada en {interface}"


def handle_resp_kill_proc(pid: int = 0, signal: int = 15, **_extra: Any) -> str:
    """Stub seguro. En un despliegue real enviaría la señal al PID."""
    if pid <= 0:
        raise ValueError("pid debe ser positivo")
    if signal not in (9, 15, 19, 23):
        raise ValueError("señal no permitida")
    if os.geteuid() != 0 and pid != os.getpid():
        return f"DRY-RUN: enviaría SIG{signal} al PID {pid}"
    os.kill(pid, signal)  # noqa: S101 — acción explícita
    return f"OK: señal {signal} enviada al PID {pid}"


def handle_net_scan(**_extra: Any) -> str:
    return "OK: net_scan ejecutado"


def handle_fim_scan(**_extra: Any) -> str:
    return "OK: fim_scan ejecutado"


def handle_lazynmap(target: str = "", **_extra: Any) -> str:
    if not target or not re.match(r"^[A-Za-z0-9.\-/:]+$", target):
        raise ValueError("target inválido")
    return f"OK: nmap contra {target}"


def handle_ai_playbook(scenario: str = "", **_extra: Any) -> str:
    if not scenario.strip():
        raise ValueError("scenario vacío")
    return f"OK: playbook generado para '{scenario[:80]}'"


def build_default_handlers() -> Dict[str, Callable[..., Any]]:
    return {
        "do_resp_block_ip": handle_resp_block_ip,
        "do_resp_kill_proc": handle_resp_kill_proc,
        "do_net_scan": handle_net_scan,
        "do_fim_scan": handle_fim_scan,
        "lazynmap": handle_lazynmap,
        "ai_playbook": handle_ai_playbook,
    }


__all__ = [
    "build_default_handlers",
    "handle_resp_block_ip",
    "handle_resp_kill_proc",
    "handle_net_scan",
    "handle_fim_scan",
    "handle_lazynmap",
    "handle_ai_playbook",
    "ActionSpec",
]
