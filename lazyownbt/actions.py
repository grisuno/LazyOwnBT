"""Registro cerrado de acciones permitidas y parser de parámetros.

Contrato: SEC-002 — Ejecución segura de comandos.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Type


@dataclass(frozen=True)
class ActionSpec:
    """Especificación declarativa de una acción ejecutable."""

    name: str
    description: str
    params: Dict[str, Type] = field(default_factory=dict)
    required: tuple = ()
    permissions: tuple = ()
    timeout_s: int = 30


class ActionParseError(ValueError):
    """Error de validación de parámetros."""


class ActionRegistry:
    """Registro cerrado de acciones permitidas (SEC-002.2)."""

    def __init__(self) -> None:
        self._actions: Dict[str, ActionSpec] = {}
        self._handlers: Dict[str, Callable[..., Any]] = {}

    def register(self, spec: ActionSpec, handler: Callable[..., Any]) -> None:
        if spec.name in self._actions:
            raise ValueError(f"Acción duplicada: {spec.name}")
        self._actions[spec.name] = spec
        self._handlers[spec.name] = handler

    def is_allowed(self, name: str) -> bool:
        return name in self._actions

    def spec(self, name: str) -> Optional[ActionSpec]:
        return self._actions.get(name)

    def handler(self, name: str) -> Optional[Callable[..., Any]]:
        return self._handlers.get(name)

    def names(self) -> List[str]:
        return sorted(self._actions)

    def validate_params(self, name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Valida y coerciona parámetros (SEC-002.3)."""
        spec = self.spec(name)
        if spec is None:
            raise ActionParseError(f"Acción no permitida: {name!r}")
        cleaned: Dict[str, Any] = {}
        for key, typ in spec.params.items():
            if key not in params:
                if key in spec.required:
                    raise ActionParseError(f"Falta parámetro obligatorio: {key}")
                continue
            value = params[key]
            if value is None or value == "":
                if key in spec.required:
                    raise ActionParseError(f"Parámetro vacío: {key}")
                continue
            try:
                cleaned[key] = typ(value)
            except (TypeError, ValueError) as exc:
                raise ActionParseError(
                    f"Parámetro {key!r} esperaba {typ.__name__}, "
                    f"recibió {value!r}: {exc}"
                ) from exc
        # Rechazar parámetros desconocidos (defensa en profundidad)
        unknown = set(params) - set(spec.params)
        if unknown:
            raise ActionParseError(f"Parámetros desconocidos: {sorted(unknown)}")
        return cleaned


# Acciones predefinidas del framework. La lista cerrada es VERSIONADA.
# Añadir una acción = modificar este registro + tests.
DEFAULT_ACTIONS: List[ActionSpec] = [
    ActionSpec(
        name="do_resp_block_ip",
        description="Bloquea una IP via iptables (requiere root).",
        params={"ip_address": str, "interface": str},
        required=("ip_address",),
        permissions=("response:block_ip",),
    ),
    ActionSpec(
        name="do_resp_kill_proc",
        description="Envía una señal a un proceso por PID.",
        params={"pid": int, "signal": int},
        required=("pid",),
        permissions=("response:kill_process",),
    ),
    ActionSpec(
        name="do_net_scan",
        description="Escanea conexiones de red activas.",
        params={},
        permissions=("network:read",),
    ),
    ActionSpec(
        name="do_fim_scan",
        description="Verifica integridad de archivos críticos.",
        params={},
        permissions=("fim:read",),
    ),
    ActionSpec(
        name="lazynmap",
        description="Wrapper de nmap con objetivos permitidos.",
        params={"target": str},
        required=("target",),
        permissions=("network:scan",),
    ),
    ActionSpec(
        name="ai_playbook",
        description="Genera un playbook defensivo con IA.",
        params={"scenario": str},
        required=("scenario",),
        permissions=("ai:playbook",),
        timeout_s=60,
    ),
]
