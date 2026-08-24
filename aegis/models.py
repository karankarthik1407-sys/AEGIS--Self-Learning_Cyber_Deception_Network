from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class SecurityEvent:
    case_id: str
    event_type: str
    actor: str
    target: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TelemetryObservation:
    node_id: str
    source: str
    category: str
    event_type: str
    severity: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProposedAction:
    action_type: str
    target: str
    namespace: str
    decoy_only: bool
    network_egress: bool
    synthetic_data_only: bool
    reversible: bool
    memory_mb: int
    cpu_cores: float
    ttl_seconds: int
    rationale: str
    action_id: str = field(default_factory=lambda: f"ACT-{uuid4().hex[:10].upper()}")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ProposedAction":
        return cls(
            action_type=str(value.get("action_type", "serve_synthetic_admin_history")),
            target=str(value.get("target", "decoy-admin-portal")),
            namespace=str(value.get("namespace", "aegis-range")),
            decoy_only=bool(value.get("decoy_only", True)),
            network_egress=bool(value.get("network_egress", False)),
            synthetic_data_only=bool(value.get("synthetic_data_only", True)),
            reversible=bool(value.get("reversible", True)),
            memory_mb=int(value.get("memory_mb", 96)),
            cpu_cores=float(value.get("cpu_cores", 0.25)),
            ttl_seconds=int(value.get("ttl_seconds", 180)),
            rationale=str(value.get("rationale", "Discriminate credential-access and collection hypotheses")),
            action_id=str(value.get("action_id") or f"ACT-{uuid4().hex[:10].upper()}"),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
