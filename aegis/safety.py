from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

from .config import Settings
from .models import ProposedAction, utc_now


@dataclass(frozen=True)
class SafetyCheck:
    rule: str
    passed: bool
    observed: Any
    required: str


class SafetyGate:
    """Deterministic verifier between adaptive proposal and deployment."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def evaluate(self, action: ProposedAction) -> dict[str, Any]:
        checks = [
            SafetyCheck("authorized_namespace", action.namespace == self.settings.authorized_namespace, action.namespace, self.settings.authorized_namespace),
            SafetyCheck("decoy_target", action.decoy_only and action.target.startswith("decoy-"), action.target, "decoy-only target prefixed with 'decoy-'"),
            SafetyCheck("no_network_egress", not action.network_egress, action.network_egress, "false"),
            SafetyCheck("synthetic_data", action.synthetic_data_only, action.synthetic_data_only, "true"),
            SafetyCheck("reversible", action.reversible, action.reversible, "true"),
            SafetyCheck("memory_ceiling", 0 < action.memory_mb <= self.settings.max_action_memory_mb, action.memory_mb, f"1..{self.settings.max_action_memory_mb} MB"),
            SafetyCheck("cpu_ceiling", 0 < action.cpu_cores <= self.settings.max_action_cpu_cores, action.cpu_cores, f">0..{self.settings.max_action_cpu_cores} core"),
            SafetyCheck("ttl_ceiling", 0 < action.ttl_seconds <= self.settings.max_action_ttl_seconds, action.ttl_seconds, f"1..{self.settings.max_action_ttl_seconds} seconds"),
        ]
        permitted = all(check.passed for check in checks)
        unsigned = {
            "certificate_version": "aegis.safety.v1",
            "created_at": utc_now(),
            "action": action.to_dict(),
            "decision": "PERMIT" if permitted else "DENY",
            "checks": [asdict(check) for check in checks],
            "failed_rules": [check.rule for check in checks if not check.passed],
        }
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        unsigned["digest"] = hashlib.sha256(canonical).hexdigest()
        return unsigned

