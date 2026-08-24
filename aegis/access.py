from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any


ROLE_SCOPES: dict[str, frozenset[str]] = {
    "viewer": frozenset({"read"}),
    "analyst": frozenset({"read", "operate"}),
    "administrator": frozenset({"read", "operate", "administer"}),
}


@dataclass(frozen=True)
class ActionContract:
    permission: str
    entitlement: str | None
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "permission": self.permission,
            "entitlement": self.entitlement,
            "rationale": self.rationale,
        }


POST_CONTRACTS: dict[str, ActionContract] = {
    "/api/simulate": ActionContract(
        "operate",
        "desktop_control_plane",
        "Advance an authorized synthetic deception scenario.",
    ),
    "/api/actions/evaluate": ActionContract(
        "operate",
        "desktop_control_plane",
        "Ask the deterministic Safety Kernel to evaluate a proposal.",
    ),
    "/api/demo/reset": ActionContract(
        "administer",
        "desktop_control_plane",
        "Reset the local demonstration case state.",
    ),
    "/api/research/experiment/run": ActionContract(
        "operate",
        "research_lab",
        "Reproduce the synthetic intent-classification experiment.",
    ),
    "/api/trace/experiment/run": ActionContract(
        "operate",
        "research_lab",
        "Reproduce the held-out activity-linkage experiment.",
    ),
    "/api/trace/graph-experiment/run": ActionContract(
        "operate",
        "research_lab",
        "Reproduce the transitivity-safe graph experiment.",
    ),
    "/api/steering/experiment/run": ActionContract(
        "operate",
        "research_lab",
        "Reproduce the safety-gated diagnostic-steering experiment.",
    ),
    "/api/models/fabric/evaluate": ActionContract(
        "operate",
        "research_lab",
        "Evaluate a shadow candidate without changing production weights.",
    ),
    "/api/hardware/dry-run": ActionContract(
        "operate",
        "hardware_dry_run",
        "Exercise the hardware contract with zero packet effects.",
    ),
    "/api/telemetry/collect": ActionContract(
        "operate",
        "resident_node",
        "Run one privacy-bounded local telemetry cycle.",
    ),
    "/api/gateway/preview": ActionContract(
        "operate",
        "offline_evidence_gateway",
        "Preview an offline evidence import without persistence.",
    ),
    "/api/gateway/import": ActionContract(
        "operate",
        "offline_evidence_gateway",
        "Commit normalized, privacy-bounded observations.",
    ),
    "/api/governance/evaluate": ActionContract(
        "administer",
        "research_lab",
        "Create an immutable model-governance evaluation record.",
    ),
    "/api/license/reload": ActionContract(
        "administer",
        None,
        "Reload the offline license envelope so a broken license can be recovered.",
    ),
}

DEFAULT_POST_CONTRACT = ActionContract(
    "operate",
    "desktop_control_plane",
    "Invoke a local control-plane mutation.",
)


@dataclass(frozen=True)
class OperatorSession:
    session_ref: str
    role: str
    scopes: frozenset[str]
    origin: str
    authentication: str

    @classmethod
    def create(
        cls,
        token: str | None,
        role: str = "administrator",
        origin: str = "loopback-control-plane",
    ) -> "OperatorSession":
        normalized_role = role.strip().lower()
        if normalized_role not in ROLE_SCOPES:
            raise ValueError(f"unsupported AEGIS operator role: {role}")
        material = token if token is not None else f"{origin}:{normalized_role}"
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:20].upper()
        return cls(
            session_ref=f"SES-{digest}",
            role=normalized_role,
            scopes=ROLE_SCOPES[normalized_role],
            origin=origin,
            authentication="DESKTOP_SESSION_TOKEN" if token is not None else "LOCAL_PROCESS_BOUNDARY",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_ref": self.session_ref,
            "role": self.role.upper(),
            "scopes": sorted(self.scopes),
            "origin": self.origin,
            "authentication": self.authentication,
            "raw_token_retained": False,
        }


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    permission: str
    role: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "permission": self.permission,
            "role": self.role,
            "reason": self.reason,
        }


class AccessController:
    def contract_for(self, path: str) -> ActionContract:
        return POST_CONTRACTS.get(path, DEFAULT_POST_CONTRACT)

    def authorize(self, session: OperatorSession, path: str) -> AccessDecision:
        contract = self.contract_for(path)
        allowed = contract.permission in session.scopes
        return AccessDecision(
            allowed=allowed,
            permission=contract.permission,
            role=session.role,
            reason=(
                "role_scope_satisfied"
                if allowed
                else f"role_{session.role}_lacks_{contract.permission}_scope"
            ),
        )

    def status(self) -> dict[str, Any]:
        return {
            "roles": {role.upper(): sorted(scopes) for role, scopes in ROLE_SCOPES.items()},
            "mutations": {
                path: contract.to_dict() for path, contract in sorted(POST_CONTRACTS.items())
            },
            "default_mutation": DEFAULT_POST_CONTRACT.to_dict(),
            "trust_boundary": (
                "Roles are assigned by the local host, never accepted from a browser header. "
                "Enterprise identity federation and multi-user session issuance are not yet implemented."
            ),
        }
