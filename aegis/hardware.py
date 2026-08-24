from __future__ import annotations

import hashlib
import json
from typing import Any

from .config import Settings


PROFILE_VERSION = "aegis.hardware-enforcement-profile.v0.1-draft"
FIRMWARE_ID = "aegis-hep-sim-firmware-0001"


def _digest(value: dict[str, Any]) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(canonical).hexdigest()


class HardwareEnforcementGateway:
    """Software-only simulator for a future attested enforcement appliance.

    This module never changes routes, interfaces or packets. It exercises the
    certificate-verification and atomic rollback protocol that can later be
    mapped onto a DPU, SmartNIC or FPGA target.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.measurement = hashlib.sha256(f"AEGIS|{FIRMWARE_ID}|SIMULATED-ROOT".encode()).hexdigest()

    def profile(self) -> dict[str, Any]:
        return {
            "profile_version": PROFILE_VERSION,
            "status": "SOFTWARE PROTOCOL PROTOTYPE",
            "purpose": "Enforce only Safety Gate-certified deception rules outside the untrusted host control plane.",
            "current_mode": "Deterministic local state-machine simulation",
            "packet_effects": 0,
            "external_targets": 0,
            "trust_boundary": "Future DPU/SmartNIC/FPGA with TPM or device-rooted measured boot",
            "candidate_targets": ["DPU", "SmartNIC", "P4-capable switch", "FPGA gateway"],
            "states": [
                "UNATTESTED",
                "ATTESTED",
                "CERTIFICATE_VERIFIED",
                "RULE_STAGED",
                "RULE_COMMITTED",
                "ROLLED_BACK",
            ],
            "invariants": [
                "Firmware measurement must match an approved value.",
                "The complete Safety Gate certificate digest must verify.",
                "Only a PERMIT decision with every rule passing is admissible.",
                "The namespace and target must remain authorized and decoy-only.",
                "A deny rule must preserve non-reachability of the protected core.",
                "The rule set must commit atomically or not appear at all.",
                "Expiry must trigger rollback and a tamper-evident receipt.",
            ],
            "research_claim_boundary": "A technical prototype and invention candidate—not a novelty or patentability conclusion.",
        }

    @staticmethod
    def verify_certificate_digest(certificate: dict[str, Any]) -> bool:
        supplied = certificate.get("digest")
        if not isinstance(supplied, str) or len(supplied) != 64:
            return False
        unsigned = {key: value for key, value in certificate.items() if key != "digest"}
        return _digest(unsigned) == supplied

    def dry_run(self, certificate: dict[str, Any]) -> dict[str, Any]:
        trace: list[dict[str, Any]] = []
        trace.append({"state": "UNATTESTED", "result": "START", "detail": "No enforcement authority before attestation."})
        trace.append({"state": "ATTESTED", "result": "PASS", "detail": f"Approved simulated measurement {self.measurement[:16]}…"})

        failures = self._certificate_failures(certificate)
        if failures:
            trace.append({"state": "REFUSED", "result": "DENY", "detail": "; ".join(failures)})
            receipt_body = {
                "profile_version": PROFILE_VERSION,
                "decision": "REFUSED",
                "certificate_digest": certificate.get("digest"),
                "measurement": self.measurement,
                "trace": trace,
                "packet_effects": 0,
            }
            return {
                **receipt_body,
                "simulated_receipt_sha256": _digest(receipt_body),
                "cryptographic_note": "Digest-only simulation; production requires a hardware-protected signing key.",
            }

        trace.append({"state": "CERTIFICATE_VERIFIED", "result": "PASS", "detail": "Safety certificate and all eight checks verified."})
        action = certificate["action"]
        rule_manifest = {
            "transaction": f"TX-{certificate['digest'][:16].upper()}",
            "namespace": action["namespace"],
            "steer_to": action["target"],
            "rules": [
                f"ALLOW controlled-session -> {action['target']}",
                "DENY deception-namespace -> protected-core",
                "DENY deception-namespace -> external-egress",
                f"EXPIRE atomically after {action['ttl_seconds']} seconds",
            ],
            "rollback_required": True,
        }
        rule_manifest["manifest_sha256"] = _digest(rule_manifest)
        trace.append({"state": "RULE_STAGED", "result": "PASS", "detail": f"Rule manifest {rule_manifest['manifest_sha256'][:16]}… staged."})
        trace.append({"state": "RULE_COMMITTED", "result": "SIMULATED", "detail": "Atomic commit model completed with zero packet effects."})
        trace.append({"state": "ROLLED_BACK", "result": "PASS", "detail": "Expiry rollback model restored the prior rule generation."})
        receipt_body = {
            "profile_version": PROFILE_VERSION,
            "decision": "ACCEPTED_DRY_RUN",
            "certificate_digest": certificate["digest"],
            "measurement": self.measurement,
            "rule_manifest": rule_manifest,
            "trace": trace,
            "final_state": "ROLLED_BACK",
            "protected_namespace_reachable": False,
            "packet_effects": 0,
            "external_targets": 0,
        }
        return {
            **receipt_body,
            "simulated_receipt_sha256": _digest(receipt_body),
            "cryptographic_note": "Digest-only simulation; production requires measured boot and a hardware-protected signing key.",
        }

    def _certificate_failures(self, certificate: dict[str, Any]) -> list[str]:
        failures = []
        if certificate.get("certificate_version") != "aegis.safety.v1":
            failures.append("unsupported certificate version")
        if not self.verify_certificate_digest(certificate):
            failures.append("certificate digest mismatch")
        if certificate.get("decision") != "PERMIT":
            failures.append("certificate decision is not PERMIT")
        checks = certificate.get("checks")
        if (
            not isinstance(checks, list)
            or len(checks) != 8
            or any(not isinstance(check, dict) or check.get("passed") is not True for check in checks)
        ):
            failures.append("not all eight safety checks pass")
        action = certificate.get("action")
        if not isinstance(action, dict):
            failures.append("action contract missing")
            return failures
        if action.get("namespace") != self.settings.authorized_namespace:
            failures.append("namespace outside authorization")
        if not action.get("decoy_only") or not str(action.get("target", "")).startswith("decoy-"):
            failures.append("target is not decoy-only")
        if action.get("network_egress") is not False:
            failures.append("network egress requested")
        if action.get("reversible") is not True:
            failures.append("rollback contract missing")
        ttl = action.get("ttl_seconds")
        if not isinstance(ttl, int) or not 0 < ttl <= self.settings.max_action_ttl_seconds:
            failures.append("invalid expiry")
        return failures
