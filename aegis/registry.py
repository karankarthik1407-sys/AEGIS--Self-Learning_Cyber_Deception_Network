from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from .evidence import GENESIS_HASH
from .models import utc_now
from .store import AegisStore


ARTIFACT_ATTESTATION_VERSION = "aegis.local-artifact-attestation.v1"
PROMOTION_LEDGER_VERSION = "aegis.promotion-ledger.v1"
ALLOWED_ARTIFACT_TYPES = {"dataset", "model", "policy", "evaluator", "rollback"}
ALLOWED_ARTIFACT_STATUS = {
    "RESEARCH",
    "BASELINE",
    "SHADOW",
    "CHAMPION",
    "RETIRED",
    "REJECTED",
}
ALLOWED_DECISIONS = {
    "HOLD_SHADOW",
    "REJECT_CANDIDATE",
    "ELIGIBLE_FOR_SIGNED_RELEASE",
    "ROLLBACK_REQUIRED",
}
ARTIFACT_PREFIX = {
    "dataset": "DST",
    "model": "MDL",
    "policy": "POL",
    "evaluator": "EVL",
    "rollback": "RBK",
}


class RegistryValidationError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise RegistryValidationError("value is not bounded canonical JSON") from error


def _bounded_text(value: Any, label: str, maximum: int) -> str:
    text = str(value).strip()
    if not text or len(text) > maximum or any(ord(character) < 32 for character in text):
        raise RegistryValidationError(f"invalid {label}")
    return text


class ArtifactGovernanceRegistry:
    """Per-install artifact attestation and append-only promotion evidence.

    HMAC provides local integrity/authenticity under a key held by this AEGIS
    installation. It is deliberately not described as a public-key signature,
    third-party timestamp or non-repudiation mechanism.
    """

    def __init__(self, store: AegisStore, key_path: Path | None = None):
        self.store = store
        self.key_path = Path(key_path or store.database_path.parent / "registry.key")
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self._key = self._load_or_create_key()
        self.key_id = "LOCAL-" + hashlib.sha256(self._key).hexdigest()[:12].upper()

    def _load_or_create_key(self) -> bytes:
        if self.key_path.is_file():
            key = self.key_path.read_bytes()
            if len(key) >= 32:
                return key
            raise RuntimeError(f"AEGIS registry key is invalid: {self.key_path}")
        key = secrets.token_bytes(32)
        try:
            descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(key)
        except FileExistsError:
            raced_key = self.key_path.read_bytes()
            if len(raced_key) < 32:
                raise RuntimeError(f"AEGIS registry key is invalid: {self.key_path}")
            return raced_key
        return key

    def _attest(self, value: Any) -> str:
        return hmac.new(self._key, _canonical(value), hashlib.sha256).hexdigest()

    def register_artifact(
        self,
        artifact_type: str,
        name: str,
        version: str,
        descriptor: dict[str, Any],
        *,
        lineage: Iterable[str] = (),
        status: str = "RESEARCH",
    ) -> dict[str, Any]:
        artifact_type = _bounded_text(artifact_type, "artifact type", 32).lower()
        if artifact_type not in ALLOWED_ARTIFACT_TYPES:
            raise RegistryValidationError("unsupported artifact type")
        name = _bounded_text(name, "artifact name", 120)
        version = _bounded_text(version, "artifact version", 64)
        status = _bounded_text(status, "artifact status", 32).upper()
        if status not in ALLOWED_ARTIFACT_STATUS:
            raise RegistryValidationError("unsupported artifact status")
        if not isinstance(descriptor, dict):
            raise RegistryValidationError("artifact descriptor must be an object")
        descriptor_bytes = _canonical(descriptor)
        if len(descriptor_bytes) > 65_536:
            raise RegistryValidationError("artifact descriptor exceeds 64 KiB")
        lineage_ids = tuple(dict.fromkeys(_bounded_text(value, "lineage id", 40) for value in lineage))
        for parent_id in lineage_ids:
            if self.get_artifact(parent_id) is None:
                raise RegistryValidationError(f"unknown lineage artifact: {parent_id}")

        descriptor_sha256 = hashlib.sha256(descriptor_bytes).hexdigest()
        identity = {
            "artifact_type": artifact_type,
            "name": name,
            "version": version,
            "descriptor_sha256": descriptor_sha256,
            "lineage": list(lineage_ids),
        }
        artifact_id = ARTIFACT_PREFIX[artifact_type] + "-" + hashlib.sha256(
            _canonical(identity)
        ).hexdigest()[:20].upper()
        existing = self.get_artifact(artifact_id)
        if existing is not None:
            if not self.verify_artifact(existing)["valid"]:
                raise RegistryValidationError("existing artifact attestation is invalid")
            return existing

        created_at = utc_now()
        attestation_payload = {
            "contract": ARTIFACT_ATTESTATION_VERSION,
            "artifact_id": artifact_id,
            **identity,
            "status": status,
            "created_at": created_at,
            "key_id": self.key_id,
        }
        attestation = self._attest(attestation_payload)
        collided = False
        with self.store.connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO artifact_registry
                       (artifact_id, artifact_type, name, version, status,
                        created_at, descriptor_sha256, key_id, attestation,
                        descriptor_json, lineage_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        artifact_id,
                        artifact_type,
                        name,
                        version,
                        status,
                        created_at,
                        descriptor_sha256,
                        self.key_id,
                        attestation,
                        descriptor_bytes.decode("utf-8"),
                        json.dumps(lineage_ids),
                    ),
                )
            except sqlite3.IntegrityError:
                collided = True
        artifact = self.get_artifact(artifact_id)
        if artifact is None:
            raise RuntimeError("artifact registration failed")
        if collided and not self.verify_artifact(artifact)["valid"]:
            raise RegistryValidationError("artifact registration conflict")
        return artifact

    def get_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifact_registry WHERE artifact_id=?", (artifact_id,)
            ).fetchone()
        return self._artifact_row(row) if row else None

    def list_artifacts(self) -> list[dict[str, Any]]:
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM artifact_registry ORDER BY created_at, artifact_id"
            ).fetchall()
        return [self._artifact_row(row) for row in rows]

    def verify_artifact(self, artifact: dict[str, Any] | str) -> dict[str, Any]:
        value = self.get_artifact(artifact) if isinstance(artifact, str) else artifact
        if value is None:
            return {"valid": False, "reason": "ARTIFACT_NOT_FOUND"}
        try:
            descriptor_sha256 = hashlib.sha256(_canonical(value["descriptor"])).hexdigest()
            identity = {
                "artifact_type": value["artifact_type"],
                "name": value["name"],
                "version": value["version"],
                "descriptor_sha256": descriptor_sha256,
                "lineage": list(value["lineage"]),
            }
            expected_id = ARTIFACT_PREFIX[value["artifact_type"]] + "-" + hashlib.sha256(
                _canonical(identity)
            ).hexdigest()[:20].upper()
            payload = {
                "contract": ARTIFACT_ATTESTATION_VERSION,
                "artifact_id": value["artifact_id"],
                **identity,
                "status": value["status"],
                "created_at": value["created_at"],
                "key_id": value["key_id"],
            }
            expected_attestation = self._attest(payload)
            checks = {
                "descriptor_digest": hmac.compare_digest(
                    descriptor_sha256, value["descriptor_sha256"]
                ),
                "artifact_identity": hmac.compare_digest(expected_id, value["artifact_id"]),
                "key_id": hmac.compare_digest(value["key_id"], self.key_id),
                "attestation": hmac.compare_digest(expected_attestation, value["attestation"]),
            }
        except (KeyError, TypeError, RegistryValidationError):
            return {"artifact_id": value.get("artifact_id"), "valid": False, "reason": "MALFORMED_ARTIFACT"}
        return {
            "artifact_id": value["artifact_id"],
            "valid": all(checks.values()),
            "checks": checks,
        }

    def verify_registry(self) -> dict[str, Any]:
        artifacts = self.list_artifacts()
        results = [self.verify_artifact(artifact) for artifact in artifacts]
        return {
            "valid": all(result["valid"] for result in results),
            "verified": sum(result["valid"] for result in results),
            "artifacts": len(artifacts),
            "results": results,
        }

    def evaluate_candidate(
        self,
        candidate_artifact_id: str,
        champion_artifact_id: str | None,
        *,
        shadow_observations: int = 0,
        human_release_signoff: bool = False,
        enterprise_validation: bool = False,
        rollback_artifact_id: str | None = None,
        actor: str = "SYSTEM",
        ignored_request_fields: Iterable[str] = (),
    ) -> dict[str, Any]:
        candidate = self.get_artifact(candidate_artifact_id)
        if candidate is None:
            raise RegistryValidationError("candidate artifact not found")
        if champion_artifact_id and self.get_artifact(champion_artifact_id) is None:
            raise RegistryValidationError("champion artifact not found")
        verification = self.verify_artifact(candidate)
        lineage_verified = bool(candidate["lineage"]) and all(
            self.verify_artifact(parent_id)["valid"] for parent_id in candidate["lineage"]
        )
        descriptor = candidate["descriptor"]
        quality_checks = [
            self._check("model_artifact", candidate["artifact_type"] == "model", candidate["artifact_type"], "model"),
            self._check("artifact_attestation", verification["valid"], verification["valid"], "valid local attestation"),
            self._check("lineage_verified", lineage_verified, lineage_verified, "at least one valid registered parent"),
            self._check("grouped_validation", descriptor.get("grouped_validation") is True, descriptor.get("grouped_validation"), "true"),
            self._check("quality_gate", descriptor.get("quality_gate_passed") is True, descriptor.get("quality_gate_passed"), "true"),
            self._check("safety_regression", int(descriptor.get("safety_violations", -1)) == 0, descriptor.get("safety_violations"), "0"),
            self._check("external_targets", int(descriptor.get("external_targets", -1)) == 0, descriptor.get("external_targets"), "0"),
        ]
        release_checks = [
            self._check("enterprise_validation", bool(enterprise_validation), bool(enterprise_validation), "approved authorized enterprise study"),
            self._check("shadow_volume", int(shadow_observations) >= 10_000, int(shadow_observations), ">= 10,000 authorized observations"),
            self._check("human_release_signoff", bool(human_release_signoff), bool(human_release_signoff), "offline named reviewer signature"),
            self._check("rollback_artifact", bool(rollback_artifact_id and self.get_artifact(rollback_artifact_id)), rollback_artifact_id or False, "registered rollback artifact"),
        ]
        quality_passed = all(check["passed"] for check in quality_checks)
        release_ready = all(check["passed"] for check in release_checks)
        decision = (
            "REJECT_CANDIDATE"
            if not quality_passed
            else "ELIGIBLE_FOR_SIGNED_RELEASE"
            if release_ready
            else "HOLD_SHADOW"
        )
        return self.append_decision(
            candidate_artifact_id,
            champion_artifact_id,
            decision,
            quality_checks + release_checks,
            {
                "actor": _bounded_text(actor, "decision actor", 64),
                "automatic_promotion": False,
                "request_fields_ignored": sorted(set(map(str, ignored_request_fields))),
                "attestation_scope": "per-install HMAC; not external code signing",
            },
        )

    def append_decision(
        self,
        candidate_artifact_id: str,
        champion_artifact_id: str | None,
        decision: str,
        checks: list[dict[str, Any]],
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        decision = _bounded_text(decision, "promotion decision", 48).upper()
        if decision not in ALLOWED_DECISIONS:
            raise RegistryValidationError("unsupported promotion decision")
        if self.get_artifact(candidate_artifact_id) is None:
            raise RegistryValidationError("candidate artifact not found")
        decision_id = "DEC-" + uuid4().hex[:20].upper()
        created_at = utc_now()
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT record_hash FROM promotion_ledger ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous["record_hash"] if previous else GENESIS_HASH
            payload = {
                "contract": PROMOTION_LEDGER_VERSION,
                "decision_id": decision_id,
                "created_at": created_at,
                "candidate_artifact_id": candidate_artifact_id,
                "champion_artifact_id": champion_artifact_id,
                "decision": decision,
                "checks": checks,
                "evidence": evidence,
                "previous_hash": previous_hash,
            }
            record_hash = hashlib.sha256(_canonical(payload)).hexdigest()
            attestation_payload = {
                "contract": PROMOTION_LEDGER_VERSION,
                "record_hash": record_hash,
                "key_id": self.key_id,
            }
            attestation = self._attest(attestation_payload)
            connection.execute(
                """INSERT INTO promotion_ledger
                   (decision_id, created_at, candidate_artifact_id,
                    champion_artifact_id, decision, previous_hash, record_hash,
                    key_id, attestation, record_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    decision_id,
                    created_at,
                    candidate_artifact_id,
                    champion_artifact_id,
                    decision,
                    previous_hash,
                    record_hash,
                    self.key_id,
                    attestation,
                    _canonical(payload).decode("utf-8"),
                ),
            )
        return self.list_decisions(limit=1)[0]

    def list_decisions(self, limit: int = 100) -> list[dict[str, Any]]:
        safe_limit = min(max(int(limit), 1), 500)
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM promotion_ledger ORDER BY sequence DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [self._decision_row(row) for row in rows]

    def verify_ledger(self, records: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        if records is None:
            with self.store.connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM promotion_ledger ORDER BY sequence ASC"
                ).fetchall()
            values = [self._decision_row(row) for row in rows]
        else:
            values = sorted(records, key=lambda value: int(value["sequence"]))
        previous_hash = GENESIS_HASH
        results = []
        for value in values:
            try:
                payload = value["record"]
                expected_hash = hashlib.sha256(_canonical(payload)).hexdigest()
                expected_attestation = self._attest(
                    {
                        "contract": PROMOTION_LEDGER_VERSION,
                        "record_hash": expected_hash,
                        "key_id": self.key_id,
                    }
                )
                checks = {
                    "previous_hash": hmac.compare_digest(payload["previous_hash"], previous_hash),
                    "record_hash": hmac.compare_digest(expected_hash, value["record_hash"]),
                    "column_consistency": all(
                        value[key] == payload[key]
                        for key in (
                            "decision_id",
                            "created_at",
                            "candidate_artifact_id",
                            "champion_artifact_id",
                            "decision",
                            "previous_hash",
                        )
                    ),
                    "key_id": hmac.compare_digest(value["key_id"], self.key_id),
                    "attestation": hmac.compare_digest(value["attestation"], expected_attestation),
                }
            except (KeyError, TypeError, RegistryValidationError):
                checks = {"malformed_record": False}
            valid = all(checks.values())
            results.append(
                {
                    "sequence": value.get("sequence"),
                    "decision_id": value.get("decision_id"),
                    "valid": valid,
                    "checks": checks,
                }
            )
            previous_hash = value.get("record_hash", "")
        return {
            "valid": all(result["valid"] for result in results),
            "records": len(values),
            "chain_head": previous_hash,
            "results": results,
        }

    def status(self) -> dict[str, Any]:
        artifacts = self.list_artifacts()
        decisions = self.list_decisions()
        return {
            "contract_version": ARTIFACT_ATTESTATION_VERSION,
            "ledger_version": PROMOTION_LEDGER_VERSION,
            "key_id": self.key_id,
            "attestation": {
                "method": "HMAC-SHA256",
                "scope": "per-install local integrity and authenticity",
                "external_digital_signature": False,
                "non_repudiation": False,
                "production_requirement": "platform code signing plus organization release signature",
            },
            "artifacts": artifacts,
            "artifact_summary": {
                "total": len(artifacts),
                "by_type": {
                    artifact_type: sum(
                        artifact["artifact_type"] == artifact_type for artifact in artifacts
                    )
                    for artifact_type in sorted(ALLOWED_ARTIFACT_TYPES)
                },
            },
            "registry_verification": self.verify_registry(),
            "decisions": decisions,
            "ledger_verification": self.verify_ledger(),
            "promotion_policy": {
                "automatic_weight_updates": False,
                "api_can_create_human_signoff": False,
                "api_can_override_shadow_volume": False,
                "required_release_evidence": [
                    "valid artifact and lineage attestations",
                    "grouped quality and safety gates",
                    "authorized enterprise validation",
                    "10,000 authorized shadow observations",
                    "offline named reviewer signature",
                    "registered rollback artifact",
                    "separate signed release transaction",
                ],
            },
        }

    @staticmethod
    def _check(rule: str, passed: bool, observed: Any, required: str) -> dict[str, Any]:
        return {"rule": rule, "passed": bool(passed), "observed": observed, "required": required}

    @staticmethod
    def _artifact_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "artifact_id": row["artifact_id"],
            "artifact_type": row["artifact_type"],
            "name": row["name"],
            "version": row["version"],
            "status": row["status"],
            "created_at": row["created_at"],
            "descriptor_sha256": row["descriptor_sha256"],
            "key_id": row["key_id"],
            "attestation": row["attestation"],
            "descriptor": json.loads(row["descriptor_json"]),
            "lineage": json.loads(row["lineage_json"]),
        }

    @staticmethod
    def _decision_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "sequence": row["sequence"],
            "decision_id": row["decision_id"],
            "created_at": row["created_at"],
            "candidate_artifact_id": row["candidate_artifact_id"],
            "champion_artifact_id": row["champion_artifact_id"],
            "decision": row["decision"],
            "previous_hash": row["previous_hash"],
            "record_hash": row["record_hash"],
            "key_id": row["key_id"],
            "attestation": row["attestation"],
            "record": json.loads(row["record_json"]),
        }
