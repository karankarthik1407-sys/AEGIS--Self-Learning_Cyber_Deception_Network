from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


TECHNIQUES: dict[str, dict[str, str]] = {
    "network_scan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "ssh_login_failure": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "admin_route_probe": {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    "synthetic_credential_opened": {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
    "decoy_service_pivot": {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    "synthetic_archive_requested": {"id": "T1560", "name": "Archive Collected Data", "tactic": "Collection"},
}


@dataclass(frozen=True)
class CaseFeatures:
    case_id: str
    technique_ids: tuple[str, ...]
    event_types: tuple[str, ...]
    target_families: tuple[str, ...]
    fingerprints: tuple[str, ...]


def technique_for(event_type: str) -> dict[str, str]:
    return TECHNIQUES.get(
        event_type,
        {"id": "UNMAPPED", "name": "Unmapped authorized-range observation", "tactic": "Unmapped"},
    )


def extract_features(case_id: str, events: list[dict[str, Any]]) -> CaseFeatures:
    techniques = tuple(technique_for(event["event_type"])["id"] for event in events)
    targets = tuple(_target_family(event["target"]) for event in events)
    fingerprints = tuple(
        str(event["payload"].get("client_fingerprint"))
        for event in events
        if event["payload"].get("client_fingerprint")
    )
    return CaseFeatures(
        case_id=case_id,
        technique_ids=techniques,
        event_types=tuple(event["event_type"] for event in events),
        target_families=targets,
        fingerprints=fingerprints,
    )


def compare_cases(left: CaseFeatures, right: CaseFeatures) -> dict[str, Any]:
    technique_overlap = _jaccard(set(left.technique_ids), set(right.technique_ids))
    target_overlap = _jaccard(set(left.target_families), set(right.target_families))
    sequence_similarity = _sequence_similarity(left.event_types, right.event_types)
    fingerprint_overlap = _jaccard(set(left.fingerprints), set(right.fingerprints)) if left.fingerprints and right.fingerprints else 0.0
    confidence = (
        0.45 * technique_overlap
        + 0.25 * sequence_similarity
        + 0.15 * target_overlap
        + 0.15 * fingerprint_overlap
    )
    confidence = round(confidence, 4)
    strength = "high" if confidence >= 0.72 else "moderate" if confidence >= 0.48 else "low"
    shared_techniques = sorted(set(left.technique_ids) & set(right.technique_ids))
    return {
        "left_case_id": left.case_id,
        "right_case_id": right.case_id,
        "confidence": confidence,
        "strength": strength,
        "scores": {
            "technique_overlap": round(technique_overlap, 4),
            "sequence_similarity": round(sequence_similarity, 4),
            "target_overlap": round(target_overlap, 4),
            "fingerprint_overlap": round(fingerprint_overlap, 4),
        },
        "supporting_evidence": [
            f"Shared ATT&CK technique {technique_id}"
            for technique_id in shared_techniques
        ],
        "limitations": [
            "Similarity can be caused by common tools or copied playbooks.",
            "The score supports campaign triage, not identification of a human or state actor.",
        ],
        "attribution_status": "UNVERIFIED — CAMPAIGN LINKAGE ONLY",
    }


def build_case_bundle(case: dict[str, Any], verification: dict[str, Any]) -> dict[str, Any]:
    mapped_events = []
    for event in reversed(case.get("events", [])):
        mapped_events.append({**event, "attack_mapping": technique_for(event["event_type"])})
    body = {
        "bundle_version": "aegis.investigation.v1",
        "scope": "Authorized defensive investigation",
        "case": {key: value for key, value in case.items() if key != "events"},
        "events": mapped_events,
        "evidence_verification": verification,
        "language_boundary": "Campaign linkage is not proof of real-world identity or state attribution.",
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
    return body


def _target_family(target: str) -> str:
    for family in ("edge", "bastion", "admin", "inventory", "finance", "identity"):
        if family in target:
            return family
    return "other"


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _sequence_similarity(left: tuple[str, ...], right: tuple[str, ...]) -> float:
    if not left or not right:
        return 0.0
    rows = len(left) + 1
    cols = len(right) + 1
    matrix = [[0] * cols for _ in range(rows)]
    for i, left_item in enumerate(left, start=1):
        for j, right_item in enumerate(right, start=1):
            if left_item == right_item:
                matrix[i][j] = matrix[i - 1][j - 1] + 1
            else:
                matrix[i][j] = max(matrix[i - 1][j], matrix[i][j - 1])
    return matrix[-1][-1] / max(len(left), len(right))

