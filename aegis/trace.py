from __future__ import annotations

import hashlib
import ipaddress
import json
import math
from dataclasses import dataclass
from typing import Any, Iterable

from .investigation import technique_for
from .models import utc_now


TRACE_CONTRACT_VERSION = "aegis.threat-trace.v1"
TRACE_CALIBRATION_VERSION = "synthetic-pair-calibration-v1"
IDENTITY_BOUNDARY = (
    "AEGIS estimates whether authorized observations belong to one activity "
    "cluster. It does not identify a human, organization, or state."
)


@dataclass(frozen=True)
class SignalFamily:
    id: str
    label: str
    weight: float
    reliability: float
    spoofability: float
    meaning: str

    @property
    def effective_weight(self) -> float:
        return self.weight * self.reliability * (1.0 - 0.5 * self.spoofability)


SIGNAL_FAMILIES: tuple[SignalFamily, ...] = (
    SignalFamily(
        "source",
        "Source context",
        0.06,
        0.45,
        0.78,
        "Pseudonymous source reference only; rotation, NAT, VPNs and compromised relays are expected.",
    ),
    SignalFamily(
        "infrastructure",
        "Infrastructure context",
        0.13,
        0.58,
        0.58,
        "Pseudonymous provider, ASN, domain-cluster or certificate relationships.",
    ),
    SignalFamily(
        "transport",
        "Transport profile",
        0.20,
        0.78,
        0.34,
        "TLS, SSH or other client-transport characteristics retained as approved references.",
    ),
    SignalFamily(
        "tooling",
        "Tooling profile",
        0.17,
        0.68,
        0.46,
        "Client, user-agent or toolchain references that may be shared or copied.",
    ),
    SignalFamily(
        "behavior",
        "Behaviour sequence",
        0.24,
        0.72,
        0.40,
        "Technique, target-family, route-choice and ordered-event similarity.",
    ),
    SignalFamily(
        "deception",
        "Deception response",
        0.20,
        0.90,
        0.14,
        "Shared response to a controlled lure or canary family inside the authorized range.",
    ),
)

FAMILY_BY_ID = {family.id: family for family in SIGNAL_FAMILIES}

FIELD_FAMILIES: dict[str, tuple[str, ...]] = {
    "source": ("source_ref",),
    "infrastructure": (
        "provider_ref",
        "asn_ref",
        "domain_cluster_ref",
        "certificate_ref",
    ),
    "transport": (
        "transport_fingerprint",
        "tls_client_ref",
        "ssh_client_ref",
    ),
    "tooling": (
        "client_fingerprint",
        "toolchain_ref",
        "user_agent_ref",
    ),
    "deception": (
        "lure_family_ref",
        "canary_family_ref",
    ),
}


@dataclass(frozen=True)
class TraceProfile:
    session_id: str
    signals: dict[str, frozenset[str]]
    event_types: tuple[str, ...]
    first_seen: str | None
    last_seen: str | None
    event_count: int

    def canonical(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "signals": {
                family.id: sorted(self.signals.get(family.id, frozenset()))
                for family in SIGNAL_FAMILIES
            },
            "event_types": list(self.event_types),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
        }


def _bounded_reference(value: Any, maximum: int = 160) -> str | None:
    if not isinstance(value, (str, int, float)):
        return None
    normalized = str(value).strip().lower()
    if not normalized or len(normalized) > maximum:
        return None
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        return normalized
    # The trace layer accepts opaque, adapter-produced references only. Reject
    # an address even if it was placed in the wrong field by a faulty adapter.
    return None


def _source_reference(value: Any) -> str | None:
    # Kept as a distinct contract hook so a future deployment can require a
    # signed pseudonymization envelope in addition to the global raw-IP refusal.
    return _bounded_reference(value)


def _values(payload: dict[str, Any], field: str) -> Iterable[Any]:
    value = payload.get(field)
    if isinstance(value, (list, tuple, set)):
        return value
    return () if value is None else (value,)


def extract_trace_profile(session_id: str, events: list[dict[str, Any]]) -> TraceProfile:
    signals: dict[str, set[str]] = {family.id: set() for family in SIGNAL_FAMILIES}
    event_types: list[str] = []
    timestamps: list[str] = []

    for event in events:
        event_type = str(event.get("event_type", "unknown"))
        event_types.append(event_type)
        timestamp = event.get("timestamp")
        if isinstance(timestamp, str) and timestamp:
            timestamps.append(timestamp)
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}

        for family_id, fields in FIELD_FAMILIES.items():
            for field in fields:
                for raw_value in _values(payload, field):
                    reference = (
                        _source_reference(raw_value)
                        if family_id == "source"
                        else _bounded_reference(raw_value)
                    )
                    if reference is not None:
                        signals[family_id].add(f"{field}:{reference}")

        technique = technique_for(event_type)["id"]
        signals["behavior"].add(f"technique:{technique.lower()}")
        signals["behavior"].add(f"event:{event_type.lower()}")
        target = _bounded_reference(event.get("target"))
        if target:
            for family in ("edge", "bastion", "admin", "inventory", "finance", "identity"):
                if family in target:
                    signals["behavior"].add(f"target-family:{family}")
                    break
        routes = payload.get("routes")
        if isinstance(routes, list):
            for route in routes[:12]:
                normalized_route = _bounded_reference(route, maximum=100)
                if normalized_route:
                    signals["behavior"].add(f"route:{normalized_route}")

    return TraceProfile(
        session_id=session_id,
        signals={family.id: frozenset(signals[family.id]) for family in SIGNAL_FAMILIES},
        event_types=tuple(event_types),
        first_seen=min(timestamps) if timestamps else None,
        last_seen=max(timestamps) if timestamps else None,
        event_count=len(events),
    )


def _jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _sequence_similarity(left: tuple[str, ...], right: tuple[str, ...]) -> float:
    if not left or not right:
        return 0.0
    previous = [0] * (len(right) + 1)
    for left_item in left:
        current = [0]
        for index, right_item in enumerate(right, start=1):
            current.append(
                previous[index - 1] + 1
                if left_item == right_item
                else max(previous[index], current[-1])
            )
        previous = current
    return previous[-1] / max(len(left), len(right))


class EvidenceDiversityLinker:
    """Correlates activity while preventing any one easy-to-spoof signal from dominating."""

    def __init__(self, calibration_slope: float = 7.0, calibration_center: float = 0.50):
        self.calibration_slope = float(calibration_slope)
        self.calibration_center = float(calibration_center)

    def raw_score(self, left: TraceProfile, right: TraceProfile) -> dict[str, Any]:
        available_weight = 0.0
        matched_weight = 0.0
        family_results = []
        matched_families = []
        divergent_families = []

        for family in SIGNAL_FAMILIES:
            left_values = left.signals.get(family.id, frozenset())
            right_values = right.signals.get(family.id, frozenset())
            available = bool(left_values and right_values)
            similarity = _jaccard(left_values, right_values) if available else 0.0
            sequence_similarity = None
            if family.id == "behavior" and available:
                sequence_similarity = _sequence_similarity(left.event_types, right.event_types)
                similarity = 0.65 * similarity + 0.35 * sequence_similarity
            if available:
                available_weight += family.effective_weight
                matched_weight += family.effective_weight * similarity
            shared_values = sorted(left_values & right_values)
            matched = available and similarity >= 0.28
            divergent = available and similarity == 0.0
            if matched:
                matched_families.append(family.id)
            if divergent:
                divergent_families.append(family.id)
            family_results.append({
                "family": family.id,
                "label": family.label,
                "available": available,
                "similarity": round(similarity, 4),
                "sequence_similarity": round(sequence_similarity, 4) if sequence_similarity is not None else None,
                "shared_values": shared_values[:8],
                "matched": matched,
                "divergent": divergent,
                "weight": family.weight,
                "reliability": family.reliability,
                "spoofability": family.spoofability,
            })

        evidence_score = matched_weight / available_weight if available_weight else 0.0
        diversity_bonus = min(0.10, max(0, len(matched_families) - 1) * 0.025)
        contradiction_penalty = sum(
            0.012 if family_id == "source" else 0.04
            for family_id in divergent_families
        )
        raw = min(1.0, max(0.0, evidence_score + diversity_bonus - contradiction_penalty))
        return {
            "raw_score": round(raw, 6),
            "evidence_score": round(evidence_score, 6),
            "diversity_bonus": round(diversity_bonus, 6),
            "contradiction_penalty": round(contradiction_penalty, 6),
            "matched_families": matched_families,
            "divergent_families": divergent_families,
            "family_results": family_results,
        }

    def probability(self, raw_score: float) -> float:
        value = 1.0 / (
            1.0 + math.exp(-self.calibration_slope * (float(raw_score) - self.calibration_center))
        )
        return value

    def compare(self, left: TraceProfile, right: TraceProfile) -> dict[str, Any]:
        score = self.raw_score(left, right)
        matched_count = len(score["matched_families"])
        probability = self.probability(score["raw_score"])
        # Diversity gates prevent one IP, certificate or fingerprint from creating
        # a high-confidence activity link by itself.
        if matched_count < 2:
            probability = min(probability, 0.49)
        elif matched_count < 3:
            probability = min(probability, 0.69)
        probability = round(probability, 4)
        strength = (
            "HIGH"
            if probability >= 0.75 and matched_count >= 3
            else "MODERATE"
            if probability >= 0.50 and matched_count >= 2
            else "LOW"
        )
        supporting = [
            f"{result['label']}: {round(result['similarity'] * 100)}% overlap"
            for result in score["family_results"]
            if result["matched"]
        ]
        alternatives = _alternative_explanations(score)
        return {
            "left_session_id": left.session_id,
            "right_session_id": right.session_id,
            "confidence": probability,
            "strength": strength,
            **score,
            "supporting_evidence": supporting,
            "alternative_explanations": alternatives,
            "calibration": {
                "version": TRACE_CALIBRATION_VERSION,
                "slope": self.calibration_slope,
                "center": self.calibration_center,
                "scope": "Synthetic grouped-pair research calibration; enterprise recalibration required.",
            },
            "attribution_status": "ACTIVITY LINKAGE ONLY — HUMAN IDENTITY NOT INFERRED",
            "identity_claim": False,
        }


def _alternative_explanations(score: dict[str, Any]) -> list[dict[str, str]]:
    matched = set(score["matched_families"])
    alternatives = []
    if matched & {"tooling", "transport"}:
        alternatives.append({
            "explanation": "Shared or copied tooling",
            "why_plausible": "Client and transport characteristics can be reused by unrelated operators.",
        })
    if matched & {"source", "infrastructure"}:
        alternatives.append({
            "explanation": "Shared infrastructure",
            "why_plausible": "NAT, VPN, hosting, proxies and compromised relays can serve unrelated activity.",
        })
    if "behavior" in matched:
        alternatives.append({
            "explanation": "Copied playbook or common objective",
            "why_plausible": "Similar route and technique choices do not prove common control.",
        })
    alternatives.append({
        "explanation": "Synthetic-range construction",
        "why_plausible": "Current demonstration evidence is generated inside one controlled research range.",
    })
    return alternatives


def build_trace_report(
    case_events: dict[str, list[dict[str, Any]]],
    linker: EvidenceDiversityLinker | None = None,
) -> dict[str, Any]:
    active_linker = linker or EvidenceDiversityLinker()
    profiles = {
        case_id: extract_trace_profile(case_id, events)
        for case_id, events in sorted(case_events.items())
    }
    links = []
    profile_values = list(profiles.values())
    for index, left in enumerate(profile_values):
        for right in profile_values[index + 1:]:
            links.append(active_linker.compare(left, right))
    links.sort(key=lambda link: link["confidence"], reverse=True)

    descriptor = {
        "contract_version": TRACE_CONTRACT_VERSION,
        "profiles": [profile.canonical() for profile in profile_values],
        "links": links,
    }
    trace_id = "TRACE-" + hashlib.sha256(
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16].upper()
    graph = _trace_graph(trace_id, profiles, links)
    timeline = []
    for case_id, events in sorted(case_events.items()):
        for event in events:
            payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
            timeline.append({
                "session_id": case_id,
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type"),
                "target": _bounded_reference(event.get("target")) or "redacted-unapproved-target",
                "source_ref": _source_reference(payload.get("source_ref")),
                "technique": technique_for(str(event.get("event_type", "unknown"))),
            })
    timeline.sort(key=lambda event: (event.get("timestamp") or "", event["session_id"]))

    leading = links[0] if links else None
    body = {
        "contract_version": TRACE_CONTRACT_VERSION,
        "trace_id": trace_id,
        "generated_at": utc_now(),
        "scope": "Authorized defensive activity correlation",
        "profiles": [profile.canonical() for profile in profile_values],
        "links": links,
        "leading_assessment": {
            "status": "RELATED_ACTIVITY_SUPPORTED" if leading and leading["strength"] != "LOW" else "INSUFFICIENT_EVIDENCE",
            "confidence": leading["confidence"] if leading else 0.0,
            "strength": leading["strength"] if leading else "LOW",
            "sessions": [leading["left_session_id"], leading["right_session_id"]] if leading else [],
            "human_identity": "NOT INFERRED",
        },
        "graph": graph,
        "timeline": timeline,
        "signal_catalog": [
            {
                "id": family.id,
                "label": family.label,
                "weight": family.weight,
                "reliability": family.reliability,
                "spoofability": family.spoofability,
                "meaning": family.meaning,
            }
            for family in SIGNAL_FAMILIES
        ],
        "source_policy": {
            "role": "context signal only",
            "raw_ip_accepted": False,
            "single_signal_high_confidence": False,
            "outbound_tracking": False,
            "external_scanning": False,
            "hack_back": False,
        },
        "standards_alignment": {
            "STIX_2_1": "Observed-data and relationship concepts; this export is not claimed as a complete STIX bundle.",
            "MITRE_ATTACK": "Behaviour nodes retain ATT&CK technique mappings.",
            "NIST_IR": "Supports authorized detection, analysis and evidence preservation activities.",
        },
        "identity_boundary": IDENTITY_BOUNDARY,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
    return body


def _trace_graph(
    trace_id: str,
    profiles: dict[str, TraceProfile],
    links: list[dict[str, Any]],
) -> dict[str, Any]:
    nodes = [{"id": trace_id, "kind": "cluster", "label": "Activity cluster"}]
    edges = []
    for profile in profiles.values():
        nodes.append({
            "id": profile.session_id,
            "kind": "session",
            "label": profile.session_id,
            "event_count": profile.event_count,
        })
        edges.append({"from": profile.session_id, "to": trace_id, "kind": "candidate-member"})
    if links:
        leading = links[0]
        for family_id in leading["matched_families"]:
            family = FAMILY_BY_ID[family_id]
            node_id = f"SIGNAL-{family_id.upper()}"
            nodes.append({"id": node_id, "kind": "signal", "label": family.label})
            for session_id in (leading["left_session_id"], leading["right_session_id"]):
                edges.append({"from": session_id, "to": node_id, "kind": "supports"})
    return {"nodes": nodes, "edges": edges}
