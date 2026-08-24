from __future__ import annotations

import math
from collections.abc import Mapping


HYPOTHESES = (
    "Reconnaissance",
    "Credential Access",
    "Lateral Movement",
    "Collection",
)

EVENT_LIKELIHOODS: dict[str, dict[str, float]] = {
    "network_scan": {
        "Reconnaissance": 0.80,
        "Credential Access": 0.10,
        "Lateral Movement": 0.07,
        "Collection": 0.03,
    },
    "ssh_login_failure": {
        "Reconnaissance": 0.18,
        "Credential Access": 0.65,
        "Lateral Movement": 0.14,
        "Collection": 0.03,
    },
    "admin_route_probe": {
        "Reconnaissance": 0.33,
        "Credential Access": 0.46,
        "Lateral Movement": 0.15,
        "Collection": 0.06,
    },
    "synthetic_credential_opened": {
        "Reconnaissance": 0.05,
        "Credential Access": 0.72,
        "Lateral Movement": 0.16,
        "Collection": 0.07,
    },
    "decoy_service_pivot": {
        "Reconnaissance": 0.04,
        "Credential Access": 0.13,
        "Lateral Movement": 0.75,
        "Collection": 0.08,
    },
    "synthetic_archive_requested": {
        "Reconnaissance": 0.02,
        "Credential Access": 0.06,
        "Lateral Movement": 0.15,
        "Collection": 0.77,
    },
}


def uniform_prior() -> dict[str, float]:
    return {name: 1.0 / len(HYPOTHESES) for name in HYPOTHESES}


def update_beliefs(prior: Mapping[str, float], event_type: str) -> dict[str, float]:
    likelihood = EVENT_LIKELIHOODS.get(event_type)
    if likelihood is None:
        return normalize(prior)

    log_scores: dict[str, float] = {}
    for hypothesis in HYPOTHESES:
        p = max(float(prior.get(hypothesis, 0.0)), 1e-9)
        l = max(float(likelihood[hypothesis]), 1e-9)
        log_scores[hypothesis] = math.log(p) + math.log(l)

    maximum = max(log_scores.values())
    scores = {key: math.exp(value - maximum) for key, value in log_scores.items()}
    return normalize(scores)


def normalize(values: Mapping[str, float]) -> dict[str, float]:
    total = sum(max(float(v), 0.0) for v in values.values())
    if total <= 0:
        return uniform_prior()
    return {name: max(float(values.get(name, 0.0)), 0.0) / total for name in HYPOTHESES}


def summarize(beliefs: Mapping[str, float]) -> dict[str, object]:
    normalized = normalize(beliefs)
    ordered = sorted(normalized.items(), key=lambda item: item[1], reverse=True)
    entropy = -sum(p * math.log2(p) for p in normalized.values() if p > 0)
    max_entropy = math.log2(len(HYPOTHESES))
    confidence = 1.0 - (entropy / max_entropy if max_entropy else 0.0)
    return {
        "top_hypothesis": ordered[0][0],
        "top_probability": round(ordered[0][1], 4),
        "confidence": round(confidence, 4),
        "entropy_bits": round(entropy, 4),
        "distribution": [
            {"name": name, "probability": round(probability, 4)}
            for name, probability in ordered
        ],
    }
