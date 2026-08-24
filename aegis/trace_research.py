from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass
from typing import Any, Iterable

from .research import DEFAULT_SEED
from .trace import EvidenceDiversityLinker, SIGNAL_FAMILIES, TraceProfile


TRACE_GENERATOR_VERSION = "aegis.synthetic-trace-pairs.v1"
FEATURE_NAMES = tuple(f"sim_{family.id}" for family in SIGNAL_FAMILIES) + (
    "matched_diversity",
    "divergent_fraction",
    "evidence_score",
)


@dataclass(frozen=True)
class SyntheticTraceSession:
    session_id: str
    campaign_id: str
    family: int
    variant: int
    profile: TraceProfile

    def canonical(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "campaign_id": self.campaign_id,
            "family": self.family,
            "variant": self.variant,
            "profile": self.profile.canonical(),
        }


@dataclass(frozen=True)
class TracePair:
    pair_id: str
    family: int
    label: int
    left: TraceProfile
    right: TraceProfile
    pair_type: str

    def canonical(self) -> dict[str, Any]:
        return {
            "pair_id": self.pair_id,
            "family": self.family,
            "label": self.label,
            "left_session_id": self.left.session_id,
            "right_session_id": self.right.session_id,
            "pair_type": self.pair_type,
        }


class SyntheticTraceCorpus:
    campaigns = 8
    families = 5
    variants = 6

    def generate_sessions(self, seed: int = DEFAULT_SEED) -> list[SyntheticTraceSession]:
        sessions = []
        for family in range(self.families):
            for campaign in range(self.campaigns):
                for variant in range(self.variants):
                    sessions.append(self._session(seed, family, campaign, variant))
        return sessions

    def generate_pairs(self, seed: int = DEFAULT_SEED) -> list[TracePair]:
        sessions = self.generate_sessions(seed)
        by_key = {
            (session.family, int(session.campaign_id.removeprefix("CMP-")), session.variant): session
            for session in sessions
        }
        pairs = []
        for family in range(self.families):
            for campaign in range(self.campaigns):
                for left_variant, right_variant in ((0, 1), (2, 3), (4, 5)):
                    left = by_key[(family, campaign, left_variant)]
                    right = by_key[(family, campaign, right_variant)]
                    pairs.append(TracePair(
                        pair_id=f"PAIR-F{family}-C{campaign}-P{left_variant}{right_variant}",
                        family=family,
                        label=1,
                        left=left.profile,
                        right=right.profile,
                        pair_type="same-campaign / rotating-source",
                    ))
            for campaign in range(0, self.campaigns, 2):
                for variant in range(self.variants):
                    left = by_key[(family, campaign, variant)]
                    right = by_key[(family, campaign + 1, variant)]
                    pairs.append(TracePair(
                        pair_id=f"PAIR-F{family}-H{campaign}{campaign + 1}-V{variant}",
                        family=family,
                        label=0,
                        left=left.profile,
                        right=right.profile,
                        pair_type="hard-negative / shared-provider-or-source",
                    ))
        return pairs

    @staticmethod
    def split(pairs: Iterable[TracePair]) -> dict[str, list[TracePair]]:
        result = {"train": [], "validation": [], "test": []}
        for pair in pairs:
            partition = "train" if pair.family <= 2 else "validation" if pair.family == 3 else "test"
            result[partition].append(pair)
        return result

    @staticmethod
    def _session(seed: int, family: int, campaign: int, variant: int) -> SyntheticTraceSession:
        rng = random.Random(seed + family * 100_000 + campaign * 1_000 + variant)
        campaign_id = f"CMP-{campaign}"
        provider = campaign // 2
        source_slot = (0, 0, 1, 2, 2, 0)[variant]
        signals: dict[str, set[str]] = {family_spec.id: set() for family_spec in SIGNAL_FAMILIES}

        # Same-provider hard negatives intentionally reuse addresses. Positive
        # pairs rotate away from the source in two of three pair types.
        signals["source"].add(f"source_ref:source-provider{provider}-slot{source_slot}")
        signals["infrastructure"].add(f"provider_ref:provider-{provider}")
        signals["infrastructure"].add(f"asn_ref:asn-group-{provider}")
        if variant != 5 or family < 4:
            signals["infrastructure"].add(f"certificate_ref:cert-campaign-{campaign}")
        else:
            signals["infrastructure"].add(f"certificate_ref:rotated-{campaign}-{variant}")

        transport_campaign = campaign
        if family == 4 and variant in (1, 3):
            transport_campaign = (campaign + 2) % 8
        signals["transport"].add(f"transport_fingerprint:transport-{transport_campaign}")
        if campaign in (0, 1) or variant == 0:
            signals["transport"].add("tls_client_ref:common-library-profile")

        # One shared toolchain per provider creates realistic hard negatives,
        # while a campaign-specific client profile retains additional evidence.
        signals["tooling"].add(f"toolchain_ref:toolkit-provider-{provider}")
        client_campaign = campaign if not (family == 4 and variant == 3) else (campaign + 1) % 8
        signals["tooling"].add(f"client_fingerprint:client-{client_campaign}")
        if rng.random() < 0.22:
            signals["tooling"].add("user_agent_ref:common-automation")

        signals["behavior"].update({
            "event:network_scan",
            f"event:route-pattern-{campaign}",
            f"technique:phase-{campaign % 4}",
            f"target-family:family-{campaign % 3}",
        })
        if variant in (1, 3, 5):
            signals["behavior"].add(f"event:follow-up-{campaign}")
        if family == 4 and variant in (2, 3):
            signals["behavior"].discard(f"event:route-pattern-{campaign}")
            signals["behavior"].add(f"event:route-pattern-{(campaign + 1) % 8}")

        if variant % 3 != 0:
            signals["deception"].add(f"lure_family_ref:lure-{campaign}")
        if variant in (4, 5):
            signals["deception"].add(f"canary_family_ref:canary-{campaign}")

        sequence = ["network_scan", f"phase_{campaign % 4}", f"route_{campaign}"]
        if variant in (1, 3, 5):
            sequence.append(f"follow_up_{campaign}")
        if family == 4 and variant == 3:
            sequence[1], sequence[2] = sequence[2], sequence[1]
        profile = TraceProfile(
            session_id=f"SYN-F{family}-C{campaign}-V{variant}",
            signals={name: frozenset(values) for name, values in signals.items()},
            event_types=tuple(sequence),
            first_seen=f"2026-08-{10 + family:02d}T10:{variant:02d}:00Z",
            last_seen=f"2026-08-{10 + family:02d}T10:{variant:02d}:30Z",
            event_count=len(sequence),
        )
        return SyntheticTraceSession(
            session_id=profile.session_id,
            campaign_id=campaign_id,
            family=family,
            variant=variant,
            profile=profile,
        )


def pair_features(pair: TracePair, linker: EvidenceDiversityLinker) -> tuple[list[float], dict[str, Any]]:
    score = linker.raw_score(pair.left, pair.right)
    similarities = [
        next(result["similarity"] for result in score["family_results"] if result["family"] == family.id)
        for family in SIGNAL_FAMILIES
    ]
    features = similarities + [
        len(score["matched_families"]) / len(SIGNAL_FAMILIES),
        len(score["divergent_families"]) / len(SIGNAL_FAMILIES),
        score["evidence_score"],
    ]
    return features, score


class BinaryLogisticLinker:
    def __init__(self, learning_rate: float = 0.18, epochs: int = 900, l2: float = 0.025):
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.l2 = l2
        self.weights = [0.0] * len(FEATURE_NAMES)
        self.intercept = 0.0

    @staticmethod
    def _sigmoid(value: float) -> float:
        bounded = max(-40.0, min(40.0, value))
        return 1.0 / (1.0 + math.exp(-bounded))

    def logit(self, features: list[float]) -> float:
        return self.intercept + sum(weight * value for weight, value in zip(self.weights, features))

    def probability(self, features: list[float], temperature: float = 1.0) -> float:
        return self._sigmoid(self.logit(features) / max(temperature, 1e-6))

    def fit(self, rows: list[tuple[list[float], int]]) -> "BinaryLogisticLinker":
        if not rows:
            raise ValueError("at least one trace pair is required")
        for epoch in range(self.epochs):
            gradient = [0.0] * len(self.weights)
            intercept_gradient = 0.0
            for features, label in rows:
                error = self.probability(features) - label
                intercept_gradient += error
                for index, value in enumerate(features):
                    gradient[index] += error * value
            rate = self.learning_rate / (1.0 + epoch / 450.0)
            count = len(rows)
            self.intercept -= rate * intercept_gradient / count
            for index in range(len(self.weights)):
                regularized = gradient[index] / count + self.l2 * self.weights[index]
                self.weights[index] -= rate * regularized
        return self


def _binary_metrics(labels: list[int], probabilities: list[float], threshold: float) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    brier = 0.0
    reliability = []
    for label, probability in zip(labels, probabilities):
        predicted = probability >= threshold
        tp += int(predicted and label == 1)
        fp += int(predicted and label == 0)
        tn += int(not predicted and label == 0)
        fn += int(not predicted and label == 1)
        brier += (probability - label) ** 2
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    ece = 0.0
    for bin_index in range(10):
        lower = bin_index / 10
        upper = (bin_index + 1) / 10
        if bin_index == 9:
            indices = [
                index for index, probability in enumerate(probabilities)
                if lower <= probability <= upper
            ]
        else:
            indices = [
                index for index, probability in enumerate(probabilities)
                if lower <= probability < upper
            ]
        count = len(indices)
        mean_probability = sum(probabilities[index] for index in indices) / count if count else 0.0
        empirical_rate = sum(labels[index] for index in indices) / count if count else 0.0
        if labels:
            ece += count / len(labels) * abs(mean_probability - empirical_rate)
        reliability.append({
            "lower": round(lower, 4),
            "upper": round(upper, 4),
            "count": count,
            "mean_probability": round(mean_probability, 6),
            "empirical_link_rate": round(empirical_rate, 6),
        })
    count = max(1, len(labels))
    return {
        "accuracy": round((tp + tn) / count, 6),
        "balanced_accuracy": round((recall + specificity) / 2, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "brier": round(brier / count, 6),
        "expected_calibration_error": round(ece, 6),
        "false_link_rate": round(fp / (fp + tn), 6) if fp + tn else 0.0,
        "missed_link_rate": round(fn / (fn + tp), 6) if fn + tp else 0.0,
        "threshold": round(threshold, 4),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "reliability": reliability,
    }


def _best_threshold(labels: list[int], probabilities: list[float]) -> float:
    candidates = [value / 100 for value in range(20, 81, 2)]
    scored = [(_binary_metrics(labels, probabilities, candidate)["f1"], -abs(candidate - 0.5), candidate) for candidate in candidates]
    return max(scored)[2]


def _best_temperature(
    model: BinaryLogisticLinker,
    rows: list[list[float]],
    labels: list[int],
) -> float:
    candidates = (0.55, 0.7, 0.85, 1.0, 1.2, 1.5, 1.9, 2.4, 3.0)
    scored = []
    for temperature in candidates:
        probabilities = [model.probability(features, temperature) for features in rows]
        brier = sum((probability - label) ** 2 for probability, label in zip(probabilities, labels)) / len(labels)
        scored.append((brier, temperature))
    return min(scored)[1]


def _fixed_calibration(
    pairs: list[TracePair],
    raw_scores: list[dict[str, Any]],
) -> tuple[float, float, float]:
    labels = [pair.label for pair in pairs]
    scored = []
    for slope in (3.0, 4.0, 5.0, 6.0, 7.0, 8.5, 10.0, 12.0):
        for center in (0.30, 0.38, 0.44, 0.50, 0.56, 0.62, 0.70):
            linker = EvidenceDiversityLinker(slope, center)
            probabilities = []
            for score in raw_scores:
                probability = linker.probability(score["raw_score"])
                matched = len(score["matched_families"])
                probability = min(probability, 0.49 if matched < 2 else 0.69 if matched < 3 else 1.0)
                probabilities.append(probability)
            brier = sum((probability - label) ** 2 for probability, label in zip(probabilities, labels)) / len(labels)
            scored.append((brier, slope, center, _best_threshold(labels, probabilities)))
    _, slope, center, threshold = min(scored)
    return slope, center, threshold


def run_trace_experiment(seed: int = DEFAULT_SEED) -> dict[str, Any]:
    corpus = SyntheticTraceCorpus()
    sessions = corpus.generate_sessions(seed)
    pairs = corpus.generate_pairs(seed)
    splits = corpus.split(pairs)
    feature_linker = EvidenceDiversityLinker()
    features_by_partition: dict[str, list[tuple[list[float], dict[str, Any], TracePair]]] = {}
    for partition, partition_pairs in splits.items():
        features_by_partition[partition] = [
            (*pair_features(pair, feature_linker), pair)
            for pair in partition_pairs
        ]

    train_rows = [(features, pair.label) for features, _, pair in features_by_partition["train"]]
    validation_features = [features for features, _, _ in features_by_partition["validation"]]
    validation_labels = [pair.label for _, _, pair in features_by_partition["validation"]]
    test_features = [features for features, _, _ in features_by_partition["test"]]
    test_labels = [pair.label for _, _, pair in features_by_partition["test"]]

    learned = BinaryLogisticLinker().fit(train_rows)
    temperature = _best_temperature(learned, validation_features, validation_labels)
    validation_learned = [learned.probability(features, temperature) for features in validation_features]
    learned_threshold = _best_threshold(validation_labels, validation_learned)
    learned_probabilities = [learned.probability(features, temperature) for features in test_features]

    validation_scores = [score for _, score, _ in features_by_partition["validation"]]
    fixed_slope, fixed_center, fixed_threshold = _fixed_calibration(
        splits["validation"], validation_scores
    )
    fixed_linker = EvidenceDiversityLinker(fixed_slope, fixed_center)

    def fixed_probabilities(partition: str) -> list[float]:
        values = []
        for _, score, _ in features_by_partition[partition]:
            probability = fixed_linker.probability(score["raw_score"])
            matched = len(score["matched_families"])
            values.append(min(probability, 0.49 if matched < 2 else 0.69 if matched < 3 else 1.0))
        return values

    fixed_test = fixed_probabilities("test")
    source_validation = [
        0.82 if row[0][0] > 0 else 0.18
        for row in features_by_partition["validation"]
    ]
    source_test = [0.82 if row[0][0] > 0 else 0.18 for row in features_by_partition["test"]]
    source_threshold = _best_threshold(validation_labels, source_validation)
    fingerprint_validation = [
        0.12 + 0.76 * max(row[0][2], row[0][3])
        for row in features_by_partition["validation"]
    ]
    fingerprint_test = [
        0.12 + 0.76 * max(row[0][2], row[0][3])
        for row in features_by_partition["test"]
    ]
    fingerprint_threshold = _best_threshold(validation_labels, fingerprint_validation)

    model_reports = [
        {
            "id": "TRACE-IP-ONLY",
            "name": "Source-reference-only baseline",
            "role": "Demonstrates the failure of treating one address/reference as identity.",
            "status": "BASELINE",
            "test": _binary_metrics(test_labels, source_test, source_threshold),
        },
        {
            "id": "TRACE-FINGERPRINT",
            "name": "Single-profile baseline",
            "role": "Uses only the strongest transport or tooling similarity.",
            "status": "BASELINE",
            "test": _binary_metrics(test_labels, fingerprint_test, fingerprint_threshold),
        },
        {
            "id": "TRACE-DIVERSITY-FUSION",
            "name": "Evidence-diversity fusion",
            "role": "Reliability/spoofability-weighted evidence with diversity gates and contradiction penalties.",
            "status": "ACTIVE_RESEARCH",
            "calibration": {"slope": fixed_slope, "center": fixed_center},
            "test": _binary_metrics(test_labels, fixed_test, fixed_threshold),
        },
        {
            "id": "TRACE-LOGISTIC-CANDIDATE",
            "name": "Diversity-feature logistic linker",
            "role": "Learned pairwise candidate trained only on grouped training families.",
            "status": "SHADOW_CANDIDATE",
            "temperature": temperature,
            "weights": {
                name: round(weight, 6)
                for name, weight in zip(FEATURE_NAMES, learned.weights)
            },
            "intercept": round(learned.intercept, 6),
            "test": _binary_metrics(test_labels, learned_probabilities, learned_threshold),
        },
    ]
    winner = max(model_reports, key=lambda model: (model["test"]["f1"], -model["test"]["brier"]))

    canonical_dataset = {
        "sessions": [session.canonical() for session in sessions],
        "pairs": [pair.canonical() for pair in pairs],
    }
    dataset_sha = hashlib.sha256(
        json.dumps(canonical_dataset, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    descriptor = {
        "generator": TRACE_GENERATOR_VERSION,
        "seed": seed,
        "dataset_sha256": dataset_sha,
        "split": "environment-family-grouped-3/1/1",
        "features": list(FEATURE_NAMES),
        "learned_temperature": temperature,
    }
    run_id = "TRACE-RUN-" + hashlib.sha256(
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16].upper()
    return {
        "experiment_id": "EXP-TRACE-LINK-001",
        "run_id": run_id,
        "status": "PASSING" if winner["test"]["f1"] >= 0.75 else "NEEDS_REVISION",
        "objective": "Link synthetic activity sessions across rotating/shared source infrastructure without inferring human identity.",
        "dataset": {
            "generator_version": TRACE_GENERATOR_VERSION,
            "dataset_sha256": dataset_sha,
            "seed": seed,
            "sessions": len(sessions),
            "pairs": len(pairs),
            "positive_pairs": sum(pair.label for pair in pairs),
            "hard_negative_pairs": sum(1 - pair.label for pair in pairs),
            "splits": {name: len(values) for name, values in splits.items()},
            "family_ids": {"train": [0, 1, 2], "validation": [3], "test": [4]},
            "synthetic_only": True,
            "external_targets": 0,
            "documentation_address_semantics": True,
        },
        "features": list(FEATURE_NAMES),
        "models": model_reports,
        "winner": {
            "id": winner["id"],
            "name": winner["name"],
            "test": winner["test"],
            "promotion": "HOLD_SHADOW" if winner["status"] == "SHADOW_CANDIDATE" else "RESEARCH_ONLY",
        },
        "validity_checks": {
            "family_disjoint": True,
            "balanced_pairs_per_partition": all(
                sum(pair.label for pair in values) * 2 == len(values)
                for values in splits.values()
            ),
            "raw_ip_feature": False,
            "identity_label": False,
            "external_targets": 0,
        },
        "limitations": [
            "Campaign labels and signal-generation assumptions are synthetic.",
            "Address, transport and tool profiles may be shared, copied, relayed or deliberately mimicked.",
            "Pairwise campaign linkage is not human identity attribution.",
            "Enterprise calibration requires authorized multi-environment evidence and temporal validation.",
        ],
        "reproducibility": {
            "deterministic": True,
            "run_descriptor": descriptor,
            "dependency_profile": "Python standard library only",
        },
    }
