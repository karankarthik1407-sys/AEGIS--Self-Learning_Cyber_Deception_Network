from __future__ import annotations

import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable


DEFAULT_SEED = 26_082_026
GENERATOR_VERSION = "aegis.synthetic-intent.v1"
CLASSES = ("Reconnaissance", "Credential Access", "Lateral Movement", "Collection")

CLASS_PATHS: dict[str, tuple[str, ...]] = {
    "Reconnaissance": (
        "dns_enumeration",
        "network_scan",
        "service_banner_probe",
        "admin_route_probe",
        "web_directory_probe",
    ),
    "Credential Access": (
        "admin_route_probe",
        "ssh_login_failure",
        "password_spray_simulation",
        "token_lure_access",
        "synthetic_credential_opened",
    ),
    "Lateral Movement": (
        "synthetic_credential_opened",
        "internal_route_probe",
        "remote_service_attempt",
        "decoy_service_pivot",
        "synthetic_share_mount",
    ),
    "Collection": (
        "synthetic_share_mount",
        "bulk_file_enumeration",
        "synthetic_database_query",
        "staging_directory_created",
        "synthetic_archive_requested",
    ),
}

COMMON_EVENTS = (
    "session_started",
    "dns_lookup",
    "http_request",
    "authentication_prompt",
    "connection_retry",
    "connection_closed",
)


@dataclass(frozen=True)
class ScenarioSample:
    sample_id: str
    label: str
    family: int
    sequence: tuple[str, ...]

    def canonical(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "label": self.label,
            "family": self.family,
            "sequence": list(self.sequence),
        }


class SyntheticIntentCorpus:
    """Build a deterministic, strictly synthetic sequence-classification corpus."""

    samples_per_family = 12
    families_per_class = 5

    def generate(self, seed: int = DEFAULT_SEED) -> list[ScenarioSample]:
        samples: list[ScenarioSample] = []
        for label_index, label in enumerate(CLASSES):
            path = CLASS_PATHS[label]
            for family in range(self.families_per_class):
                for variant in range(self.samples_per_family):
                    rng = random.Random(seed + label_index * 100_000 + family * 1_000 + variant)
                    sequence = self._sequence(path, label_index, family, variant, rng)
                    samples.append(ScenarioSample(
                        sample_id=f"SYN-{label_index + 1}-{family + 1}-{variant + 1:02d}",
                        label=label,
                        family=family,
                        sequence=tuple(sequence),
                    ))
        return samples

    @staticmethod
    def split(samples: Iterable[ScenarioSample]) -> dict[str, list[ScenarioSample]]:
        result = {"train": [], "validation": [], "test": []}
        for sample in samples:
            partition = "train" if sample.family <= 2 else "validation" if sample.family == 3 else "test"
            result[partition].append(sample)
        return result

    def _sequence(
        self,
        path: tuple[str, ...],
        label_index: int,
        family: int,
        variant: int,
        rng: random.Random,
    ) -> list[str]:
        # Families change the observable route, while the family identifier itself
        # never becomes a model feature. This lets the split reject near-duplicate
        # leakage while preserving a learnable intent signal.
        core_count = 3 if variant % 4 else 4
        start = (family + variant) % len(path)
        core = [path[(start + offset) % len(path)] for offset in range(core_count)]

        # Two early-stage traces per family are intentionally underdetermined:
        # most observed actions resemble the next intent class, with only one
        # weak event from the labelled objective. A useful model should expose
        # this ambiguity rather than receiving a perfectly separable toy set.
        if variant in (10, 11):
            adjacent = CLASS_PATHS[CLASSES[(label_index + 1) % len(CLASSES)]]
            adjacent_start = (family + variant) % len(adjacent)
            core = [adjacent[(adjacent_start + offset) % len(adjacent)] for offset in range(3)]
            core.insert(2, path[(start + 1) % len(path)])

        # Controlled ambiguity: some sessions contain an event associated with a
        # neighbouring intent, and some lose a class event. This avoids a toy-perfect
        # benchmark while keeping every event harmless and synthetic.
        if variant % 5 == 0:
            adjacent = CLASS_PATHS[CLASSES[(label_index + 1) % len(CLASSES)]]
            core.insert(1, adjacent[(family + variant) % len(adjacent)])
        if variant % 7 == 0 and len(core) > 3:
            core.pop(rng.randrange(len(core)))

        noise_count = 1 + ((family + variant) % 3)
        noise = [rng.choice(COMMON_EVENTS[1:-1]) for _ in range(noise_count)]
        insertion = min(len(core), 1 + family % 3)
        middle = core[:insertion] + noise + core[insertion:]
        if variant % 6 == 0 and len(middle) > 3:
            left = 1 + rng.randrange(len(middle) - 2)
            middle[left - 1], middle[left] = middle[left], middle[left - 1]
        return [COMMON_EVENTS[0], *middle, COMMON_EVENTS[-1]]


def sequence_features(sequence: Iterable[str]) -> list[str]:
    events = list(sequence)
    tokens = [f"evt:{event}" for event in events]
    tokens.extend(f"seq:{left}>{right}" for left, right in zip(events, events[1:]))
    tokens.append(f"len:{min(9, len(events))}")
    return tokens


class MultinomialSequenceNB:
    """Small dependency-free multinomial baseline with temperature calibration."""

    def __init__(self, alpha: float = 0.75):
        self.alpha = alpha
        self.class_counts: Counter[str] = Counter()
        self.token_counts: dict[str, Counter[str]] = defaultdict(Counter)
        self.token_totals: Counter[str] = Counter()
        self.vocabulary: set[str] = set()
        self.sample_count = 0

    def fit(self, samples: Iterable[ScenarioSample]) -> "MultinomialSequenceNB":
        for sample in samples:
            features = sequence_features(sample.sequence)
            self.sample_count += 1
            self.class_counts[sample.label] += 1
            self.token_counts[sample.label].update(features)
            self.token_totals[sample.label] += len(features)
            self.vocabulary.update(features)
        if not self.sample_count:
            raise ValueError("at least one training sample is required")
        return self

    def log_scores(self, sequence: Iterable[str]) -> dict[str, float]:
        counts = Counter(token for token in sequence_features(sequence) if token in self.vocabulary)
        vocabulary_size = max(1, len(self.vocabulary))
        scores: dict[str, float] = {}
        for label in CLASSES:
            prior = (self.class_counts[label] + self.alpha) / (self.sample_count + self.alpha * len(CLASSES))
            denominator = self.token_totals[label] + self.alpha * vocabulary_size
            score = math.log(prior)
            for token, count in counts.items():
                likelihood = (self.token_counts[label][token] + self.alpha) / denominator
                score += count * math.log(likelihood)
            scores[label] = score
        return scores

    def probabilities(self, sequence: Iterable[str], temperature: float = 1.0) -> dict[str, float]:
        if temperature <= 0:
            raise ValueError("temperature must be positive")
        scaled = {label: score / temperature for label, score in self.log_scores(sequence).items()}
        maximum = max(scaled.values())
        exponentials = {label: math.exp(value - maximum) for label, value in scaled.items()}
        total = sum(exponentials.values())
        return {label: value / total for label, value in exponentials.items()}


def _round(value: float) -> float:
    return round(float(value), 6)


def _metrics(samples: list[ScenarioSample], probabilities: list[dict[str, float]]) -> dict[str, Any]:
    confusion = [[0 for _ in CLASSES] for _ in CLASSES]
    correct = 0
    brier_total = 0.0
    nll_total = 0.0
    confidence_records: list[tuple[float, int]] = []

    for sample, distribution in zip(samples, probabilities):
        predicted = max(CLASSES, key=lambda label: distribution[label])
        true_index = CLASSES.index(sample.label)
        predicted_index = CLASSES.index(predicted)
        confusion[true_index][predicted_index] += 1
        is_correct = int(predicted == sample.label)
        correct += is_correct
        confidence = distribution[predicted]
        confidence_records.append((confidence, is_correct))
        brier_total += sum((distribution[label] - int(label == sample.label)) ** 2 for label in CLASSES)
        nll_total -= math.log(max(distribution[sample.label], 1e-12))

    per_class = []
    f1_values = []
    for index, label in enumerate(CLASSES):
        true_positive = confusion[index][index]
        false_positive = sum(confusion[row][index] for row in range(len(CLASSES)) if row != index)
        false_negative = sum(confusion[index][column] for column in range(len(CLASSES)) if column != index)
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
        recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        f1_values.append(f1)
        per_class.append({
            "label": label,
            "precision": _round(precision),
            "recall": _round(recall),
            "f1": _round(f1),
            "support": sum(confusion[index]),
        })

    reliability = []
    ece = 0.0
    bin_count = 10
    for bin_index in range(bin_count):
        lower = bin_index / bin_count
        upper = (bin_index + 1) / bin_count
        records = [
            (confidence, outcome)
            for confidence, outcome in confidence_records
            if ((lower <= confidence <= upper) if bin_index == bin_count - 1 else (lower <= confidence < upper))
        ]
        count = len(records)
        mean_confidence = sum(record[0] for record in records) / count if count else 0.0
        empirical_accuracy = sum(record[1] for record in records) / count if count else 0.0
        if samples:
            ece += (count / len(samples)) * abs(empirical_accuracy - mean_confidence)
        reliability.append({
            "lower": _round(lower),
            "upper": _round(upper),
            "count": count,
            "mean_confidence": _round(mean_confidence),
            "empirical_accuracy": _round(empirical_accuracy),
        })

    count = max(1, len(samples))
    return {
        "accuracy": _round(correct / count),
        "macro_f1": _round(sum(f1_values) / len(f1_values)),
        "multiclass_brier": _round(brier_total / count),
        "expected_calibration_error": _round(ece),
        "negative_log_likelihood": _round(nll_total / count),
        "confusion_matrix": {"labels": list(CLASSES), "rows": confusion},
        "per_class": per_class,
        "reliability": reliability,
    }


def _temperature(model: MultinomialSequenceNB, validation: list[ScenarioSample]) -> float:
    candidates = (0.6, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0)
    scored = []
    for candidate in candidates:
        predictions = [model.probabilities(sample.sequence, candidate) for sample in validation]
        scored.append((_metrics(validation, predictions)["multiclass_brier"], candidate))
    return min(scored)[1]


def run_intent_experiment(seed: int = DEFAULT_SEED) -> dict[str, Any]:
    corpus = SyntheticIntentCorpus()
    samples = corpus.generate(seed)
    splits = corpus.split(samples)
    model = MultinomialSequenceNB(alpha=0.75).fit(splits["train"])
    temperature = _temperature(model, splits["validation"])

    calibrated = [model.probabilities(sample.sequence, temperature) for sample in splits["test"]]
    uncalibrated = [model.probabilities(sample.sequence) for sample in splits["test"]]
    calibrated_metrics = _metrics(splits["test"], calibrated)
    uncalibrated_metrics = _metrics(splits["test"], uncalibrated)
    uniform = [{label: 1 / len(CLASSES) for label in CLASSES} for _ in splits["test"]]
    baseline_metrics = _metrics(splits["test"], uniform)

    canonical_samples = [sample.canonical() for sample in samples]
    dataset_sha = hashlib.sha256(json.dumps(canonical_samples, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    run_descriptor = {
        "generator": GENERATOR_VERSION,
        "seed": seed,
        "dataset_sha256": dataset_sha,
        "alpha": model.alpha,
        "temperature": temperature,
        "split": "family-grouped-3/1/1",
    }
    run_id = "RUN-" + hashlib.sha256(json.dumps(run_descriptor, sort_keys=True).encode()).hexdigest()[:16].upper()
    class_counts = Counter(sample.label for sample in samples)

    return {
        "experiment_id": "EXP-INTENT-NB-001",
        "run_id": run_id,
        "status": "PASSING",
        "objective": "Classify the next-stage intent of a contained synthetic session from its ordered event trace.",
        "dataset": {
            "generator_version": GENERATOR_VERSION,
            "dataset_sha256": dataset_sha,
            "seed": seed,
            "samples": len(samples),
            "classes": list(CLASSES),
            "class_counts": {label: class_counts[label] for label in CLASSES},
            "splits": {name: len(values) for name, values in splits.items()},
            "family_ids": {"train": [0, 1, 2], "validation": [3], "test": [4]},
            "split_policy": "Scenario-family grouping; no family appears in more than one split.",
            "synthetic_only": True,
            "external_targets": 0,
        },
        "model": {
            "family": "Calibrated multinomial event-sequence Naive Bayes",
            "features": "event tokens + adjacent-event bigrams + sequence-length bin",
            "vocabulary_size": len(model.vocabulary),
            "laplace_alpha": model.alpha,
            "temperature": temperature,
            "calibration_selection": "Lowest multiclass Brier score on held-out family 3",
            "dependency_profile": "Python standard library only",
        },
        "metrics": calibrated_metrics,
        "uncalibrated_metrics": {
            key: uncalibrated_metrics[key]
            for key in ("accuracy", "macro_f1", "multiclass_brier", "expected_calibration_error", "negative_log_likelihood")
        },
        "baseline": {
            "name": "Uniform four-class predictor",
            **{key: baseline_metrics[key] for key in ("accuracy", "macro_f1", "multiclass_brier", "expected_calibration_error")},
        },
        "delta_over_baseline": {
            "accuracy": _round(calibrated_metrics["accuracy"] - baseline_metrics["accuracy"]),
            "macro_f1": _round(calibrated_metrics["macro_f1"] - baseline_metrics["macro_f1"]),
            "brier_reduction": _round(baseline_metrics["multiclass_brier"] - calibrated_metrics["multiclass_brier"]),
        },
        "limitations": [
            "This is a seeded synthetic benchmark, not evidence of performance on live enterprise traffic.",
            "Event-generation assumptions can favour the feature representation; external validation is still required.",
            "Intent classes describe behaviour hypotheses and must never be treated as human identity attribution.",
            "The baseline validates the experiment pipeline; temporal neural and graph models remain comparison candidates.",
        ],
        "reproducibility": {
            "deterministic": True,
            "run_descriptor": run_descriptor,
            "randomness": "One local pseudorandom generator per sample; no network or external data access.",
        },
    }


def dataset_summary(seed: int = DEFAULT_SEED) -> dict[str, Any]:
    report = run_intent_experiment(seed)
    return {
        "dataset": report["dataset"],
        "feature_contract": report["model"]["features"],
        "sample_preview": [
            sample.canonical()
            for sample in SyntheticIntentCorpus().generate(seed)[:8]
        ],
        "warning": "Preview data is synthetic and contains no real hosts, credentials, victims or external targets.",
    }
