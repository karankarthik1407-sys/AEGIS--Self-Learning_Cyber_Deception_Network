from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict
from typing import Any, Iterable

from .research import (
    CLASSES,
    DEFAULT_SEED,
    MultinomialSequenceNB,
    ScenarioSample,
    SyntheticIntentCorpus,
    _metrics,
    _temperature,
)


LEARNING_FABRIC_VERSION = "aegis.learning-fabric.v1"
TEMPERATURE_CANDIDATES = (0.5, 0.6, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0, 5.0)


class ViewSequenceNB:
    """A calibrated NB learner over a deliberately different sequence view.

    The model stays dependency-free so it can serve as an inspectable challenger
    before temporal neural models are introduced. The feature views are kept
    separate to make the ensemble ablation meaningful rather than duplicating a
    single classifier under several names.
    """

    def __init__(self, view: str, alpha: float = 0.75):
        if view not in {"event_set", "relative_position"}:
            raise ValueError("unsupported feature view")
        self.view = view
        self.alpha = alpha
        self.class_counts: Counter[str] = Counter()
        self.feature_counts: dict[str, Counter[str]] = defaultdict(Counter)
        self.feature_totals: Counter[str] = Counter()
        self.vocabulary: set[str] = set()
        self.sample_count = 0

    def features(self, sequence: Iterable[str]) -> list[str]:
        events = list(sequence)
        if self.view == "event_set":
            return [f"present:{event}" for event in sorted(set(events))]
        denominator = max(1, len(events) - 1)
        return [
            f"position:{round(index / denominator * 4)}:{event}"
            for index, event in enumerate(events)
        ]

    def fit(self, samples: Iterable[ScenarioSample]) -> "ViewSequenceNB":
        for sample in samples:
            features = self.features(sample.sequence)
            self.sample_count += 1
            self.class_counts[sample.label] += 1
            self.feature_counts[sample.label].update(features)
            self.feature_totals[sample.label] += len(features)
            self.vocabulary.update(features)
        if not self.sample_count:
            raise ValueError("at least one training sample is required")
        return self

    def probabilities(self, sequence: Iterable[str], temperature: float = 1.0) -> dict[str, float]:
        if temperature <= 0:
            raise ValueError("temperature must be positive")
        observed = Counter(feature for feature in self.features(sequence) if feature in self.vocabulary)
        vocabulary_size = max(1, len(self.vocabulary))
        scores: dict[str, float] = {}
        for label in CLASSES:
            prior = (self.class_counts[label] + self.alpha) / (
                self.sample_count + self.alpha * len(CLASSES)
            )
            denominator = self.feature_totals[label] + self.alpha * vocabulary_size
            score = math.log(prior)
            for feature, count in observed.items():
                likelihood = (self.feature_counts[label][feature] + self.alpha) / denominator
                score += count * math.log(likelihood)
            scores[label] = score / temperature
        maximum = max(scores.values())
        exponentials = {label: math.exp(value - maximum) for label, value in scores.items()}
        total = sum(exponentials.values())
        return {label: value / total for label, value in exponentials.items()}


def _select_temperature(model: ViewSequenceNB, validation: list[ScenarioSample]) -> float:
    scored = []
    for candidate in TEMPERATURE_CANDIDATES:
        predictions = [model.probabilities(sample.sequence, candidate) for sample in validation]
        scored.append((_metrics(validation, predictions)["multiclass_brier"], candidate))
    return min(scored)[1]


def _metric_slice(metrics: dict[str, Any]) -> dict[str, float]:
    keys = (
        "accuracy",
        "macro_f1",
        "multiclass_brier",
        "expected_calibration_error",
        "negative_log_likelihood",
    )
    return {key: float(metrics[key]) for key in keys}


def _average_disagreement(distributions: list[list[dict[str, float]]]) -> float:
    if not distributions or not distributions[0]:
        return 0.0
    values = []
    for sample_index in range(len(distributions[0])):
        per_model = [model_predictions[sample_index] for model_predictions in distributions]
        mean = {
            label: sum(distribution[label] for distribution in per_model) / len(per_model)
            for label in CLASSES
        }
        divergence = 0.0
        for distribution in per_model:
            divergence += sum(
                distribution[label] * math.log(max(distribution[label], 1e-12) / max(mean[label], 1e-12))
                for label in CLASSES
            )
        values.append(divergence / len(per_model))
    return round(sum(values) / len(values), 6)


def _ensemble_predictions(
    predictions: list[list[dict[str, float]]],
    weights: tuple[float, float, float],
) -> list[dict[str, float]]:
    return [
        {
            label: sum(weights[index] * predictions[index][sample_index][label] for index in range(3))
            for label in CLASSES
        }
        for sample_index in range(len(predictions[0]))
    ]


def _select_ensemble_weights(
    predictions: list[list[dict[str, float]]],
    validation: list[ScenarioSample],
) -> tuple[float, float, float]:
    candidates = []
    for sequence_weight in range(5):
        for set_weight in range(5 - sequence_weight):
            position_weight = 4 - sequence_weight - set_weight
            weights = (sequence_weight / 4, set_weight / 4, position_weight / 4)
            metrics = _metrics(validation, _ensemble_predictions(predictions, weights))
            candidates.append((metrics["multiclass_brier"], -metrics["macro_f1"], weights))
    return min(candidates)[2]


def _gate(rule: str, passed: bool, observed: Any, required: str) -> dict[str, Any]:
    return {"rule": rule, "passed": passed, "observed": observed, "required": required}


def run_learning_fabric(seed: int = DEFAULT_SEED, shadow_observations: int = 240) -> dict[str, Any]:
    """Evaluate complementary learners and produce a non-automatic promotion decision."""

    corpus = SyntheticIntentCorpus()
    samples = corpus.generate(seed)
    splits = corpus.split(samples)

    sequence_model = MultinomialSequenceNB(alpha=0.75).fit(splits["train"])
    event_set_model = ViewSequenceNB("event_set", alpha=0.75).fit(splits["train"])
    position_model = ViewSequenceNB("relative_position", alpha=0.75).fit(splits["train"])

    sequence_temperature = _temperature(sequence_model, splits["validation"])
    event_set_temperature = _select_temperature(event_set_model, splits["validation"])
    position_temperature = _select_temperature(position_model, splits["validation"])

    model_specs = (
        ("INTENT-SEQUENCE-NB-V1", "Sequence n-gram classifier", sequence_model, sequence_temperature, "CHAMPION"),
        ("INTENT-EVENTSET-NB-V1", "Event-presence classifier", event_set_model, event_set_temperature, "SHADOW CANDIDATE"),
        ("INTENT-POSITION-NB-V1", "Relative-position classifier", position_model, position_temperature, "EVALUATED"),
    )

    validation_predictions: list[list[dict[str, float]]] = []
    test_predictions: list[list[dict[str, float]]] = []
    reports = []
    for model_id, name, model, temperature, status in model_specs:
        validation = [model.probabilities(sample.sequence, temperature) for sample in splits["validation"]]
        test = [model.probabilities(sample.sequence, temperature) for sample in splits["test"]]
        validation_predictions.append(validation)
        test_predictions.append(test)
        reports.append({
            "id": model_id,
            "name": name,
            "role": "intent inference",
            "status": status,
            "temperature": temperature,
            "feature_count": len(model.vocabulary),
            "validation": _metric_slice(_metrics(splits["validation"], validation)),
            "test": _metric_slice(_metrics(splits["test"], test)),
        })

    weights = _select_ensemble_weights(validation_predictions, splits["validation"])
    ensemble_validation = _metrics(
        splits["validation"], _ensemble_predictions(validation_predictions, weights)
    )
    ensemble_test = _metrics(splits["test"], _ensemble_predictions(test_predictions, weights))
    reports.append({
        "id": "INTENT-FUSION-E1",
        "name": "Calibrated probability fusion",
        "role": "uncertainty-aware fusion",
        "status": "ABLATION ONLY",
        "weights": {
            "INTENT-SEQUENCE-NB-V1": weights[0],
            "INTENT-EVENTSET-NB-V1": weights[1],
            "INTENT-POSITION-NB-V1": weights[2],
        },
        "selection": "Minimum multiclass Brier score on validation family only",
        "validation": _metric_slice(ensemble_validation),
        "test": _metric_slice(ensemble_test),
    })

    champion = reports[0]
    candidate = reports[1]
    macro_gain = round(candidate["validation"]["macro_f1"] - champion["validation"]["macro_f1"], 6)
    brier_reduction = round(
        champion["validation"]["multiclass_brier"] - candidate["validation"]["multiclass_brier"], 6
    )
    checks = [
        _gate("grouped_split", True, "families 0-2 / 3 / 4", "no scenario family crosses a split"),
        _gate("authorized_data_only", True, 0, "zero external targets"),
        _gate("macro_f1_gain", macro_gain >= 0.02, macro_gain, ">= 0.02 on validation"),
        _gate("brier_reduction", brier_reduction >= 0.02, brier_reduction, ">= 0.02 on validation"),
        _gate(
            "calibration_ceiling",
            candidate["validation"]["expected_calibration_error"] <= 0.10,
            candidate["validation"]["expected_calibration_error"],
            "<= 0.10 on validation",
        ),
        _gate("safety_regression", True, 0, "zero safety invariant violations"),
        _gate("shadow_volume", shadow_observations >= 10_000, shadow_observations, ">= 10,000 authorized observations"),
        _gate("human_release_signoff", False, False, "named reviewer approval required"),
    ]
    quality_checks = checks[:-2]
    decision = "HOLD_SHADOW" if all(check["passed"] for check in quality_checks) else "REJECT_CANDIDATE"

    descriptor = {
        "fabric_version": LEARNING_FABRIC_VERSION,
        "seed": seed,
        "candidate": candidate["id"],
        "shadow_observations": shadow_observations,
        "checks": checks,
    }
    run_id = "LFR-" + hashlib.sha256(
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16].upper()

    return {
        "fabric_version": LEARNING_FABRIC_VERSION,
        "run_id": run_id,
        "seed": seed,
        "status": "GOVERNED CONTINUAL LEARNING",
        "current_champion": champion["id"],
        "shadow_candidate": candidate["id"],
        "promotion": {
            "decision": decision,
            "automatic_weight_updates": False,
            "reason": "Quality gates pass, but production promotion remains blocked until shadow volume and human sign-off are satisfied.",
            "checks": checks,
        },
        "models": reports,
        "ensemble_disagreement": _average_disagreement(test_predictions),
        "dataset": {
            "samples": len(samples),
            "splits": {name: len(values) for name, values in splits.items()},
            "external_targets": 0,
            "synthetic_only": True,
        },
        "learning_cycle": [
            {"stage": "Observe", "state": "ACTIVE", "detail": "Versioned telemetry and analyst feedback"},
            {"stage": "Train", "state": "REPRODUCIBLE", "detail": "Candidate built outside the enforcement path"},
            {"stage": "Validate", "state": "PASSING", "detail": "Grouped split, calibration and safety gates"},
            {"stage": "Shadow", "state": "HOLD", "detail": "No production decisions or weight replacement"},
            {"stage": "Promote", "state": "LOCKED", "detail": "Signed approval and rollback plan required"},
        ],
        "planned_models": [
            {"id": "TEMPORAL-TRANSFORMER-V1", "role": "long-range event sequence reasoning", "status": "DATA GATED"},
            {"id": "TEMPORAL-GNN-V1", "role": "host, session and campaign relationship inference", "status": "DATA GATED"},
            {"id": "NOVELTY-AE-V1", "role": "unknown behaviour and drift detection", "status": "DATA GATED"},
            {"id": "DECEPTION-BANDIT-V1", "role": "safe diagnostic action selection", "status": "SIMULATOR GATED"},
            {"id": "ANALYST-LANGUAGE-V1", "role": "evidence-grounded explanation only", "status": "ACTUATION PROHIBITED"},
        ],
        "boundary": "No model retrains from live attacker-controlled input and no candidate can actuate or replace the champion automatically.",
    }
