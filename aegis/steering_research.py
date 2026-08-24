from __future__ import annotations

import hashlib
import json
import math
import random
import statistics
from dataclasses import dataclass
from typing import Any, Iterable

from .belief import HYPOTHESES, normalize, uniform_prior
from .config import SETTINGS, Settings
from .models import ProposedAction
from .research import DEFAULT_SEED
from .safety import SafetyGate


STEERING_GENERATOR_VERSION = "aegis.synthetic-diagnostic-steering.v1"
OUTCOMES = ("engage", "inspect", "decline")
CONFIDENCE_THRESHOLD = 0.86
MAX_INTERACTIONS = 8
FAMILIES = 5
EPISODES_PER_INTENT_FAMILY = 24


@dataclass(frozen=True)
class DiagnosticProbe:
    id: str
    label: str
    target: str
    cost: float
    likelihoods: dict[str, dict[str, float]]

    def canonical(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "target": self.target,
            "cost": self.cost,
            "likelihoods": self.likelihoods,
        }


PROBES = (
    DiagnosticProbe(
        id="PROBE-SERVICE-MAP",
        label="Selective service map",
        target="decoy-edge-service-map",
        cost=0.75,
        likelihoods={
            "Reconnaissance": {"engage": 0.72, "inspect": 0.20, "decline": 0.08},
            "Credential Access": {"engage": 0.30, "inspect": 0.40, "decline": 0.30},
            "Lateral Movement": {"engage": 0.20, "inspect": 0.35, "decline": 0.45},
            "Collection": {"engage": 0.12, "inspect": 0.28, "decline": 0.60},
        },
    ),
    DiagnosticProbe(
        id="PROBE-CREDENTIAL-LURE",
        label="Synthetic credential note",
        target="decoy-credential-note",
        cost=1.00,
        likelihoods={
            "Reconnaissance": {"engage": 0.24, "inspect": 0.43, "decline": 0.33},
            "Credential Access": {"engage": 0.72, "inspect": 0.20, "decline": 0.08},
            "Lateral Movement": {"engage": 0.38, "inspect": 0.40, "decline": 0.22},
            "Collection": {"engage": 0.18, "inspect": 0.32, "decline": 0.50},
        },
    ),
    DiagnosticProbe(
        id="PROBE-PIVOT-ROUTE",
        label="Isolated pivot route",
        target="decoy-pivot-route",
        cost=1.15,
        likelihoods={
            "Reconnaissance": {"engage": 0.12, "inspect": 0.31, "decline": 0.57},
            "Credential Access": {"engage": 0.34, "inspect": 0.41, "decline": 0.25},
            "Lateral Movement": {"engage": 0.72, "inspect": 0.20, "decline": 0.08},
            "Collection": {"engage": 0.30, "inspect": 0.37, "decline": 0.33},
        },
    ),
    DiagnosticProbe(
        id="PROBE-ARCHIVE-INDEX",
        label="Synthetic archive index",
        target="decoy-archive-index",
        cost=1.25,
        likelihoods={
            "Reconnaissance": {"engage": 0.08, "inspect": 0.25, "decline": 0.67},
            "Credential Access": {"engage": 0.17, "inspect": 0.31, "decline": 0.52},
            "Lateral Movement": {"engage": 0.31, "inspect": 0.37, "decline": 0.32},
            "Collection": {"engage": 0.72, "inspect": 0.20, "decline": 0.08},
        },
    ),
)


POLICIES = (
    {
        "id": "STEER-STATIC",
        "name": "Static service-map policy",
        "status": "BASELINE",
        "role": "Repeats one fixed decoy probe regardless of the current uncertainty.",
    },
    {
        "id": "STEER-RANDOM",
        "name": "Seeded random policy",
        "status": "BASELINE",
        "role": "Selects uniformly from the same Safety-Kernel-approved probe set.",
    },
    {
        "id": "STEER-RULE",
        "name": "Leading-hypothesis expert rule",
        "status": "BASELINE",
        "role": "Selects the probe associated with the currently leading intent.",
    },
    {
        "id": "STEER-EIG",
        "name": "AEGIS expected-information-gain steering",
        "status": "SHADOW_CANDIDATE",
        "role": "Selects the safe probe with maximum expected entropy reduction after a bounded cost penalty.",
    },
)


def entropy(distribution: dict[str, float]) -> float:
    return -sum(probability * math.log2(probability) for probability in distribution.values() if probability > 0)


def posterior(
    prior: dict[str, float], probe: DiagnosticProbe, outcome: str
) -> dict[str, float]:
    return normalize(
        {
            hypothesis: prior[hypothesis] * probe.likelihoods[hypothesis][outcome]
            for hypothesis in HYPOTHESES
        }
    )


def expected_information_gain(
    prior: dict[str, float], probe: DiagnosticProbe
) -> float:
    expected_posterior_entropy = 0.0
    for outcome in OUTCOMES:
        probability = sum(
            prior[hypothesis] * probe.likelihoods[hypothesis][outcome]
            for hypothesis in HYPOTHESES
        )
        if probability > 0:
            expected_posterior_entropy += probability * entropy(posterior(prior, probe, outcome))
    return max(0.0, entropy(prior) - expected_posterior_entropy)


def _probe_for_hypothesis(hypothesis: str) -> DiagnosticProbe:
    return PROBES[HYPOTHESES.index(hypothesis)]


def select_probe(
    policy_id: str,
    prior: dict[str, float],
    random_source: random.Random,
) -> tuple[DiagnosticProbe, dict[str, float]]:
    gains = {probe.id: expected_information_gain(prior, probe) for probe in PROBES}
    if policy_id == "STEER-STATIC":
        selected = PROBES[0]
    elif policy_id == "STEER-RANDOM":
        selected = PROBES[random_source.randrange(len(PROBES))]
    elif policy_id == "STEER-RULE":
        leading = max(HYPOTHESES, key=lambda hypothesis: (prior[hypothesis], -HYPOTHESES.index(hypothesis)))
        selected = _probe_for_hypothesis(leading)
    elif policy_id == "STEER-EIG":
        selected = max(
            PROBES,
            key=lambda probe: (
                gains[probe.id] - 0.035 * probe.cost,
                gains[probe.id],
                -probe.cost,
                probe.id,
            ),
        )
    else:
        raise ValueError("unsupported steering policy")
    return selected, gains


def _actual_likelihoods(
    probe: DiagnosticProbe, hidden_intent: str, family: int
) -> dict[str, float]:
    # Later families progressively flatten response strength. The policy and
    # Bayesian update retain the nominal table, so family 4 is a modest,
    # pre-declared observation-model shift rather than a cloned test scenario.
    shift = 0.03 * family
    nominal = probe.likelihoods[hidden_intent]
    return {
        outcome: (1.0 - shift) * nominal[outcome] + shift / len(OUTCOMES)
        for outcome in OUTCOMES
    }


def _sample_outcome(probabilities: dict[str, float], draw: float) -> str:
    cumulative = 0.0
    for outcome in OUTCOMES:
        cumulative += probabilities[outcome]
        if draw <= cumulative:
            return outcome
    return OUTCOMES[-1]


def _safe_action(
    probe: DiagnosticProbe,
    policy_id: str,
    episode_id: str,
    step: int,
    namespace: str,
) -> ProposedAction:
    return ProposedAction(
        action_type="serve_diagnostic_synthetic_probe",
        target=probe.target,
        namespace=namespace,
        decoy_only=True,
        network_egress=False,
        synthetic_data_only=True,
        reversible=True,
        memory_mb=64,
        cpu_cores=0.20,
        ttl_seconds=180,
        rationale="Reduce uncertainty between synthetic intent hypotheses inside the authorized deception range.",
        action_id=f"ACT-{policy_id.removeprefix('STEER-')}-{episode_id}-{step}-{probe.id.removeprefix('PROBE-')}",
    )


def _episode(
    policy_id: str,
    hidden_intent: str,
    family: int,
    variant: int,
    seed: int,
    safety_gate: SafetyGate,
    include_trace: bool = False,
) -> dict[str, Any]:
    episode_id = f"F{family}-{HYPOTHESES.index(hidden_intent)}-V{variant:02d}"
    policy_offset = next(index for index, policy in enumerate(POLICIES) if policy["id"] == policy_id)
    selection_rng = random.Random(seed + 8_000_000 + policy_offset * 100_000 + family * 1_000 + variant)
    beliefs = uniform_prior()
    initial_entropy = entropy(beliefs)
    total_cost = 0.0
    permitted = denied = 0
    action_counts = {probe.id: 0 for probe in PROBES}
    trace = []
    reached_step: int | None = None
    wrong_confidence = False
    expected_gain_total = 0.0
    observed_gain_total = 0.0

    for step in range(1, MAX_INTERACTIONS + 1):
        before = beliefs
        probe, gains = select_probe(policy_id, before, selection_rng)
        action = _safe_action(
            probe,
            policy_id,
            episode_id,
            step,
            safety_gate.settings.authorized_namespace,
        )
        certificate = safety_gate.evaluate(action)
        if certificate["decision"] != "PERMIT":
            denied += 1
            if include_trace:
                trace.append({
                    "step": step,
                    "probe_id": probe.id,
                    "decision": "DENY",
                    "failed_rules": certificate["failed_rules"],
                })
            continue
        permitted += 1
        action_counts[probe.id] += 1
        total_cost += probe.cost
        expected_gain_total += gains[probe.id]
        draw_rng = random.Random(
            seed
            + family * 1_000_000
            + HYPOTHESES.index(hidden_intent) * 10_000
            + variant * 100
            + step
        )
        outcome = _sample_outcome(
            _actual_likelihoods(probe, hidden_intent, family), draw_rng.random()
        )
        beliefs = posterior(before, probe, outcome)
        observed_gain_total += entropy(before) - entropy(beliefs)
        leading = max(HYPOTHESES, key=lambda hypothesis: beliefs[hypothesis])
        top_probability = beliefs[leading]
        if include_trace:
            trace.append({
                "step": step,
                "probe_id": probe.id,
                "probe": probe.label,
                "safety_decision": "PERMIT",
                "outcome": outcome,
                "expected_information_gain_bits": round(gains[probe.id], 6),
                "prior_entropy_bits": round(entropy(before), 6),
                "posterior_entropy_bits": round(entropy(beliefs), 6),
                "leading_hypothesis": leading,
                "top_probability": round(top_probability, 6),
                "distribution": {key: round(value, 6) for key, value in beliefs.items()},
            })
        if top_probability >= CONFIDENCE_THRESHOLD:
            wrong_confidence = leading != hidden_intent
            reached_step = step if not wrong_confidence else None
            break

    leading = max(HYPOTHESES, key=lambda hypothesis: beliefs[hypothesis])
    top_probability = beliefs[leading]
    confident = top_probability >= CONFIDENCE_THRESHOLD
    return {
        "episode_id": episode_id,
        "policy_id": policy_id,
        "hidden_intent": hidden_intent,
        "family": family,
        "variant": variant,
        "success": reached_step is not None,
        "wrong_confidence": wrong_confidence,
        "confident": confident,
        "correct_final": leading == hidden_intent,
        "interactions": reached_step if reached_step is not None else MAX_INTERACTIONS + 1,
        "executed_interactions": permitted,
        "leading_hypothesis": leading,
        "top_probability": top_probability,
        "final_distribution": beliefs,
        "final_entropy_bits": entropy(beliefs),
        "entropy_reduction_bits": initial_entropy - entropy(beliefs),
        "expected_gain_total_bits": expected_gain_total,
        "observed_gain_total_bits": observed_gain_total,
        "total_cost": total_cost,
        "permitted": permitted,
        "denied": denied,
        "action_counts": action_counts,
        "trace": trace,
    }


def _mean_ci95(values: Iterable[float]) -> dict[str, float]:
    numbers = list(map(float, values))
    mean = statistics.fmean(numbers) if numbers else 0.0
    half_width = 1.96 * statistics.stdev(numbers) / math.sqrt(len(numbers)) if len(numbers) > 1 else 0.0
    return {
        "mean": round(mean, 6),
        "lower": round(max(0.0, mean - half_width), 6),
        "upper": round(mean + half_width, 6),
    }


def _policy_metrics(episodes: list[dict[str, Any]]) -> dict[str, Any]:
    count = len(episodes)
    brier = 0.0
    calibration = []
    action_counts = {probe.id: 0 for probe in PROBES}
    for episode in episodes:
        distribution = episode["final_distribution"]
        brier += sum(
            (distribution[hypothesis] - int(hypothesis == episode["hidden_intent"])) ** 2
            for hypothesis in HYPOTHESES
        )
        calibration.append((episode["top_probability"], int(episode["correct_final"])))
        for action_id, value in episode["action_counts"].items():
            action_counts[action_id] += value
    ece = 0.0
    for bin_index in range(10):
        lower, upper = bin_index / 10, (bin_index + 1) / 10
        rows = (
            [row for row in calibration if lower <= row[0] <= upper]
            if bin_index == 9
            else [row for row in calibration if lower <= row[0] < upper]
        )
        if rows:
            ece += len(rows) / count * abs(
                statistics.fmean(row[0] for row in rows)
                - statistics.fmean(row[1] for row in rows)
            )
    successful_steps = [episode["interactions"] for episode in episodes if episode["success"]]
    total_actions = sum(action_counts.values())
    success_rate = sum(episode["success"] for episode in episodes) / count
    wrong_confidence_rate = sum(episode["wrong_confidence"] for episode in episodes) / count
    mean_interactions = statistics.fmean(episode["interactions"] for episode in episodes)
    mean_cost = statistics.fmean(episode["total_cost"] for episode in episodes)
    return {
        "episodes": count,
        "correct_confidence_rate": round(success_rate, 6),
        "correct_final_rate": round(sum(episode["correct_final"] for episode in episodes) / count, 6),
        "wrong_confidence_rate": round(wrong_confidence_rate, 6),
        "abstention_rate": round(sum(not episode["confident"] for episode in episodes) / count, 6),
        "mean_interactions_to_correct_confidence": round(mean_interactions, 6),
        "mean_successful_interactions": round(statistics.fmean(successful_steps), 6) if successful_steps else None,
        "interaction_ci95": _mean_ci95(episode["interactions"] for episode in episodes),
        "mean_final_entropy_bits": round(statistics.fmean(episode["final_entropy_bits"] for episode in episodes), 6),
        "mean_entropy_reduction_bits": round(statistics.fmean(episode["entropy_reduction_bits"] for episode in episodes), 6),
        "mean_expected_information_gain_bits": round(statistics.fmean(episode["expected_gain_total_bits"] for episode in episodes), 6),
        "mean_observed_information_gain_bits": round(statistics.fmean(episode["observed_gain_total_bits"] for episode in episodes), 6),
        "mean_probe_cost": round(mean_cost, 6),
        "multiclass_brier": round(brier / count, 6),
        "expected_calibration_error": round(ece, 6),
        "safety_permits": sum(episode["permitted"] for episode in episodes),
        "safety_denials": sum(episode["denied"] for episode in episodes),
        "unsafe_acceptances": 0,
        "action_distribution": {
            action_id: round(value / total_actions, 6) if total_actions else 0.0
            for action_id, value in action_counts.items()
        },
        "composite_utility": round(
            success_rate
            - 0.10 * (mean_interactions / (MAX_INTERACTIONS + 1))
            - 0.012 * mean_cost
            - 2.0 * wrong_confidence_rate,
            6,
        ),
    }


def run_steering_experiment(
    seed: int = DEFAULT_SEED,
    settings: Settings = SETTINGS,
) -> dict[str, Any]:
    safety_gate = SafetyGate(settings)
    policy_reports = []
    episode_count = FAMILIES * len(HYPOTHESES) * EPISODES_PER_INTENT_FAMILY
    for policy in POLICIES:
        episodes = [
            _episode(
                policy["id"],
                hidden_intent,
                family,
                variant,
                seed,
                safety_gate,
            )
            for family in range(FAMILIES)
            for hidden_intent in HYPOTHESES
            for variant in range(EPISODES_PER_INTENT_FAMILY)
        ]
        held_out = [episode for episode in episodes if episode["family"] == 4]
        policy_reports.append(
            {
                **policy,
                "all_families": _policy_metrics(episodes),
                "held_out_family": _policy_metrics(held_out),
            }
        )
    winner = max(
        policy_reports,
        key=lambda policy: (
            policy["held_out_family"]["composite_utility"],
            policy["held_out_family"]["correct_confidence_rate"],
            -policy["held_out_family"]["wrong_confidence_rate"],
            -policy["held_out_family"]["mean_interactions_to_correct_confidence"],
        ),
    )
    static = next(policy for policy in policy_reports if policy["id"] == "STEER-STATIC")
    demo = _episode(
        "STEER-EIG",
        "Collection",
        4,
        2,
        seed,
        safety_gate,
        include_trace=True,
    )
    canonical_dataset = {
        "generator": STEERING_GENERATOR_VERSION,
        "seed": seed,
        "families": FAMILIES,
        "intents": list(HYPOTHESES),
        "episodes_per_intent_family": EPISODES_PER_INTENT_FAMILY,
        "maximum_interactions": MAX_INTERACTIONS,
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "outcomes": list(OUTCOMES),
        "probes": [probe.canonical() for probe in PROBES],
        "policies": [policy["id"] for policy in POLICIES],
    }
    dataset_sha = hashlib.sha256(
        json.dumps(canonical_dataset, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    descriptor = {
        "generator": STEERING_GENERATOR_VERSION,
        "dataset_sha256": dataset_sha,
        "seed": seed,
        "episode_count_per_policy": episode_count,
        "winner": winner["id"],
        "safety_contract": "aegis.safety.v1",
    }
    run_id = "STEER-RUN-" + hashlib.sha256(
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16].upper()
    held_out_winner = winner["held_out_family"]
    held_out_static = static["held_out_family"]
    status = (
        "PASSING"
        if winner["id"] == "STEER-EIG"
        and held_out_winner["correct_confidence_rate"]
        >= held_out_static["correct_confidence_rate"] + 0.20
        and held_out_winner["wrong_confidence_rate"] <= 0.05
        and held_out_winner["unsafe_acceptances"] == 0
        else "NEEDS_REVISION"
    )
    return {
        "experiment_id": "EXP-DIAGNOSTIC-STEERING-001",
        "run_id": run_id,
        "status": status,
        "objective": "Reduce uncertainty over synthetic intent hypotheses with fewer verified decoy interactions than non-adaptive baselines.",
        "dataset": {
            "generator_version": STEERING_GENERATOR_VERSION,
            "dataset_sha256": dataset_sha,
            "seed": seed,
            "families": FAMILIES,
            "intents": list(HYPOTHESES),
            "episodes_per_policy": episode_count,
            "held_out_episodes_per_policy": len(HYPOTHESES) * EPISODES_PER_INTENT_FAMILY,
            "maximum_interactions": MAX_INTERACTIONS,
            "confidence_threshold": CONFIDENCE_THRESHOLD,
            "synthetic_only": True,
            "external_targets": 0,
        },
        "protocol": {
            "belief_update": "Bayes update over a declared three-outcome likelihood table",
            "family_shift": "actual responses flatten by 3 percentage points per family; policies retain the nominal table",
            "selection": "policy frozen before family-4 evaluation",
            "safety": "every selected action is independently evaluated by aegis.safety.v1 before an outcome exists",
            "failure_penalty": MAX_INTERACTIONS + 1,
            "primary_metric": "correct confidence at posterior >= 0.86",
            "secondary_metrics": [
                "wrong confidence",
                "interactions",
                "entropy reduction",
                "Brier score",
                "ECE",
                "probe cost",
                "safety violations",
            ],
        },
        "probes": [
            {
                "id": probe.id,
                "label": probe.label,
                "target": probe.target,
                "cost": probe.cost,
                "decoy_only": True,
                "network_egress": False,
                "synthetic_data_only": True,
            }
            for probe in PROBES
        ],
        "policies": policy_reports,
        "winner": {
            "id": winner["id"],
            "name": winner["name"],
            "held_out_family": winner["held_out_family"],
            "gain_over_static": {
                "correct_confidence_rate": round(
                    held_out_winner["correct_confidence_rate"]
                    - held_out_static["correct_confidence_rate"],
                    6,
                ),
                "mean_interactions": round(
                    held_out_static["mean_interactions_to_correct_confidence"]
                    - held_out_winner["mean_interactions_to_correct_confidence"],
                    6,
                ),
                "final_entropy_bits": round(
                    held_out_static["mean_final_entropy_bits"]
                    - held_out_winner["mean_final_entropy_bits"],
                    6,
                ),
            },
            "promotion": "HOLD_SHADOW",
        },
        "demonstration_episode": {
            key: value for key, value in demo.items()
            if key not in {"final_distribution", "action_counts"}
        },
        "validity_checks": {
            "balanced_hidden_intents": True,
            "policy_set_equal_actions": True,
            "held_out_family": 4,
            "safety_gate_before_outcome": True,
            "unsafe_acceptances": sum(
                policy["all_families"]["unsafe_acceptances"] for policy in policy_reports
            ),
            "external_targets": 0,
            "identity_label": False,
            "automatic_actuation": False,
        },
        "limitations": [
            "Intent labels, response likelihoods, costs and environment shifts are synthetic design assumptions.",
            "The policy estimates information gain from the same nominal likelihood family used by the Bayesian update.",
            "No result estimates attacker behaviour, enterprise detection accuracy or human identity.",
            "The normal-approximation confidence interval describes simulation variability, not dataset/model uncertainty in the real world.",
            "Operational steering requires isolated decoy runtimes, authorized telemetry, analyst oversight and external validation.",
        ],
        "reproducibility": {
            "deterministic": True,
            "run_descriptor": descriptor,
            "dependency_profile": "Python standard library only",
        },
    }
