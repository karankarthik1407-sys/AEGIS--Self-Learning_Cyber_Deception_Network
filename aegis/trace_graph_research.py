from __future__ import annotations

import hashlib
import json
import statistics
from dataclasses import dataclass
from itertools import combinations
from typing import Any, Iterable

from .research import DEFAULT_SEED
from .trace import EvidenceDiversityLinker
from .trace_research import (
    BinaryLogisticLinker,
    SyntheticTraceCorpus,
    SyntheticTraceSession,
    TracePair,
    _best_temperature,
    _best_threshold,
    pair_features,
)


TRACE_GRAPH_VERSION = "aegis.synthetic-trace-graph.v1"
MAX_CAMPAIGN_CLUSTER_SIZE = 8


@dataclass(frozen=True)
class ScoredEdge:
    left: str
    right: str
    probability: float
    matched_families: tuple[str, ...]
    edge_type: str = "observed"

    @property
    def key(self) -> tuple[str, str]:
        return tuple(sorted((self.left, self.right)))


def sessions_for_family(
    sessions: Iterable[SyntheticTraceSession], family: int
) -> list[SyntheticTraceSession]:
    return sorted(
        (session for session in sessions if session.family == family),
        key=lambda session: session.session_id,
    )


def exhaustive_pairs(sessions: Iterable[SyntheticTraceSession]) -> list[TracePair]:
    values = list(sessions)
    pairs = []
    for left, right in combinations(values, 2):
        if left.family != right.family:
            raise ValueError("graph pairs must remain inside one environment family")
        label = int(left.campaign_id == right.campaign_id)
        pairs.append(
            TracePair(
                pair_id=f"GRAPH-{left.session_id}--{right.session_id}",
                family=left.family,
                label=label,
                left=left.profile,
                right=right.profile,
                pair_type="same-campaign" if label else "cross-campaign",
            )
        )
    return pairs


def _truth_labels(sessions: Iterable[SyntheticTraceSession]) -> dict[str, str]:
    return {session.session_id: session.campaign_id for session in sessions}


def _cluster_labels(clusters: Iterable[Iterable[str]]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for index, cluster in enumerate(clusters):
        for member in cluster:
            labels[member] = f"CLUSTER-{index:02d}"
    return labels


def clustering_metrics(
    truth: dict[str, str], clusters: Iterable[Iterable[str]]
) -> dict[str, Any]:
    cluster_list = [sorted(cluster) for cluster in clusters]
    predicted = _cluster_labels(cluster_list)
    if set(predicted) != set(truth):
        raise ValueError("predicted clusters must cover each session exactly once")

    by_predicted: dict[str, set[str]] = {}
    by_truth: dict[str, set[str]] = {}
    for member, label in predicted.items():
        by_predicted.setdefault(label, set()).add(member)
    for member, label in truth.items():
        by_truth.setdefault(label, set()).add(member)

    member_precision = []
    member_recall = []
    for member in sorted(truth):
        predicted_group = by_predicted[predicted[member]]
        truth_group = by_truth[truth[member]]
        overlap = len(predicted_group & truth_group)
        member_precision.append(overlap / len(predicted_group))
        member_recall.append(overlap / len(truth_group))
    bcubed_precision = sum(member_precision) / len(member_precision)
    bcubed_recall = sum(member_recall) / len(member_recall)
    bcubed_f1 = (
        2 * bcubed_precision * bcubed_recall / (bcubed_precision + bcubed_recall)
        if bcubed_precision + bcubed_recall
        else 0.0
    )

    tp = fp = fn = tn = 0
    members = sorted(truth)
    for left, right in combinations(members, 2):
        actual = truth[left] == truth[right]
        inferred = predicted[left] == predicted[right]
        tp += int(actual and inferred)
        fp += int(not actual and inferred)
        fn += int(actual and not inferred)
        tn += int(not actual and not inferred)
    pair_precision = tp / (tp + fp) if tp + fp else 0.0
    pair_recall = tp / (tp + fn) if tp + fn else 0.0
    pair_f1 = (
        2 * pair_precision * pair_recall / (pair_precision + pair_recall)
        if pair_precision + pair_recall
        else 0.0
    )
    purity = sum(
        max(
            sum(1 for member in cluster if truth[member] == truth_label)
            for truth_label in by_truth
        )
        for cluster in cluster_list
    ) / len(truth)
    split_campaigns = sum(
        len({predicted[member] for member in members_of_truth}) > 1
        for members_of_truth in by_truth.values()
    )
    return {
        "b_cubed_precision": round(bcubed_precision, 6),
        "b_cubed_recall": round(bcubed_recall, 6),
        "b_cubed_f1": round(bcubed_f1, 6),
        "pairwise_precision": round(pair_precision, 6),
        "pairwise_recall": round(pair_recall, 6),
        "pairwise_f1": round(pair_f1, 6),
        "purity": round(purity, 6),
        "false_merge_rate": round(fp / (tp + fp), 6) if tp + fp else 0.0,
        "split_campaign_rate": round(split_campaigns / len(by_truth), 6),
        "clusters": len(cluster_list),
        "largest_cluster": max(map(len, cluster_list), default=0),
        "pair_confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


class _UnionFind:
    def __init__(self, members: Iterable[str]):
        self.parent = {member: member for member in members}
        self.groups = {member: {member} for member in members}

    def find(self, member: str) -> str:
        parent = self.parent[member]
        if parent != member:
            self.parent[member] = self.find(parent)
        return self.parent[member]

    def members(self, member: str) -> set[str]:
        return self.groups[self.find(member)]

    def union(self, left: str, right: str) -> bool:
        left_root, right_root = self.find(left), self.find(right)
        if left_root == right_root:
            return False
        if len(self.groups[left_root]) < len(self.groups[right_root]):
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        self.groups[left_root].update(self.groups.pop(right_root))
        return True

    def clusters(self) -> list[list[str]]:
        return sorted(
            (sorted(group) for group in self.groups.values()),
            key=lambda group: (group[0], len(group)),
        )


def connected_components(
    members: Iterable[str], edges: Iterable[ScoredEdge], threshold: float
) -> list[list[str]]:
    union_find = _UnionFind(members)
    for edge in sorted(edges, key=lambda value: (-value.probability, value.key)):
        if edge.probability >= threshold:
            union_find.union(edge.left, edge.right)
    return union_find.clusters()


def guarded_components(
    members: Iterable[str],
    edges: Iterable[ScoredEdge],
    threshold: float,
    max_cluster_size: int = MAX_CAMPAIGN_CLUSTER_SIZE,
    seed_threshold: float = 0.70,
    minimum_cross_support: float = 0.45,
) -> tuple[list[list[str]], list[dict[str, Any]]]:
    edge_list = list(edges)
    lookup = {edge.key: edge.probability for edge in edge_list}
    union_find = _UnionFind(members)
    decisions = []
    for edge in sorted(edge_list, key=lambda value: (-value.probability, value.key)):
        if edge.probability < threshold:
            continue
        left_group, right_group = union_find.members(edge.left), union_find.members(edge.right)
        if left_group == right_group:
            continue
        cross_scores = [
            lookup.get(tuple(sorted((left, right))), 0.0)
            for left in left_group
            for right in right_group
        ]
        support = sum(score >= threshold for score in cross_scores) / len(cross_scores)
        mean_probability = sum(cross_scores) / len(cross_scores)
        median_probability = statistics.median(cross_scores)
        proposed_size = len(left_group) + len(right_group)
        # A single edge may seed a cohort only when it clears a deliberately
        # higher bar. Once a cohort exists, multiple cross-pair observations
        # must agree; this is what prevents an otherwise plausible bridge from
        # gaining the power of ordinary transitive closure.
        singleton_gate = edge.probability >= seed_threshold
        cohort_gate = (
            support >= minimum_cross_support
            and mean_probability >= threshold + 0.04
            and median_probability >= threshold
        )
        allowed = (
            proposed_size <= max_cluster_size
            and len(edge.matched_families) >= 3
            and (singleton_gate if len(cross_scores) == 1 else cohort_gate)
        )
        reason = (
            "MERGED_COHORT_SUPPORT"
            if allowed
            else "REJECT_MAX_CLUSTER"
            if proposed_size > max_cluster_size
            else "REJECT_EVIDENCE_DIVERSITY"
            if len(edge.matched_families) < 3
            else "REJECT_TRANSITIVE_BRIDGE"
        )
        if edge.edge_type == "bridge_stress" or allowed:
            decisions.append(
                {
                    "left": edge.left,
                    "right": edge.right,
                    "edge_type": edge.edge_type,
                    "edge_probability": round(edge.probability, 6),
                    "cross_support": round(support, 6),
                    "mean_cross_probability": round(mean_probability, 6),
                    "proposed_cluster_size": proposed_size,
                    "decision": "MERGE" if allowed else "REJECT",
                    "reason": reason,
                }
            )
        if allowed:
            union_find.union(edge.left, edge.right)
    return union_find.clusters(), decisions


def _score_pairs(
    pairs: Iterable[TracePair],
    model: BinaryLogisticLinker,
    linker: EvidenceDiversityLinker,
    temperature: float,
) -> list[ScoredEdge]:
    edges = []
    for pair in pairs:
        features, score = pair_features(pair, linker)
        edges.append(
            ScoredEdge(
                left=pair.left.session_id,
                right=pair.right.session_id,
                probability=model.probability(features, temperature),
                matched_families=tuple(score["matched_families"]),
            )
        )
    return edges


def _source_edges(
    pairs: Iterable[TracePair], linker: EvidenceDiversityLinker
) -> list[ScoredEdge]:
    edges = []
    for pair in pairs:
        _, score = pair_features(pair, linker)
        source = next(
            result for result in score["family_results"] if result["family"] == "source"
        )
        if source["similarity"] > 0:
            edges.append(
                ScoredEdge(
                    left=pair.left.session_id,
                    right=pair.right.session_id,
                    probability=0.82,
                    matched_families=("source",),
                    edge_type="source_only",
                )
            )
    return edges


def _inject_bridges(
    edges: list[ScoredEdge],
    sessions: list[SyntheticTraceSession],
    threshold: float,
) -> tuple[list[ScoredEdge], list[tuple[str, str]]]:
    by_campaign_variant = {
        (session.campaign_id, session.variant): session.session_id for session in sessions
    }
    bridge_probability = min(0.86, max(0.68, threshold + 0.12))
    overrides = {}
    bridge_keys = []
    for campaign in range(7):
        left = by_campaign_variant[(f"CMP-{campaign}", 0)]
        right = by_campaign_variant[(f"CMP-{campaign + 1}", 0)]
        key = tuple(sorted((left, right)))
        overrides[key] = ScoredEdge(
            left=left,
            right=right,
            probability=bridge_probability,
            matched_families=("transport", "tooling", "behavior"),
            edge_type="bridge_stress",
        )
        bridge_keys.append(key)
    stressed = [overrides.get(edge.key, edge) for edge in edges]
    return stressed, bridge_keys


def _select_graph_guard(
    members: list[str],
    edges: list[ScoredEdge],
    sessions: list[SyntheticTraceSession],
    truth: dict[str, str],
    pair_threshold: float,
) -> dict[str, float]:
    stressed_edges, _ = _inject_bridges(edges, sessions, pair_threshold)
    candidates = []
    for association_threshold in (0.16, 0.20, 0.24, 0.28, 0.32, 0.36, 0.40):
        for seed_threshold in (0.62, 0.66, 0.70, 0.74, 0.78, 0.82):
            for minimum_cross_support in (0.35, 0.45, 0.55, 0.65):
                clusters, decisions = guarded_components(
                    members,
                    stressed_edges,
                    association_threshold,
                    seed_threshold=seed_threshold,
                    minimum_cross_support=minimum_cross_support,
                )
                metrics = clustering_metrics(truth, clusters)
                bridge_merges = sum(
                    decision["edge_type"] == "bridge_stress"
                    and decision["decision"] == "MERGE"
                    for decision in decisions
                )
                score = (
                    metrics["b_cubed_f1"]
                    - metrics["false_merge_rate"]
                    - 0.20 * metrics["split_campaign_rate"]
                    - 0.05 * bridge_merges
                )
                candidates.append(
                    (
                        score,
                        metrics["b_cubed_f1"],
                        -metrics["false_merge_rate"],
                        -metrics["split_campaign_rate"],
                        -association_threshold,
                        -seed_threshold,
                        -minimum_cross_support,
                        {
                            "association_threshold": association_threshold,
                            "seed_threshold": seed_threshold,
                            "minimum_cross_support": minimum_cross_support,
                        },
                    )
                )
    return max(candidates)[-1]


def _cluster_preview(
    clusters: list[list[str]], truth: dict[str, str]
) -> list[dict[str, Any]]:
    previews = []
    for index, members in enumerate(sorted(clusters, key=lambda value: (-len(value), value))):
        campaign_counts: dict[str, int] = {}
        for member in members:
            campaign_counts[truth[member]] = campaign_counts.get(truth[member], 0) + 1
        previews.append(
            {
                "id": f"CLUSTER-{index + 1:02d}",
                "size": len(members),
                "campaign_composition": dict(sorted(campaign_counts.items())),
                "members": members,
            }
        )
    return previews


def run_trace_graph_experiment(seed: int = DEFAULT_SEED) -> dict[str, Any]:
    corpus = SyntheticTraceCorpus()
    all_sessions = corpus.generate_sessions(seed)
    partitions = {
        "train": [session for session in all_sessions if session.family <= 2],
        "validation": sessions_for_family(all_sessions, 3),
        "test": sessions_for_family(all_sessions, 4),
    }
    # Reuse the balanced, hard-negative pair protocol from EXP-TRACE rather
    # than teaching the pair model on the exhaustive graph. The graph layer
    # then sees every validation/test pair, preserving a clean separation
    # between local edge learning and global clustering evaluation.
    train_pairs = SyntheticTraceCorpus.split(corpus.generate_pairs(seed))["train"]
    validation_pairs = exhaustive_pairs(partitions["validation"])
    test_pairs = exhaustive_pairs(partitions["test"])

    linker = EvidenceDiversityLinker()
    train_rows = [(pair_features(pair, linker)[0], pair.label) for pair in train_pairs]
    validation_features = [pair_features(pair, linker)[0] for pair in validation_pairs]
    validation_labels = [pair.label for pair in validation_pairs]
    model = BinaryLogisticLinker(learning_rate=0.18, epochs=900, l2=0.025).fit(train_rows)
    temperature = _best_temperature(model, validation_features, validation_labels)
    validation_probabilities = [
        model.probability(features, temperature) for features in validation_features
    ]
    threshold = _best_threshold(validation_labels, validation_probabilities)
    validation_edges = _score_pairs(validation_pairs, model, linker, temperature)
    graph_guard = _select_graph_guard(
        [session.session_id for session in partitions["validation"]],
        validation_edges,
        partitions["validation"],
        _truth_labels(partitions["validation"]),
        threshold,
    )
    clean_edges = _score_pairs(test_pairs, model, linker, temperature)
    stressed_edges, bridge_keys = _inject_bridges(clean_edges, partitions["test"], threshold)

    members = [session.session_id for session in partitions["test"]]
    truth = _truth_labels(partitions["test"])
    source_clusters = connected_components(members, _source_edges(test_pairs, linker), 0.5)
    naive_clean = connected_components(members, clean_edges, threshold)
    naive_stress = connected_components(members, stressed_edges, threshold)
    guarded_clean, clean_decisions = guarded_components(
        members,
        clean_edges,
        graph_guard["association_threshold"],
        seed_threshold=graph_guard["seed_threshold"],
        minimum_cross_support=graph_guard["minimum_cross_support"],
    )
    guarded_stress, stress_decisions = guarded_components(
        members,
        stressed_edges,
        graph_guard["association_threshold"],
        seed_threshold=graph_guard["seed_threshold"],
        minimum_cross_support=graph_guard["minimum_cross_support"],
    )

    methods = [
        {
            "id": "GRAPH-SOURCE-CC",
            "name": "Source-reference connected components",
            "role": "Failure baseline: a shared address reference creates an unconditional edge.",
            "status": "BASELINE",
            "stress": clustering_metrics(truth, source_clusters),
        },
        {
            "id": "GRAPH-PAIRWISE-CC",
            "name": "Naive learned-edge components",
            "role": "Strong local pair scores, but ordinary transitive closure accepts bridge chains.",
            "status": "BASELINE",
            "clean": clustering_metrics(truth, naive_clean),
            "stress": clustering_metrics(truth, naive_stress),
        },
        {
            "id": "GRAPH-COHORT-GUARD",
            "name": "AEGIS cohort-supported graph guard",
            "role": "Requires evidence diversity and cluster-level cross-support before every merge.",
            "status": "SHADOW_CANDIDATE",
            "clean": clustering_metrics(truth, guarded_clean),
            "stress": clustering_metrics(truth, guarded_stress),
        },
    ]
    winner = methods[-1]
    stress_bridge_decisions = [
        decision for decision in stress_decisions if decision["edge_type"] == "bridge_stress"
    ]

    canonical_dataset = {
        "generator": TRACE_GRAPH_VERSION,
        "seed": seed,
        "sessions": [session.canonical() for session in all_sessions],
        "partition_family_ids": {"train": [0, 1, 2], "validation": [3], "test": [4]},
        "pair_counts": {
            "train": len(train_pairs),
            "validation": len(validation_pairs),
            "test": len(test_pairs),
        },
    }
    dataset_sha = hashlib.sha256(
        json.dumps(canonical_dataset, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    descriptor = {
        "generator": TRACE_GRAPH_VERSION,
        "dataset_sha256": dataset_sha,
        "seed": seed,
        "split": "environment-family-grouped-3/1/1",
        "threshold": threshold,
        "temperature": temperature,
        "graph_guard": graph_guard,
        "stress_bridges": len(bridge_keys),
        "guard": "diversity+cross-support+size-cap.v1",
    }
    run_id = "GRAPH-RUN-" + hashlib.sha256(
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16].upper()
    status = (
        "PASSING"
        if winner["stress"]["b_cubed_f1"] >= 0.85
        and winner["stress"]["false_merge_rate"] <= 0.05
        and all(decision["decision"] == "REJECT" for decision in stress_bridge_decisions)
        else "NEEDS_REVISION"
    )
    return {
        "experiment_id": "EXP-TRACE-GRAPH-001",
        "run_id": run_id,
        "status": status,
        "objective": "Form campaign-level activity clusters without allowing one locally plausible edge to trigger unsupported transitive merges.",
        "dataset": {
            "generator_version": TRACE_GRAPH_VERSION,
            "dataset_sha256": dataset_sha,
            "seed": seed,
            "sessions": len(all_sessions),
            "graph_test_nodes": len(partitions["test"]),
            "pair_counts": canonical_dataset["pair_counts"],
            "positive_test_pairs": sum(pair.label for pair in test_pairs),
            "negative_test_pairs": sum(1 - pair.label for pair in test_pairs),
            "family_ids": canonical_dataset["partition_family_ids"],
            "synthetic_only": True,
            "external_targets": 0,
        },
        "protocol": {
            "pair_model": "diversity-feature logistic linker",
            "calibration": "temperature and threshold selected on family 3 only",
            "test_family": 4,
            "threshold": round(threshold, 4),
            "temperature": temperature,
            "association_threshold": graph_guard["association_threshold"],
            "seed_threshold": graph_guard["seed_threshold"],
            "stress_test": "seven cross-campaign bridge edges form a chain across all eight campaigns",
            "max_cluster_size": MAX_CAMPAIGN_CLUSTER_SIZE,
            "minimum_evidence_families": 3,
            "minimum_cross_support": graph_guard["minimum_cross_support"],
        },
        "methods": methods,
        "winner": {
            "id": winner["id"],
            "name": winner["name"],
            "clean": winner["clean"],
            "stress": winner["stress"],
            "promotion": "HOLD_SHADOW",
        },
        "bridge_audit": {
            "injected": len(bridge_keys),
            "evaluated": len(stress_bridge_decisions),
            "rejected": sum(
                decision["decision"] == "REJECT" for decision in stress_bridge_decisions
            ),
            "decisions": stress_bridge_decisions,
        },
        "cluster_preview": _cluster_preview(guarded_stress, truth),
        "validity_checks": {
            "family_disjoint": True,
            "test_family_used_for_training": False,
            "all_pairs_evaluated": len(test_pairs) == 1128,
            "raw_ip_feature": False,
            "identity_label": False,
            "external_targets": 0,
            "automatic_attribution": False,
            "bridge_rejections_auditable": len(stress_bridge_decisions) == len(bridge_keys),
        },
        "limitations": [
            "This is a deterministic synthetic clustering stress test, not an operational attribution result.",
            "The graph represents activity sessions and campaign hypotheses, never a person, organization or state.",
            "Maximum cluster size is a research guardrail and must be recalibrated on authorized enterprise data.",
            "Temporal graph neural networks remain a future comparator; this release establishes an interpretable safety baseline first.",
        ],
        "reproducibility": {
            "deterministic": True,
            "run_descriptor": descriptor,
            "dependency_profile": "Python standard library only",
            "clean_merge_audit_records": len(clean_decisions),
        },
    }
