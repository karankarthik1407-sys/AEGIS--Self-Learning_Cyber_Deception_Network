import unittest

from aegis.research import DEFAULT_SEED
from aegis.trace_graph_research import (
    clustering_metrics,
    exhaustive_pairs,
    run_trace_graph_experiment,
    sessions_for_family,
)
from aegis.trace_research import SyntheticTraceCorpus


class TraceGraphResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_trace_graph_experiment(DEFAULT_SEED)

    def test_exhaustive_environment_graph_has_expected_pair_contract(self):
        sessions = SyntheticTraceCorpus().generate_sessions(DEFAULT_SEED)
        graph_sessions = sessions_for_family(sessions, 4)
        pairs = exhaustive_pairs(graph_sessions)
        self.assertEqual(len(graph_sessions), 48)
        self.assertEqual(len(pairs), 1128)
        self.assertEqual(sum(pair.label for pair in pairs), 120)
        self.assertTrue(all(pair.family == 4 for pair in pairs))

    def test_b_cubed_and_pairwise_metrics_are_exact_for_perfect_clusters(self):
        truth = {"a": "x", "b": "x", "c": "y", "d": "y"}
        metrics = clustering_metrics(truth, [["a", "b"], ["c", "d"]])
        self.assertEqual(metrics["b_cubed_f1"], 1.0)
        self.assertEqual(metrics["pairwise_f1"], 1.0)
        self.assertEqual(metrics["false_merge_rate"], 0.0)

    def test_graph_experiment_is_deterministic_and_manifested(self):
        again = run_trace_graph_experiment(DEFAULT_SEED)
        self.assertEqual(self.report, again)
        self.assertEqual(len(self.report["dataset"]["dataset_sha256"]), 64)
        self.assertTrue(self.report["run_id"].startswith("GRAPH-RUN-"))

    def test_guard_rejects_every_adversarial_transitive_bridge(self):
        audit = self.report["bridge_audit"]
        self.assertEqual(audit["injected"], 7)
        self.assertEqual(audit["evaluated"], 7)
        self.assertEqual(audit["rejected"], 7)
        self.assertTrue(all(item["decision"] == "REJECT" for item in audit["decisions"]))

    def test_guard_beats_naive_transitive_closure_under_stress(self):
        methods = {method["id"]: method for method in self.report["methods"]}
        naive = methods["GRAPH-PAIRWISE-CC"]["stress"]
        guarded = methods["GRAPH-COHORT-GUARD"]["stress"]
        self.assertGreater(guarded["b_cubed_f1"], naive["b_cubed_f1"] + 0.35)
        self.assertLess(guarded["false_merge_rate"], naive["false_merge_rate"])
        self.assertEqual(guarded["false_merge_rate"], 0.0)

    def test_graph_candidate_passes_but_remains_shadow_only(self):
        self.assertEqual(self.report["status"], "PASSING")
        self.assertEqual(self.report["winner"]["promotion"], "HOLD_SHADOW")
        self.assertGreaterEqual(self.report["winner"]["stress"]["b_cubed_f1"], 0.85)

    def test_validity_contract_excludes_identity_raw_ip_and_external_targets(self):
        checks = self.report["validity_checks"]
        self.assertTrue(checks["family_disjoint"])
        self.assertFalse(checks["test_family_used_for_training"])
        self.assertFalse(checks["raw_ip_feature"])
        self.assertFalse(checks["identity_label"])
        self.assertFalse(checks["automatic_attribution"])
        self.assertEqual(checks["external_targets"], 0)


if __name__ == "__main__":
    unittest.main()
