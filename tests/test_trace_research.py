import unittest

from aegis.research import DEFAULT_SEED
from aegis.trace_research import SyntheticTraceCorpus, run_trace_experiment


class ThreatTraceResearchTests(unittest.TestCase):
    def test_grouped_pair_split_is_balanced_and_disjoint(self):
        corpus = SyntheticTraceCorpus()
        splits = corpus.split(corpus.generate_pairs(DEFAULT_SEED))
        family_sets = {
            name: {pair.family for pair in pairs}
            for name, pairs in splits.items()
        }
        self.assertEqual(family_sets, {
            "train": {0, 1, 2},
            "validation": {3},
            "test": {4},
        })
        self.assertEqual([len(splits[name]) for name in ("train", "validation", "test")], [144, 48, 48])
        for pairs in splits.values():
            self.assertEqual(sum(pair.label for pair in pairs) * 2, len(pairs))

    def test_trace_experiment_is_deterministic(self):
        first = run_trace_experiment(DEFAULT_SEED)
        second = run_trace_experiment(DEFAULT_SEED)
        self.assertEqual(first, second)
        self.assertEqual(len(first["dataset"]["dataset_sha256"]), 64)
        self.assertEqual(first["dataset"]["sessions"], 240)
        self.assertEqual(first["dataset"]["pairs"], 240)

    def test_learned_multisignal_candidate_beats_source_only_baseline(self):
        report = run_trace_experiment(DEFAULT_SEED)
        models = {model["id"]: model for model in report["models"]}
        source = models["TRACE-IP-ONLY"]["test"]
        learned = models["TRACE-LOGISTIC-CANDIDATE"]["test"]
        self.assertGreater(learned["f1"], source["f1"] + 0.50)
        self.assertLess(learned["false_link_rate"], source["false_link_rate"])
        self.assertLess(learned["brier"], source["brier"])

    def test_validity_contract_blocks_identity_and_external_target_claims(self):
        report = run_trace_experiment(DEFAULT_SEED)
        self.assertEqual(report["status"], "PASSING")
        self.assertTrue(report["validity_checks"]["family_disjoint"])
        self.assertFalse(report["validity_checks"]["raw_ip_feature"])
        self.assertFalse(report["validity_checks"]["identity_label"])
        self.assertEqual(report["validity_checks"]["external_targets"], 0)
        self.assertEqual(report["winner"]["promotion"], "HOLD_SHADOW")
        self.assertEqual(len(report["winner"]["test"]["reliability"]), 10)


if __name__ == "__main__":
    unittest.main()
