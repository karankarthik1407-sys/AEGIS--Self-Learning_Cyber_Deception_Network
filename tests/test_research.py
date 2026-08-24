import unittest

from aegis.research import DEFAULT_SEED, SyntheticIntentCorpus, run_intent_experiment


class ResearchExperimentTests(unittest.TestCase):
    def test_family_grouped_split_is_balanced_and_disjoint(self):
        corpus = SyntheticIntentCorpus()
        split = corpus.split(corpus.generate(DEFAULT_SEED))
        family_sets = {name: {sample.family for sample in samples} for name, samples in split.items()}
        self.assertEqual(family_sets["train"], {0, 1, 2})
        self.assertEqual(family_sets["validation"], {3})
        self.assertEqual(family_sets["test"], {4})
        self.assertTrue(family_sets["train"].isdisjoint(family_sets["test"]))
        self.assertEqual([len(split[name]) for name in ("train", "validation", "test")], [144, 48, 48])

    def test_experiment_is_deterministic_and_beats_uniform_baseline(self):
        first = run_intent_experiment(DEFAULT_SEED)
        second = run_intent_experiment(DEFAULT_SEED)
        self.assertEqual(first, second)
        self.assertGreater(first["metrics"]["accuracy"], 0.70)
        self.assertGreater(first["metrics"]["macro_f1"], 0.70)
        self.assertGreater(first["delta_over_baseline"]["accuracy"], 0.40)
        self.assertEqual(first["dataset"]["external_targets"], 0)

    def test_calibration_and_provenance_contracts_are_complete(self):
        report = run_intent_experiment(DEFAULT_SEED)
        self.assertEqual(len(report["metrics"]["reliability"]), 10)
        self.assertEqual(len(report["metrics"]["confusion_matrix"]["rows"]), 4)
        self.assertEqual(len(report["dataset"]["dataset_sha256"]), 64)
        self.assertTrue(0 <= report["metrics"]["expected_calibration_error"] <= 1)
        self.assertTrue(report["reproducibility"]["deterministic"])


if __name__ == "__main__":
    unittest.main()
