import unittest

from aegis.learning import run_learning_fabric
from aegis.research import DEFAULT_SEED


class LearningFabricTests(unittest.TestCase):
    def test_complementary_models_are_measured_under_one_split(self):
        report = run_learning_fabric(DEFAULT_SEED)
        self.assertEqual(len(report["models"]), 4)
        self.assertEqual(report["dataset"]["splits"], {"train": 144, "validation": 48, "test": 48})
        self.assertEqual(report["dataset"]["external_targets"], 0)
        self.assertGreater(report["models"][1]["test"]["macro_f1"], report["models"][0]["test"]["macro_f1"])

    def test_candidate_cannot_auto_promote(self):
        report = run_learning_fabric(DEFAULT_SEED)
        checks = {check["rule"]: check for check in report["promotion"]["checks"]}
        self.assertEqual(report["promotion"]["decision"], "HOLD_SHADOW")
        self.assertFalse(report["promotion"]["automatic_weight_updates"])
        self.assertFalse(checks["shadow_volume"]["passed"])
        self.assertFalse(checks["human_release_signoff"]["passed"])

    def test_learning_report_is_deterministic_for_fixed_inputs(self):
        first = run_learning_fabric(DEFAULT_SEED, 240)
        second = run_learning_fabric(DEFAULT_SEED, 240)
        self.assertEqual(first, second)
        self.assertEqual(len(first["run_id"]), 20)


if __name__ == "__main__":
    unittest.main()
