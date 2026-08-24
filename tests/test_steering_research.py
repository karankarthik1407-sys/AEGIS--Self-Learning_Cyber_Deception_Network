import unittest

from aegis.belief import HYPOTHESES, uniform_prior
from aegis.research import DEFAULT_SEED
from aegis.steering_research import (
    OUTCOMES,
    PROBES,
    expected_information_gain,
    posterior,
    run_steering_experiment,
)


class DiagnosticSteeringResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_steering_experiment(DEFAULT_SEED)

    def test_probe_likelihoods_are_complete_normalized_and_decoy_only(self):
        for probe in PROBES:
            self.assertTrue(probe.target.startswith("decoy-"))
            self.assertGreater(probe.cost, 0)
            self.assertEqual(set(probe.likelihoods), set(HYPOTHESES))
            for distribution in probe.likelihoods.values():
                self.assertEqual(set(distribution), set(OUTCOMES))
                self.assertAlmostEqual(sum(distribution.values()), 1.0)

    def test_bayesian_outcome_update_is_normalized_and_informative(self):
        prior = uniform_prior()
        updated = posterior(prior, PROBES[0], "engage")
        self.assertAlmostEqual(sum(updated.values()), 1.0)
        self.assertGreater(updated["Reconnaissance"], prior["Reconnaissance"])
        self.assertGreater(expected_information_gain(prior, PROBES[0]), 0.0)

    def test_experiment_is_deterministic_and_manifested(self):
        again = run_steering_experiment(DEFAULT_SEED)
        self.assertEqual(self.report, again)
        self.assertEqual(len(self.report["dataset"]["dataset_sha256"]), 64)
        self.assertTrue(self.report["run_id"].startswith("STEER-RUN-"))

    def test_comparators_share_balanced_episode_and_action_contracts(self):
        episode_counts = {
            policy["all_families"]["episodes"] for policy in self.report["policies"]
        }
        self.assertEqual(episode_counts, {480})
        self.assertTrue(self.report["validity_checks"]["balanced_hidden_intents"])
        self.assertTrue(self.report["validity_checks"]["policy_set_equal_actions"])
        self.assertEqual(len(self.report["probes"]), 4)

    def test_information_gain_candidate_beats_static_held_out_baseline(self):
        policies = {policy["id"]: policy for policy in self.report["policies"]}
        static = policies["STEER-STATIC"]["held_out_family"]
        candidate = policies["STEER-EIG"]["held_out_family"]
        self.assertGreaterEqual(
            candidate["correct_confidence_rate"],
            static["correct_confidence_rate"] + 0.35,
        )
        self.assertLess(
            candidate["mean_interactions_to_correct_confidence"],
            static["mean_interactions_to_correct_confidence"],
        )
        self.assertLess(candidate["mean_final_entropy_bits"], static["mean_final_entropy_bits"])

    def test_every_executed_probe_is_safety_verified_before_outcome(self):
        self.assertTrue(self.report["validity_checks"]["safety_gate_before_outcome"])
        self.assertEqual(self.report["validity_checks"]["unsafe_acceptances"], 0)
        for policy in self.report["policies"]:
            self.assertEqual(policy["all_families"]["safety_denials"], 0)
            self.assertGreater(policy["all_families"]["safety_permits"], 0)

    def test_candidate_passes_research_protocol_but_remains_shadow(self):
        self.assertEqual(self.report["status"], "PASSING")
        self.assertEqual(self.report["winner"]["id"], "STEER-EIG")
        self.assertEqual(self.report["winner"]["promotion"], "HOLD_SHADOW")
        self.assertLessEqual(
            self.report["winner"]["held_out_family"]["wrong_confidence_rate"], 0.05
        )

    def test_validity_boundary_excludes_identity_external_targets_and_actuation(self):
        checks = self.report["validity_checks"]
        self.assertEqual(checks["held_out_family"], 4)
        self.assertEqual(checks["external_targets"], 0)
        self.assertFalse(checks["identity_label"])
        self.assertFalse(checks["automatic_actuation"])
        self.assertTrue(
            all(step["safety_decision"] == "PERMIT" for step in self.report["demonstration_episode"]["trace"])
        )


if __name__ == "__main__":
    unittest.main()
