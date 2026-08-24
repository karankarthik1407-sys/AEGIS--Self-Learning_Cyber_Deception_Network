import unittest

from aegis.belief import summarize, uniform_prior, update_beliefs


class BeliefEngineTests(unittest.TestCase):
    def test_distribution_remains_normalized(self):
        beliefs = update_beliefs(uniform_prior(), "network_scan")
        self.assertAlmostEqual(sum(beliefs.values()), 1.0, places=9)
        self.assertEqual(summarize(beliefs)["top_hypothesis"], "Reconnaissance")

    def test_diagnostic_evidence_changes_leading_hypothesis(self):
        beliefs = uniform_prior()
        beliefs = update_beliefs(beliefs, "ssh_login_failure")
        beliefs = update_beliefs(beliefs, "synthetic_credential_opened")
        summary = summarize(beliefs)
        self.assertEqual(summary["top_hypothesis"], "Credential Access")
        self.assertGreater(summary["top_probability"], 0.8)


if __name__ == "__main__":
    unittest.main()
