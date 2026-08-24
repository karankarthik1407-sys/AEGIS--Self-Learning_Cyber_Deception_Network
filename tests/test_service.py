import tempfile
import unittest
from pathlib import Path

from aegis.service import AegisService


class AegisServiceTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.service = AegisService(Path(self.tempdir.name) / "service.db")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_bootstrap_and_vertical_slice(self):
        overview = self.service.overview()
        self.assertEqual(overview["active_cases"], 2)
        self.assertEqual(overview["system_state"], "CONTAINED")

        result = self.service.simulate()
        self.assertEqual(result["case"]["evidence_count"], 2)
        self.assertGreater(result["case"]["risk_score"], 0)

        certificate = self.service.evaluate_action()
        self.assertEqual(certificate["decision"], "PERMIT")

        evidence = self.service.verify_evidence()
        self.assertTrue(evidence["valid"])
        self.assertEqual(evidence["verified_events"], 5)


if __name__ == "__main__":
    unittest.main()
