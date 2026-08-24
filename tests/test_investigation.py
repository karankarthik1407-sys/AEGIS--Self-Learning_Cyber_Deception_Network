import tempfile
import unittest
from pathlib import Path

from aegis.investigation import compare_cases, extract_features
from aegis.service import AegisService


class InvestigationTests(unittest.TestCase):
    def test_similarity_never_claims_identity(self):
        left_events = [
            {"event_type": "network_scan", "target": "decoy-edge-01", "payload": {"client_fingerprint": "same"}},
            {"event_type": "admin_route_probe", "target": "decoy-admin-portal", "payload": {"client_fingerprint": "same"}},
        ]
        right_events = [
            {"event_type": "network_scan", "target": "decoy-edge-02", "payload": {"client_fingerprint": "same"}},
            {"event_type": "admin_route_probe", "target": "decoy-admin-portal", "payload": {"client_fingerprint": "same"}},
        ]
        link = compare_cases(extract_features("A", left_events), extract_features("B", right_events))
        self.assertGreater(link["confidence"], 0.7)
        self.assertEqual(link["attribution_status"], "UNVERIFIED — CAMPAIGN LINKAGE ONLY")
        self.assertTrue(link["limitations"])

    def test_service_builds_calibrated_campaign_link(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AegisService(Path(directory) / "campaign.db")
            result = service.campaigns()
            self.assertEqual(len(result["links"]), 1)
            self.assertEqual(set(result["campaigns"][0]["linked_cases"]), {"AEGIS-26-0001", "AEGIS-26-0002"})
            self.assertIn("does not identify", result["boundary"])

    def test_bundle_is_manifested_and_scope_limited(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AegisService(Path(directory) / "bundle.db")
            bundle = service.case_bundle("AEGIS-26-0001")
            self.assertIsNotNone(bundle)
            self.assertEqual(len(bundle["manifest_sha256"]), 64)
            self.assertIn("not proof", bundle["language_boundary"])
            self.assertTrue(all("attack_mapping" in event for event in bundle["events"]))


if __name__ == "__main__":
    unittest.main()

