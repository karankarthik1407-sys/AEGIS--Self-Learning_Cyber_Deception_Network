import ipaddress
import json
import tempfile
import unittest
from pathlib import Path

from aegis.agent import LocalNodeAgent
from aegis.sensor_gateway import (
    MAX_RECORDS,
    SAMPLE_RECORDS,
    GatewayValidationError,
    SensorEvidenceGateway,
)
from aegis.store import AegisStore


def contains_raw_ip(value):
    if isinstance(value, dict):
        return any(contains_raw_ip(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_raw_ip(item) for item in value)
    if not isinstance(value, str):
        return False
    for token in value.replace("[", " ").replace("]", " ").replace(",", " ").split():
        try:
            ipaddress.ip_address(token.strip(".;:()"))
            return True
        except ValueError:
            pass
    return False


class SensorEvidenceGatewayTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.store = AegisStore(root / "gateway.db")
        self.gateway = SensorEvidenceGateway(self.store, LocalNodeAgent(root).node_id)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_status_advertises_offline_privacy_boundary(self):
        status = self.gateway.status()
        self.assertEqual(len(status["connectors"]), 2)
        self.assertFalse(status["privacy"]["raw_ip_persisted"])
        self.assertFalse(status["privacy"]["packet_content_persisted"])
        self.assertFalse(status["privacy"]["outbound_connection"])
        self.assertFalse(status["privacy"]["automatic_case_promotion"])

    def test_suricata_preview_pseudonymizes_and_discards_content(self):
        report = self.gateway.process(
            "suricata-eve-json",
            SAMPLE_RECORDS["suricata-eve-json"],
        )
        self.assertEqual(report["counts"]["accepted"], 2)
        self.assertEqual(report["counts"]["inserted"], 0)
        serialized = json.dumps(report)
        self.assertNotIn("198.51.100.27", serialized)
        self.assertNotIn("192.0.2.40", serialized)
        self.assertNotIn("THIS FIELD MUST NEVER SURVIVE", serialized)
        self.assertNotIn("decoy-admin.example", serialized)
        self.assertFalse(contains_raw_ip(report))
        payload = report["outcomes"][0]["safe_payload"]
        self.assertIn("source_ref", payload)
        self.assertIn("transport_fingerprint", payload)
        self.assertIn("alert_category_ref", payload)

    def test_zeek_preview_reduces_values_and_discards_raw_identifiers(self):
        report = self.gateway.process("zeek-conn-json", SAMPLE_RECORDS["zeek-conn-json"])
        self.assertEqual(report["counts"]["accepted"], 2)
        serialized = json.dumps(report)
        self.assertNotIn("203.0.113.61", serialized)
        self.assertNotIn("CsampleOpaqueRawUid", serialized)
        payload = report["outcomes"][0]["safe_payload"]
        self.assertEqual(payload["origin_bytes_bucket"], "lt-1024")
        self.assertEqual(payload["response_bytes_bucket"], "lt-4096")
        self.assertTrue(payload["flow_ref"].startswith("flow-"))

    def test_unsupported_connector_and_event_are_refused(self):
        with self.assertRaises(GatewayValidationError):
            self.gateway.process("unknown", [{}])
        record = dict(SAMPLE_RECORDS["suricata-eve-json"][0], event_type="fileinfo")
        report = self.gateway.process("suricata-eve-json", [record])
        self.assertEqual(report["counts"]["accepted"], 0)
        self.assertEqual(report["outcomes"][0]["status"], "REJECTED")

    def test_commit_persists_only_normalized_telemetry_and_deduplicates(self):
        first = self.gateway.process(
            "suricata-eve-json",
            SAMPLE_RECORDS["suricata-eve-json"],
            commit=True,
        )
        second = self.gateway.process(
            "suricata-eve-json",
            SAMPLE_RECORDS["suricata-eve-json"],
            commit=True,
        )
        self.assertEqual(first["counts"]["inserted"], 2)
        self.assertEqual(second["counts"]["inserted"], 0)
        self.assertEqual(second["counts"]["deduplicated"], 2)
        self.assertEqual(self.store.telemetry_summary()["total_observations"], 2)
        self.assertEqual(self.store.gateway_import_summary()["total_imports"], 1)
        self.assertFalse(contains_raw_ip(self.store.list_telemetry()))

    def test_count_and_record_size_limits_fail_closed(self):
        with self.assertRaises(GatewayValidationError):
            self.gateway.process("zeek-conn-json", SAMPLE_RECORDS["zeek-conn-json"] * (MAX_RECORDS + 1))
        huge = dict(SAMPLE_RECORDS["zeek-conn-json"][0], ignored="x" * 65_000)
        report = self.gateway.process("zeek-conn-json", [huge])
        self.assertEqual(report["counts"]["rejected"], 1)
        self.assertIn("exceeds", report["outcomes"][0]["reason"])

    def test_gateway_does_not_create_or_promote_investigation_events(self):
        before = self.store.event_count()
        report = self.gateway.process(
            "zeek-conn-json",
            SAMPLE_RECORDS["zeek-conn-json"],
            commit=True,
        )
        self.assertEqual(self.store.event_count(), before)
        self.assertFalse(report["privacy_assertions"]["automatic_case_promotion"])
        self.assertEqual(len(report["manifest_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
