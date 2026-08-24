import base64
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.licensing import (
    LICENSE_CONTRACT_VERSION,
    SIGNATURE_ALGORITHM,
    LicenseManager,
    canonical_license_payload,
    public_key_id,
)


class OfflineLicenseTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.now = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.tempdir.cleanup()

    def _signed_envelope(self, **overrides):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        (self.root / "license_public_key.pem").write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        claims = {
            "license_id": "LIC-AEGIS-ENTERPRISE-0001",
            "customer": "Authorized Evaluation Organization",
            "edition": "ENTERPRISE",
            "issued_at": (self.now - timedelta(days=1)).isoformat(),
            "not_before": (self.now - timedelta(hours=1)).isoformat(),
            "expires_at": (self.now + timedelta(days=365)).isoformat(),
            "max_nodes": 250,
            "entitlements": [
                "desktop_control_plane",
                "resident_node",
                "research_lab",
                "offline_evidence_gateway",
                "hardware_dry_run",
                "local_audit",
                "multi_node",
            ],
            "deployment_id": "DEPLOYMENT-ALPHA",
        }
        claims.update(overrides)
        envelope = {
            "contract_version": LICENSE_CONTRACT_VERSION,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "key_id": public_key_id(public_key),
            "claims": claims,
        }
        envelope["signature"] = base64.urlsafe_b64encode(
            private_key.sign(canonical_license_payload(envelope))
        ).decode("ascii").rstrip("=")
        (self.root / "license.json").write_text(json.dumps(envelope), encoding="utf-8")
        return envelope

    def _manager(self):
        return LicenseManager(self.root, clock=lambda: self.now)

    def test_absent_envelope_activates_noncommercial_research_entitlements(self):
        status = self._manager().status()
        self.assertEqual(status["state"], "RESEARCH")
        self.assertTrue(status["valid"])
        self.assertFalse(status["commercial_use"])
        self.assertIn("research_lab", status["entitlements"])
        self.assertFalse(status["signature_verified"])

    def test_valid_enterprise_envelope_verifies_offline(self):
        self._signed_envelope()
        manager = self._manager()
        status = manager.status()

        self.assertEqual(status["state"], "VALID")
        self.assertTrue(status["signature_verified"])
        self.assertTrue(status["commercial_use"])
        self.assertEqual(status["max_nodes"], 250)
        self.assertTrue(manager.is_entitled("multi_node"))

    def test_claim_tampering_invalidates_the_signature_and_locks_features(self):
        envelope = self._signed_envelope()
        envelope["claims"]["max_nodes"] = 100_000
        (self.root / "license.json").write_text(json.dumps(envelope), encoding="utf-8")
        manager = self._manager()

        self.assertEqual(manager.status()["state"], "INVALID")
        self.assertFalse(manager.is_entitled("desktop_control_plane"))
        self.assertTrue(manager.is_entitled("local_audit"))

    def test_expired_signature_remains_verified_but_entitlements_lock(self):
        self._signed_envelope(
            issued_at=(self.now - timedelta(days=11)).isoformat(),
            not_before=(self.now - timedelta(days=10)).isoformat(),
            expires_at=(self.now - timedelta(seconds=1)).isoformat(),
        )
        manager = self._manager()
        status = manager.status()

        self.assertEqual(status["state"], "EXPIRED")
        self.assertTrue(status["signature_verified"])
        self.assertFalse(status["valid"])
        self.assertFalse(manager.is_entitled("multi_node"))

    def test_future_and_unknown_entitlements_fail_closed(self):
        self._signed_envelope(
            not_before=(self.now + timedelta(days=2)).isoformat(),
            expires_at=(self.now + timedelta(days=20)).isoformat(),
        )
        self.assertEqual(self._manager().status()["state"], "NOT_YET_VALID")

        self._signed_envelope(entitlements=["local_audit", "teleport_intruder"])
        status = self._manager().status()
        self.assertEqual(status["state"], "INVALID")
        self.assertIn("unknown entitlements", status["reason"])


if __name__ == "__main__":
    unittest.main()
