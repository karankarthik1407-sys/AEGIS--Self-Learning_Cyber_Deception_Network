import tempfile
import unittest
from pathlib import Path

from aegis.belief import uniform_prior
from aegis.models import SecurityEvent
from aegis.store import AegisStore


class EvidenceLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = AegisStore(Path(self.tempdir.name) / "test.db")
        self.store.create_case("CASE-1", "test", "test case", uniform_prior())

    def tearDown(self):
        self.tempdir.cleanup()

    def test_hash_chain_verifies_and_detects_tampering(self):
        for event_type in ("network_scan", "ssh_login_failure"):
            self.store.append_event(SecurityEvent("CASE-1", event_type, "actor", "decoy-target"))
        valid = self.store.verify_case("CASE-1")
        self.assertTrue(valid["valid"])
        self.assertEqual(valid["verified_events"], 2)

        with self.store.connect() as connection:
            connection.execute("UPDATE events SET target='protected-target' WHERE sequence=1")
        invalid = self.store.verify_case("CASE-1")
        self.assertFalse(invalid["valid"])
        self.assertEqual(invalid["failure_position"], 1)


if __name__ == "__main__":
    unittest.main()

