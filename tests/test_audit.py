import sqlite3
import tempfile
import unittest
from pathlib import Path

from aegis.audit import AuditJournal, AuditUnavailable
from aegis.store import AegisStore


class OperatorAuditJournalTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.store = AegisStore(self.root / "audit.db")
        self.journal = AuditJournal(self.store)

    def tearDown(self):
        self.tempdir.cleanup()

    def _append(self, decision: str = "ACCEPTED"):
        return self.journal.append(
            command_id="CMD-TEST-0001",
            session_ref="SES-TEST",
            operator_role="analyst",
            method="POST",
            path="/api/simulate",
            permission="operate",
            entitlement="desktop_control_plane",
            decision=decision,
            status_code=0 if decision == "ACCEPTED" else 201,
            request_sha256="a" * 64,
        )

    def test_two_stage_command_is_hash_linked_and_minimized(self):
        first = self._append("ACCEPTED")
        second = self._append("COMPLETED")
        verification = self.journal.verify()

        self.assertEqual(second["previous_hash"], first["record_hash"])
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["records"], 2)
        self.assertEqual(verification["commands"], 1)
        self.assertFalse(self.journal.summary()["request_payload_retained"])

    def test_append_only_sql_triggers_reject_update_and_delete(self):
        self._append()
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.connect() as connection:
                connection.execute("UPDATE operator_audit SET path='/changed' WHERE sequence=1")
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.connect() as connection:
                connection.execute("DELETE FROM operator_audit WHERE sequence=1")

    def test_out_of_band_tampering_is_detected(self):
        self._append()
        with self.store.connect() as connection:
            connection.execute("DROP TRIGGER operator_audit_no_update")
            connection.execute("UPDATE operator_audit SET path='/tampered' WHERE sequence=1")
        verification = self.journal.verify()
        self.assertFalse(verification["valid"])
        self.assertEqual(verification["failure_sequence"], 1)

    def test_missing_key_with_existing_records_fails_closed(self):
        self._append()
        self.journal.key_path.unlink()
        reopened = AuditJournal(self.store)

        self.assertFalse(reopened.operational)
        self.assertFalse(reopened.verify()["valid"])
        with self.assertRaises(AuditUnavailable):
            reopened.append(
                command_id="CMD-TEST-0002",
                session_ref="SES-TEST",
                operator_role="analyst",
                method="POST",
                path="/api/simulate",
                permission="operate",
                entitlement="desktop_control_plane",
                decision="ACCEPTED",
                status_code=0,
                request_sha256="b" * 64,
            )


if __name__ == "__main__":
    unittest.main()
