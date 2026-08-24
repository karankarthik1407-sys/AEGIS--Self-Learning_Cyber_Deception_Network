import copy
import sqlite3
import tempfile
import unittest
from pathlib import Path

from aegis.registry import ArtifactGovernanceRegistry, RegistryValidationError
from aegis.store import AegisStore


class ArtifactGovernanceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = AegisStore(Path(self.tempdir.name) / "registry.db")
        self.registry = ArtifactGovernanceRegistry(self.store)
        self.dataset = self.registry.register_artifact(
            "dataset",
            "Synthetic grouped corpus",
            "v1",
            {
                "dataset_sha256": "a" * 64,
                "grouped_split": True,
                "synthetic_only": True,
                "external_targets": 0,
            },
        )
        self.model = self.registry.register_artifact(
            "model",
            "Shadow candidate",
            "v1",
            {
                "model_family": "inspectable test learner",
                "grouped_validation": True,
                "quality_gate_passed": True,
                "safety_violations": 0,
                "external_targets": 0,
            },
            lineage=[self.dataset["artifact_id"]],
            status="SHADOW",
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_registered_artifacts_have_valid_local_attestations(self):
        result = self.registry.verify_registry()
        self.assertTrue(result["valid"])
        self.assertEqual(result["verified"], 2)
        self.assertEqual(len(self.model["attestation"]), 64)
        self.assertTrue(self.model["key_id"].startswith("LOCAL-"))

    def test_registration_is_idempotent_and_preserves_lineage(self):
        duplicate = self.registry.register_artifact(
            "dataset",
            "Synthetic grouped corpus",
            "v1",
            self.dataset["descriptor"],
        )
        self.assertEqual(duplicate["artifact_id"], self.dataset["artifact_id"])
        self.assertEqual(len(self.registry.list_artifacts()), 2)
        self.assertEqual(self.model["lineage"], [self.dataset["artifact_id"]])

    def test_modified_descriptor_copy_fails_verification(self):
        tampered = copy.deepcopy(self.model)
        tampered["descriptor"]["external_targets"] = 9
        result = self.registry.verify_artifact(tampered)
        self.assertFalse(result["valid"])
        self.assertFalse(result["checks"]["descriptor_digest"])

    def test_invalid_type_unknown_lineage_and_oversize_descriptor_fail_closed(self):
        with self.assertRaises(RegistryValidationError):
            self.registry.register_artifact("executable", "Bad", "v1", {})
        with self.assertRaises(RegistryValidationError):
            self.registry.register_artifact("model", "Bad", "v1", {}, lineage=["DST-MISSING"])
        with self.assertRaises(RegistryValidationError):
            self.registry.register_artifact("dataset", "Huge", "v1", {"value": "x" * 70_000})

    def test_candidate_quality_cannot_bypass_release_gates(self):
        record = self.registry.evaluate_candidate(
            self.model["artifact_id"],
            None,
            ignored_request_fields=("human_release_signoff", "shadow_observations"),
        )
        checks = {check["rule"]: check for check in record["record"]["checks"]}
        self.assertEqual(record["decision"], "HOLD_SHADOW")
        self.assertFalse(record["record"]["evidence"]["automatic_promotion"])
        self.assertFalse(checks["human_release_signoff"]["passed"])
        self.assertFalse(checks["shadow_volume"]["passed"])
        self.assertEqual(
            record["record"]["evidence"]["request_fields_ignored"],
            ["human_release_signoff", "shadow_observations"],
        )

    def test_multiple_decisions_form_a_valid_hash_chain(self):
        self.registry.evaluate_candidate(self.model["artifact_id"], None)
        self.registry.evaluate_candidate(self.model["artifact_id"], None)
        verification = self.registry.verify_ledger()
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["records"], 2)
        decisions = list(reversed(self.registry.list_decisions()))
        self.assertEqual(decisions[1]["previous_hash"], decisions[0]["record_hash"])

    def test_modified_ledger_copy_is_detected(self):
        self.registry.evaluate_candidate(self.model["artifact_id"], None)
        records = self.registry.list_decisions()
        records[0]["record"]["decision"] = "ELIGIBLE_FOR_SIGNED_RELEASE"
        verification = self.registry.verify_ledger(records)
        self.assertFalse(verification["valid"])
        self.assertFalse(verification["results"][0]["checks"]["record_hash"])

    def test_registry_and_ledger_tables_reject_update_and_delete(self):
        self.registry.evaluate_candidate(self.model["artifact_id"], None)
        with self.assertRaises(sqlite3.DatabaseError):
            with self.store.connect() as connection:
                connection.execute(
                    "UPDATE artifact_registry SET status='CHAMPION' WHERE artifact_id=?",
                    (self.model["artifact_id"],),
                )
        with self.assertRaises(sqlite3.DatabaseError):
            with self.store.connect() as connection:
                connection.execute("DELETE FROM promotion_ledger")


if __name__ == "__main__":
    unittest.main()
