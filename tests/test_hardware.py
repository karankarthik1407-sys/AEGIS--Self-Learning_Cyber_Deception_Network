import unittest

from aegis.config import SETTINGS
from aegis.hardware import HardwareEnforcementGateway
from aegis.models import ProposedAction
from aegis.safety import SafetyGate


class HardwareProtocolTests(unittest.TestCase):
    def setUp(self):
        self.gate = SafetyGate(SETTINGS)
        self.gateway = HardwareEnforcementGateway(SETTINGS)

    def test_permitted_certificate_completes_dry_run_and_rollback(self):
        certificate = self.gate.evaluate(ProposedAction.from_dict({"action_id": "ACT-HW-SAFE"}))
        receipt = self.gateway.dry_run(certificate)
        self.assertEqual(receipt["decision"], "ACCEPTED_DRY_RUN")
        self.assertEqual(receipt["final_state"], "ROLLED_BACK")
        self.assertFalse(receipt["protected_namespace_reachable"])
        self.assertEqual(receipt["packet_effects"], 0)
        self.assertEqual(len(receipt["simulated_receipt_sha256"]), 64)

    def test_tampered_certificate_is_refused(self):
        certificate = self.gate.evaluate(ProposedAction.from_dict({"action_id": "ACT-HW-TAMPER"}))
        certificate["action"]["target"] = "production-core"
        receipt = self.gateway.dry_run(certificate)
        self.assertEqual(receipt["decision"], "REFUSED")
        self.assertIn("certificate digest mismatch", receipt["trace"][-1]["detail"])
        self.assertEqual(receipt["packet_effects"], 0)

    def test_denied_safety_certificate_never_reaches_rule_staging(self):
        action = ProposedAction.from_dict({
            "action_id": "ACT-HW-DENY",
            "target": "production-core",
            "namespace": "production",
            "decoy_only": False,
            "network_egress": True,
        })
        receipt = self.gateway.dry_run(self.gate.evaluate(action))
        states = [item["state"] for item in receipt["trace"]]
        self.assertEqual(receipt["decision"], "REFUSED")
        self.assertNotIn("RULE_STAGED", states)
        self.assertEqual(receipt["packet_effects"], 0)


if __name__ == "__main__":
    unittest.main()
