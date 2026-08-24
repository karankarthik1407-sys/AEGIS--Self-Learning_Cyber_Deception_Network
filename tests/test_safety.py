import unittest

from aegis.config import Settings
from aegis.models import ProposedAction
from aegis.safety import SafetyGate


class SafetyGateTests(unittest.TestCase):
    def setUp(self):
        self.gate = SafetyGate(Settings())

    def test_safe_default_is_permitted(self):
        certificate = self.gate.evaluate(ProposedAction.from_dict({}))
        self.assertEqual(certificate["decision"], "PERMIT")
        self.assertEqual(certificate["failed_rules"], [])
        self.assertEqual(len(certificate["digest"]), 64)

    def test_unsafe_egress_and_target_are_denied(self):
        action = ProposedAction.from_dict({
            "target": "production-payments",
            "decoy_only": False,
            "network_egress": True,
            "synthetic_data_only": False,
            "reversible": False,
            "memory_mb": 4096,
            "ttl_seconds": 7200,
        })
        certificate = self.gate.evaluate(action)
        self.assertEqual(certificate["decision"], "DENY")
        self.assertIn("decoy_target", certificate["failed_rules"])
        self.assertIn("no_network_egress", certificate["failed_rules"])
        self.assertIn("synthetic_data", certificate["failed_rules"])


if __name__ == "__main__":
    unittest.main()

