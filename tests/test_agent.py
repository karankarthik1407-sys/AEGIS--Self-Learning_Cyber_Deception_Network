import tempfile
import unittest
from pathlib import Path

from aegis.agent import LocalNodeAgent


class LocalNodeAgentTests(unittest.TestCase):
    def test_snapshot_reports_real_local_runtime_without_false_enforcement_claims(self):
        with tempfile.TemporaryDirectory() as tempdir:
            agent = LocalNodeAgent(Path(tempdir))
            snapshot = agent.snapshot()
        self.assertEqual(snapshot["state"], "ONLINE")
        self.assertTrue(snapshot["capabilities"]["local_heartbeat"])
        self.assertFalse(snapshot["capabilities"]["host_network_enforcement"])
        self.assertFalse(snapshot["capabilities"]["external_scanning"])
        self.assertGreaterEqual(snapshot["active_collectors"], 2)
        self.assertTrue(snapshot["node_id"].startswith("NODE-"))


if __name__ == "__main__":
    unittest.main()
