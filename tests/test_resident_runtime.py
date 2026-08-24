import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import urlopen

from aegis.runtime import ResidentControlPlane
from aegis.windows_service import SERVICE_NAME, WindowsServiceHost


class ResidentRuntimeTests(unittest.TestCase):
    def test_resident_runtime_serves_loopback_and_stops_cleanly(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = ResidentControlPlane(
                "127.0.0.1",
                0,
                Path(directory) / "resident.db",
                telemetry_interval_seconds=10,
                static_root=Path(__file__).resolve().parents[1] / "web",
            )
            thread = threading.Thread(target=runtime.run, daemon=True)
            thread.start()
            host, port = runtime.address
            with urlopen(f"http://{host}:{port}/api/health", timeout=3) as response:
                health = json.loads(response.read())
            self.assertEqual(health["release"], "1.2.0")
            self.assertTrue(runtime.request_stop())
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertGreaterEqual(
                runtime.service.telemetry_status()["summary"]["total_observations"],
                2,
            )

    def test_windows_service_contract_is_explicit_off_windows(self):
        self.assertEqual(SERVICE_NAME, "AEGISNode")
        if os.name == "nt":
            self.skipTest("Dispatch refusal applies only off Windows.")
        host = WindowsServiceHost("127.0.0.1", 8765, Path("unused.db"), 30)
        with self.assertRaises(RuntimeError):
            host.dispatch()


if __name__ == "__main__":
    unittest.main()
