import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from aegis.config import Settings
from aegis.desktop import (
    DesktopSession,
    EmbeddedDesktopRuntime,
    probe_aegis,
    run_headless_check,
)
from aegis.runtime import ResidentControlPlane
from aegis.version import PRODUCT_VERSION


STATIC_ROOT = Path(__file__).resolve().parents[1] / "web"


class DesktopRuntimeTests(unittest.TestCase):
    def test_product_version_is_desktop_release(self):
        self.assertEqual(PRODUCT_VERSION, "1.2.0")

    def test_desktop_data_root_honours_explicit_override(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "AEGIS data"
            with patch.dict(os.environ, {"AEGIS_DATA_ROOT": str(target)}):
                self.assertEqual(Settings().desktop_data_root, target.resolve())

    def test_probe_rejects_an_unavailable_endpoint(self):
        self.assertIsNone(probe_aegis("http://127.0.0.1:1", timeout=0.05))

    def test_embedded_runtime_injects_token_and_rejects_untokened_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = EmbeddedDesktopRuntime(
                Path(directory),
                telemetry_interval_seconds=3600,
                static_root=STATIC_ROOT,
            )
            url = runtime.start()
            try:
                with urlopen(f"{url}/", timeout=3) as response:
                    html = response.read().decode("utf-8")
                self.assertIn(runtime.session_token, html)

                wrong_host = Request(
                    f"{url}/api/health",
                    method="GET",
                    headers={"Host": "untrusted.invalid"},
                )
                with self.assertRaises(HTTPError) as misdirected:
                    urlopen(wrong_host, timeout=3)
                self.assertEqual(misdirected.exception.code, 421)

                request = Request(
                    f"{url}/api/demo/reset",
                    data=b"{}",
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with self.assertRaises(HTTPError) as denied:
                    urlopen(request, timeout=3)
                self.assertEqual(denied.exception.code, 403)

                permitted = Request(
                    f"{url}/api/demo/reset",
                    data=b"{}",
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "X-AEGIS-Desktop-Token": runtime.session_token,
                    },
                )
                with urlopen(permitted, timeout=3) as response:
                    payload = json.loads(response.read())
                self.assertIn("overview", payload)
            finally:
                runtime.stop()

    def test_desktop_session_attaches_to_matching_resident_service(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = ResidentControlPlane(
                "127.0.0.1",
                0,
                Path(directory) / "service.db",
                telemetry_interval_seconds=3600,
                static_root=STATIC_ROOT,
                session_token="s" * 43,
            )
            import threading

            thread = threading.Thread(target=runtime.run, daemon=True)
            thread.start()
            host, port = runtime.address
            try:
                session = DesktopSession.open(
                    Path(directory) / "desktop",
                    service_url=f"http://{host}:{port}",
                    static_root=STATIC_ROOT,
                )
                self.assertEqual(session.mode, "resident-service")
                self.assertIsNone(session.embedded)
                session.close()
                self.assertIsNotNone(probe_aegis(f"http://{host}:{port}"))
            finally:
                runtime.request_stop()
                thread.join(timeout=5)

    def test_headless_check_exercises_packaged_runtime_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_headless_check(Path(directory), static_root=STATIC_ROOT)
        self.assertEqual(result["status"], "healthy")
        self.assertEqual(result["release"], "1.2.0")
        self.assertEqual(result["mode"], "embedded-desktop")
        self.assertTrue(result["loopback"])


if __name__ == "__main__":
    unittest.main()
