import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from aegis.access import AccessController, OperatorSession
from aegis.server import handler_factory
from aegis.service import AegisService


STATIC_ROOT = Path(__file__).resolve().parents[1] / "web"


class AccessContractTests(unittest.TestCase):
    def test_roles_are_monotonic_and_admin_routes_remain_admin_only(self):
        controller = AccessController()
        viewer = OperatorSession.create("v" * 40, "viewer")
        analyst = OperatorSession.create("a" * 40, "analyst")
        administrator = OperatorSession.create("z" * 40, "administrator")

        self.assertFalse(controller.authorize(viewer, "/api/simulate").allowed)
        self.assertTrue(controller.authorize(analyst, "/api/simulate").allowed)
        self.assertFalse(controller.authorize(analyst, "/api/demo/reset").allowed)
        self.assertTrue(controller.authorize(administrator, "/api/demo/reset").allowed)

    def test_session_reference_is_pseudonymous_and_token_is_not_exposed(self):
        token = "secret-desktop-token-" * 3
        session = OperatorSession.create(token, "analyst", "test-loopback")
        status = session.to_dict()

        self.assertTrue(status["session_ref"].startswith("SES-"))
        self.assertNotIn(token, json.dumps(status))
        self.assertFalse(status["raw_token_retained"])
        self.assertEqual(status["role"], "ANALYST")


class ScopedHttpSessionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.token = "scope-token-" * 4

    def tearDown(self):
        self.tempdir.cleanup()

    def _server(self, role: str, invalid_license: bool = False):
        root = Path(self.tempdir.name)
        if invalid_license:
            (root / "license.json").write_text("{}", encoding="utf-8")
        service = AegisService(root / "access.db")
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            handler_factory(service, STATIC_ROOT, self.token, operator_role=role),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return service, server, thread, f"http://127.0.0.1:{server.server_port}"

    def _request(self, base: str, path: str, method: str = "GET"):
        request = Request(
            base + path,
            data=b"{}" if method == "POST" else None,
            method=method,
            headers={
                "Content-Type": "application/json",
                "X-AEGIS-Desktop-Token": self.token,
            },
        )
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read())

    def test_viewer_mutation_is_denied_and_sealed_in_the_audit_chain(self):
        service, server, thread, base = self._server("viewer")
        try:
            status, access = self._request(base, "/api/access/status")
            self.assertEqual(status, 200)
            self.assertEqual(access["operator"]["role"], "VIEWER")

            status, denied = self._request(base, "/api/simulate", "POST")
            self.assertEqual(status, 403)
            self.assertEqual(denied["error"], "operator_scope_required")

            _, audit = self._request(base, "/api/audit/events?limit=10")
            self.assertEqual(audit["events"][0]["decision"], "DENIED_ROLE")
            self.assertTrue(audit["summary"]["valid"])
            self.assertEqual(audit["summary"]["commands"], 1)
            self.assertEqual(service.store.event_count(), 4)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_analyst_command_has_pre_and_post_receipts_but_reset_is_denied(self):
        _, server, thread, base = self._server("analyst")
        try:
            status, _ = self._request(base, "/api/simulate", "POST")
            self.assertEqual(status, 201)
            status, denied = self._request(base, "/api/demo/reset", "POST")
            self.assertEqual(status, 403)
            self.assertEqual(denied["error"], "operator_scope_required")

            _, audit = self._request(base, "/api/audit/events?limit=10")
            decisions = [event["decision"] for event in audit["events"]]
            self.assertEqual(decisions, ["DENIED_ROLE", "COMPLETED", "ACCEPTED"])
            self.assertEqual(audit["summary"]["commands"], 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_invalid_installed_license_locks_mutations_but_not_recovery(self):
        _, server, thread, base = self._server("administrator", invalid_license=True)
        try:
            status, denied = self._request(base, "/api/simulate", "POST")
            self.assertEqual(status, 403)
            self.assertEqual(denied["error"], "license_entitlement_required")

            status, reloaded = self._request(base, "/api/license/reload", "POST")
            self.assertEqual(status, 200)
            self.assertEqual(reloaded["access"]["license"]["state"], "INVALID")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
