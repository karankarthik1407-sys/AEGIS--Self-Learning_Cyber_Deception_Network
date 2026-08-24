import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

from aegis.server import handler_factory
from aegis.service import AegisService


HTTP_TEST_TIMEOUT_SECONDS = 15


class HttpIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        service = AegisService(Path(self.tempdir.name) / "http.db")
        static_root = Path(__file__).resolve().parents[1] / "web"
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory(service, static_root))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tempdir.cleanup()

    def request_json(self, path, method="GET", payload=None):
        data = json.dumps(payload or {}).encode() if method == "POST" else None
        request = Request(
            self.base + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with urlopen(request, timeout=HTTP_TEST_TIMEOUT_SECONDS) as response:
            return response.status, json.loads(response.read())

    def test_static_console_and_live_routes(self):
        with urlopen(self.base + "/", timeout=HTTP_TEST_TIMEOUT_SECONDS) as response:
            html = response.read().decode()
            self.assertIn("AEGIS — Autonomous Deception Intelligence", html)
            self.assertIn('id="simulateButton"', html)
            for workspace in ("mission", "cases", "campaigns", "trace", "graph", "steering", "deception", "evidence", "trust", "research", "models", "telemetry", "gateway", "governance", "access", "system"):
                self.assertIn(f'id="workspace-{workspace}"', html)

        status, health = self.request_json("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(health["status"], "healthy")

        status, simulation = self.request_json("/api/simulate", method="POST")
        self.assertEqual(status, 201)
        self.assertEqual(simulation["overview"]["system_state"], "CONTAINED")

        status, certificate = self.request_json("/api/actions/evaluate", method="POST")
        self.assertEqual(status, 201)
        self.assertEqual(certificate["decision"], "PERMIT")

        _, access = self.request_json("/api/access/status")
        self.assertEqual(access["license"]["state"], "RESEARCH")
        self.assertEqual(access["operator"]["role"], "ADMINISTRATOR")
        self.assertTrue(access["audit"]["valid"])

        _, operator_audit = self.request_json("/api/audit/events?limit=20")
        self.assertEqual(operator_audit["summary"]["commands"], 2)
        self.assertEqual(operator_audit["summary"]["records"], 4)
        self.assertTrue(operator_audit["summary"]["valid"])

        _, evidence = self.request_json("/api/evidence/verify")
        self.assertTrue(evidence["valid"])

        _, campaigns = self.request_json("/api/investigation/campaigns")
        self.assertEqual(len(campaigns["campaigns"]), 1)
        self.assertIn("CAMPAIGN LINKAGE ONLY", campaigns["links"][0]["attribution_status"])

        _, indicators = self.request_json("/api/investigation/indicators")
        self.assertGreaterEqual(len(indicators["techniques"]), 3)
        self.assertTrue(indicators["behavioural_indicators"])

        _, assets = self.request_json("/api/deception/assets")
        self.assertFalse(assets["protected_namespace_reachable"])
        self.assertEqual(len(assets["assets"]), 6)

        _, research = self.request_json("/api/research/status")
        self.assertEqual(research["reproducibility"]["external_targets"], 0)
        self.assertEqual(research["reproducibility"]["automated_tests"], 88)

        _, experiment = self.request_json("/api/research/experiment")
        self.assertGreater(experiment["metrics"]["macro_f1"], 0.70)
        self.assertEqual(experiment["dataset"]["external_targets"], 0)

        _, hardware = self.request_json("/api/hardware/profile")
        self.assertEqual(hardware["packet_effects"], 0)

        status, dry_run = self.request_json("/api/hardware/dry-run", method="POST")
        self.assertEqual(status, 201)
        self.assertEqual(dry_run["receipt"]["decision"], "ACCEPTED_DRY_RUN")
        self.assertEqual(dry_run["receipt"]["packet_effects"], 0)

        _, bundle = self.request_json("/api/cases/AEGIS-26-0001/bundle")
        self.assertEqual(len(bundle["manifest_sha256"]), 64)

        _, trace = self.request_json("/api/trace/report")
        self.assertEqual(trace["leading_assessment"]["human_identity"], "NOT INFERRED")
        self.assertFalse(trace["source_policy"]["raw_ip_accepted"])
        self.assertEqual(len(trace["manifest_sha256"]), 64)

        _, trace_experiment = self.request_json("/api/trace/experiment")
        self.assertGreater(trace_experiment["winner"]["test"]["f1"], 0.90)
        self.assertEqual(trace_experiment["winner"]["promotion"], "HOLD_SHADOW")

        status, rerun = self.request_json("/api/trace/experiment/run", method="POST")
        self.assertEqual(status, 201)
        self.assertEqual(rerun["dataset"]["external_targets"], 0)

        _, graph = self.request_json("/api/trace/graph-experiment")
        self.assertEqual(graph["status"], "PASSING")
        self.assertEqual(graph["bridge_audit"]["rejected"], 7)
        self.assertEqual(graph["winner"]["stress"]["false_merge_rate"], 0.0)

        status, graph_rerun = self.request_json("/api/trace/graph-experiment/run", method="POST")
        self.assertEqual(status, 201)
        self.assertEqual(graph_rerun["dataset"]["external_targets"], 0)

        _, steering = self.request_json("/api/steering/experiment")
        self.assertEqual(steering["status"], "PASSING")
        self.assertEqual(steering["winner"]["id"], "STEER-EIG")
        self.assertEqual(steering["winner"]["promotion"], "HOLD_SHADOW")
        self.assertEqual(steering["validity_checks"]["unsafe_acceptances"], 0)

        status, steering_rerun = self.request_json("/api/steering/experiment/run", method="POST")
        self.assertEqual(status, 201)
        self.assertEqual(steering_rerun["dataset"]["external_targets"], 0)

        _, gateway = self.request_json("/api/gateway/status")
        self.assertEqual(len(gateway["connectors"]), 2)
        self.assertFalse(gateway["privacy"]["raw_ip_persisted"])

        _, sample = self.request_json("/api/gateway/sample?connector=suricata-eve-json")
        status, preview = self.request_json(
            "/api/gateway/preview",
            method="POST",
            payload={"connector": "suricata-eve-json", "records": sample["records"]},
        )
        self.assertEqual(status, 201)
        self.assertEqual(preview["counts"]["accepted"], 2)
        self.assertEqual(preview["counts"]["inserted"], 0)

        status, imported = self.request_json(
            "/api/gateway/import",
            method="POST",
            payload={"connector": "suricata-eve-json", "records": sample["records"]},
        )
        self.assertEqual(status, 201)
        self.assertEqual(imported["counts"]["inserted"], 2)
        self.assertFalse(imported["privacy_assertions"]["automatic_case_promotion"])

    def test_installed_node_and_governed_learning_routes(self):
        _, agents = self.request_json("/api/system/agents")
        self.assertEqual(agents["agents"][0]["state"], "ONLINE")
        self.assertTrue(agents["agents"][0]["capabilities"]["local_heartbeat"])
        self.assertFalse(agents["agents"][0]["capabilities"]["host_network_enforcement"])

        _, fabric = self.request_json("/api/models/fabric")
        self.assertEqual(fabric["promotion"]["decision"], "HOLD_SHADOW")
        self.assertGreaterEqual(len(fabric["models"]), 4)

        status, evaluated = self.request_json("/api/models/fabric/evaluate", method="POST")
        self.assertEqual(status, 201)
        self.assertFalse(evaluated["promotion"]["automatic_weight_updates"])

        status, collected = self.request_json("/api/telemetry/collect", method="POST")
        self.assertEqual(status, 201)
        self.assertGreaterEqual(collected["observation_count"], 2)

        _, telemetry_status = self.request_json("/api/telemetry/status")
        self.assertFalse(telemetry_status["privacy"]["outbound_transmission"])
        _, telemetry_events = self.request_json("/api/telemetry/events?limit=10")
        self.assertGreaterEqual(len(telemetry_events["events"]), 2)

        _, governance = self.request_json("/api/governance/status")
        self.assertEqual(governance["artifact_summary"]["total"], 10)
        self.assertTrue(governance["registry_verification"]["valid"])
        self.assertTrue(governance["ledger_verification"]["valid"])
        self.assertFalse(governance["attestation"]["external_digital_signature"])

        status, evaluated = self.request_json(
            "/api/governance/evaluate",
            method="POST",
            payload={
                "human_release_signoff": True,
                "shadow_observations": 999999,
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(evaluated["decision_record"]["decision"], "HOLD_SHADOW")
        self.assertIn(
            "human_release_signoff",
            evaluated["decision_record"]["record"]["evidence"]["request_fields_ignored"],
        )

        _, verification = self.request_json("/api/governance/verify")
        self.assertTrue(verification["registry"]["valid"])
        self.assertTrue(verification["ledger"]["valid"])



if __name__ == "__main__":
    unittest.main()
