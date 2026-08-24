import os
import stat
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

from aegis.agent import LocalNodeAgent
from aegis.models import TelemetryObservation
from aegis.store import AegisStore
from aegis.telemetry import (
    CollectorOutput,
    EndpointTelemetryRuntime,
    Pseudonymizer,
    WindowsEventLogCollector,
)


WINDOWS_EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-08-20T10:11:12.0000000Z" />
    <EventRecordID>8891</EventRecordID>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">Alice.Admin</Data>
    <Data Name="IpAddress">203.0.113.44</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\whoami.exe</Data>
    <Data Name="CommandLine">whoami /all SECRET-COMMAND</Data>
    <Data Name="Status">0xC000006D</Data>
  </EventData>
</Event>"""


class FixedCollector:
    id = "COL-FIXED"
    name = "Fixed test collector"

    def collect(self):
        return CollectorOutput(
            "ACTIVE",
            "Deterministic observation.",
            (
                TelemetryObservation(
                    node_id="NODE-TEST",
                    source="unit-test",
                    category="integrity",
                    event_type="fixed_observation",
                    severity="info",
                    payload={"safe": True},
                    timestamp="2026-08-20T10:00:00Z",
                ),
            ),
        )


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.agent = LocalNodeAgent(Path(__file__).resolve().parents[1])

    def tearDown(self):
        self.tempdir.cleanup()

    def test_pseudonymizer_is_stable_local_and_non_reversible_in_storage(self):
        key_path = self.root / "node.key"
        first = Pseudonymizer(key_path)
        reference = first.reference("account", "Alice.Admin")
        second = Pseudonymizer(key_path)
        self.assertEqual(reference, second.reference("account", "alice.admin"))
        self.assertNotIn("alice", reference.lower())
        self.assertEqual(len(key_path.read_bytes()), 32)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)

    def test_invalid_pseudonymization_key_fails_closed(self):
        key_path = self.root / "node.key"
        key_path.write_bytes(b"short")
        with self.assertRaises(RuntimeError):
            Pseudonymizer(key_path)

    def test_windows_event_is_allowlisted_and_identity_is_pseudonymized(self):
        collector = WindowsEventLogCollector(
            self.agent,
            Pseudonymizer(self.root / "node.key"),
        )
        observation = collector._observation(ET.fromstring(WINDOWS_EVENT_XML), "Security")
        self.assertIsNotNone(observation)
        payload = observation.payload
        self.assertEqual(observation.event_type, "authentication_failure")
        self.assertEqual(payload["windows_event_id"], 4625)
        self.assertEqual(payload["NewProcessName"], "whoami.exe")
        self.assertIn("TargetUserName_ref", payload)
        self.assertIn("IpAddress_ref", payload)
        serialized = str(payload).lower()
        self.assertNotIn("alice.admin", serialized)
        self.assertNotIn("203.0.113.44", serialized)
        self.assertNotIn("secret-command", serialized)
        self.assertNotIn("CommandLine", payload)

    def test_windows_query_uses_bounded_argument_list_and_accepts_xml_headers(self):
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(
                returncode=0,
                stdout='<?xml version="1.0" encoding="utf-8"?>' + WINDOWS_EVENT_XML,
                stderr="",
            )

        collector = WindowsEventLogCollector(
            self.agent,
            Pseudonymizer(self.root / "node.key"),
            max_events_per_channel=12,
            runner=runner,
        )
        events, warning = collector._query("Security", (4625,))
        self.assertIsNone(warning)
        self.assertEqual(len(events), 1)
        command, kwargs = calls[0]
        self.assertEqual(command[:3], ["wevtutil", "qe", "Security"])
        self.assertIn("/c:12", command)
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["timeout"], 12)

    def test_runtime_persists_and_deduplicates_overlapping_observations(self):
        store = AegisStore(self.root / "aegis.db")
        runtime = EndpointTelemetryRuntime(store, self.agent, collectors=[FixedCollector()])
        first = runtime.collect_once()
        second = runtime.collect_once()
        self.assertEqual(first["inserted_count"], 1)
        self.assertEqual(second["inserted_count"], 0)
        self.assertEqual(store.telemetry_summary()["total_observations"], 1)
        self.assertFalse(runtime.status()["privacy"]["outbound_transmission"])

    def test_default_runtime_collects_real_health_and_integrity(self):
        store = AegisStore(self.root / "default.db")
        runtime = EndpointTelemetryRuntime(store, self.agent)
        run = runtime.collect_once()
        event_types = {event["event_type"] for event in store.list_telemetry()}
        self.assertIn("host_health_sample", event_types)
        self.assertIn("runtime_manifest_observed", event_types)
        self.assertGreaterEqual(run["observation_count"], 2)
        self.assertEqual(run["collectors"][0]["state"], "ACTIVE")


if __name__ == "__main__":
    unittest.main()
