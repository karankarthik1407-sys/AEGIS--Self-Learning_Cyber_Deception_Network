import hashlib
import json
import unittest

from aegis.trace import (
    EvidenceDiversityLinker,
    SIGNAL_FAMILIES,
    TraceProfile,
    build_trace_report,
    extract_trace_profile,
)


def profile(session_id, **signals):
    values = {
        family.id: frozenset(signals.get(family.id, ()))
        for family in SIGNAL_FAMILIES
    }
    return TraceProfile(
        session_id=session_id,
        signals=values,
        event_types=tuple(signals.get("event_types", ())),
        first_seen="2026-08-20T10:00:00Z",
        last_seen="2026-08-20T10:01:00Z",
        event_count=1,
    )


class ThreatTraceTests(unittest.TestCase):
    def test_raw_ip_is_rejected_but_opaque_source_reference_is_retained(self):
        extracted = extract_trace_profile("S-1", [{
            "timestamp": "2026-08-20T10:00:00Z",
            "event_type": "network_scan",
            "target": "decoy-edge-01",
            "payload": {"source_ref": "198.51.100.41"},
        }])
        self.assertEqual(extracted.signals["source"], frozenset())

        misplaced = extract_trace_profile("S-1B", [{
            "timestamp": "2026-08-20T10:00:00Z",
            "event_type": "network_scan",
            "target": "198.51.100.42",
            "payload": {"provider_ref": "198.51.100.41"},
        }])
        self.assertEqual(misplaced.signals["infrastructure"], frozenset())

        opaque = extract_trace_profile("S-2", [{
            "timestamp": "2026-08-20T10:00:00Z",
            "event_type": "network_scan",
            "target": "decoy-edge-01",
            "payload": {"source_ref": "source-hmac-41"},
        }])
        self.assertIn("source_ref:source-hmac-41", opaque.signals["source"])

    def test_source_signal_alone_cannot_create_high_confidence_link(self):
        left = profile("S-LEFT", source={"source_ref:shared-relay"})
        right = profile("S-RIGHT", source={"source_ref:shared-relay"})
        link = EvidenceDiversityLinker().compare(left, right)
        self.assertLessEqual(link["confidence"], 0.49)
        self.assertEqual(link["strength"], "LOW")
        self.assertFalse(link["identity_claim"])

    def test_rotating_sources_can_link_on_diverse_independent_evidence(self):
        shared = {
            "infrastructure": {"provider_ref:provider-3", "certificate_ref:cert-iris"},
            "transport": {"transport_fingerprint:transport-4b0d"},
            "tooling": {"client_fingerprint:client-hera"},
            "behavior": {"event:network_scan", "target-family:admin"},
            "deception": {"lure_family_ref:lure-rotation"},
            "event_types": ("network_scan", "admin_route_probe"),
        }
        left = profile("S-LEFT", source={"source_ref:relay-a"}, **shared)
        right = profile("S-RIGHT", source={"source_ref:relay-b"}, **shared)
        link = EvidenceDiversityLinker().compare(left, right)
        self.assertEqual(link["strength"], "HIGH")
        self.assertGreaterEqual(link["confidence"], 0.75)
        self.assertIn("source", link["divergent_families"])
        self.assertGreaterEqual(len(link["matched_families"]), 4)

    def test_trace_report_preserves_alternatives_and_identity_boundary(self):
        report = build_trace_report({
            "CASE-A": [{
                "timestamp": "2026-08-20T10:00:00Z",
                "event_type": "network_scan",
                "target": "decoy-edge-01",
                "payload": {
                    "source_ref": "source-east",
                    "provider_ref": "provider-3",
                    "transport_fingerprint": "transport-4b0d",
                    "client_fingerprint": "client-hera",
                },
            }],
            "CASE-B": [{
                "timestamp": "2026-08-20T10:01:00Z",
                "event_type": "network_scan",
                "target": "decoy-edge-02",
                "payload": {
                    "source_ref": "source-west",
                    "provider_ref": "provider-3",
                    "transport_fingerprint": "transport-4b0d",
                    "client_fingerprint": "client-hera",
                },
            }],
        })
        leading = report["links"][0]
        self.assertFalse(leading["identity_claim"])
        self.assertGreaterEqual(len(leading["alternative_explanations"]), 2)
        self.assertEqual(report["leading_assessment"]["human_identity"], "NOT INFERRED")
        self.assertFalse(report["source_policy"]["raw_ip_accepted"])
        self.assertFalse(report["source_policy"]["hack_back"])

    def test_trace_manifest_and_graph_are_reproducible(self):
        events = {
            "CASE-A": [{
                "timestamp": "2026-08-20T10:00:00Z",
                "event_type": "network_scan",
                "target": "decoy-edge-01",
                "payload": {"source_ref": "source-a"},
            }]
        }
        first = build_trace_report(events)
        second = build_trace_report(events)
        self.assertEqual(first["trace_id"], second["trace_id"])
        self.assertEqual(len(first["manifest_sha256"]), 64)
        manifest = first.pop("manifest_sha256")
        canonical = json.dumps(first, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(manifest, hashlib.sha256(canonical).hexdigest())
        self.assertEqual(first["graph"]["nodes"][0]["kind"], "cluster")


if __name__ == "__main__":
    unittest.main()
