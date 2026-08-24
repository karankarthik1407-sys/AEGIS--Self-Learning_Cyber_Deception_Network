from __future__ import annotations

from pathlib import Path
from typing import Any

from .access import AccessController, OperatorSession
from .agent import LocalNodeAgent
from .audit import AuditJournal
from .belief import summarize, uniform_prior, update_beliefs
from .config import SETTINGS, Settings
from .hardware import HardwareEnforcementGateway
from .investigation import TECHNIQUES, build_case_bundle, compare_cases, extract_features, technique_for
from .learning import run_learning_fabric
from .licensing import LicenseManager
from .models import ProposedAction, SecurityEvent
from .research import DEFAULT_SEED, dataset_summary, run_intent_experiment
from .registry import ArtifactGovernanceRegistry, RegistryValidationError
from .safety import SafetyGate
from .sensor_gateway import SensorEvidenceGateway
from .store import AegisStore
from .telemetry import EndpointTelemetryRuntime
from .trace import build_trace_report
from .trace_research import run_trace_experiment
from .trace_graph_research import run_trace_graph_experiment
from .version import PRODUCT_VERSION
from .steering_research import run_steering_experiment as run_diagnostic_steering_experiment


CASE_ID = "AEGIS-26-0001"
SECONDARY_CASE_ID = "AEGIS-26-0002"

PRIMARY_TRACE_SIGNALS = {
    "source_ref": "source-docnet-east-17",
    "provider_ref": "provider-synthetic-03",
    "asn_ref": "asn-synthetic-64500",
    "domain_cluster_ref": "domain-cluster-iris",
    "transport_fingerprint": "transport-4b0d",
    "tls_client_ref": "tls-profile-07",
    "toolchain_ref": "toolchain-hera",
    "client_fingerprint": "fp-7d3a9c",
}

SECONDARY_TRACE_SIGNALS = {
    **PRIMARY_TRACE_SIGNALS,
    "source_ref": "source-docnet-west-91",
}

SCENARIO_EVENTS = [
    {
        "event_type": "network_scan",
        "actor": "range-agent-07",
        "target": "decoy-edge-01",
        "payload": {**PRIMARY_TRACE_SIGNALS, "ports": [22, 80, 443], "sensor": "synthetic-zeek"},
        "summary": "A range agent enumerated exposed services on the decoy edge.",
    },
    {
        "event_type": "ssh_login_failure",
        "actor": "range-agent-07",
        "target": "decoy-bastion-01",
        "payload": {**PRIMARY_TRACE_SIGNALS, "username": "ops-admin", "attempts": 4, "sensor": "synthetic-cowrie"},
        "summary": "Repeated SSH attempts indicate a possible credential-access objective.",
    },
    {
        "event_type": "admin_route_probe",
        "actor": "range-agent-07",
        "target": "decoy-admin-portal",
        "payload": {**PRIMARY_TRACE_SIGNALS, "routes": ["/admin", "/backup", "/internal"], "status": [401, 404, 401], "canary_family_ref": "canary-privileged-route"},
        "summary": "The agent searched for privileged web routes and backup material.",
    },
    {
        "event_type": "synthetic_credential_opened",
        "actor": "range-agent-07",
        "target": "decoy-ops-notes",
        "payload": {**PRIMARY_TRACE_SIGNALS, "artifact": "rotation-notes.txt", "classification": "synthetic", "lure_family_ref": "lure-credential-rotation"},
        "summary": "A synthetic credential document was opened inside the authorized range.",
    },
    {
        "event_type": "decoy_service_pivot",
        "actor": "range-agent-07",
        "target": "decoy-inventory-api",
        "payload": {**PRIMARY_TRACE_SIGNALS, "source": "decoy-bastion-01", "protocol": "https", "result": "contained"},
        "summary": "The agent pivoted between two decoy services; no protected asset was reachable.",
    },
    {
        "event_type": "synthetic_archive_requested",
        "actor": "range-agent-07",
        "target": "decoy-finance-share",
        "payload": {**PRIMARY_TRACE_SIGNALS, "archive": "FY26-models.zip", "bytes": 248320, "classification": "synthetic"},
        "summary": "The agent requested a synthetic archive, increasing the collection hypothesis.",
    },
]

SECONDARY_SCENARIO_EVENTS = [
    {
        "event_type": "network_scan",
        "actor": "range-agent-12",
        "target": "decoy-edge-02",
        "payload": {**SECONDARY_TRACE_SIGNALS, "ports": [22, 443], "sensor": "synthetic-zeek"},
        "summary": "A second authorized synthetic session repeated the same narrow service-discovery pattern.",
    },
    {
        "event_type": "admin_route_probe",
        "actor": "range-agent-12",
        "target": "decoy-admin-portal",
        "payload": {**SECONDARY_TRACE_SIGNALS, "routes": ["/admin", "/internal"], "status": [401, 401], "canary_family_ref": "canary-privileged-route"},
        "summary": "The second session selected the same privileged web paths with a matching client fingerprint.",
    },
    {
        "event_type": "synthetic_credential_opened",
        "actor": "range-agent-12",
        "target": "decoy-identity-notes",
        "payload": {**SECONDARY_TRACE_SIGNALS, "artifact": "service-rotation.md", "classification": "synthetic", "lure_family_ref": "lure-credential-rotation"},
        "summary": "The second session opened a synthetic credential lure, supporting—but not proving—a campaign link.",
    },
]


class AegisService:
    def __init__(
        self,
        database_path: Path | None = None,
        settings: Settings = SETTINGS,
        telemetry_interval_seconds: int = 30,
    ):
        self.settings = settings
        self.store = AegisStore(database_path or settings.database_path)
        self.access_controller = AccessController()
        self.license_manager = LicenseManager(self.store.database_path.parent)
        self.audit_journal = AuditJournal(self.store)
        self.safety_gate = SafetyGate(settings)
        self.hardware_gateway = HardwareEnforcementGateway(settings)
        self.node_agent = LocalNodeAgent(settings.root)
        self.telemetry_runtime = EndpointTelemetryRuntime(
            self.store,
            self.node_agent,
            interval_seconds=telemetry_interval_seconds,
        )
        self.sensor_gateway = SensorEvidenceGateway(self.store, self.node_agent.node_id)
        self.artifact_registry = ArtifactGovernanceRegistry(self.store)
        self._experiment_cache: dict[int, dict[str, Any]] = {}
        self._learning_cache: dict[tuple[int, int], dict[str, Any]] = {}
        self._trace_experiment_cache: dict[int, dict[str, Any]] = {}
        self._trace_graph_experiment_cache: dict[int, dict[str, Any]] = {}
        self._steering_experiment_cache: dict[int, dict[str, Any]] = {}
        self._governance_identities: dict[str, str] | None = None
        self.bootstrap()

    def bootstrap(self) -> None:
        if not self.store.get_case(CASE_ID):
            self.store.create_case(
                CASE_ID,
                source="Authorized enterprise mini-range / east segment",
                summary="Synthetic session initialized; awaiting diagnostic telemetry.",
                hypotheses=uniform_prior(),
            )
            self._apply_scenario_event(CASE_ID, SCENARIO_EVENTS[0])
        if not self.store.get_case(SECONDARY_CASE_ID):
            self.store.create_case(
                SECONDARY_CASE_ID,
                source="Authorized enterprise mini-range / west segment",
                summary="Secondary synthetic session initialized for campaign-linkage evaluation.",
                hypotheses=uniform_prior(),
                risk_score=20,
            )
            for event_spec in SECONDARY_SCENARIO_EVENTS:
                self._apply_scenario_event(SECONDARY_CASE_ID, event_spec)

    def overview(self) -> dict[str, Any]:
        cases = self.store.list_cases()
        certificate_counts = self.store.certificate_counts()
        confidence_values = [summarize(case["hypotheses"])["confidence"] for case in cases]
        latest = self.store.latest_events(1)
        node = self.node_agent.snapshot()
        license_status = self.license_manager.status()
        return {
            "product": self.settings.product_name,
            "profile": self.settings.deployment_profile,
            "release": PRODUCT_VERSION,
            "mode": "LOCAL NODE ACTIVE / AUTHORIZED RANGE",
            "system_state": "CONTAINED",
            "node_state": node["state"],
            "active_collectors": node["active_collectors"],
            "active_cases": sum(case["status"] == "active" for case in cases),
            "protected_assets": 3,
            "decoy_assets": 6,
            "evidence_events": self.store.event_count(),
            "telemetry_observations": self.store.telemetry_summary()["total_observations"],
            "gateway_imports": self.store.gateway_import_summary()["total_imports"],
            "blocked_actions": certificate_counts["DENY"],
            "permitted_actions": certificate_counts["PERMIT"],
            "campaign_links": len(self.campaigns()["links"]),
            "trace_confidence": self.threat_trace()["leading_assessment"]["confidence"],
            "mean_model_confidence": round(sum(confidence_values) / len(confidence_values), 4) if confidence_values else 0.0,
            "latest_event_at": latest[0]["timestamp"] if latest else None,
            "resource_profile": {"ram_target_gb": 8, "gpu": "GTX 1650", "vram_gb": 4},
            "license_state": license_status["state"],
            "license_edition": license_status["edition"],
        }

    def access_status(self, session: OperatorSession) -> dict[str, Any]:
        return {
            "release": PRODUCT_VERSION,
            "license": self.license_manager.status(),
            "operator": session.to_dict(),
            "authorization": self.access_controller.status(),
            "audit": self.audit_journal.summary(),
            "safety_invariant": (
                "Licensing and operator roles can reduce access. They cannot relax the Safety "
                "Kernel, authorize external targeting, enable hack-back or create person attribution."
            ),
        }

    def reload_license(self, session: OperatorSession) -> dict[str, Any]:
        return {
            "status": "reloaded",
            "access": {
                "release": PRODUCT_VERSION,
                "license": self.license_manager.reload(),
                "operator": session.to_dict(),
                "authorization": self.access_controller.status(),
                "audit": self.audit_journal.summary(),
                "safety_invariant": (
                    "License reload cannot modify the Safety Kernel or expand the authorized namespace."
                ),
            },
        }

    def audit_events(self, limit: int = 100) -> dict[str, Any]:
        return {
            "events": self.audit_journal.list_events(limit),
            "summary": self.audit_journal.summary(),
        }

    def verify_audit(self) -> dict[str, Any]:
        return self.audit_journal.verify()

    def audit_operational(self) -> bool:
        return self.audit_journal.operational

    def record_operator_command(
        self,
        *,
        command_id: str,
        session_ref: str,
        operator_role: str,
        method: str,
        path: str,
        permission: str,
        entitlement: str | None,
        decision: str,
        status_code: int,
        request_sha256: str,
    ) -> dict[str, Any]:
        return self.audit_journal.append(
            command_id=command_id,
            session_ref=session_ref,
            operator_role=operator_role,
            method=method,
            path=path,
            permission=permission,
            entitlement=entitlement,
            decision=decision,
            status_code=status_code,
            request_sha256=request_sha256,
        )

    def list_cases(self) -> list[dict[str, Any]]:
        cases = self.store.list_cases()
        for case in cases:
            case["belief_summary"] = summarize(case["hypotheses"])
        return cases

    def case_detail(self, case_id: str) -> dict[str, Any] | None:
        case = self.store.get_case(case_id)
        if case is None:
            return None
        case["belief_summary"] = summarize(case["hypotheses"])
        case["events"] = list(reversed(self.store.list_events(case_id)))
        return case

    def simulate(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        requested_case = str((payload or {}).get("case_id", CASE_ID))
        case_id = requested_case if requested_case in (CASE_ID, SECONDARY_CASE_ID) else CASE_ID
        scenario = SCENARIO_EVENTS if case_id == CASE_ID else SECONDARY_SCENARIO_EVENTS
        event_count = len(self.store.list_events(case_id, limit=10000))
        event_spec = scenario[event_count % len(scenario)]
        record = self._apply_scenario_event(case_id, event_spec)
        return {"event": record, "case": self.case_detail(case_id), "overview": self.overview()}

    def evaluate_action(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        action = ProposedAction.from_dict(payload or {})
        certificate = self.safety_gate.evaluate(action)
        self.store.save_certificate(CASE_ID, certificate)
        return certificate

    def verify_evidence(self) -> dict[str, Any]:
        cases = [self.store.verify_case(case["id"]) for case in self.store.list_cases()]
        return {
            "valid": all(case["valid"] for case in cases),
            "verified_cases": len(cases),
            "verified_events": sum(int(case["verified_events"]) for case in cases),
            "cases": cases,
        }

    def reset_demo(self) -> dict[str, Any]:
        self.store.reset()
        self.bootstrap()
        return {"status": "reset", "overview": self.overview(), "case": self.case_detail(CASE_ID)}

    def campaigns(self) -> dict[str, Any]:
        cases = self.store.list_cases()
        features = {
            case["id"]: extract_features(case["id"], self.store.list_events(case["id"], limit=10000))
            for case in cases
        }
        links = []
        for index, left in enumerate(cases):
            for right in cases[index + 1:]:
                links.append(compare_cases(features[left["id"]], features[right["id"]]))
        links.sort(key=lambda item: item["confidence"], reverse=True)
        campaigns = []
        if links:
            strongest = links[0]
            campaigns.append({
                "id": "CMP-AEGIS-001",
                "label": "Credential-to-Collection Behaviour Cluster",
                "linked_cases": [strongest["left_case_id"], strongest["right_case_id"]],
                "confidence": strongest["confidence"],
                "strength": strongest["strength"],
                "status": "MONITORING",
                "narrative": "Two authorized-range sessions share discovery choices, privileged-route interest and a client fingerprint. Common tooling remains a competing explanation.",
                "attribution_status": strongest["attribution_status"],
                "supporting_evidence": strongest["supporting_evidence"],
            })
        return {
            "campaigns": campaigns,
            "links": links,
            "method": "Calibrated behavioural linkage across technique, sequence, target-family and pseudonymous fingerprint features.",
            "boundary": "AEGIS links activity; it does not identify a person or state without independently verified legal evidence.",
        }

    def indicators(self) -> dict[str, Any]:
        cases = self.store.list_cases()
        technique_cases: dict[str, set[str]] = {}
        technique_counts: dict[str, int] = {}
        for case in cases:
            for event in self.store.list_events(case["id"], limit=10000):
                technique = technique_for(event["event_type"])
                technique_cases.setdefault(technique["id"], set()).add(case["id"])
                technique_counts[technique["id"]] = technique_counts.get(technique["id"], 0) + 1
        techniques = []
        for technique_id, case_ids in technique_cases.items():
            metadata = next(value for value in TECHNIQUES.values() if value["id"] == technique_id)
            techniques.append({
                **metadata,
                "case_ids": sorted(case_ids),
                "observations": technique_counts[technique_id],
                "scope": "synthetic authorized range",
            })
        techniques.sort(key=lambda value: (-value["observations"], value["id"]))
        return {
            "techniques": techniques,
            "behavioural_indicators": [
                {"type": "client_fingerprint", "value": "fp-7d3a9c", "confidence": 0.78, "scope": "pseudonymous synthetic signal"},
                {"type": "route_sequence", "value": "/admin → /internal", "confidence": 0.66, "scope": "authorized decoy interaction"},
                {"type": "service_preference", "value": "SSH then privileged HTTP", "confidence": 0.61, "scope": "behavioural pattern"},
            ],
            "warning": "Indicators can be shared, spoofed or copied. Preserve provenance and uncertainty.",
        }

    def deception_assets(self) -> dict[str, Any]:
        return {
            "assets": [
                {"id": "decoy-edge-01", "type": "Network decoy", "surface": "22/80/443", "state": "ENGAGED", "sessions": 2, "isolation": "VERIFIED"},
                {"id": "decoy-bastion-01", "type": "Stateful SSH", "surface": "22", "state": "ENGAGED", "sessions": 1, "isolation": "VERIFIED"},
                {"id": "decoy-admin-portal", "type": "HTTP application", "surface": "443", "state": "ENGAGED", "sessions": 2, "isolation": "VERIFIED"},
                {"id": "decoy-inventory-api", "type": "Synthetic API", "surface": "8443", "state": "READY", "sessions": 0, "isolation": "VERIFIED"},
                {"id": "decoy-finance-share", "type": "Synthetic file service", "surface": "445", "state": "READY", "sessions": 0, "isolation": "VERIFIED"},
                {"id": "decoy-identity-notes", "type": "Credential lure", "surface": "artifact", "state": "TRIGGERED", "sessions": 1, "isolation": "VERIFIED"},
            ],
            "protected_namespace_reachable": False,
            "world_version": "world-graph-0010",
        }

    def research_status(self) -> dict[str, Any]:
        experiment = self.research_experiment()
        learning = self.learning_status()
        graph = self._trace_graph_experiment_cache.get(DEFAULT_SEED)
        steering = self._steering_experiment_cache.get(DEFAULT_SEED)
        return {
            "release": "1.0.0-research",
            "experiments": [
                {"id": "EXP-B0", "name": "Monitoring only", "status": "READY", "metric": "reference"},
                {"id": "EXP-B1", "name": "Static decoys", "status": "READY", "metric": "baseline"},
                {"id": "EXP-LINK", "name": "Campaign linkage calibration", "status": "RUNNING", "metric": "pairwise F1 / Brier"},
                {"id": "EXP-SAFE", "name": "Safety invariant adversarial suite", "status": "PASSING", "metric": "0 violations"},
                {"id": "EXP-INTENT", "name": "Calibrated intent sequence model", "status": experiment["status"], "metric": f"macro-F1 {experiment['metrics']['macro_f1']:.3f}"},
                {"id": "EXP-FABRIC", "name": "Multi-model learning fabric", "status": "SHADOW", "metric": f"candidate F1 {learning['models'][1]['test']['macro_f1']:.3f}"},
                {"id": "EXP-HEP", "name": "Hardware enforcement protocol", "status": "PROTOTYPE", "metric": "0 packet effects"},
                {"id": "EXP-TEL", "name": "Privacy-bounded endpoint telemetry", "status": "ACTIVE", "metric": "allowlist / local HMAC"},
                {"id": "EXP-TRACE", "name": "Evidence-diverse activity tracing", "status": self.trace_experiment()["status"], "metric": f"test F1 {self.trace_experiment()['winner']['test']['f1']:.3f}"},
                {"id": "EXP-GATE", "name": "Privacy-bounded sensor normalization", "status": "ACTIVE", "metric": "Suricata + Zeek offline conformance"},
                {"id": "EXP-GRAPH", "name": "Transitivity-safe campaign clustering", "status": graph["status"] if graph else "READY", "metric": f"stress B³-F1 {graph['winner']['stress']['b_cubed_f1']:.3f}" if graph else "B³-F1 / false-merge stress"},
                {"id": "EXP-REG", "name": "Attested artifact and promotion ledger", "status": "ACTIVE", "metric": "HMAC integrity / hash-chain verification"},
                {"id": "EXP-STEER", "name": "Expected-information-gain deception steering", "status": steering["status"] if steering else "READY", "metric": f"held-out correct confidence {steering['winner']['held_out_family']['correct_confidence_rate']:.3f}" if steering else "correct confidence / interactions / calibration"},
                {"id": "EXP-CTRL", "name": "Licensed operator trust boundary", "status": "ACTIVE", "metric": "Ed25519 / scoped roles / HMAC audit"},
            ],
            "reproducibility": {
                "event_contract": "v1",
                "seeded_scenarios": 20,
                "dataset_sequences": experiment["dataset"]["samples"],
                "automated_tests": 88,
                "external_targets": 0,
            },
        }

    def learning_status(self, seed: int = DEFAULT_SEED, shadow_observations: int = 240) -> dict[str, Any]:
        key = (seed, shadow_observations)
        if key not in self._learning_cache:
            self._learning_cache[key] = run_learning_fabric(seed, shadow_observations)
        return self._learning_cache[key]

    def evaluate_learning_candidate(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        raw_seed = (payload or {}).get("seed", DEFAULT_SEED)
        try:
            seed = min(max(int(raw_seed), 0), 2_147_483_647)
        except (TypeError, ValueError):
            seed = DEFAULT_SEED
        # The public endpoint cannot manufacture shadow volume or release sign-off.
        # It evaluates the reproducible research corpus and returns a HOLD decision.
        key = (seed, 240)
        self._learning_cache.pop(key, None)
        return self.learning_status(seed, 240)

    def system_agents(self) -> dict[str, Any]:
        return {
            "agents": [self.node_agent.snapshot()],
            "control_plane": "ONLINE",
            "telemetry_runtime": self.telemetry_runtime.status(),
        }

    def telemetry_status(self) -> dict[str, Any]:
        return self.telemetry_runtime.status()

    def telemetry_events(self, limit: int = 100) -> dict[str, Any]:
        return {
            "events": self.store.list_telemetry(limit=limit),
            "summary": self.store.telemetry_summary(),
        }

    def collect_telemetry(self) -> dict[str, Any]:
        return self.telemetry_runtime.collect_once()

    def gateway_status(self) -> dict[str, Any]:
        return {**self.sensor_gateway.status(), "summary": self.store.gateway_import_summary()}

    def gateway_sample(self, connector_id: str) -> dict[str, Any]:
        return self.sensor_gateway.sample(connector_id)

    def preview_gateway_records(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        value = payload or {}
        return self.sensor_gateway.process(
            str(value.get("connector", "suricata-eve-json")),
            value.get("records"),
            commit=False,
        )

    def import_gateway_records(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        value = payload or {}
        return self.sensor_gateway.process(
            str(value.get("connector", "suricata-eve-json")),
            value.get("records"),
            commit=True,
        )

    def start_background_services(self) -> bool:
        return self.telemetry_runtime.start()

    def stop_background_services(self) -> None:
        self.telemetry_runtime.stop()

    def research_experiment(self, seed: int = DEFAULT_SEED) -> dict[str, Any]:
        if seed not in self._experiment_cache:
            self._experiment_cache[seed] = run_intent_experiment(seed)
        return self._experiment_cache[seed]

    def run_research_experiment(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        raw_seed = (payload or {}).get("seed", DEFAULT_SEED)
        try:
            seed = int(raw_seed)
        except (TypeError, ValueError):
            seed = DEFAULT_SEED
        seed = min(max(seed, 0), 2_147_483_647)
        self._experiment_cache.pop(seed, None)
        return self.research_experiment(seed)

    def threat_trace(self) -> dict[str, Any]:
        case_events = {
            case["id"]: self.store.list_events(case["id"], limit=10000)
            for case in self.store.list_cases()
        }
        return build_trace_report(case_events)

    def trace_experiment(self, seed: int = DEFAULT_SEED) -> dict[str, Any]:
        if seed not in self._trace_experiment_cache:
            self._trace_experiment_cache[seed] = run_trace_experiment(seed)
        return self._trace_experiment_cache[seed]

    def run_trace_experiment(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        raw_seed = (payload or {}).get("seed", DEFAULT_SEED)
        try:
            seed = min(max(int(raw_seed), 0), 2_147_483_647)
        except (TypeError, ValueError):
            seed = DEFAULT_SEED
        self._trace_experiment_cache.pop(seed, None)
        return self.trace_experiment(seed)

    def trace_graph_experiment(self, seed: int = DEFAULT_SEED) -> dict[str, Any]:
        if seed not in self._trace_graph_experiment_cache:
            self._trace_graph_experiment_cache[seed] = run_trace_graph_experiment(seed)
        return self._trace_graph_experiment_cache[seed]

    def run_trace_graph_experiment(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        raw_seed = (payload or {}).get("seed", DEFAULT_SEED)
        try:
            seed = min(max(int(raw_seed), 0), 2_147_483_647)
        except (TypeError, ValueError):
            seed = DEFAULT_SEED
        self._trace_graph_experiment_cache.pop(seed, None)
        return self.trace_graph_experiment(seed)

    def steering_experiment(self, seed: int = DEFAULT_SEED) -> dict[str, Any]:
        if seed not in self._steering_experiment_cache:
            self._steering_experiment_cache[seed] = run_diagnostic_steering_experiment(
                seed,
                self.settings,
            )
        return self._steering_experiment_cache[seed]

    def run_steering_experiment(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        raw_seed = (payload or {}).get("seed", DEFAULT_SEED)
        try:
            seed = min(max(int(raw_seed), 0), 2_147_483_647)
        except (TypeError, ValueError):
            seed = DEFAULT_SEED
        self._steering_experiment_cache.pop(seed, None)
        return self.steering_experiment(seed)

    def governance_status(self) -> dict[str, Any]:
        identities = self._ensure_governance_registry()
        return {
            **self.artifact_registry.status(),
            "release": "1.0.0-governance",
            "default_candidate": identities["candidate"],
            "default_champion": identities["champion"],
            "boundary": "Local HMAC attestations and hash chaining detect modification inside one installation; production still requires asymmetric organization signatures, platform code signing and an offline reviewer workflow.",
        }

    def evaluate_governance_candidate(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        identities = self._ensure_governance_registry()
        value = payload or {}
        candidate_id = str(value.get("candidate_artifact_id") or identities["candidate"])
        candidate = self.artifact_registry.get_artifact(candidate_id)
        if candidate is None or candidate["artifact_type"] != "model":
            raise RegistryValidationError("registered model candidate required")
        ignored = set(value) - {"candidate_artifact_id"}
        decision = self.artifact_registry.evaluate_candidate(
            candidate_id,
            identities["champion"],
            shadow_observations=0,
            human_release_signoff=False,
            enterprise_validation=False,
            rollback_artifact_id=None,
            actor="LOOPBACK_API",
            ignored_request_fields=ignored,
        )
        return {"decision_record": decision, "governance": self.governance_status()}

    def verify_governance(self) -> dict[str, Any]:
        self._ensure_governance_registry()
        return {
            "registry": self.artifact_registry.verify_registry(),
            "ledger": self.artifact_registry.verify_ledger(),
        }

    def _ensure_governance_registry(self) -> dict[str, str]:
        if self._governance_identities is not None:
            return self._governance_identities

        intent = self.research_experiment()
        learning = self.learning_status()
        trace = self.trace_experiment()
        graph = self.trace_graph_experiment()
        steering = self.steering_experiment()

        intent_dataset = self.artifact_registry.register_artifact(
            "dataset",
            "AEGIS Synthetic Intent Corpus",
            intent["dataset"]["generator_version"],
            {
                **intent["dataset"],
                "experiment_id": intent["experiment_id"],
                "run_id": intent["run_id"],
                "grouped_split": True,
            },
            status="RESEARCH",
        )
        learning_models = {model["id"]: model for model in learning["models"]}

        def register_intent_model(model_id: str, status: str) -> dict[str, Any]:
            model = learning_models[model_id]
            return self.artifact_registry.register_artifact(
                "model",
                model["name"],
                "v1",
                {
                    "model_id": model_id,
                    "model_family": model["name"],
                    "source_run_id": learning["run_id"],
                    "validation": model["validation"],
                    "test": model["test"],
                    "grouped_validation": True,
                    "quality_gate_passed": model["validation"]["macro_f1"] >= 0.80,
                    "safety_violations": 0,
                    "external_targets": 0,
                    "synthetic_only": True,
                },
                lineage=[intent_dataset["artifact_id"]],
                status=status,
            )

        champion = register_intent_model("INTENT-SEQUENCE-NB-V1", "CHAMPION")
        candidate = register_intent_model("INTENT-EVENTSET-NB-V1", "SHADOW")

        trace_dataset = self.artifact_registry.register_artifact(
            "dataset",
            "AEGIS Synthetic Trace Pair Corpus",
            trace["dataset"]["generator_version"],
            {**trace["dataset"], "run_id": trace["run_id"], "grouped_split": True},
            status="RESEARCH",
        )
        trace_model = next(model for model in trace["models"] if model["id"] == "TRACE-LOGISTIC-CANDIDATE")
        self.artifact_registry.register_artifact(
            "model",
            trace_model["name"],
            "v1",
            {
                "model_id": trace_model["id"],
                "model_family": trace_model["name"],
                "source_run_id": trace["run_id"],
                "test": trace_model["test"],
                "grouped_validation": True,
                "quality_gate_passed": trace_model["test"]["f1"] >= 0.75,
                "safety_violations": 0,
                "external_targets": 0,
                "identity_label": False,
                "synthetic_only": True,
            },
            lineage=[trace_dataset["artifact_id"]],
            status="SHADOW",
        )

        graph_dataset = self.artifact_registry.register_artifact(
            "dataset",
            "AEGIS Synthetic Trace Graph Corpus",
            graph["dataset"]["generator_version"],
            {**graph["dataset"], "run_id": graph["run_id"], "grouped_split": True},
            status="RESEARCH",
        )
        self.artifact_registry.register_artifact(
            "model",
            graph["winner"]["name"],
            "v1",
            {
                "model_id": graph["winner"]["id"],
                "model_family": graph["winner"]["name"],
                "source_run_id": graph["run_id"],
                "clean": graph["winner"]["clean"],
                "stress": graph["winner"]["stress"],
                "bridge_rejections": graph["bridge_audit"]["rejected"],
                "grouped_validation": True,
                "quality_gate_passed": graph["status"] == "PASSING",
                "safety_violations": 0,
                "external_targets": 0,
                "identity_label": False,
                "synthetic_only": True,
            },
            lineage=[graph_dataset["artifact_id"], trace_dataset["artifact_id"]],
            status="SHADOW",
        )
        safety_policy = self.artifact_registry.register_artifact(
            "policy",
            "AEGIS Safety Kernel Invariant Set",
            "v1",
            {
                "policy_id": "SAFETY-KERNEL-8-INVARIANTS",
                "authorized_namespace": self.settings.authorized_namespace,
                "decoy_only": True,
                "network_egress": False,
                "synthetic_data_only": True,
                "maximum_ttl_seconds": self.settings.max_action_ttl_seconds,
                "automatic_model_actuation": False,
            },
            status="RESEARCH",
        )
        steering_dataset = self.artifact_registry.register_artifact(
            "dataset",
            "AEGIS Synthetic Diagnostic Steering Corpus",
            steering["dataset"]["generator_version"],
            {
                **steering["dataset"],
                "run_id": steering["run_id"],
                "grouped_split": True,
                "held_out_family": steering["validity_checks"]["held_out_family"],
            },
            status="RESEARCH",
        )
        self.artifact_registry.register_artifact(
            "model",
            steering["winner"]["name"],
            "v1",
            {
                "model_id": steering["winner"]["id"],
                "model_family": "Bayesian expected-information-gain decision policy",
                "source_run_id": steering["run_id"],
                "held_out": steering["winner"]["held_out_family"],
                "gain_over_static": steering["winner"]["gain_over_static"],
                "grouped_validation": True,
                "quality_gate_passed": steering["status"] == "PASSING",
                "safety_violations": steering["validity_checks"]["unsafe_acceptances"],
                "external_targets": steering["validity_checks"]["external_targets"],
                "identity_label": steering["validity_checks"]["identity_label"],
                "automatic_actuation": steering["validity_checks"]["automatic_actuation"],
                "synthetic_only": True,
            },
            lineage=[steering_dataset["artifact_id"], safety_policy["artifact_id"]],
            status="SHADOW",
        )
        if not self.artifact_registry.list_decisions():
            self.artifact_registry.evaluate_candidate(
                candidate["artifact_id"],
                champion["artifact_id"],
                actor="SYSTEM_BOOTSTRAP",
            )
        self._governance_identities = {
            "candidate": candidate["artifact_id"],
            "champion": champion["artifact_id"],
        }
        return self._governance_identities

    def research_dataset(self) -> dict[str, Any]:
        return dataset_summary(DEFAULT_SEED)

    def hardware_profile(self) -> dict[str, Any]:
        return self.hardware_gateway.profile()

    def hardware_dry_run(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        action = ProposedAction.from_dict(payload or {})
        certificate = self.safety_gate.evaluate(action)
        receipt = self.hardware_gateway.dry_run(certificate)
        return {"certificate": certificate, "receipt": receipt}

    def case_bundle(self, case_id: str) -> dict[str, Any] | None:
        case = self.case_detail(case_id)
        if case is None:
            return None
        return build_case_bundle(case, self.store.verify_case(case_id))

    def topology(self) -> dict[str, Any]:
        return {
            "nodes": [
                {"id": "range-agent-07", "label": "Range Agent", "kind": "actor", "x": 8, "y": 49, "state": "observed"},
                {"id": "decoy-edge-01", "label": "Edge Decoy", "kind": "decoy", "x": 30, "y": 28, "state": "engaged"},
                {"id": "decoy-bastion-01", "label": "SSH Bastion", "kind": "decoy", "x": 50, "y": 49, "state": "engaged"},
                {"id": "decoy-admin-portal", "label": "Admin Portal", "kind": "decoy", "x": 70, "y": 25, "state": "ready"},
                {"id": "decoy-inventory-api", "label": "Inventory API", "kind": "decoy", "x": 70, "y": 72, "state": "ready"},
                {"id": "protected-core", "label": "Protected Core", "kind": "protected", "x": 92, "y": 49, "state": "isolated"},
            ],
            "edges": [
                {"from": "range-agent-07", "to": "decoy-edge-01", "state": "observed"},
                {"from": "decoy-edge-01", "to": "decoy-bastion-01", "state": "contained"},
                {"from": "decoy-bastion-01", "to": "decoy-admin-portal", "state": "decoy"},
                {"from": "decoy-bastion-01", "to": "decoy-inventory-api", "state": "decoy"},
                {"from": "decoy-admin-portal", "to": "protected-core", "state": "blocked"},
                {"from": "decoy-inventory-api", "to": "protected-core", "state": "blocked"},
            ],
        }

    def latest_certificate(self) -> dict[str, Any] | None:
        return self.store.latest_certificate()

    def _apply_scenario_event(self, case_id: str, event_spec: dict[str, Any]) -> dict[str, Any]:
        case = self.store.get_case(case_id)
        if case is None:
            raise RuntimeError("case bootstrap failed")
        event = SecurityEvent(
            case_id=case_id,
            event_type=event_spec["event_type"],
            actor=event_spec["actor"],
            target=event_spec["target"],
            payload=event_spec["payload"],
        )
        record = self.store.append_event(event)
        beliefs = update_beliefs(case["hypotheses"], event.event_type)
        belief_summary = summarize(beliefs)
        top_probability = float(belief_summary["top_probability"])
        case_event_count = len(self.store.list_events(case_id, limit=10000))
        risk = min(98, 28 + int(top_probability * 62) + min(case_event_count, 8))
        self.store.update_case_beliefs(
            case_id,
            hypotheses=beliefs,
            stage=str(belief_summary["top_hypothesis"]),
            risk_score=risk,
            summary=event_spec["summary"],
        )
        return record
