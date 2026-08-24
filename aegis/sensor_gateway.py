from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .models import TelemetryObservation, utc_now
from .store import AegisStore
from .telemetry import Pseudonymizer


GATEWAY_CONTRACT_VERSION = "aegis.sensor-gateway.v1"
MAX_RECORDS = 256
MAX_RECORD_BYTES = 64_000
SUPPORTED_SURICATA_EVENTS = {
    "alert",
    "anomaly",
    "dns",
    "flow",
    "http",
    "ssh",
    "tls",
}


@dataclass(frozen=True)
class ConnectorSpec:
    id: str
    name: str
    format: str
    status: str
    role: str
    retained: tuple[str, ...]
    discarded: tuple[str, ...]
    official_reference: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "format": self.format,
            "status": self.status,
            "role": self.role,
            "retained": list(self.retained),
            "discarded": list(self.discarded),
            "official_reference": self.official_reference,
        }


CONNECTORS = (
    ConnectorSpec(
        id="suricata-eve-json",
        name="Suricata EVE JSON",
        format="JSON array or newline-delimited JSON",
        status="OFFLINE_IMPORT_READY",
        role="Normalizes selected EVE alert, flow and protocol metadata without retaining packet content.",
        retained=(
            "timestamp",
            "event type",
            "protocol/application",
            "bounded ports",
            "pseudonymous endpoint/flow/domain/fingerprint references",
            "selected alert/flow state",
        ),
        discarded=(
            "packet/pcap payload",
            "raw IP addresses",
            "raw domain/SNI/hostname",
            "HTTP URI/body/header content",
            "file content",
            "credentials",
        ),
        official_reference="https://docs.suricata.io/en/latest/output/eve/eve-json-format.html",
    ),
    ConnectorSpec(
        id="zeek-conn-json",
        name="Zeek conn.log JSON",
        format="JSON array or newline-delimited JSON",
        status="OFFLINE_IMPORT_READY",
        role="Normalizes selected connection metadata from Zeek JSON logs into privacy-bounded observations.",
        retained=(
            "timestamp",
            "protocol/service",
            "bounded ports",
            "coarse duration/byte buckets",
            "connection state/history",
            "pseudonymous endpoint/flow references",
        ),
        discarded=(
            "raw IP addresses",
            "packet content",
            "raw UID/community ID",
            "hostnames",
            "application content",
            "credentials",
        ),
        official_reference="https://docs.zeek.org/en/current/reference/logs/conn.html",
    ),
)

CONNECTOR_BY_ID = {connector.id: connector for connector in CONNECTORS}


SAMPLE_RECORDS: dict[str, list[dict[str, Any]]] = {
    "suricata-eve-json": [
        {
            "timestamp": "2026-08-20T18:00:01.123456+00:00",
            "flow_id": 7788990011,
            "event_type": "alert",
            "src_ip": "198.51.100.27",
            "src_port": 53391,
            "dest_ip": "192.0.2.40",
            "dest_port": 443,
            "proto": "TCP",
            "app_proto": "tls",
            "alert": {
                "signature_id": 990001,
                "category": "Synthetic authorized-range policy test",
                "severity": 2,
                "action": "allowed",
            },
            "tls": {"ja3": {"hash": "0123456789abcdef"}, "sni": "decoy-admin.example"},
            "payload": "THIS FIELD MUST NEVER SURVIVE",
        },
        {
            "timestamp": "2026-08-20T18:00:03.000000+00:00",
            "flow_id": 7788990011,
            "event_type": "flow",
            "src_ip": "198.51.100.27",
            "src_port": 53391,
            "dest_ip": "192.0.2.40",
            "dest_port": 443,
            "proto": "TCP",
            "app_proto": "tls",
            "flow": {"state": "established", "reason": "timeout", "age": 2},
        },
    ],
    "zeek-conn-json": [
        {
            "ts": 1787248810.25,
            "uid": "CsampleOpaqueRawUid",
            "id.orig_h": "203.0.113.61",
            "id.orig_p": 49222,
            "id.resp_h": "192.0.2.55",
            "id.resp_p": 22,
            "proto": "tcp",
            "service": "ssh",
            "duration": 3.187,
            "orig_bytes": 821,
            "resp_bytes": 1302,
            "conn_state": "SF",
            "history": "ShADadfF",
            "local_orig": False,
            "local_resp": True,
        },
        {
            "ts": 1787248818.75,
            "uid": "CsampleSecondRawUid",
            "id.orig_h": "203.0.113.99",
            "id.orig_p": 50410,
            "id.resp_h": "192.0.2.55",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 0.42,
            "orig_bytes": 220,
            "resp_bytes": 490,
            "conn_state": "S0",
            "history": "S",
            "local_orig": False,
            "local_resp": True,
        },
    ],
}


class GatewayValidationError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _timestamp(value: Any) -> str:
    try:
        if isinstance(value, (int, float)) and math.isfinite(float(value)):
            moment = datetime.fromtimestamp(float(value), timezone.utc)
        elif isinstance(value, str) and 1 <= len(value) <= 64:
            normalized = value.strip().replace("Z", "+00:00")
            moment = datetime.fromisoformat(normalized)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            moment = moment.astimezone(timezone.utc)
        else:
            raise ValueError
    except (OverflowError, OSError, ValueError):
        raise GatewayValidationError("valid bounded timestamp required") from None
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _token(value: Any, maximum: int = 48, default: str = "unknown") -> str:
    normalized = str(value or "").strip().lower()
    if not normalized or len(normalized) > maximum:
        return default
    return normalized if re.fullmatch(r"[a-z0-9_.:+-]+", normalized) else default


def _port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _finite_number(value: Any, minimum: float = 0.0, maximum: float = 86_400.0) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return round(number, 3) if math.isfinite(number) and minimum <= number <= maximum else None


def _byte_bucket(value: Any) -> str | None:
    try:
        size = max(0, int(value))
    except (TypeError, ValueError):
        return None
    boundaries = (0, 256, 1_024, 4_096, 16_384, 65_536, 262_144, 1_048_576)
    for boundary in boundaries[1:]:
        if size < boundary:
            return f"lt-{boundary}"
    return "gte-1048576"


def _reference(pseudonymizer: Pseudonymizer, kind: str, value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    if not normalized or len(normalized) > 512:
        return None
    return pseudonymizer.reference(kind, normalized)


def _endpoint_reference(pseudonymizer: Pseudonymizer, kind: str, value: Any) -> str:
    try:
        normalized = ipaddress.ip_address(str(value).strip()).compressed
    except ValueError:
        raise GatewayValidationError(f"{kind} must contain an IPv4 or IPv6 address") from None
    return pseudonymizer.reference(kind, normalized)


def _contains_raw_ip(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_raw_ip(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_raw_ip(item) for item in value)
    if not isinstance(value, str):
        return False
    candidates = [value.strip()]
    candidates.extend(
        candidate.strip("[](){}<>,;\"'")
        for candidate in re.findall(r"[0-9A-Fa-f:.]{3,}", value)
    )
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            continue
    return False


class SensorEvidenceGateway:
    def __init__(self, store: AegisStore, node_id: str):
        self.store = store
        self.node_id = node_id
        self.pseudonymizer = Pseudonymizer(store.database_path.parent / "node.key")
        self._normalizers: dict[str, Callable[[dict[str, Any]], TelemetryObservation]] = {
            "suricata-eve-json": self._suricata,
            "zeek-conn-json": self._zeek,
        }

    def status(self) -> dict[str, Any]:
        return {
            "contract_version": GATEWAY_CONTRACT_VERSION,
            "mode": "OFFLINE AUTHORIZED IMPORT / NO SENSOR CONTROL",
            "connectors": [connector.to_dict() for connector in CONNECTORS],
            "limits": {"records_per_import": MAX_RECORDS, "bytes_per_record": MAX_RECORD_BYTES},
            "privacy": {
                "pseudonymization": "HMAC-SHA-256 / local per-install key",
                "raw_ip_persisted": False,
                "packet_content_persisted": False,
                "raw_domain_persisted": False,
                "outbound_connection": False,
                "automatic_case_promotion": False,
            },
            "last_import": self.store.latest_gateway_import(),
        }

    def sample(self, connector_id: str) -> dict[str, Any]:
        connector = self._connector(connector_id)
        return {
            "connector": connector.to_dict(),
            "records": SAMPLE_RECORDS[connector.id],
            "synthetic_only": True,
            "address_semantics": "RFC 5737 documentation ranges; no connection is attempted.",
        }

    def process(self, connector_id: str, records: Any, commit: bool = False) -> dict[str, Any]:
        connector = self._connector(connector_id)
        if not isinstance(records, list):
            raise GatewayValidationError("records must be a JSON array")
        if not records:
            raise GatewayValidationError("at least one record is required")
        if len(records) > MAX_RECORDS:
            raise GatewayValidationError(f"at most {MAX_RECORDS} records are accepted per import")

        input_sha = hashlib.sha256(_canonical(records)).hexdigest()
        accepted: list[TelemetryObservation] = []
        outcomes = []
        for index, record in enumerate(records):
            try:
                if not isinstance(record, dict):
                    raise GatewayValidationError("record must be a JSON object")
                if len(_canonical(record)) > MAX_RECORD_BYTES:
                    raise GatewayValidationError(f"record exceeds {MAX_RECORD_BYTES} bytes")
                observation = self._normalizers[connector.id](record)
                if _contains_raw_ip(observation.to_dict()):
                    raise GatewayValidationError("privacy invariant: normalized output contains a raw IP")
                accepted.append(observation)
                outcomes.append({
                    "index": index,
                    "status": "ACCEPTED",
                    "event_type": observation.event_type,
                    "timestamp": observation.timestamp,
                    "severity": observation.severity,
                    "safe_payload": observation.payload,
                })
            except GatewayValidationError as error:
                outcomes.append({"index": index, "status": "REJECTED", "reason": str(error)[:180]})

        inserted = 0
        if commit:
            for observation in accepted:
                inserted += int(self.store.append_telemetry(observation)["inserted"])

        safe_descriptor = {
            "contract_version": GATEWAY_CONTRACT_VERSION,
            "connector_id": connector.id,
            "input_sha256": input_sha,
            "mode": "COMMIT" if commit else "PREVIEW",
            "outcomes": outcomes,
        }
        manifest_sha = hashlib.sha256(_canonical(safe_descriptor)).hexdigest()
        import_id = "IMP-" + hashlib.sha256(
            _canonical({"connector": connector.id, "input": input_sha, "mode": safe_descriptor["mode"]})
        ).hexdigest()[:16].upper()
        report = {
            **safe_descriptor,
            "import_id": import_id,
            "created_at": utc_now(),
            "counts": {
                "received": len(records),
                "accepted": len(accepted),
                "rejected": len(records) - len(accepted),
                "inserted": inserted,
                "deduplicated": len(accepted) - inserted if commit else 0,
            },
            "manifest_sha256": manifest_sha,
            "privacy_assertions": {
                "raw_ip_in_output": False,
                "raw_domain_in_output": False,
                "payload_content_in_output": False,
                "automatic_case_promotion": False,
                "outbound_connection": False,
            },
            "scope": "Authorized offline sensor evidence normalization",
        }
        if commit:
            self.store.save_gateway_import(report)
        return report

    @staticmethod
    def _connector(connector_id: str) -> ConnectorSpec:
        connector = CONNECTOR_BY_ID.get(str(connector_id))
        if connector is None:
            raise GatewayValidationError("unsupported connector")
        return connector

    def _suricata(self, record: dict[str, Any]) -> TelemetryObservation:
        event_type = _token(record.get("event_type"))
        if event_type not in SUPPORTED_SURICATA_EVENTS:
            raise GatewayValidationError("unsupported Suricata event_type")
        timestamp = _timestamp(record.get("timestamp"))
        source_ref = _endpoint_reference(self.pseudonymizer, "source", record.get("src_ip"))
        destination_ref = _endpoint_reference(self.pseudonymizer, "destination", record.get("dest_ip"))
        payload: dict[str, Any] = {
            "contract_version": GATEWAY_CONTRACT_VERSION,
            "provider_contract": "suricata-eve-json",
            "source_ref": source_ref,
            "destination_ref": destination_ref,
            "protocol": _token(record.get("proto"), 16),
            "application_protocol": _token(record.get("app_proto"), 32),
            "privacy": "raw endpoints and content discarded before persistence",
        }
        for key, raw in (("source_port", record.get("src_port")), ("destination_port", record.get("dest_port"))):
            value = _port(raw)
            if value is not None:
                payload[key] = value
        flow_ref = _reference(self.pseudonymizer, "flow", record.get("flow_id"))
        if flow_ref:
            payload["flow_ref"] = flow_ref

        severity = "info"
        if event_type == "alert":
            alert = record.get("alert") if isinstance(record.get("alert"), dict) else {}
            try:
                alert_severity = int(alert.get("severity", 4))
            except (TypeError, ValueError):
                alert_severity = 4
            severity = "high" if alert_severity <= 1 else "medium" if alert_severity == 2 else "low"
            signature_id = alert.get("signature_id")
            if isinstance(signature_id, int) and 0 <= signature_id <= 2_147_483_647:
                payload["signature_id"] = signature_id
            category_ref = _reference(self.pseudonymizer, "alert-category", alert.get("category"))
            if category_ref:
                payload["alert_category_ref"] = category_ref
            payload["alert_action"] = _token(alert.get("action"), 24)
        elif event_type == "flow":
            flow = record.get("flow") if isinstance(record.get("flow"), dict) else {}
            payload["flow_state"] = _token(flow.get("state"), 24)
            payload["flow_reason"] = _token(flow.get("reason"), 24)

        tls = record.get("tls") if isinstance(record.get("tls"), dict) else {}
        ja3 = tls.get("ja3") if isinstance(tls.get("ja3"), dict) else {}
        transport = _reference(self.pseudonymizer, "transport", ja3.get("hash"))
        if transport:
            payload["transport_fingerprint"] = transport
        domain_ref = _reference(self.pseudonymizer, "domain", tls.get("sni"))
        if domain_ref:
            payload["domain_cluster_ref"] = domain_ref

        dns = record.get("dns") if isinstance(record.get("dns"), dict) else {}
        dns_ref = _reference(self.pseudonymizer, "domain", dns.get("rrname"))
        if dns_ref:
            payload["domain_cluster_ref"] = dns_ref
            payload["dns_type"] = _token(dns.get("rrtype"), 16)

        ssh = record.get("ssh") if isinstance(record.get("ssh"), dict) else {}
        client_ref = _reference(self.pseudonymizer, "client", ssh.get("client") or ssh.get("client_software"))
        if client_ref:
            payload["client_fingerprint"] = client_ref

        return TelemetryObservation(
            node_id=self.node_id,
            source="suricata-eve-gateway",
            category="network-evidence",
            event_type=f"suricata_{event_type}",
            severity=severity,
            payload=payload,
            timestamp=timestamp,
        )

    def _zeek(self, record: dict[str, Any]) -> TelemetryObservation:
        timestamp = _timestamp(record.get("ts"))
        source_ref = _endpoint_reference(self.pseudonymizer, "source", record.get("id.orig_h"))
        destination_ref = _endpoint_reference(self.pseudonymizer, "destination", record.get("id.resp_h"))
        conn_state = _token(record.get("conn_state"), 12)
        payload: dict[str, Any] = {
            "contract_version": GATEWAY_CONTRACT_VERSION,
            "provider_contract": "zeek-conn-json",
            "source_ref": source_ref,
            "destination_ref": destination_ref,
            "protocol": _token(record.get("proto"), 16),
            "service": _token(record.get("service"), 32),
            "connection_state": conn_state,
            "history": _token(record.get("history"), 32),
            "privacy": "raw endpoints, flow identifiers and content discarded before persistence",
        }
        for key, raw in (("source_port", record.get("id.orig_p")), ("destination_port", record.get("id.resp_p"))):
            value = _port(raw)
            if value is not None:
                payload[key] = value
        duration = _finite_number(record.get("duration"))
        if duration is not None:
            payload["duration_seconds"] = duration
        for key, raw in (("origin_bytes_bucket", record.get("orig_bytes")), ("response_bytes_bucket", record.get("resp_bytes"))):
            value = _byte_bucket(raw)
            if value:
                payload[key] = value
        for key in ("local_orig", "local_resp"):
            if isinstance(record.get(key), bool):
                payload[key] = record[key]
        flow_ref = _reference(self.pseudonymizer, "flow", record.get("uid") or record.get("community_id"))
        if flow_ref:
            payload["flow_ref"] = flow_ref

        severity = "low" if conn_state in {"s0", "rej", "rstos0", "rstrh"} else "info"
        return TelemetryObservation(
            node_id=self.node_id,
            source="zeek-conn-gateway",
            category="network-evidence",
            event_type="zeek_connection",
            severity=severity,
            payload=payload,
            timestamp=timestamp,
        )
