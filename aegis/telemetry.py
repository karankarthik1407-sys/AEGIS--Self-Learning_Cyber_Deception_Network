from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any, Protocol

from . import __version__
from .agent import LocalNodeAgent
from .models import TelemetryObservation, utc_now
from .store import AegisStore


TELEMETRY_CONTRACT_VERSION = "aegis.telemetry.v1"
EVENT_NAMESPACE = "{http://schemas.microsoft.com/win/2004/08/events/event}"


@dataclass(frozen=True)
class CollectorOutput:
    state: str
    detail: str
    observations: tuple[TelemetryObservation, ...] = ()


class PassiveCollector(Protocol):
    id: str
    name: str

    def collect(self) -> CollectorOutput: ...


class Pseudonymizer:
    """Creates stable local references without storing raw identity fields."""

    def __init__(self, key_path: Path):
        self.key_path = Path(key_path)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        if self.key_path.is_file():
            key = self.key_path.read_bytes()
            if len(key) >= 32:
                return key
            raise RuntimeError(f"AEGIS pseudonymization key is invalid: {self.key_path}")
        key = secrets.token_bytes(32)
        try:
            descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(key)
        except FileExistsError:
            raced_key = self.key_path.read_bytes()
            if len(raced_key) < 32:
                raise RuntimeError(f"AEGIS pseudonymization key is invalid: {self.key_path}")
            return raced_key
        return key

    def reference(self, kind: str, value: str) -> str:
        normalized = f"{kind}:{value.strip().lower()}".encode("utf-8", errors="replace")
        digest = hmac.new(self._key, normalized, hashlib.sha256).hexdigest()[:14]
        return f"{kind}-{digest}"


class HostHealthCollector:
    id = "COL-HOST-HEALTH"
    name = "Host health sampler"

    def __init__(self, agent: LocalNodeAgent):
        self.agent = agent

    def collect(self) -> CollectorOutput:
        snapshot = self.agent.snapshot()
        host = snapshot["host"]
        payload: dict[str, Any] = {
            "contract_version": TELEMETRY_CONTRACT_VERSION,
            "platform": host["platform"],
            "architecture": host["architecture"],
            "cpu_logical": host["cpu_logical"],
            "memory_available_gib": host["memory_available_gib"],
            "storage_free_gib": host["storage_free_gib"],
            "runtime_uptime_seconds": snapshot["uptime_seconds"],
        }
        if hasattr(os, "getloadavg"):
            try:
                payload["load_average_1m"] = round(os.getloadavg()[0], 3)
            except OSError:
                pass
        observation = TelemetryObservation(
            node_id=self.agent.node_id,
            source="local-runtime",
            category="health",
            event_type="host_health_sample",
            severity="info",
            payload=payload,
        )
        return CollectorOutput("ACTIVE", "Read-only local resource envelope captured.", (observation,))


class RuntimeIntegrityCollector:
    id = "COL-RUNTIME-INTEGRITY"
    name = "Runtime integrity manifest"

    def __init__(self, agent: LocalNodeAgent):
        self.agent = agent

    def collect(self) -> CollectorOutput:
        candidates = []
        for relative in ("aegis", "web"):
            directory = self.agent.root / relative
            if not directory.is_dir():
                continue
            candidates.extend(
                path for path in directory.rglob("*")
                if path.is_file() and path.suffix.lower() in {".py", ".js", ".css", ".html"}
            )
        entries = []
        for path in sorted(candidates)[:128]:
            relative = path.relative_to(self.agent.root).as_posix()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            entries.append((relative, digest))
        manifest = hashlib.sha256(
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        observation = TelemetryObservation(
            node_id=self.agent.node_id,
            source="aegis-runtime",
            category="integrity",
            event_type="runtime_manifest_observed",
            severity="info",
            payload={
                "contract_version": TELEMETRY_CONTRACT_VERSION,
                "release": __version__,
                "files_measured": len(entries),
                "manifest_sha256": manifest,
            },
        )
        state = "ACTIVE" if entries else "DEGRADED"
        detail = "Critical runtime assets measured." if entries else "No runtime assets were found to measure."
        return CollectorOutput(state, detail, (observation,))


class WindowsEventLogCollector:
    id = "COL-WINDOWS-EVENTLOG"
    name = "Windows security event sampler"

    EVENT_TYPES = {
        4624: ("authentication_success", "info"),
        4625: ("authentication_failure", "medium"),
        4688: ("process_created", "info"),
        4719: ("audit_policy_changed", "high"),
        4720: ("account_created", "high"),
        4740: ("account_locked", "medium"),
        1102: ("audit_log_cleared", "critical"),
        7045: ("service_installed", "high"),
    }
    SECURITY_IDS = (4624, 4625, 4688, 4719, 4720, 4740, 1102)
    SYSTEM_IDS = (7045,)
    PSEUDONYM_FIELDS = {
        "TargetUserName": "account",
        "SubjectUserName": "account",
        "IpAddress": "source",
        "WorkstationName": "host",
        "ServiceName": "service",
    }
    PROCESS_FIELDS = {"ProcessName", "NewProcessName", "ParentProcessName"}
    SAFE_FIELDS = {"LogonType", "Status", "SubStatus", "ElevatedToken"}

    def __init__(
        self,
        agent: LocalNodeAgent,
        pseudonymizer: Pseudonymizer,
        lookback_ms: int = 600_000,
        max_events_per_channel: int = 64,
        runner: Any = subprocess.run,
    ):
        self.agent = agent
        self.pseudonymizer = pseudonymizer
        self.lookback_ms = min(max(int(lookback_ms), 60_000), 3_600_000)
        self.max_events_per_channel = min(max(int(max_events_per_channel), 1), 256)
        self.runner = runner

    @staticmethod
    def _event_query(event_ids: tuple[int, ...], lookback_ms: int) -> str:
        clauses = " or ".join(f"EventID={event_id}" for event_id in event_ids)
        return f"*[System[({clauses}) and TimeCreated[timediff(@SystemTime) <= {lookback_ms}]]]"

    def _query(self, channel: str, event_ids: tuple[int, ...]) -> tuple[list[ET.Element], str | None]:
        query = self._event_query(event_ids, self.lookback_ms)
        command = [
            "wevtutil", "qe", channel,
            f"/q:{query}",
            f"/c:{self.max_events_per_channel}",
            "/rd:true",
            "/f:xml",
        ]
        try:
            result = self.runner(command, capture_output=True, text=True, timeout=12, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            return [], f"{channel}: {type(error).__name__}"
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "query failed").strip().splitlines()[0][:160]
            return [], f"{channel}: {message}"
        raw = re.sub(r"<\?xml[^>]*\?>", "", result.stdout, flags=re.IGNORECASE).strip()
        if not raw:
            return [], None
        try:
            root = ET.fromstring(f"<Events>{raw}</Events>")
        except ET.ParseError:
            return [], f"{channel}: invalid XML returned by wevtutil"
        return list(root), None

    def _observation(self, event: ET.Element, channel_hint: str) -> TelemetryObservation | None:
        system = event.find(f"{EVENT_NAMESPACE}System")
        if system is None:
            return None
        event_id_node = system.find(f"{EVENT_NAMESPACE}EventID")
        if event_id_node is None or not event_id_node.text:
            return None
        try:
            event_id = int(event_id_node.text)
        except ValueError:
            return None
        if event_id not in self.EVENT_TYPES:
            return None
        event_type, severity = self.EVENT_TYPES[event_id]
        provider_node = system.find(f"{EVENT_NAMESPACE}Provider")
        time_node = system.find(f"{EVENT_NAMESPACE}TimeCreated")
        record_node = system.find(f"{EVENT_NAMESPACE}EventRecordID")
        channel_node = system.find(f"{EVENT_NAMESPACE}Channel")
        timestamp = time_node.attrib.get("SystemTime", utc_now()) if time_node is not None else utc_now()
        payload: dict[str, Any] = {
            "contract_version": TELEMETRY_CONTRACT_VERSION,
            "windows_event_id": event_id,
            "channel": channel_node.text if channel_node is not None and channel_node.text else channel_hint,
            "provider": provider_node.attrib.get("Name", "unknown") if provider_node is not None else "unknown",
            "record_id": record_node.text if record_node is not None else None,
            "privacy": "selected fields only; identifiers pseudonymized locally",
        }
        event_data = event.find(f"{EVENT_NAMESPACE}EventData")
        if event_data is not None:
            for data_node in event_data.findall(f"{EVENT_NAMESPACE}Data"):
                name = data_node.attrib.get("Name", "")
                value = (data_node.text or "").strip()
                if not value or value == "-":
                    continue
                if name in self.PSEUDONYM_FIELDS:
                    payload[f"{name}_ref"] = self.pseudonymizer.reference(self.PSEUDONYM_FIELDS[name], value)
                elif name in self.PROCESS_FIELDS:
                    payload[name] = PureWindowsPath(value).name.lower()[:160]
                elif name in self.SAFE_FIELDS:
                    payload[name] = value[:80]
        return TelemetryObservation(
            node_id=self.agent.node_id,
            source="windows-event-log",
            category="endpoint_security",
            event_type=event_type,
            severity=severity,
            payload=payload,
            timestamp=timestamp,
        )

    def collect(self) -> CollectorOutput:
        if platform.system().lower() != "windows":
            return CollectorOutput("NOT_APPLICABLE", "Windows event collection is only enabled on Windows.")
        if shutil.which("wevtutil") is None:
            return CollectorOutput("UNAVAILABLE", "Windows wevtutil was not found.")
        observations: list[TelemetryObservation] = []
        warnings = []
        for channel, event_ids in (("Security", self.SECURITY_IDS), ("System", self.SYSTEM_IDS)):
            events, warning = self._query(channel, event_ids)
            if warning:
                warnings.append(warning)
            for event in events:
                observation = self._observation(event, channel)
                if observation is not None:
                    observations.append(observation)
        if observations:
            detail = f"Captured {len(observations)} allowlisted events."
            if warnings:
                detail += " Some channels were unavailable."
            return CollectorOutput("ACTIVE" if not warnings else "DEGRADED", detail, tuple(observations))
        if warnings:
            return CollectorOutput("PERMISSION_REQUIRED", "; ".join(warnings)[:320])
        return CollectorOutput("ACTIVE", "No allowlisted events occurred in the lookback window.")


class EndpointTelemetryRuntime:
    """Runs passive collectors and persists their observations locally."""

    def __init__(
        self,
        store: AegisStore,
        agent: LocalNodeAgent,
        interval_seconds: int = 30,
        collectors: list[PassiveCollector] | None = None,
    ):
        self.store = store
        self.agent = agent
        self.interval_seconds = min(max(int(interval_seconds), 10), 3_600)
        key_path = store.database_path.parent / "node.key"
        pseudonymizer = Pseudonymizer(key_path)
        self.collectors: list[PassiveCollector] = collectors or [
            HostHealthCollector(agent),
            RuntimeIntegrityCollector(agent),
            WindowsEventLogCollector(agent, pseudonymizer),
        ]
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._collection_lock = threading.Lock()

    def collect_once(self) -> dict[str, Any]:
        if not self._collection_lock.acquire(blocking=False):
            latest = self.store.latest_collector_run()
            return {"status": "ALREADY_RUNNING", "latest_run": latest, "summary": self.store.telemetry_summary()}
        started_at = utc_now()
        started_monotonic = time.monotonic()
        collector_results = []
        observation_count = 0
        inserted_count = 0
        try:
            for collector in self.collectors:
                collector_started = time.monotonic()
                try:
                    output = collector.collect()
                except Exception as error:  # Collector failure must not stop the resident agent.
                    output = CollectorOutput("ERROR", f"{type(error).__name__}: {str(error)[:180]}")
                inserted = 0
                for observation in output.observations:
                    stored = self.store.append_telemetry(observation)
                    inserted += int(stored["inserted"])
                observation_count += len(output.observations)
                inserted_count += inserted
                collector_results.append({
                    "id": collector.id,
                    "name": collector.name,
                    "state": output.state,
                    "observed": len(output.observations),
                    "inserted": inserted,
                    "duration_ms": round((time.monotonic() - collector_started) * 1000, 2),
                    "detail": output.detail,
                })
            degraded_states = {"ERROR", "DEGRADED", "PERMISSION_REQUIRED", "UNAVAILABLE"}
            status = "DEGRADED" if any(result["state"] in degraded_states for result in collector_results) else "COMPLETE"
            finished_at = utc_now()
            descriptor = {
                "node_id": self.agent.node_id,
                "started_at": started_at,
                "finished_at": finished_at,
                "collectors": collector_results,
            }
            run_id = "TEL-" + hashlib.sha256(
                json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()[:16].upper()
            run = {
                "contract_version": TELEMETRY_CONTRACT_VERSION,
                "run_id": run_id,
                "node_id": self.agent.node_id,
                "started_at": started_at,
                "finished_at": finished_at,
                "duration_ms": round((time.monotonic() - started_monotonic) * 1000, 2),
                "status": status,
                "observation_count": observation_count,
                "inserted_count": inserted_count,
                "collectors": collector_results,
            }
            self.store.save_collector_run(run)
            return {**run, "summary": self.store.telemetry_summary()}
        finally:
            self._collection_lock.release()

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return False
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="aegis-telemetry", daemon=True)
        self._thread.start()
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive() and self._thread is not threading.current_thread():
            self._thread.join(timeout=timeout)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> dict[str, Any]:
        latest = self.store.latest_collector_run()
        return {
            "contract_version": TELEMETRY_CONTRACT_VERSION,
            "runtime_state": "RUNNING" if self.is_running() else "ON_DEMAND",
            "interval_seconds": self.interval_seconds,
            "latest_run": latest,
            "summary": self.store.telemetry_summary(),
            "privacy": {
                "storage": "local SQLite only",
                "outbound_transmission": False,
                "raw_command_lines": False,
                "raw_usernames": False,
                "raw_ip_addresses": False,
                "pseudonymization": "HMAC-SHA256 with a local per-install key",
            },
            "scope": "Read-only local telemetry. No scanning, interception, exploitation or response action.",
        }

    def _run_loop(self) -> None:
        self.collect_once()
        while not self._stop_event.wait(self.interval_seconds):
            self.collect_once()
