from __future__ import annotations

import ctypes
import hashlib
import os
import platform
import shutil
import socket
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .models import utc_now


AGENT_CONTRACT_VERSION = "aegis.node-agent.v1"


@dataclass(frozen=True)
class CollectorState:
    id: str
    name: str
    source: str
    state: str
    mode: str
    privilege: str
    detail: str


def _memory_bytes() -> tuple[int | None, int | None]:
    """Return total and available memory without adding a runtime dependency."""

    if os.name == "nt":
        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.c_ulong),
                ("memory_load", ctypes.c_ulong),
                ("total_physical", ctypes.c_ulonglong),
                ("available_physical", ctypes.c_ulonglong),
                ("total_page_file", ctypes.c_ulonglong),
                ("available_page_file", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong),
                ("available_virtual", ctypes.c_ulonglong),
                ("available_extended_virtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatus()
        status.length = ctypes.sizeof(MemoryStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
            return int(status.total_physical), int(status.available_physical)

    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        values: dict[str, int] = {}
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            name, _, raw_value = line.partition(":")
            if raw_value:
                values[name] = int(raw_value.strip().split()[0]) * 1024
        if "MemTotal" in values:
            return values["MemTotal"], values.get("MemAvailable")
    return None, None


def _gib(value: int | None) -> float | None:
    return round(value / (1024 ** 3), 2) if value is not None else None


class LocalNodeAgent:
    """Passive local runtime contract for the machine hosting AEGIS.

    This release actively reports its heartbeat, resource envelope and runtime
    integrity. Selected Windows Event Log collection is active when available.
    Privileged ETW/WFP/eBPF adapters are never implied to be active merely
    because the console is running.
    """

    def __init__(self, root: Path):
        self.root = Path(root)
        self.service_mode = os.environ.get("AEGIS_SERVICE_MODE") == "1"
        self.desktop_mode = os.environ.get("AEGIS_DESKTOP_MODE") == "1"
        self.started_at = utc_now()
        self._started_monotonic = time.monotonic()
        identity = f"{socket.gethostname()}|{platform.system()}|{platform.machine()}|AEGIS"
        self.node_id = "NODE-" + hashlib.sha256(identity.encode()).hexdigest()[:12].upper()

    def collectors(self) -> list[CollectorState]:
        system = platform.system().lower()
        return [
            CollectorState(
                id="COL-HOST-HEALTH",
                name="Host health",
                source="Local runtime",
                state="ACTIVE",
                mode="read-only",
                privilege="user",
                detail="Real node heartbeat, storage, memory and runtime envelope.",
            ),
            CollectorState(
                id="COL-RUNTIME-INTEGRITY",
                name="Runtime integrity manifest",
                source="AEGIS runtime",
                state="ACTIVE",
                mode="read-only hashing",
                privilege="user",
                detail="Measures critical Python and console assets into a SHA-256 manifest.",
            ),
            CollectorState(
                id="COL-EVENT-CONTRACT",
                name="Security event contract",
                source="AEGIS ingestion API",
                state="ACTIVE",
                mode="normalized",
                privilege="user",
                detail="Accepts versioned authorized telemetry; current demonstration events remain synthetic.",
            ),
            CollectorState(
                id="COL-WINDOWS-EVENTLOG",
                name="Windows security event sampler",
                source="Windows Event Log",
                state="ACTIVE" if system == "windows" else "NOT_APPLICABLE",
                mode="read-only / allowlisted",
                privilege="service or authorized user",
                detail="Queries selected Security and System event IDs; identity fields are pseudonymized before storage.",
            ),
            CollectorState(
                id="COL-WIN-WFP",
                name="Windows network enforcement",
                source="WFP callout",
                state="NOT_ENABLED" if system == "windows" else "NOT_APPLICABLE",
                mode="enforcement",
                privilege="kernel",
                detail="Cannot receive a rule without a valid Safety Gate certificate.",
            ),
            CollectorState(
                id="COL-LINUX-EBPF",
                name="Linux kernel sensor",
                source="eBPF",
                state="ADAPTER_READY" if system == "linux" else "NOT_APPLICABLE",
                mode="passive / enforcement",
                privilege="kernel",
                detail="Loader and signed policy package remain a later enterprise adapter.",
            ),
            CollectorState(
                id="COL-DECEPTION",
                name="Deception node runtime",
                source="Isolated containers / VMs",
                state="SIMULATED",
                mode="decoy-only",
                privilege="isolated",
                detail="Control contract is active; deployable decoy images are not included in this release.",
            ),
        ]

    def snapshot(self) -> dict[str, Any]:
        system = platform.system().lower()
        disk = shutil.disk_usage(self.root)
        total_memory, available_memory = _memory_bytes()
        collectors = self.collectors()
        active = [collector for collector in collectors if collector.state == "ACTIVE"]
        return {
            "contract_version": AGENT_CONTRACT_VERSION,
            "node_id": self.node_id,
            "state": "ONLINE",
            "runtime_mode": "LOCAL ACTIVE / READ-ONLY",
            "launch_mode": (
                "windows-service"
                if self.service_mode
                else "desktop-executable"
                if self.desktop_mode
                else "foreground-development"
            ),
            "service_installed": self.service_mode,
            "started_at": self.started_at,
            "observed_at": utc_now(),
            "uptime_seconds": int(time.monotonic() - self._started_monotonic),
            "host": {
                "platform": platform.system(),
                "release": platform.release(),
                "architecture": platform.machine(),
                "python": platform.python_version(),
                "cpu_logical": os.cpu_count(),
                "memory_total_gib": _gib(total_memory),
                "memory_available_gib": _gib(available_memory),
                "storage_total_gib": _gib(disk.total),
                "storage_free_gib": _gib(disk.free),
            },
            "collectors": [asdict(collector) for collector in collectors],
            "active_collectors": len(active),
            "capabilities": {
                "local_heartbeat": True,
                "normalized_ingestion": True,
                "passive_enterprise_telemetry": system == "windows",
                "host_network_enforcement": False,
                "external_scanning": False,
                "hack_back": False,
            },
            "deployment_profiles": [
                {"name": "Endpoint Agent", "state": "FOUNDATION", "shape": "signed Windows service / Linux daemon"},
                {"name": "Network Sensor", "state": "PLANNED", "shape": "passive TAP or mirrored traffic"},
                {"name": "Control Plane", "state": "ACTIVE", "shape": "local or on-premises private service"},
                {"name": "Hardware Module", "state": "RESEARCH", "shape": "PCIe SmartNIC, DPU or FPGA"},
            ],
            "boundary": "Host health and runtime integrity are real on every supported host. On Windows, selected event-log telemetry is collected read-only when permissions allow. Deception deployment and privileged enforcement remain disabled research contracts.",
        }
