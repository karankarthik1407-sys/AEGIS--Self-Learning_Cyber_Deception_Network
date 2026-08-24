from __future__ import annotations

import json
import hashlib
import sqlite3
from pathlib import Path
from typing import Any

from .evidence import GENESIS_HASH, event_digest, verify_records
from .models import SecurityEvent, TelemetryObservation, utc_now


class AegisStore:
    def __init__(self, database_path: Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    stage TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    hypotheses_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    target TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );

                CREATE INDEX IF NOT EXISTS idx_events_case_sequence
                    ON events(case_id, sequence);

                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT,
                    created_at TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    digest TEXT NOT NULL UNIQUE,
                    certificate_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS telemetry_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observation_id TEXT NOT NULL UNIQUE,
                    observed_at TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    category TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    digest TEXT NOT NULL UNIQUE
                );

                CREATE INDEX IF NOT EXISTS idx_telemetry_observed_at
                    ON telemetry_events(observed_at DESC);

                CREATE INDEX IF NOT EXISTS idx_telemetry_node_category
                    ON telemetry_events(node_id, category);

                CREATE TABLE IF NOT EXISTS collector_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL UNIQUE,
                    node_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    observation_count INTEGER NOT NULL,
                    results_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS gateway_imports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    import_id TEXT NOT NULL UNIQUE,
                    connector_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    received_count INTEGER NOT NULL,
                    accepted_count INTEGER NOT NULL,
                    rejected_count INTEGER NOT NULL,
                    inserted_count INTEGER NOT NULL,
                    manifest_sha256 TEXT NOT NULL UNIQUE,
                    report_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS artifact_registry (
                    artifact_id TEXT PRIMARY KEY,
                    artifact_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    descriptor_sha256 TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    attestation TEXT NOT NULL,
                    descriptor_json TEXT NOT NULL,
                    lineage_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_artifact_registry_type
                    ON artifact_registry(artifact_type, created_at);

                CREATE TABLE IF NOT EXISTS promotion_ledger (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    decision_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    candidate_artifact_id TEXT NOT NULL,
                    champion_artifact_id TEXT,
                    decision TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL UNIQUE,
                    key_id TEXT NOT NULL,
                    attestation TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS operator_audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    session_ref TEXT NOT NULL,
                    operator_role TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    permission TEXT NOT NULL,
                    entitlement TEXT,
                    decision TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL UNIQUE,
                    key_id TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_operator_audit_command
                    ON operator_audit(command_id, sequence);

                CREATE INDEX IF NOT EXISTS idx_operator_audit_created_at
                    ON operator_audit(created_at DESC);

                CREATE TRIGGER IF NOT EXISTS artifact_registry_no_update
                BEFORE UPDATE ON artifact_registry
                BEGIN
                    SELECT RAISE(ABORT, 'artifact registry is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS artifact_registry_no_delete
                BEFORE DELETE ON artifact_registry
                BEGIN
                    SELECT RAISE(ABORT, 'artifact registry is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS promotion_ledger_no_update
                BEFORE UPDATE ON promotion_ledger
                BEGIN
                    SELECT RAISE(ABORT, 'promotion ledger is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS promotion_ledger_no_delete
                BEFORE DELETE ON promotion_ledger
                BEGIN
                    SELECT RAISE(ABORT, 'promotion ledger is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS operator_audit_no_update
                BEFORE UPDATE ON operator_audit
                BEGIN
                    SELECT RAISE(ABORT, 'operator audit journal is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS operator_audit_no_delete
                BEFORE DELETE ON operator_audit
                BEGIN
                    SELECT RAISE(ABORT, 'operator audit journal is append-only');
                END;
                """
            )

    def reset(self) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM certificates")
            connection.execute("DELETE FROM events")
            connection.execute("DELETE FROM cases")

    def create_case(
        self,
        case_id: str,
        source: str,
        summary: str,
        hypotheses: dict[str, float],
        stage: str = "Reconnaissance",
        risk_score: int = 24,
    ) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO cases
                   (id, created_at, updated_at, source, status, risk_score, stage, summary, hypotheses_json)
                   VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)""",
                (case_id, now, now, source, risk_score, stage, summary, json.dumps(hypotheses, sort_keys=True)),
            )

    def update_case_beliefs(
        self,
        case_id: str,
        hypotheses: dict[str, float],
        stage: str,
        risk_score: int,
        summary: str,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """UPDATE cases
                   SET updated_at=?, hypotheses_json=?, stage=?, risk_score=?, summary=?
                   WHERE id=?""",
                (utc_now(), json.dumps(hypotheses, sort_keys=True), stage, risk_score, summary, case_id),
            )

    def append_event(self, event: SecurityEvent) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT event_hash FROM events WHERE case_id=? ORDER BY sequence DESC LIMIT 1",
                (event.case_id,),
            ).fetchone()
            previous_hash = row["event_hash"] if row else GENESIS_HASH
            digest = event_digest(event, previous_hash)
            cursor = connection.execute(
                """INSERT INTO events
                   (case_id, timestamp, event_type, actor, target, payload_json, previous_hash, event_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.case_id,
                    event.timestamp,
                    event.event_type,
                    event.actor,
                    event.target,
                    json.dumps(event.payload, sort_keys=True),
                    previous_hash,
                    digest,
                ),
            )
            connection.execute("UPDATE cases SET updated_at=? WHERE id=?", (event.timestamp, event.case_id))
            return {
                "sequence": cursor.lastrowid,
                **event.to_dict(),
                "previous_hash": previous_hash,
                "event_hash": digest,
            }

    def list_cases(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT c.*,
                          (SELECT COUNT(*) FROM events e WHERE e.case_id=c.id) AS evidence_count
                   FROM cases c ORDER BY c.updated_at DESC"""
            ).fetchall()
        return [self._case_row(row) for row in rows]

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """SELECT c.*,
                          (SELECT COUNT(*) FROM events e WHERE e.case_id=c.id) AS evidence_count
                   FROM cases c WHERE c.id=?""",
                (case_id,),
            ).fetchone()
        return self._case_row(row) if row else None

    def list_events(self, case_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT * FROM events WHERE case_id=?
                   ORDER BY sequence ASC LIMIT ?""",
                (case_id, limit),
            ).fetchall()
        return [self._event_row(row) for row in rows]

    def latest_events(self, limit: int = 12) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events ORDER BY sequence DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._event_row(row) for row in rows]

    def event_count(self) -> int:
        with self.connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def certificate_counts(self) -> dict[str, int]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT decision, COUNT(*) AS count FROM certificates GROUP BY decision"
            ).fetchall()
        counts = {"PERMIT": 0, "DENY": 0}
        counts.update({row["decision"]: int(row["count"]) for row in rows})
        return counts

    def save_certificate(self, case_id: str | None, certificate: dict[str, Any]) -> None:
        action = certificate["action"]
        with self.connect() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO certificates
                   (case_id, created_at, action_id, action_type, decision, digest, certificate_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    case_id,
                    certificate["created_at"],
                    action["action_id"],
                    action["action_type"],
                    certificate["decision"],
                    certificate["digest"],
                    json.dumps(certificate, sort_keys=True),
                ),
            )

    def latest_certificate(self) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT certificate_json FROM certificates ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return json.loads(row["certificate_json"]) if row else None

    def append_telemetry(self, observation: TelemetryObservation) -> dict[str, Any]:
        canonical = json.dumps(
            observation.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        observation_id = "OBS-" + digest[:16].upper()
        with self.connect() as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO telemetry_events
                   (observation_id, observed_at, node_id, source, category,
                    event_type, severity, payload_json, digest)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    observation_id,
                    observation.timestamp,
                    observation.node_id,
                    observation.source,
                    observation.category,
                    observation.event_type,
                    observation.severity,
                    json.dumps(observation.payload, sort_keys=True, ensure_ascii=False),
                    digest,
                ),
            )
            inserted = cursor.rowcount == 1
            row = connection.execute(
                "SELECT * FROM telemetry_events WHERE digest=?", (digest,)
            ).fetchone()
        if row is None:
            raise RuntimeError("telemetry insert failed")
        return {**self._telemetry_row(row), "inserted": inserted}

    def list_telemetry(self, limit: int = 100, node_id: str | None = None) -> list[dict[str, Any]]:
        safe_limit = min(max(int(limit), 1), 500)
        with self.connect() as connection:
            if node_id:
                rows = connection.execute(
                    """SELECT * FROM telemetry_events WHERE node_id=?
                       ORDER BY id DESC LIMIT ?""",
                    (node_id, safe_limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM telemetry_events ORDER BY id DESC LIMIT ?", (safe_limit,)
                ).fetchall()
        return [self._telemetry_row(row) for row in rows]

    def telemetry_summary(self) -> dict[str, Any]:
        with self.connect() as connection:
            total = int(connection.execute("SELECT COUNT(*) FROM telemetry_events").fetchone()[0])
            latest = connection.execute(
                "SELECT observed_at FROM telemetry_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            category_rows = connection.execute(
                "SELECT category, COUNT(*) AS count FROM telemetry_events GROUP BY category"
            ).fetchall()
            severity_rows = connection.execute(
                "SELECT severity, COUNT(*) AS count FROM telemetry_events GROUP BY severity"
            ).fetchall()
        return {
            "total_observations": total,
            "latest_observed_at": latest["observed_at"] if latest else None,
            "categories": {row["category"]: int(row["count"]) for row in category_rows},
            "severities": {row["severity"]: int(row["count"]) for row in severity_rows},
        }

    def save_collector_run(self, run: dict[str, Any]) -> None:
        with self.connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO collector_runs
                   (run_id, node_id, started_at, finished_at, status,
                    observation_count, results_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    run["run_id"],
                    run["node_id"],
                    run["started_at"],
                    run["finished_at"],
                    run["status"],
                    int(run["observation_count"]),
                    json.dumps(run["collectors"], sort_keys=True, ensure_ascii=False),
                ),
            )

    def latest_collector_run(self) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM collector_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return {
            "run_id": row["run_id"],
            "node_id": row["node_id"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "status": row["status"],
            "observation_count": row["observation_count"],
            "collectors": json.loads(row["results_json"]),
        }

    def save_gateway_import(self, report: dict[str, Any]) -> None:
        counts = report["counts"]
        with self.connect() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO gateway_imports
                   (import_id, connector_id, created_at, received_count,
                    accepted_count, rejected_count, inserted_count,
                    manifest_sha256, report_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    report["import_id"],
                    report["connector_id"],
                    report["created_at"],
                    int(counts["received"]),
                    int(counts["accepted"]),
                    int(counts["rejected"]),
                    int(counts["inserted"]),
                    report["manifest_sha256"],
                    json.dumps(report, sort_keys=True, ensure_ascii=False),
                ),
            )

    def latest_gateway_import(self) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT report_json FROM gateway_imports ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return json.loads(row["report_json"]) if row else None

    def gateway_import_summary(self) -> dict[str, Any]:
        with self.connect() as connection:
            total = int(connection.execute("SELECT COUNT(*) FROM gateway_imports").fetchone()[0])
            rows = connection.execute(
                """SELECT connector_id, COUNT(*) AS imports,
                          SUM(received_count) AS received,
                          SUM(accepted_count) AS accepted,
                          SUM(inserted_count) AS inserted
                   FROM gateway_imports GROUP BY connector_id"""
            ).fetchall()
        return {
            "total_imports": total,
            "connectors": {
                row["connector_id"]: {
                    "imports": int(row["imports"] or 0),
                    "received": int(row["received"] or 0),
                    "accepted": int(row["accepted"] or 0),
                    "inserted": int(row["inserted"] or 0),
                }
                for row in rows
            },
        }

    def verify_case(self, case_id: str) -> dict[str, Any]:
        result = verify_records(self.list_events(case_id, limit=10000))
        return {"case_id": case_id, **result}

    @staticmethod
    def _case_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "source": row["source"],
            "status": row["status"],
            "risk_score": row["risk_score"],
            "stage": row["stage"],
            "summary": row["summary"],
            "hypotheses": json.loads(row["hypotheses_json"]),
            "evidence_count": row["evidence_count"],
        }

    @staticmethod
    def _event_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "sequence": row["sequence"],
            "case_id": row["case_id"],
            "timestamp": row["timestamp"],
            "event_type": row["event_type"],
            "actor": row["actor"],
            "target": row["target"],
            "payload": json.loads(row["payload_json"]),
            "previous_hash": row["previous_hash"],
            "event_hash": row["event_hash"],
        }

    @staticmethod
    def _telemetry_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "observation_id": row["observation_id"],
            "timestamp": row["observed_at"],
            "node_id": row["node_id"],
            "source": row["source"],
            "category": row["category"],
            "event_type": row["event_type"],
            "severity": row["severity"],
            "payload": json.loads(row["payload_json"]),
            "digest": row["digest"],
        }
