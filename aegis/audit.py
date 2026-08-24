from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import utc_now
from .store import AegisStore


AUDIT_GENESIS_HASH = "0" * 64


class AuditUnavailable(RuntimeError):
    pass


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class AuditJournal:
    def __init__(self, store: AegisStore, key_path: Path | None = None):
        self.store = store
        self.key_path = Path(key_path or (store.database_path.parent / "audit.key"))
        self._lock = threading.Lock()
        self._key: bytes | None = None
        self._key_error: str | None = None
        self._load_or_create_key()

    def _event_count(self) -> int:
        with self.store.connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM operator_audit").fetchone()[0])

    def _load_or_create_key(self) -> None:
        try:
            if self.key_path.is_file():
                key = self.key_path.read_bytes()
                if len(key) != 32:
                    raise AuditUnavailable("audit key must contain exactly 32 bytes")
                self._key = key
                return
            if self._event_count() > 0:
                raise AuditUnavailable("audit key is missing while journal records already exist")
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            key = secrets.token_bytes(32)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            descriptor = os.open(self.key_path, flags, 0o600)
            try:
                os.write(descriptor, key)
            finally:
                os.close(descriptor)
            try:
                self.key_path.chmod(0o600)
            except OSError:
                pass
            self._key = key
        except (OSError, AuditUnavailable) as error:
            self._key = None
            self._key_error = str(error)

    @property
    def operational(self) -> bool:
        return self._key is not None

    @property
    def key_id(self) -> str | None:
        if self._key is None:
            return None
        return "AUDIT-HMAC-" + hashlib.sha256(self._key).hexdigest()[:16].upper()

    def append(
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
        if self._key is None:
            raise AuditUnavailable(self._key_error or "audit journal is unavailable")
        if len(request_sha256) != 64 or any(character not in "0123456789abcdef" for character in request_sha256.lower()):
            raise ValueError("request_sha256 must be a SHA-256 hex digest")
        with self._lock:
            connection = self.store.connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT record_hash FROM operator_audit ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                previous_hash = row["record_hash"] if row else AUDIT_GENESIS_HASH
                record = {
                    "command_id": str(command_id)[:96],
                    "created_at": utc_now(),
                    "session_ref": str(session_ref)[:96],
                    "operator_role": str(operator_role).upper()[:32],
                    "method": str(method).upper()[:16],
                    "path": str(path)[:512],
                    "permission": str(permission)[:64],
                    "entitlement": str(entitlement)[:96] if entitlement else None,
                    "decision": str(decision).upper()[:64],
                    "status_code": int(status_code),
                    "request_sha256": request_sha256.lower(),
                    "previous_hash": previous_hash,
                    "key_id": self.key_id,
                }
                record_hash = hmac.new(self._key, _canonical(record), hashlib.sha256).hexdigest()
                cursor = connection.execute(
                    """INSERT INTO operator_audit
                       (command_id, created_at, session_ref, operator_role, method, path,
                        permission, entitlement, decision, status_code, request_sha256,
                        previous_hash, record_hash, key_id, record_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record["command_id"],
                        record["created_at"],
                        record["session_ref"],
                        record["operator_role"],
                        record["method"],
                        record["path"],
                        record["permission"],
                        record["entitlement"],
                        record["decision"],
                        record["status_code"],
                        record["request_sha256"],
                        record["previous_hash"],
                        record_hash,
                        record["key_id"],
                        json.dumps(record, sort_keys=True, ensure_ascii=False),
                    ),
                )
                connection.commit()
                return {"sequence": cursor.lastrowid, **record, "record_hash": record_hash}
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    @staticmethod
    def _row_record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "command_id": row["command_id"],
            "created_at": row["created_at"],
            "session_ref": row["session_ref"],
            "operator_role": row["operator_role"],
            "method": row["method"],
            "path": row["path"],
            "permission": row["permission"],
            "entitlement": row["entitlement"],
            "decision": row["decision"],
            "status_code": int(row["status_code"]),
            "request_sha256": row["request_sha256"],
            "previous_hash": row["previous_hash"],
            "key_id": row["key_id"],
        }

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        safe_limit = min(max(int(limit), 1), 500)
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM operator_audit ORDER BY sequence DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [
            {"sequence": int(row["sequence"]), **self._row_record(row), "record_hash": row["record_hash"]}
            for row in rows
        ]

    def verify(self) -> dict[str, Any]:
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM operator_audit ORDER BY sequence ASC"
            ).fetchall()
        if self._key is None:
            return {
                "valid": False,
                "records": len(rows),
                "commands": len({row["command_id"] for row in rows}),
                "chain_head": rows[-1]["record_hash"] if rows else AUDIT_GENESIS_HASH,
                "key_id": None,
                "algorithm": "HMAC-SHA256",
                "error": self._key_error or "audit_key_unavailable",
                "external_signature": False,
                "non_repudiation": False,
            }
        expected_previous = AUDIT_GENESIS_HASH
        for row in rows:
            record = self._row_record(row)
            expected_hash = hmac.new(self._key, _canonical(record), hashlib.sha256).hexdigest()
            try:
                stored_record = json.loads(row["record_json"])
            except (TypeError, json.JSONDecodeError):
                stored_record = None
            valid = (
                record["previous_hash"] == expected_previous
                and hmac.compare_digest(expected_hash, row["record_hash"])
                and stored_record == record
                and row["key_id"] == self.key_id
            )
            if not valid:
                return {
                    "valid": False,
                    "records": len(rows),
                    "commands": len({item["command_id"] for item in rows}),
                    "chain_head": rows[-1]["record_hash"] if rows else AUDIT_GENESIS_HASH,
                    "key_id": self.key_id,
                    "algorithm": "HMAC-SHA256",
                    "failure_sequence": int(row["sequence"]),
                    "external_signature": False,
                    "non_repudiation": False,
                }
            expected_previous = row["record_hash"]
        return {
            "valid": True,
            "records": len(rows),
            "commands": len({row["command_id"] for row in rows}),
            "chain_head": expected_previous,
            "key_id": self.key_id,
            "algorithm": "HMAC-SHA256",
            "failure_sequence": None,
            "external_signature": False,
            "non_repudiation": False,
        }

    def summary(self) -> dict[str, Any]:
        verification = self.verify()
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT decision, COUNT(*) AS count FROM operator_audit GROUP BY decision"
            ).fetchall()
            latest = connection.execute(
                "SELECT created_at FROM operator_audit ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        return {
            **verification,
            "operational": self.operational,
            "decisions": {row["decision"]: int(row["count"]) for row in rows},
            "latest_event_at": latest["created_at"] if latest else None,
            "request_payload_retained": False,
            "raw_session_token_retained": False,
            "trust_scope": (
                "Append-only local integrity evidence. It is not an external signature, "
                "trusted timestamp, WORM archive or non-repudiation proof."
            ),
        }
