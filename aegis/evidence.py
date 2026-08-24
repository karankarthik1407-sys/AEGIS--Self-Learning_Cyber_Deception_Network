from __future__ import annotations

import hashlib
import json
from typing import Any

from .models import SecurityEvent


GENESIS_HASH = "0" * 64


def canonical_event(event: SecurityEvent, previous_hash: str) -> str:
    body = {"event": event.to_dict(), "previous_hash": previous_hash}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def event_digest(event: SecurityEvent, previous_hash: str) -> str:
    return hashlib.sha256(canonical_event(event, previous_hash).encode("utf-8")).hexdigest()


def verify_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    previous = GENESIS_HASH
    for position, record in enumerate(records, start=1):
        event = SecurityEvent(
            case_id=record["case_id"],
            event_type=record["event_type"],
            actor=record["actor"],
            target=record["target"],
            payload=record["payload"],
            timestamp=record["timestamp"],
        )
        calculated = event_digest(event, previous)
        if record["previous_hash"] != previous or record["event_hash"] != calculated:
            return {
                "valid": False,
                "verified_events": position - 1,
                "failure_position": position,
                "expected_hash": calculated,
                "observed_hash": record["event_hash"],
            }
        previous = record["event_hash"]
    return {"valid": True, "verified_events": len(records), "head_hash": previous}
