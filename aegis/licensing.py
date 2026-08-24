from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


LICENSE_CONTRACT_VERSION = "AEGIS-LICENSE-1"
SIGNATURE_ALGORITHM = "Ed25519"
KNOWN_EDITIONS = frozenset({"EVALUATION", "ENTERPRISE"})
KNOWN_ENTITLEMENTS = frozenset(
    {
        "desktop_control_plane",
        "resident_node",
        "research_lab",
        "offline_evidence_gateway",
        "hardware_dry_run",
        "local_audit",
        "multi_node",
        "enterprise_connectors",
    }
)
RESEARCH_ENTITLEMENTS = frozenset(
    {
        "desktop_control_plane",
        "resident_node",
        "research_lab",
        "offline_evidence_gateway",
        "hardware_dry_run",
        "local_audit",
    }
)


class LicenseValidationError(ValueError):
    pass


def canonical_license_payload(envelope: dict[str, Any]) -> bytes:
    signed = {
        "contract_version": envelope.get("contract_version"),
        "signature_algorithm": envelope.get("signature_algorithm"),
        "key_id": envelope.get("key_id"),
        "claims": envelope.get("claims"),
    }
    return json.dumps(
        signed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def public_key_id(public_key: Any) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "ED25519-" + hashlib.sha256(raw).hexdigest()[:16].upper()


def _decode_signature(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise LicenseValidationError("signature must be a bounded base64url string")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise LicenseValidationError("signature is not valid base64url") from error


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise LicenseValidationError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise LicenseValidationError(f"{field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise LicenseValidationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


class LicenseManager:
    def __init__(
        self,
        installation_root: Path,
        license_path: Path | None = None,
        public_key_path: Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        root = Path(installation_root)
        self.license_path = Path(
            license_path or os.environ.get("AEGIS_LICENSE_PATH", root / "license.json")
        )
        self.public_key_path = Path(
            public_key_path
            or os.environ.get("AEGIS_LICENSE_PUBLIC_KEY_PATH", root / "license_public_key.pem")
        )
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._status: dict[str, Any] = {}
        self.reload()

    def _research_status(self) -> dict[str, Any]:
        return {
            "state": "RESEARCH",
            "valid": True,
            "signature_verified": False,
            "license_id": "AEGIS-RESEARCH-LOCAL",
            "customer": "Local research installation",
            "edition": "RESEARCH",
            "commercial_use": False,
            "max_nodes": 1,
            "entitlements": sorted(RESEARCH_ENTITLEMENTS),
            "issued_at": None,
            "not_before": None,
            "expires_at": None,
            "key_id": None,
            "reason": "No enterprise envelope installed; safe Research Edition entitlements are active.",
            "contract_version": LICENSE_CONTRACT_VERSION,
            "signature_algorithm": SIGNATURE_ALGORITHM,
        }

    def _invalid_status(self, reason: str, state: str = "INVALID") -> dict[str, Any]:
        return {
            "state": state,
            "valid": False,
            "signature_verified": False,
            "license_id": None,
            "customer": None,
            "edition": "LOCKED",
            "commercial_use": False,
            "max_nodes": 0,
            "entitlements": ["local_audit"],
            "issued_at": None,
            "not_before": None,
            "expires_at": None,
            "key_id": None,
            "reason": reason,
            "contract_version": LICENSE_CONTRACT_VERSION,
            "signature_algorithm": SIGNATURE_ALGORITHM,
        }

    def reload(self) -> dict[str, Any]:
        if not self.license_path.is_file():
            self._status = self._research_status()
            return self.status()
        try:
            if self.license_path.stat().st_size > 131_072:
                raise LicenseValidationError("license envelope exceeds 128 KiB")
            envelope = json.loads(self.license_path.read_text(encoding="utf-8"))
            self._status = self._verify(envelope)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, LicenseValidationError) as error:
            self._status = self._invalid_status(str(error))
        except ImportError:
            self._status = self._invalid_status(
                "The Ed25519 verifier is unavailable; signed entitlements remain locked.",
                state="VERIFIER_UNAVAILABLE",
            )
        return self.status()

    def _verify(self, envelope: Any) -> dict[str, Any]:
        if not isinstance(envelope, dict):
            raise LicenseValidationError("license envelope must be a JSON object")
        if envelope.get("contract_version") != LICENSE_CONTRACT_VERSION:
            raise LicenseValidationError("unsupported license contract version")
        if envelope.get("signature_algorithm") != SIGNATURE_ALGORITHM:
            raise LicenseValidationError("unsupported license signature algorithm")
        key_id = envelope.get("key_id")
        if not isinstance(key_id, str) or not key_id.startswith("ED25519-"):
            raise LicenseValidationError("license key_id is invalid")
        claims = envelope.get("claims")
        if not isinstance(claims, dict):
            raise LicenseValidationError("license claims must be a JSON object")
        required = {
            "license_id",
            "customer",
            "edition",
            "issued_at",
            "not_before",
            "expires_at",
            "max_nodes",
            "entitlements",
        }
        missing = sorted(required - set(claims))
        if missing:
            raise LicenseValidationError(f"license claims missing: {', '.join(missing)}")

        license_id = claims["license_id"]
        customer = claims["customer"]
        edition = claims["edition"]
        max_nodes = claims["max_nodes"]
        entitlements = claims["entitlements"]
        if not isinstance(license_id, str) or not 4 <= len(license_id) <= 128:
            raise LicenseValidationError("license_id is invalid")
        if not isinstance(customer, str) or not 2 <= len(customer) <= 256:
            raise LicenseValidationError("customer is invalid")
        if edition not in KNOWN_EDITIONS:
            raise LicenseValidationError("license edition is unsupported")
        if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or not 1 <= max_nodes <= 100_000:
            raise LicenseValidationError("max_nodes must be between 1 and 100000")
        if not isinstance(entitlements, list) or not entitlements:
            raise LicenseValidationError("entitlements must be a non-empty list")
        if any(not isinstance(item, str) for item in entitlements):
            raise LicenseValidationError("every entitlement must be a string")
        normalized_entitlements = sorted(set(entitlements))
        unknown = sorted(set(normalized_entitlements) - KNOWN_ENTITLEMENTS)
        if unknown:
            raise LicenseValidationError(f"unknown entitlements: {', '.join(unknown)}")
        if "local_audit" not in normalized_entitlements:
            raise LicenseValidationError("signed editions must include local_audit")

        issued_at = _timestamp(claims["issued_at"], "issued_at")
        not_before = _timestamp(claims["not_before"], "not_before")
        expires_at = _timestamp(claims["expires_at"], "expires_at")
        if expires_at <= not_before:
            raise LicenseValidationError("expires_at must follow not_before")
        if issued_at > not_before:
            raise LicenseValidationError("issued_at must not follow not_before")

        if not self.public_key_path.is_file():
            raise LicenseValidationError("license public key is not installed")
        if self.public_key_path.stat().st_size > 16_384:
            raise LicenseValidationError("license public key file is unexpectedly large")
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            public_key = serialization.load_pem_public_key(self.public_key_path.read_bytes())
        except (OSError, ValueError, TypeError) as error:
            raise LicenseValidationError("license public key could not be loaded") from error
        if not isinstance(public_key, Ed25519PublicKey):
            raise LicenseValidationError("license public key is not Ed25519")
        expected_key_id = public_key_id(public_key)
        if key_id != expected_key_id:
            raise LicenseValidationError("license key_id does not match the installed public key")
        signature = _decode_signature(envelope.get("signature"))
        try:
            public_key.verify(signature, canonical_license_payload(envelope))
        except InvalidSignature as error:
            raise LicenseValidationError("license signature verification failed") from error

        now = self.clock().astimezone(timezone.utc)
        state = "VALID"
        valid = True
        reason = "Offline Ed25519 signature and validity window verified."
        if now < not_before:
            state = "NOT_YET_VALID"
            valid = False
            reason = "The signed license validity window has not started."
        elif now >= expires_at:
            state = "EXPIRED"
            valid = False
            reason = "The signed license validity window has expired."

        return {
            "state": state,
            "valid": valid,
            "signature_verified": True,
            "license_id": license_id,
            "customer": customer,
            "edition": edition,
            "commercial_use": valid and edition == "ENTERPRISE",
            "max_nodes": max_nodes if valid else 0,
            "entitlements": normalized_entitlements if valid else ["local_audit"],
            "issued_at": issued_at.isoformat(),
            "not_before": not_before.isoformat(),
            "expires_at": expires_at.isoformat(),
            "key_id": key_id,
            "reason": reason,
            "contract_version": LICENSE_CONTRACT_VERSION,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "deployment_id": claims.get("deployment_id"),
        }

    def status(self) -> dict[str, Any]:
        return copy.deepcopy(self._status)

    def is_entitled(self, entitlement: str | None) -> bool:
        if entitlement is None:
            return True
        return entitlement in self._status.get("entitlements", [])
