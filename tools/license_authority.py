#!/usr/bin/env python3
"""Offline AEGIS license-authority utility.

This tool is intentionally excluded from the frozen endpoint executables. Keep the
encrypted private key on an offline administrative system; deploy only its public
key and the signed license envelope to an AEGIS installation.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from aegis.licensing import (
    KNOWN_ENTITLEMENTS,
    LICENSE_CONTRACT_VERSION,
    SIGNATURE_ALGORITHM,
    LicenseManager,
    canonical_license_payload,
    public_key_id,
)


DEFAULT_ENTERPRISE_ENTITLEMENTS = sorted(KNOWN_ENTITLEMENTS)


def _password(environment_name: str | None, confirm: bool = False) -> bytes:
    if environment_name:
        value = os.environ.get(environment_name)
        if value is None:
            raise ValueError(f"password environment variable is not set: {environment_name}")
    else:
        value = getpass.getpass("Private-key password: ")
        if confirm:
            repeated = getpass.getpass("Confirm private-key password: ")
            if repeated != value:
                raise ValueError("private-key passwords do not match")
    encoded = value.encode("utf-8")
    if len(encoded) < 12:
        raise ValueError("private-key password must contain at least 12 UTF-8 bytes")
    return encoded


def _write_new(path: Path, payload: bytes, mode: int = 0o600) -> None:
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    try:
        target.chmod(mode)
    except OSError:
        pass


def keygen(private_path: Path, public_path: Path, password: bytes) -> str:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_new(private_path, private_bytes, 0o600)
    try:
        _write_new(public_path, public_bytes, 0o644)
    except Exception:
        try:
            Path(private_path).unlink()
        except OSError:
            pass
        raise
    return public_key_id(public_key)


def issue(
    private_path: Path,
    password: bytes,
    output_path: Path,
    *,
    license_id: str,
    customer: str,
    edition: str,
    max_nodes: int,
    valid_days: int,
    entitlements: list[str],
    deployment_id: str | None,
) -> dict:
    private_key = serialization.load_pem_private_key(
        Path(private_path).read_bytes(),
        password=password,
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private key is not Ed25519")
    unknown = sorted(set(entitlements) - KNOWN_ENTITLEMENTS)
    if unknown:
        raise ValueError(f"unknown entitlements: {', '.join(unknown)}")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    claims = {
        "license_id": license_id,
        "customer": customer,
        "edition": edition,
        "issued_at": now.isoformat(),
        "not_before": now.isoformat(),
        "expires_at": (now + timedelta(days=valid_days)).isoformat(),
        "max_nodes": max_nodes,
        "entitlements": sorted(set(entitlements)),
    }
    if deployment_id:
        claims["deployment_id"] = deployment_id
    envelope = {
        "contract_version": LICENSE_CONTRACT_VERSION,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "key_id": public_key_id(private_key.public_key()),
        "claims": claims,
    }
    envelope["signature"] = base64.urlsafe_b64encode(
        private_key.sign(canonical_license_payload(envelope))
    ).decode("ascii").rstrip("=")
    payload = (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_new(output_path, payload, 0o600)
    return envelope


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage the offline AEGIS license authority")
    subparsers = parser.add_subparsers(dest="command", required=True)

    key_parser = subparsers.add_parser("keygen", help="Generate an encrypted Ed25519 authority key")
    key_parser.add_argument("--private-key", type=Path, required=True)
    key_parser.add_argument("--public-key", type=Path, required=True)
    key_parser.add_argument("--password-env")

    issue_parser = subparsers.add_parser("issue", help="Issue a signed offline license envelope")
    issue_parser.add_argument("--private-key", type=Path, required=True)
    issue_parser.add_argument("--output", type=Path, required=True)
    issue_parser.add_argument("--license-id", required=True)
    issue_parser.add_argument("--customer", required=True)
    issue_parser.add_argument("--edition", choices=("EVALUATION", "ENTERPRISE"), default="ENTERPRISE")
    issue_parser.add_argument("--max-nodes", type=int, default=1)
    issue_parser.add_argument("--valid-days", type=int, default=365)
    issue_parser.add_argument("--deployment-id")
    issue_parser.add_argument("--entitlement", action="append", choices=sorted(KNOWN_ENTITLEMENTS))
    issue_parser.add_argument("--password-env")

    verify_parser = subparsers.add_parser("verify", help="Verify an envelope against a public key")
    verify_parser.add_argument("--license", type=Path, required=True)
    verify_parser.add_argument("--public-key", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "keygen":
            key_id = keygen(
                args.private_key,
                args.public_key,
                _password(args.password_env, confirm=True),
            )
            print(json.dumps({"status": "created", "key_id": key_id}, sort_keys=True))
            print("Keep the encrypted private key offline. Deploy only the public key.", file=sys.stderr)
            return 0
        if args.command == "issue":
            if not 1 <= args.max_nodes <= 100_000:
                raise ValueError("max-nodes must be between 1 and 100000")
            if not 1 <= args.valid_days <= 3650:
                raise ValueError("valid-days must be between 1 and 3650")
            envelope = issue(
                args.private_key,
                _password(args.password_env),
                args.output,
                license_id=args.license_id,
                customer=args.customer,
                edition=args.edition,
                max_nodes=args.max_nodes,
                valid_days=args.valid_days,
                entitlements=args.entitlement or DEFAULT_ENTERPRISE_ENTITLEMENTS,
                deployment_id=args.deployment_id,
            )
            print(json.dumps({
                "status": "issued",
                "license_id": envelope["claims"]["license_id"],
                "key_id": envelope["key_id"],
                "expires_at": envelope["claims"]["expires_at"],
            }, sort_keys=True))
            return 0
        manager = LicenseManager(
            args.license.parent,
            license_path=args.license,
            public_key_path=args.public_key,
        )
        status = manager.status()
        print(json.dumps(status, indent=2, sort_keys=True))
        return 0 if status["valid"] and status["signature_verified"] else 1
    except Exception as error:
        print(f"license authority error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
