# AEGIS access, licensing and command-audit guide

Version 1.2.0 · Enterprise Control Boundary · 23 August 2026

## 1. What changed and why

AEGIS v1.2 adds a control boundary between the desktop interface and every
state-changing command. The boundary exists for two reasons:

1. a licensable endpoint product needs a verifiable entitlement contract and
   explicit operator authority; and
2. a security product must be able to explain who was allowed to request a
   change, why the request was allowed or denied, and whether the command
   completed.

This layer does not make the research build production-certified. It creates a
testable foundation for signed licensing, least privilege and command
accountability while preserving the defensive authorization boundary.

## 2. Runtime decision order

Every HTTP `POST` handled by the local control plane follows this order:

| Order | Gate | Failure result |
| --- | --- | --- |
| 1 | Local audit journal is operational | `503`; mutation is not executed |
| 2 | Desktop request uses a loopback Host | `421`; denial receipt is sealed |
| 3 | Desktop session token matches | `403`; denial receipt is sealed without retaining the token |
| 4 | Server-assigned role contains the required scope | `403`; `DENIED_ROLE` receipt |
| 5 | Current license contains the route entitlement | `403`; `DENIED_LICENSE` receipt |
| 6 | JSON body passes size and type checks | `400`/`413`; `DENIED_INPUT` receipt |
| 7 | `ACCEPTED` receipt is appended successfully | `503` on failure; route is not called |
| 8 | Route executes | Existing domain and Safety Kernel checks still apply |
| 9 | `COMPLETED` or `FAILED` receipt is appended | A completion-audit failure is surfaced as `500` |

For deception actions, the deterministic Safety Kernel remains authoritative
inside step 8. A role or license can remove permission; neither can create a
Safety Kernel permit, expand the authorized namespace, turn on network egress,
enable hack-back or infer a person.

## 3. Offline signed license envelope

### 3.1 Cryptographic contract

The license format is `AEGIS-LICENSE-1`. A vendor or organization authority
signs a canonical JSON payload with Ed25519. AEGIS verifies the signature using
the separately deployed public key and does not contact a licensing server.

The signed payload contains all security-relevant envelope fields:

```json
{
  "contract_version": "AEGIS-LICENSE-1",
  "signature_algorithm": "Ed25519",
  "key_id": "ED25519-…",
  "claims": {
    "license_id": "LIC-AEGIS-ENTERPRISE-0001",
    "customer": "Authorized Organization",
    "edition": "ENTERPRISE",
    "issued_at": "2026-08-23T12:00:00+00:00",
    "not_before": "2026-08-23T12:00:00+00:00",
    "expires_at": "2027-08-23T12:00:00+00:00",
    "max_nodes": 250,
    "entitlements": [
      "desktop_control_plane",
      "resident_node",
      "research_lab",
      "offline_evidence_gateway",
      "hardware_dry_run",
      "local_audit",
      "multi_node"
    ],
    "deployment_id": "OPTIONAL-DEPLOYMENT-REFERENCE"
  }
}
```

The Base64URL signature is added as the top-level `signature` field. Modifying
any signed field invalidates verification.

AEGIS derives `key_id` from the raw public-key digest. A mismatched key ID,
wrong algorithm, unknown entitlement, malformed timestamp, invalid node limit,
missing claim, invalid signature or missing public key fails closed.

### 3.2 License states

| State | Meaning | Mutation entitlements |
| --- | --- | --- |
| `RESEARCH` | No enterprise envelope is installed | Safe local Research Edition set |
| `VALID` | Signature, key identity, schema and time window verify | Signed entitlement set |
| `NOT_YET_VALID` | Signature verifies, start time is in the future | `local_audit` only |
| `EXPIRED` | Signature verifies, expiry has passed | `local_audit` only |
| `INVALID` | Format, key or signature validation failed | `local_audit` only |
| `VERIFIER_UNAVAILABLE` | Ed25519 dependency cannot load | `local_audit` only |

The absence of a license is intentionally different from a broken installed
license. Absence activates a non-commercial, one-node Research Edition for the
implemented synthetic and local experiments. A present but invalid license does
not silently fall back.

The recovery route `/api/license/reload` is entitlement-independent but still
requires the `administrator` scope and a valid desktop session. This prevents a
bad license from making its own replacement impossible.

### 3.3 Current trust-anchor boundary

The installer accepts a license and matching public key, stores them under the
protected machine data directory and applies an ACL that grants full access to
Local System and Administrators and read/execute access to ordinary Users. The
private signing key must never be deployed to an endpoint.

This is an administrative trust boundary, not tamper-proof DRM. A production
release still needs a vendor public key embedded in a code-signed binary, an
offline key ceremony, HSM-backed private-key custody, signed upgrades and
independent validation. An administrator who can replace the executable remains
outside the assurance of this Python research build.

See `LICENSE_AUTHORITY_RUNBOOK.md` for the offline key and issuance workflow.

## 4. Operator roles

Roles are monotonic: each higher role contains all lower-role scopes.

| Role | Scopes | Intended use |
| --- | --- | --- |
| `viewer` | `read` | Inspect local status and evidence |
| `analyst` | `read`, `operate` | Run bounded simulations, research evaluations, safe telemetry collection and gateway workflows |
| `administrator` | `read`, `operate`, `administer` | Reset state, evaluate governance candidates and reload licensing |

The role is assigned when the local HTTP handler is created. A request header
cannot select or elevate it. The desktop session contains a pseudonymous
`SES-…` reference derived from the token; the raw token is never returned by an
API or written to SQLite.

The default native desktop and resident service role is `administrator` because
v1.2 is still a single-operator local product. The development server supports:

```bash
python -m aegis.server --operator-role viewer
python -m aegis.server --operator-role analyst
python -m aegis.server --operator-role administrator
```

Enterprise OIDC/Windows-integrated identity, session issuance, revocation,
multi-user separation and read-route authorization remain deferred. The current
implementation should therefore be treated as a local role-enforcement
foundation, not enterprise IAM.

## 5. Route contract

Representative mutation requirements are:

| Route | Scope | Entitlement |
| --- | --- | --- |
| `/api/simulate` | `operate` | `desktop_control_plane` |
| `/api/actions/evaluate` | `operate` | `desktop_control_plane` |
| `/api/demo/reset` | `administer` | `desktop_control_plane` |
| `/api/telemetry/collect` | `operate` | `resident_node` |
| `/api/gateway/preview` | `operate` | `offline_evidence_gateway` |
| `/api/gateway/import` | `operate` | `offline_evidence_gateway` |
| research/model reruns | `operate` | `research_lab` |
| `/api/governance/evaluate` | `administer` | `research_lab` |
| `/api/hardware/dry-run` | `operate` | `hardware_dry_run` |
| `/api/license/reload` | `administer` | recovery route; no entitlement |

The complete live mapping is returned by `GET /api/access/status` and displayed
in the Access & Audit workspace.

## 6. Tamper-evident command journal

### 6.1 Record construction

The journal stores metadata, not request content. Each record includes:

- command ID shared by the preflight and outcome receipts;
- UTC creation time;
- pseudonymous session reference and server-assigned role;
- method and route;
- required scope and entitlement;
- decision and status code;
- SHA-256 digest of the request bytes;
- previous record hash and local audit key ID.

For record `i`, AEGIS computes:

```text
record_hash_i = HMAC-SHA256(
    installation_audit_key,
    canonical_json(record_i including previous_hash_i)
)

previous_hash_1 = 64 zeroes
previous_hash_i = record_hash_(i-1)
```

The verifier recomputes every HMAC, checks each previous-hash link, compares the
canonical JSON copy with the normalized SQL columns and checks the key identity.
SQLite triggers reject ordinary `UPDATE` and `DELETE` operations on the table.

### 6.2 Fail-closed behavior

The 32-byte audit key is generated once beside the machine database. If journal
records exist but that key is missing or malformed, a new key is not silently
generated. Verification reports failure and all mutations return `503` before
route execution. This preserves the meaning of an existing chain.

### 6.3 What local HMAC proves

It provides modification detection while the per-install key and database
boundary remain trustworthy. It does not provide:

- external non-repudiation;
- a trusted or independently witnessed timestamp;
- write-once media;
- survival after simultaneous database-and-key compromise;
- a remote transparency log or SIEM export; or
- proof that the Windows host itself was uncompromised.

Production should periodically anchor signed chain heads into organization-
controlled append-only storage and protect the signing key in TPM/HSM-backed
custody.

## 7. APIs and workspace

| Method and route | Result |
| --- | --- |
| `GET /api/access/status` | License, operator, role map, mutation contract and audit summary |
| `GET /api/license/status` | Current license decision only |
| `GET /api/audit/events?limit=80` | Latest minimized receipts plus summary |
| `GET /api/audit/verify` | Full-chain verification result |
| `POST /api/license/reload` | Reload envelope and public key from disk |

The sixteenth analyst workspace, **Access & Audit**, visualizes the live license
state, customer and key claims, active entitlements, operator scopes, session
reference, full audit-chain state and recent command receipts. Its wording
separates implemented local guarantees from production gaps.

## 8. Verification evidence

The v1.2 test suite contains 88 tests. New adversarial coverage verifies:

- monotonic role behavior and admin-only routes;
- absence of raw session tokens from public status;
- viewer denial and analyst/admin separation over the live HTTP path;
- two-stage `ACCEPTED`/`COMPLETED` command receipts;
- invalid-license mutation lock and entitlement-independent recovery;
- valid, tampered, expired, future and unknown-entitlement license envelopes;
- append-only update/delete triggers;
- detection of out-of-band row tampering; and
- fail-closed behavior when an existing journal loses its key.

Synthetic and unit-test evidence does not establish Windows production
qualification, IAM assurance, regulatory compliance or attack resistance.

## 9. Primary implementation references

- `cryptography` Ed25519 signing and verification documentation:
  https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
- OWASP Logging Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP REST Security Cheat Sheet, including pre/post security-event auditing:
  https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet, including session-lifecycle logging:
  https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- NIST SP 800-92, *Guide to Computer Security Log Management*:
  https://doi.org/10.6028/NIST.SP.800-92

These sources guide implementation hygiene. They do not certify AEGIS or imply
that this particular combination is novel or patentable.
