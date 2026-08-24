# AEGIS Model Governance Guide

Version 1.0.0 · attested-lifecycle checkpoint · 20 August 2026

## Why this layer exists

“Self-learning” is unsafe when it means that live input can silently rewrite a
production model. A security system is exposed to adversarial, mislabeled and
distribution-shifted data. AEGIS therefore separates four events that are often
collapsed into one:

1. online belief updates;
2. offline candidate training;
3. evidence-backed promotion eligibility; and
4. a separately authorized production release.

Version 1.0 implements the durable evidence layer for steps 2 and 3. It does
not implement production release authority.

## Artifact contract

The registry accepts bounded canonical-JSON descriptors for five artifact
types: dataset, model, policy, evaluator and rollback. Each record contains:

- a type-derived immutable artifact ID;
- a human-readable name and version;
- the SHA-256 digest of its canonical descriptor;
- zero or more registered parent artifact IDs;
- a lifecycle status;
- creation time and per-install key identifier; and
- an HMAC-SHA256 attestation over the complete identity envelope.

Artifact identity includes the type, name, version, descriptor digest and
lineage. Changing any of those values changes the expected ID and invalidates
the attestation. Registration is idempotent: an identical artifact returns the
existing record. Unknown lineage, unsupported types/statuses, malformed JSON
and descriptors larger than 64 KiB fail closed.

SQLite triggers reject `UPDATE` and `DELETE` for the artifact table. A lifecycle
change is represented by a new decision or new artifact, never by rewriting
history.

## Built-in v1.0 artifacts

The service materializes ten reproducible descriptors when Governance Ledger
is first opened:

| Type | Artifact | Parent lineage |
| --- | --- | --- |
| Dataset | Synthetic intent corpus | None |
| Model | Sequence n-gram champion | Intent corpus |
| Model | Event-presence shadow candidate | Intent corpus |
| Dataset | Synthetic trace-pair corpus | None |
| Model | Diversity-feature logistic linker | Trace-pair corpus |
| Dataset | Synthetic trace-graph corpus | None |
| Model | Cohort-supported graph guard | Trace-graph and trace-pair corpora |
| Policy | Safety Kernel invariant set | None |
| Dataset | Synthetic diagnostic-steering corpus | None |
| Model | Expected-information-gain decision-policy candidate | Diagnostic-steering corpus and Safety Kernel policy |

The descriptors contain experiment run IDs, grouped split facts, metrics,
synthetic/external-target boundaries and safety results. The registry stores
metadata and digests—not serialized model binaries or raw training records. A
production registry must separately address artifact-blob storage, encryption,
retention, malware scanning and signed distribution.

## Promotion ledger

Each promotion evaluation creates a new record with:

- candidate and champion artifact IDs;
- quality and release-gate results;
- the decision and trusted evidence scope;
- the previous record hash;
- a SHA-256 hash of the canonical record; and
- a local HMAC attestation of that hash.

The first record points to the all-zero genesis hash. Verification walks the
ledger in sequence and checks previous-hash continuity, canonical record hash,
database-column consistency, local key ID and HMAC. Update/delete triggers make
the database path append-only under ordinary application credentials. This is
tamper evidence, not protection against an administrator who can replace the
database, key and program together.

## Quality gates versus release gates

The evaluator makes the separation visible.

Quality gates currently check:

- the candidate is a registered model;
- artifact attestation and parent lineage verify;
- grouped validation is declared in the manifested experiment;
- the candidate's release-specific quality criterion passed;
- safety regressions are zero; and
- external targets are zero.

Production release evidence additionally requires:

- validation in an approved, authorized enterprise environment;
- at least 10,000 authorized shadow observations;
- an offline named-reviewer signature;
- a registered rollback artifact; and
- a separate signed release transaction.

The loopback evaluation API accepts only a registered candidate ID. Submitted
fields such as `human_release_signoff`, `shadow_observations` or
`enterprise_validation` are ignored and listed in the decision evidence. The
v1.0 public path always supplies zero/false for these trusted facts. Passing
offline quality therefore produces `HOLD_SHADOW`, never automatic promotion.

Even if all evidence were available to an internal trusted caller, the highest
result is `ELIGIBLE_FOR_SIGNED_RELEASE`. Changing deployed weights is a separate
operation and is not implemented in this Research Edition.

## What “attested” means here

The registry key is a random 32-byte secret stored as `registry.key` beside the
local database with restrictive creation permissions where supported. HMAC
provides integrity and authenticity to another process that trusts the same
installation and key.

It does not provide:

- a public-key signature independently verifiable by a customer;
- non-repudiation;
- a trusted timestamp;
- platform binary/code signing;
- hardware-backed key protection;
- remote attestation; or
- protection after total host/key compromise.

Production should replace or wrap this boundary with customer/organization
signatures, platform code signing, HSM/TPM-backed keys, authenticated reviewer
identities, trusted time, revocation, key rotation and an independently
replicated transparency/audit service. The local HMAC remains useful as a
development integrity control and a concrete contract for that adapter.

## API and interface

- `GET /api/governance/status` returns the artifact inventory, verification,
  decision history, promotion policy and explicit attestation limitations.
- `GET /api/governance/verify` rechecks the registry and complete ledger.
- `POST /api/governance/evaluate` appends a bounded candidate evaluation. It
  cannot create a human signature or production promotion.
- Governance Ledger renders artifact lineage, the local trust scope, latest
  gate evidence and the hash-linked history.

No route registers arbitrary files, changes an artifact, deletes a decision,
installs weights or actuates a security control.

## Reproduce and inspect

```bash
python -m unittest tests.test_registry -v
python -m unittest discover -s tests -v
```

The registry suite covers valid attestations, idempotent identity, lineage,
malformed/oversized refusal, descriptor-tamper detection, release-gate locking,
multi-record chain verification, ledger-copy tampering and SQL update/delete
refusal.

## Code map

| File | Responsibility |
| --- | --- |
| `aegis/registry.py` | artifact identity, local key, attestations, release checks, decision records and verification |
| `aegis/store.py` | immutable registry/ledger tables and SQL triggers |
| `aegis/service.py` | built-in artifact materialization and API-safe evaluation evidence |
| `aegis/server.py` | loopback governance endpoints |
| `web/index.html`, `web/app.js`, `web/styles.css` | Governance Ledger workspace |
| `tests/test_registry.py` | artifact, gate, chain and immutability contracts |

## Research and assurance alignment

The governance work should be mapped—not claimed certified—to NIST's AI Risk
Management Framework functions and secure-development practices. The current
artifact supplies evidence for mapping/measuring/managing model changes, while
production engineering must also cover organizational governance and secure
software release:

- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
- [NIST Secure Software Development Framework, SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)

These references are engineering guidance. AEGIS v1.0 is not NIST-certified or
independently audited.
