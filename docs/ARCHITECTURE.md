# AEGIS architecture decision record — enterprise control boundary v1.2

## Product boundary

AEGIS is one product name and one control plane. Internal components use clear
functional names so the paper, patent material, interface, and commercial product
do not fragment into separate brands.

## Deployment profiles

| Profile | Intended use | Runtime shape |
|---|---|---|
| Research Edition | Solo local development with scale-out training when required | Local node runtime, SQLite, packaged analyst console, seeded experiments, optional remote accelerator jobs |
| Enterprise | Authorized on-premises or private cloud pilot | PostgreSQL/Timescale, ordered event bus, OIDC/RBAC, signed nodes, HA adapters |
| Sovereign | Regulated or air-gapped deployment | Offline updates, customer-managed keys, strict export, no external model dependency |

All profiles retain the same versioned event contract, safety certificate,
evidence schema, and control-plane API.

The research design is not bounded by the development laptop. Training and
inference are separate contracts: large temporal or graph experiments may use
approved external compute, while signed, compressed model artifacts are tested
and deployed locally through the model registry and Safety Kernel.

## Installed application shape

The console is not the runtime boundary. The licensed software product has four
layers:

1. a resident Windows service or Linux daemon that stays active without an open
   UI, with code signing mandatory for production release;
2. read-only and enforcement collectors attached through versioned adapters;
3. an on-premises/private control plane containing evidence, policy, models and
   deception orchestration; and
4. a packaged desktop/on-premises analyst console.

Version 1.0 retains the resident process lifecycle, durable telemetry spool,
real host-health and runtime-integrity collectors, a privacy-bounded Windows
Event Log sampler, loopback analyst API, Windows Service Control Manager host,
and reversible installation scripts. The Research Edition is not code-signed,
and its Windows service path has fixture/contract coverage rather than completed
enterprise Windows qualification. It adds a safety-gated diagnostic-steering
research service and a fifteenth console workspace. ETW, WFP and eBPF remain
adapter contracts—not falsely reported as live integrations.

## Resident telemetry contract

`TelemetryObservation` is separate from the synthetic investigation
`SecurityEvent` contract. It records a node, source, category, event type,
severity, timestamp, versioned payload and canonical digest. A collector failure
is isolated to its run result; it cannot stop the resident control plane.

The default runtime executes three passive collectors:

| Collector | Real input | Persistence boundary |
| --- | --- | --- |
| Host health | Local OS/runtime resource APIs | Coarse resource envelope; no process enumeration |
| Runtime integrity | AEGIS Python/JS/CSS/HTML files | File count and aggregate SHA-256 manifest |
| Windows Event Log | `wevtutil qe` Security/System queries | Eight allowlisted event types and selected fields only |

Windows identity-like values are transformed locally into stable references
using HMAC-SHA-256 and a random per-install key. Raw usernames, IP addresses,
workstation names and service names do not enter SQLite. Process paths are
reduced to basenames; command lines are never selected. Overlapping query windows
are safe because the canonical observation digest is unique. No telemetry
transport or cloud destination exists in this release.

The selected Windows IDs are 4624, 4625, 4688, 4719, 4720, 4740 and 1102 from
the Security channel, and 7045 from System. Availability depends on Windows
audit policy and service-account access. The implementation uses Microsoft's
documented [`wevtutil`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
query interface; it does not claim ETW or kernel interception.

## Sensor Evidence Gateway boundary

Version 0.7 adds `aegis.sensor-gateway.v1` between analyst-selected sensor
records and the telemetry spool. Two strict offline adapters cover a selected
subset of Suricata EVE JSON and Zeek JSON `conn.log`.

The gateway has two separate operations:

1. **preview** validates and normalizes records without persistence; and
2. **commit** repeats the exact normalization, stores deduplicated
   `TelemetryObservation` values and writes a safe import manifest.

Raw endpoint addresses, DNS/SNI values, flow identifiers, TLS/SSH fingerprints
and alert categories are transformed to per-install HMAC references before an
output object exists. Byte values are bucketed. Packet, PCAP, HTTP, file and
application content fields are never selected. A recursive raw-address
invariant rejects malformed output. Input batches are limited to 256 records,
64,000 canonical bytes per record and the server's 1 MiB request boundary.

This is not live sensor integration: there is no socket, tailer, message bus,
packet capture, sensor credential or control command. The desktop renderer submits a
local JSON/JSONL selection to the loopback API. Committed gateway observations
cannot automatically create an investigation case, label a model or trigger a
response. That future promotion requires a separate governed contract.

## Control flow

1. Passive endpoint collectors emit privacy-bounded `TelemetryObservation`
   records into the durable local spool.
2. Approved correlation logic may normalize relevant observations into
   investigation `SecurityEvent` records; v1.0 deliberately does not perform
   that conversion automatically.
3. Evidence storage appends each case event to a per-case cryptographic chain.
4. The Belief Engine and model fabric update a calibrated distribution over
   competing intents while retaining inter-model disagreement.
5. The Investigation Engine maps behaviours to ATT&CK and compares cases using
   technique, sequence, target-family, and pseudonymous-fingerprint features.
6. Adaptive Steering proposes a diagnostic deception action.
7. The deterministic Safety Gate evaluates policy, containment, provenance,
   reversibility, resource, and lifetime invariants.
8. Only a permitted certificate may be handed to a decoy node.
9. Observed outcomes return to the same event and evidence contracts.

## Reproducible model contract

The first publishable baseline is deliberately small and inspectable. A seeded
generator creates 240 synthetic sequences for Reconnaissance, Credential Access,
Lateral Movement, and Collection. Five scenario families per class are assigned
as complete groups: families 0–2 train, family 3 calibrates, and family 4 tests.
No family crosses a split.

The dependency-free multinomial sequence model consumes event tokens, adjacent
event bigrams, and a length bin. Laplace smoothing is fixed at 0.75. Temperature
is selected only on the validation family by minimizing multiclass Brier score.
The held-out report includes accuracy, macro-F1, Brier score, expected calibration
error, negative log-likelihood, a confusion matrix, per-class metrics, and
reliability bins. The dataset digest, seed, run descriptor, and limitations travel
with the result.

This model is a serious reproducible baseline, not the final learning claim.
Temporal neural, graph, and language-assisted candidates must beat it under the
same family-grouped protocol and safety boundary.

## Multi-model intelligence fabric

Version 0.5 retains three complementary learners under the exact same split:

- an order-sensitive event and bigram model;
- an order-insensitive event-presence model; and
- a relative-position model.

A probability-fusion challenger chooses weights using only the validation
family. The held-out test family is reported once for release evaluation. This
is deliberately an ablation framework rather than a claim that an ensemble is
automatically superior. The current event-presence challenger improves held-out
macro-F1 from 0.854 to 0.937 on the synthetic corpus, while the fusion model has
the same macro-F1 but a worse Brier score than that single challenger. That
negative result is retained because it constrains the next experiment.

Planned components have separate roles: a temporal Transformer for long-range
sequence reasoning, temporal GNN for entity/campaign structure, novelty model
for unknown behaviour, constrained contextual bandit for diagnostic deception,
and a language model for grounded explanation. The language model is prohibited
from actuation.

## Diagnostic-steering contract

Version 1.0 implements `aegis.synthetic-diagnostic-steering.v1`. The controller
maintains a posterior over four intent hypotheses and chooses among four
pre-authorized synthetic probes by maximizing expected entropy reduction after
a bounded cost penalty. Static, seeded-random and leading-intent rules use the
same probe set as comparators.

The safety order is architectural, not presentational:

1. the policy selects a candidate probe;
2. the candidate becomes a complete `ProposedAction`;
3. the independent Safety Gate checks all eight invariants;
4. only `PERMIT` allows an observation to exist;
5. only that permitted observation may update the posterior; and
6. the loop stops at posterior confidence 0.86 or abstains after eight actions.

No output is handed to a deployment adapter. The environment response model,
costs and intent labels are synthetic. The family-4 protocol is held out from
policy development, but it is still generated from a shifted version of the
declared nominal likelihood model. The result is registered as a shadow decision
policy with two lineage parents: its dataset and the Safety Kernel policy.

## Governed continual learning

"Self-learning" means a controlled lifecycle, not blind weight updates from
attacker-controlled telemetry:

1. collect versioned observations and analyst feedback;
2. train an isolated candidate;
3. validate grouped performance, calibration, safety, drift and provenance;
4. execute the candidate in shadow mode with no decision authority;
5. obtain named human release approval and a rollback package; and
6. canary-promote a signed artifact through the model registry.

The v0.5 candidate is held in shadow. Quality gates pass, but the required
10,000 authorized shadow observations and human sign-off do not. The public API
cannot override either gate, so no live model can silently retrain or replace
the champion.

## Investigation and attribution boundary

AEGIS can associate authorized observations with cases, preserve behavioural
sequences, map events to ATT&CK, expose pseudonymous infrastructure signals, and
rank possible campaign relationships. Its current pairwise linkage score is:

`0.45 technique overlap + 0.25 sequence similarity + 0.15 target-family overlap + 0.15 pseudonymous fingerprint overlap`

Every score retains its features, supporting evidence, limitations, and the
status `UNVERIFIED — CAMPAIGN LINKAGE ONLY`. AEGIS does not convert similarity
into a claim about a named person, organization, or state. Such attribution needs
corroboration and an appropriate legal process.

## Evidence-diverse Threat Trace contract

Version 0.6 adds a stricter activity-linkage layer alongside the legacy
behavioural campaign view. `aegis.threat-trace.v1` extracts six signal families:
source context, infrastructure, transport, tooling, behaviour and controlled
deception response. All network identity-like inputs must already be represented
as opaque references. The extractor rejects raw IPv4/IPv6 literals in every
reference field.

The deterministic linker applies reliability/spoofability-adjusted family
weights, a bounded diversity bonus and contradiction penalties. It caps a
single-family result below 0.50 and a two-family result below 0.70. Therefore a
shared address, certificate or fingerprint cannot independently create a high
link. A rotated source is treated as a small contradiction, allowing stronger
independent evidence to support a relationship.

Each link returns its family scores, shared values, divergent families,
calibration descriptor, supporting evidence, alternative explanations and
`identity_claim: false`. The full report includes an activity graph, ordered
timeline, source policy, standards-alignment notes and a manifest SHA-256.
No path performs geolocation, outbound pursuit, external scanning, exploitation
or hack-back.

`aegis.synthetic-trace-pairs.v1` provides the first falsifiable comparison: 240
sessions and 240 balanced pairs, grouped 144/48/48 by environment family. A
source-only baseline, single-profile baseline, fixed diversity fusion and binary
logistic shadow candidate share the exact test family. The learned candidate is
not promoted; the synthetic calibration explicitly requires enterprise
recalibration and temporal validation.

## Transitivity-safe campaign graph contract

Version 0.8 adds an interpretable clustering layer over the pairwise trace
model. Training remains on the balanced hard-negative pair corpus from
environment families 0–2. Family 3 is expanded to all 1,128 unordered pairs to
select temperature, pair threshold and graph-guard settings. Family 4 is then
expanded to all 1,128 pairs among 48 held-out sessions for final evaluation.

Three graph builders share the held-out nodes: source-reference connected
components, ordinary thresholded learned-edge components and an AEGIS guarded
union-find. The guard accepts a merge only when the proposed edge has evidence
diversity, a new seed clears a higher threshold, existing cohorts agree across
their cross-component scores and the resulting component stays below a size
cap. Every adversarial bridge receives an auditable decision record.

The graph experiment injects a seven-edge chain across eight synthetic campaign
cohorts. The release manifest records the complete corpus digest, grouped split,
calibration values, guard settings and deterministic run ID. Nodes and labels
are activity sessions and synthetic campaigns only. The graph contract has no
raw IP feature, entity label, automatic attribution or response path. The
candidate remains `HOLD_SHADOW` regardless of its synthetic result.

## Attested artifact and promotion boundary

Version 0.9 introduced `aegis.local-artifact-attestation.v1` and
`aegis.promotion-ledger.v1`. Canonical dataset, model and policy descriptors
receive content digests, immutable IDs, explicit parent lineage and a
per-install HMAC-SHA256 attestation. The registry rejects unknown lineage and
uses SQLite triggers to prevent update/delete operations under normal
application access.

Promotion evaluation produces a separate append-only record containing the
candidate/champion identities, gate evidence, previous record hash, record hash
and local attestation. Verification walks the entire chain and checks canonical
content, database-column consistency, hash continuity and key identity. The
loopback API may choose a registered candidate but cannot supply trusted release
facts: enterprise validation, authorized shadow volume, human sign-off and a
rollback artifact remain false/absent and submitted substitutes are recorded as
ignored.

The local registry key is separate from the telemetry pseudonymization key.
HMAC establishes only per-install integrity/authenticity. It is not an
asymmetric organization signature, trusted timestamp, code-signing certificate,
remote attestation or non-repudiation mechanism. Production requires an adapter
for hardware-backed keys, organization signatures, reviewer identity, trusted
time, revocation and a separately authorized release transaction. Version 1.0
registers the steering corpus and decision policy, bringing the built-in total
to four datasets, five model/decision-policy descriptors and one safety policy.
No v1.0 path replaces weights or gives a candidate actuation authority.

## Evidence bundle boundary

The case export contains the case snapshot, ordered canonical events, per-event
hashes, ATT&CK mappings, evidence verification, scope statement, language
boundary, and a manifest SHA-256 digest. It is an investigator-ready research
artifact, not yet a substitute for jurisdiction-specific forensic handling,
digital signatures, trusted timestamps, or evidence-custody procedures.

## Foundation trust boundary

The adaptive model is never trusted as an actuator. The verifier is small,
deterministic, testable, and independent of the proposal mechanism. In this
research build, there is no enforcement deployment adapter at all; the
certificate is shown to the analyst but cannot touch a network or external
system. The read-only endpoint collectors are not actuators.

## Hardware Enforcement Profile

The future hardware path is a separate trust boundary, not generic “hardware
support.” AEGIS models a gateway that:

1. establishes an approved firmware measurement;
2. verifies the full Safety Gate certificate and its digest;
3. rejects every non-PERMIT or out-of-scope action;
4. stages a rule set that preserves protected-core and egress denial;
5. commits the complete generation atomically;
6. expires and rolls back the generation; and
7. emits a tamper-evident receipt.

The v0.7 implementation is only a deterministic state-machine simulation. It has
zero packet effects, touches no interface, and uses a SHA-256 receipt rather than
a hardware-protected signing key. A later lab profile can map the same contract
onto a DPU, SmartNIC, P4-capable switch, or FPGA with TPM/device-rooted measured
boot. That future combination is an invention candidate, not a conclusion of
novelty or patentability.

## Enterprise licensing shape

- Control Plane license: management, policy, inference, evidence, analyst console
- Node entitlement: signed sensor/decoy deployments per protected environment
- Integration SDK: SIEM, SOAR, identity, endpoint, cloud, ticketing connectors
- Research module: scenario runner, baselines, ablations, reports
- Support tiers: updates, connector certification, private deployment assistance

Version 1.2 encodes only technical entitlement identifiers, node limits and
validity windows. Pricing, payment, contract rights and remedies remain outside
the executable and require legal, tax, support, liability, export-control and
customer-procurement review.

## Native desktop boundary — v1.1

The desktop is a process boundary and product experience improvement, not a new
source of security truth. `AEGIS.exe` hosts the existing analyst surface inside
Windows WebView2 and connects only to a loopback `ResidentControlPlane`.

Installed mode attaches to the exact-version `AEGISNode.exe` Windows Service.
Portable mode creates a random high-entropy mutation token, binds an ephemeral
loopback port, starts the same control-plane contract on a background thread and
stops it when the final window closes. The UI cannot choose an arbitrary remote
URL. Downloads, file URLs, external navigation and remote debugging are disabled
in release mode.

The local HTTP boundary remains because it provides a small testable interface
between the renderer and governed engine. Desktop-mode handlers reject
non-loopback Host values and every POST lacking the current session token. GET
responses deny framing and apply same-origin resource and opener policies. The
token blocks ordinary cross-origin form/fetch actions; it is not an authorization
system for mutually hostile local Windows users.

Executable freezing produces two separately inventoryable components:

- `AEGIS.exe`: operator window and portable-runtime coordinator;
- `AEGISNode.exe`: always-on Service Control Manager host.

Keeping the service separate allows UI closure or failure without ending the
collector. Both executables are unsigned research artifacts until Authenticode,
independent review and Windows qualification are complete.

## Licensed operator control boundary — v1.2

Every state-changing loopback request now crosses four independent controls
before the route executes:

1. desktop session authenticity;
2. a server-assigned operator role and required scope;
3. a current offline license entitlement; and
4. a durable audit preflight receipt.

The controls are reductive. They may prevent an operation that the Safety Kernel
would otherwise consider, but they cannot create a permit or modify any safety
invariant.

### License component

`LicenseManager` parses a bounded `AEGIS-LICENSE-1` JSON envelope and verifies a
canonical payload with an Ed25519 public key. The signature covers the contract
version, algorithm, key ID and claims. Strict validation rejects unknown
editions/entitlements, invalid node limits, naive timestamps, invalid validity
ordering and key-identity mismatch.

No envelope means Research Edition. A present invalid, expired or future
envelope retains only local audit access and locks ordinary mutations. This
distinction avoids silently treating damaged enterprise material as a valid
commercial state.

The endpoint receives only the public key and signed envelope. The offline
authority utility encrypts private Ed25519 keys with PKCS#8 and refuses output
overwrite. It is deliberately outside both frozen executables.

### Access component

`AccessController` owns a static route contract. `viewer`, `analyst` and
`administrator` scopes are monotonic. `OperatorSession` is constructed by the
HTTP host; browser headers cannot choose a role. Only a SHA-256-derived session
reference can leave memory.

This is not yet enterprise IAM. The local role must later be bound to Windows-
integrated or OIDC identity, session expiry/revocation, named-user policy and
read-route authorization.

### Audit component

`AuditJournal` writes a first HMAC-linked receipt with decision `ACCEPTED` before
calling a mutation route. It writes `COMPLETED` or `FAILED` before returning the
response. Denials receive one terminal record. Both accepted and terminal
records share a random command ID.

The record retains a request SHA-256 digest, never the JSON body or raw desktop
token. A per-install 32-byte key produces HMAC-SHA256 hashes. Each record embeds
the preceding hash and key identity. The verifier checks link order, HMAC,
canonical JSON versus normalized SQL columns, and key identity. SQLite triggers
reject update/delete through ordinary SQL paths.

If an existing journal loses its key, AEGIS refuses to create a replacement
chain and locks mutations. This is modification evidence inside one installation,
not an organization signature, trusted timestamp, WORM archive, remote
transparency log or host-compromise defense.

### Windows storage component

The packaged installer restricts `%ProgramData%\AEGIS` to Local System and
Administrators for full control and Users for read/execute. It can install a
license/public-key pair at deployment time. An administrator remains inside the
trust base until a vendor root key is embedded in a code-signed binary and audit
heads are anchored outside the endpoint.

### New read models

- `GET /api/access/status`
- `GET /api/license/status`
- `GET /api/audit/events`
- `GET /api/audit/verify`
- `POST /api/license/reload` (administrator recovery)

The Access & Audit workspace presents these read models without creating a
second security policy in JavaScript. The server remains the authority.
