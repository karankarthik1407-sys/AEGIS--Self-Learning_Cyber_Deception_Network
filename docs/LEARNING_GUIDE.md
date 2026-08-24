# AEGIS Learning Guide

Version 1.2.0 · living technical companion · 23 August 2026

This guide explains what AEGIS currently does, why each component exists, what
the experiment proves, and what must be built next. It is intentionally honest:
a planned capability is never presented as an implemented one.

## 1. The one-sentence mental model

AEGIS observes authorized activity, maintains competing explanations of intent,
links related behaviour, proposes diagnostic deception, proves that a proposal
is safe, and preserves the resulting evidence—while candidate models learn in a
separate governed pipeline.

The installed product is not the dashboard. The product is the node runtime,
collectors, model service, Safety Kernel, evidence store and deception fabric.
The dashboard is the analyst's window into those services.

## 2. What is active today

| Component | v1.0 truth state | Meaning |
| --- | --- | --- |
| Local node heartbeat | Active and real | Reads this host's OS, architecture, CPU, memory, storage and process uptime |
| Host-health telemetry | Active and real | Periodically stores a coarse local resource envelope |
| Runtime integrity | Active and real | Hashes critical AEGIS assets into one aggregate manifest |
| Durable telemetry spool | Active and real | Deduplicates observations and records isolated collector runs in local SQLite |
| Windows Event Log | Implemented; host-dependent | Reads eight selected event IDs when running on Windows with sufficient permission; fixture-tested, not yet enterprise-qualified |
| Windows Service host | Implemented; unsigned | Runs the resident node through the Service Control Manager; production signing and Windows qualification remain open |
| Event contract | Active | Accepts normalized `SecurityEvent` records |
| Threat scenarios | Synthetic | Safe authorized-range event sequences only |
| Bayesian belief update | Active | Revises four competing intent hypotheses after each event |
| Multi-model benchmark | Active | Trains and evaluates three complementary classifiers plus a fusion ablation |
| Continual-learning gate | Active | Produces `HOLD_SHADOW`; cannot self-promote a candidate |
| Campaign linkage | Active research model | Links cases probabilistically; never identifies a person |
| Threat Trace | Active research model | Links sessions across rotating/shared source context using six evidence families, explicit alternatives and a manifested activity graph |
| Evidence Gateway | Active offline importer | Previews and explicitly commits minimized Suricata EVE or Zeek connection observations; no live sensor connection or automatic case promotion |
| Campaign Graph Guard | Active synthetic research | Tests all held-out pairs, rejects unsupported transitive bridges and preserves activity-only clusters; shadow-only |
| Diagnostic Steering | Active synthetic research | Selects the highest-value safe decoy probe, verifies it before observation, updates beliefs and compares four policies on a held-out family; shadow-only |
| Artifact Governance | Active local integrity layer | Registers ten dataset/model/policy descriptors, verifies lineage and appends hash-linked promotion evidence; not external code signing |
| Evidence ledger | Active | Hash-chains every event and verifies integrity |
| Safety Kernel | Active | Produces deterministic `PERMIT` or `DENY` certificates |
| Decoy deployment | Simulated | Asset state and control contracts exist; deployable images do not |
| Hardware enforcement | Simulated | State machine and receipts exist; packet effects remain zero |
| ETW/WFP/eBPF | Adapter contract | Explicitly not reported as active; Windows Event Log collection is not ETW |

## 3. Event and evidence flow

1. A sensor emits a normalized event with a case, actor, target, type, timestamp
   and structured payload.
2. The store appends the event to SQLite and includes the previous event hash in
   the new digest.
3. The Belief Engine updates a distribution over Reconnaissance, Credential
   Access, Lateral Movement and Collection.
4. Investigation logic attaches ATT&CK behaviours and compares case features.
5. A model may propose a diagnostic decoy action.
6. The Safety Kernel checks eight non-negotiable invariants.
7. Only a `PERMIT` certificate may cross into a future deployment adapter.
8. The result returns through the same event and evidence contracts.

The model is intentionally not the final authority. This separation protects the
system when a model is wrong, poisoned, compromised or simply uncertain.

## 4. How the resident telemetry plane works

The endpoint runtime and the investigation simulator use different records on
purpose. `TelemetryObservation` represents something the local node actually
measured. `SecurityEvent` represents normalized evidence assigned to an
investigation case. Keeping them separate prevents an operating-system event
from silently becoming an accusation or model label.

Every 10–3,600 seconds, the scheduler runs each collector independently:

1. Host health samples local CPU-count, memory, storage, platform and runtime
   uptime without enumerating user documents or processes.
2. Runtime integrity hashes up to 128 AEGIS source/interface files and stores an
   aggregate SHA-256 manifest—not file contents.
3. On Windows, `wevtutil` queries a ten-minute lookback for selected event IDs.
   The process uses an argument list, no shell, a twelve-second timeout and a
   maximum of 64 events per channel by default.
4. An allowlist retains only the event identifier, channel, provider, record ID,
   safe status fields, process basename and pseudonymous references.
5. HMAC-SHA-256 transforms usernames, IP addresses, workstation names and
   service names before storage using a random key held beside the local database.
6. A canonical digest deduplicates events when periodic lookback windows overlap.
7. Collector status, latency, observed count and insert count are stored as a
   run record. One failed collector does not kill the resident node.

Selected Windows events are authentication success/failure (4624/4625), process
creation (4688), audit-policy change (4719), account creation (4720), account
lockout (4740), audit-log clearing (1102), and service installation (7045). These
signals are useful for authorized endpoint investigation, but none identifies a
criminal. AEGIS still needs corroborated case evidence and lawful investigative
process before any attribution.

The v1.0 telemetry and gateway planes have no outbound transport. Raw command lines, raw
usernames and raw IP addresses are never stored. This data minimization improves
privacy but creates a deliberate tradeoff: an analyst cannot reconstruct every
forensic detail from AEGIS alone. Enterprise deployment should integrate an
approved evidence-retention system under its own access and custody rules.

### Offline sensor evidence gateway

The v0.7 Evidence Gateway introduces an explicit airlock for selected Suricata
EVE and Zeek connection JSON. It validates bounded records, pseudonymizes raw
endpoints and sensitive linkage values in memory, buckets byte counts, discards
packet/application content, shows a safe preview, and requires a second commit
operation. The original record is never written to AEGIS storage.

Committed records remain `TelemetryObservation` values. They do not silently
become `SecurityEvent` case evidence or labels. This keeps sensor ingestion,
investigative judgment and model governance as distinct trust decisions. The
full field contract and workflow are in `docs/EVIDENCE_GATEWAY_GUIDE.md`.

## 5. Why AEGIS uses multiple models

Different models capture different evidence. Combining them is useful only when
an ablation proves that the added complexity improves the chosen objective.

### Implemented research learners

| Model | Feature view | Strength | Known limitation |
| --- | --- | --- | --- |
| Sequence n-gram NB | Events, adjacent transitions and length | Preserves local order and is easy to inspect | Repeated/noisy tokens can dominate |
| Event-set NB | Unique observed event types | Robust to harmless repetition and small reorderings | Discards order |
| Relative-position NB | Event plus coarse position | Tests whether early/late placement matters | Sensitive to route-family shift |
| Probability fusion | Validation-selected weighted probabilities | Can use complementary uncertainty | More models did not beat the best single candidate on every metric |

All learners use the same 144/48/48 family-grouped train/validation/test split.
No scenario family appears in more than one partition.

### Current reproducible result

| Model | Held-out macro-F1 | Held-out Brier | Status |
| --- | ---: | ---: | --- |
| Sequence champion | 0.854 | 0.210 | Active research baseline |
| Event-set candidate | 0.937 | 0.086 | Shadow candidate |
| Position model | 0.854 | 0.209 | Evaluated |
| Fusion ablation | 0.937 | 0.108 | Ablation only |

These are synthetic-corpus results for seed `26082026`. They validate the
research machinery; they do not estimate enterprise detection performance.

The useful negative result is that fusion matched the candidate's macro-F1 but
had worse probability error. AEGIS therefore retains the simpler event-set model
as the primary challenger instead of claiming that an ensemble is automatically
better.

### The v0.6 activity-linkage experiment

Threat Trace adds a separate binary pair experiment. It compares source-only,
single-profile, fixed evidence-diversity and learned logistic linkers on 240
balanced pairs split by complete environment family. The source-only baseline
has test F1 0.286 and false-link rate 1.000 on the deliberately difficult
synthetic family. The diversity-feature logistic candidate reaches F1 0.979,
Brier 0.041 and false-link rate 0.000. Both results are properties of the seeded
synthetic corpus, not Internet or enterprise estimates.

The scientific lesson is not “the model finds criminals.” It is that an
address-like reference is a weak, shareable observation, while diverse evidence
can support an activity relationship. Every result keeps alternative
explanations and `identity_claim: false`. See `docs/THREAT_TRACE_GUIDE.md` for
the full contract, equations, experiment and investigator workflow.

### The v0.8 transitivity-safe graph experiment

A good pair model is not automatically a safe graph model. Ordinary connected
components treat “A resembles B” and “B resembles C” as permission to merge all
three, even when A and C contradict one another. One false edge can therefore
contaminate an entire activity cluster.

Graph Lab trains the existing diversity-feature edge model on the 144 balanced
family 0–2 pairs, tunes it and the merge guard on all 1,128 family 3 pairs, and
evaluates all 1,128 family 4 pairs. A seven-edge stress chain joins all eight
synthetic campaigns. Naive closure collapses the 48-node graph into one cluster
(B³-F1 0.222; false-merge rate 0.894). The cohort-supported guard requires
evidence diversity, a high-confidence seed, agreement across cross-cluster
pairs and a size cap; it rejects all seven bridges and returns eight six-node
cohorts (B³-F1 1.000; false-merge rate 0.000).

These numbers describe one deterministic synthetic stress protocol. They do
not prove enterprise performance or identify anyone. The graph candidate stays
`HOLD_SHADOW`. See `docs/GRAPH_RESEARCH_GUIDE.md` for the split, metrics,
algorithm, limitations and reproduction path.

### The v1.0 diagnostic-steering experiment

Diagnostic steering turns “adaptive deception” into a measurable question:
which permitted synthetic interaction should AEGIS present next if the objective
is to reduce uncertainty between four intent hypotheses? For every candidate,
the controller computes expected entropy reduction, subtracts a small declared
cost penalty, and selects the best probe. The selected action then passes through
the same eight-invariant Safety Kernel used elsewhere. Only a `PERMIT` allows a
synthetic outcome to exist and update the posterior.

The experiment compares static, seeded-random, leading-intent rule and EIG
policies on 480 episodes each. Family 4—96 episodes per policy—is held out. The
EIG policy reaches correct confidence ≥ 0.86 in 0.5938 of held-out episodes,
versus 0.1875 for static, and saves 1.3021 penalized interactions. Wrong high
confidence is 0.0313 and unsafe acceptances are zero. The expert rule's wrong-
confidence rate is 0.1042, showing why “more decisive” is not automatically
safer. All values come from a declared synthetic likelihood model and cannot be
read as live attacker accuracy. See `docs/DIAGNOSTIC_STEERING_GUIDE.md`.

### The v1.0 artifact and promotion ledger

AEGIS now materializes four synthetic datasets, five evaluated model/decision-policy descriptors and
Safety Kernel policy as immutable descriptor records. SHA-256 binds canonical
content; explicit parent IDs bind model-to-dataset lineage; a separate local
key creates HMAC-SHA256 attestations. SQL triggers refuse record update/delete.

A candidate evaluation appends its quality and release checks to a hash-linked
promotion ledger. Offline quality may pass, but enterprise validation, 10,000
authorized shadow observations, an offline named-reviewer signature and a
rollback artifact remain missing. Browser/API attempts to submit those values
are ignored and recorded. The candidate therefore remains `HOLD_SHADOW`, and no
path replaces deployed weights. HMAC proves only local integrity/authenticity;
it is not organization code signing or non-repudiation. See
`docs/MODEL_GOVERNANCE_GUIDE.md`.

## 6. What self-learning means here

AEGIS already updates beliefs online, but it does not rewrite model weights from
every live event. Safe self-learning is governed continual learning:

1. **Observe:** collect versioned telemetry, labels and analyst feedback.
2. **Train:** build a candidate outside the enforcement path.
3. **Validate:** test grouped generalization, calibration, poisoning, evasion,
   drift, resource cost and safety regressions.
4. **Shadow:** let the candidate predict without controlling decisions.
5. **Approve:** require a named reviewer, signed artifact and rollback package.
6. **Canary:** expose a small authorized scope and monitor defined failure gates.
7. **Promote or roll back:** change the champion only through the registry.

The current candidates pass selected offline quality gates but fail production
release gates by design: no authorized enterprise validation, zero trusted
shadow observations, no offline reviewer signature and no registered rollback
artifact. Their correct state is therefore `HOLD_SHADOW`.

## 7. Planned deep-learning roles

Deep learning is introduced after the data contract and baseline are strong
enough to make the comparison meaningful.

| Candidate | Job | Minimum evidence before implementation |
| --- | --- | --- |
| Temporal Transformer/TCN | Long-range event-sequence reasoning | Larger multi-environment sequence corpus and temporal external validation |
| Temporal GNN | Host, session and campaign relationships | Versioned graph schema, negative edges and time-aware labels |
| Novelty autoencoder | Unknown behaviour and drift | Large benign baseline with seasonality and admin hard negatives |
| Constrained contextual bandit | Select diagnostic decoy actions | Simulator with action cost, information gain and safety outcomes |
| Language model | Evidence-grounded explanation and synthetic artifact proposals | Retrieval grounding, prompt-injection suite and an actuation prohibition |

Large training runs may use approved external accelerators. Deployment artifacts
should be distilled, quantized or exported to an efficient local runtime. The
scientific design is not limited by the development laptop; endpoint latency,
memory and failure isolation still remain product requirements.

## 8. Code map

| File | Responsibility |
| --- | --- |
| `aegis/models.py` | Versioned telemetry, event and proposed-action records |
| `aegis/store.py` | SQLite cases, events, telemetry, collector runs, certificates and evidence access |
| `aegis/belief.py` | Online probabilistic intent update |
| `aegis/research.py` | Synthetic corpus, calibrated baseline and metrics |
| `aegis/learning.py` | Multi-model ablation and promotion-gate report |
| `aegis/investigation.py` | ATT&CK mapping, linkage and case bundles |
| `aegis/trace.py` | Raw-IP-refusing, evidence-diverse activity profiles, linkage graph and manifested trace report |
| `aegis/trace_research.py` | Grouped synthetic pair corpus, baselines, logistic candidate and calibration metrics |
| `aegis/trace_graph_research.py` | All-pairs clustering, graph baselines, cohort merge guard, bridge stress audit and B³ metrics |
| `aegis/sensor_gateway.py` | Strict Suricata/Zeek normalization, pseudonymization, preview/commit and import manifests |
| `aegis/registry.py` | Immutable artifact identity, lineage, local attestation, release gates and promotion-chain verification |
| `aegis/steering_research.py` | Bayesian posterior update, expected-information-gain selection, safety-gated simulator and four-policy experiment |
| `aegis/safety.py` | Deterministic eight-invariant Safety Kernel |
| `aegis/access.py` | Server-assigned operator roles, scopes and per-route mutation contracts |
| `aegis/licensing.py` | Canonical offline Ed25519 license-envelope verification and fail-closed states |
| `aegis/audit.py` | Two-stage command receipts and per-install HMAC-SHA256 chain verification |
| `aegis/agent.py` | Real local heartbeat and honest collector registry |
| `aegis/telemetry.py` | Passive collectors, local pseudonymization, deduplication and scheduler |
| `aegis/hardware.py` | Zero-packet-effect hardware enforcement simulation |
| `aegis/service.py` | Product orchestration |
| `aegis/server.py` | Local API and analyst-console host |
| `aegis/runtime.py` | Resident service/API lifecycle and orderly shutdown |
| `aegis/windows_service.py` | Windows Service Control Manager entry point |
| `aegis/desktop.py` | Native window, resident-service discovery, embedded-runtime lifecycle and desktop security controls |
| `install/` | Reversible Research Edition Windows install/uninstall scripts |
| `packaging/windows/` | Reproducible `AEGIS.exe`/`AEGISNode.exe` build and native installer inputs |
| `tools/license_authority.py` | Offline encrypted key generation, license issuance and independent verification |
| `web/` | Sixteen-workspace analyst interface |

## 9. Reproduce the milestone

From the `aegis-platform` directory:

```bash
python -m unittest discover -s tests -v
python -m aegis.server --port 8765
```

The suite currently contains 88 tests. To exercise the resident lifecycle in a
terminal without installing a service:

```bash
python -m aegis.windows_service --console --port 8765
```

Install the desktop extra and run `python -m aegis.desktop`, then inspect:

- **Learning Fabric:** compare models and run the promotion gate.
- **Threat Trace:** inspect rotated source context, evidence diversity,
  alternatives and the source-only versus multi-signal experiment.
- **Graph Lab:** reproduce the bridge-chain stress protocol, inspect each
  rejected merge and compare cluster-level failure metrics.
- **Steering Lab:** reproduce the held-out four-policy protocol, compare wrong
  confidence and interaction cost, and audit verify-before-observe updates.
- **Governance Ledger:** inspect artifact lineage, verify local attestations,
  evaluate a shadow candidate and verify the promotion chain.
- **Access & Audit:** inspect effective license entitlements, operator scope and
  paired preflight/outcome receipts, then verify the complete command chain.
- **Telemetry Nexus:** run a collection cycle and inspect the privacy envelope.
- **Evidence Gateway:** preview a safe sensor batch before explicitly committing
  only its minimized observations.
- **Enforcement & Trust:** test one compliant and one forbidden action.
- **System & Agents:** distinguish active collectors from planned adapters.
- **Evidence Vault:** verify and export a manifested synthetic case.

## 10. Next engineering milestones

1. Build and validate v1.2 on an isolated Windows machine, verify service/data
   ACLs and code-sign the installer/runtime.
2. Bind local roles to Windows-integrated or OIDC identity with expiry,
   revocation, named-user evidence and read-route authorization; embed the vendor
   license root in the signed executable and add offline revocation/rotation.
3. Package the same resident contract as a hardened Linux daemon, then implement
   a read-only eBPF/audit adapter only after permissions and privacy review.
4. Add an explicit, analyst-governed correlation pipeline from selected endpoint
   observations to case evidence; never turn raw telemetry into identity claims.
5. Build a larger benign-plus-attack range corpus with provenance and hard
   negatives.
6. Replace/wrap local HMAC attestations and audit heads with organization
   signatures, remote append-only anchoring, hardware-backed keys, trusted time
   and an offline reviewer workflow.
7. Implement one temporal neural candidate and run a complete ablation against
   all v0.4 baselines.
8. Build isolated SSH/HTTP deception nodes with egress denial and short TTLs.
9. Run adversarial poisoning, drift, prompt-injection and policy-bypass suites.
10. Conduct an external authorized pilot only after the safety and privacy review.

## 11. Rules that must never be weakened

- No external scanning, exploitation or hack-back.
- No person/state attribution from behavioural similarity alone.
- No model-to-actuator path that bypasses the Safety Kernel.
- No hidden live retraining from attacker-controlled input.
- No real credentials or production records inside generated decoys.
- No claim of patent novelty until a documented professional prior-art review.
- No claim of enterprise accuracy until independently validated enterprise data
  and deployment conditions exist.
