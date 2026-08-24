# AEGIS Changelog

## Repository foundation — post-1.2 checkpoint

- Established the private GitHub repository as the canonical source ledger.
- Added ownership, contribution, security, conduct, roadmap and citation files.
- Added structured defect, product-capability and pre-registered research issue
  forms plus an evidence-led pull-request template.
- Added pinned, least-privilege CI for Python 3.10–3.13, UI structure, Python/JS
  syntax, release-version consistency and repository confidentiality checks.
- Added weekly grouped dependency maintenance for Python and GitHub Actions.
- Added explicit governance and patent-sensitive disclosure controls. The
  repository remains private; this checkpoint does not authorize publication.

## 1.2.0 — Enterprise Control Boundary

- Added the strict `AEGIS-LICENSE-1` offline envelope with canonical JSON,
  Ed25519 signatures, public-key identity, bounded claims, time-window checks,
  explicit entitlements and distinct Research/valid/locked states.
- Added an offline authority utility for encrypted Ed25519 key generation,
  license issuance and independent verification. The endpoint bundle never
  contains the private signing key.
- Added monotonic viewer, analyst and administrator roles. Roles are assigned by
  the local host rather than trusted from a request header, and session tokens
  are represented only by pseudonymous references outside memory.
- Added an explicit route contract connecting every mutation to a required role
  scope and commercial/research entitlement. License reload remains an admin-
  only recovery operation even when other entitlements are locked.
- Added fail-closed mutation preflight: commands do not reach a route unless an
  `ACCEPTED` audit receipt is durably sealed first.
- Added paired `COMPLETED`/`FAILED` receipts, a per-install HMAC-SHA256 hash
  chain, canonical-record/column verification, request-digest-only retention,
  key identity and append-only SQLite update/delete triggers.
- Added mutation lockout when an existing audit journal loses or corrupts its
  key; AEGIS does not silently start a replacement chain.
- Added the sixteenth analyst workspace, Access & Audit, with live license,
  entitlement, operator, route-contract and command-chain evidence.
- Hardened the Windows installer data-root ACL and added optional paired license
  and public-key installation parameters.
- Added the Access/Audit Guide and offline License Authority Runbook.
- Expanded the complete suite from 74 to 88 tests, including adversarial
  tampering, role-separation, entitlement and audit-key-loss cases.

Boundaries retained: local HMAC is not external non-repudiation, trusted time or
WORM storage. The external public-key file is an administrator-protected
prototype trust anchor, not embedded vendor DRM. Enterprise IAM, revocation,
HSM/TPM custody, code signing and Windows qualification remain required. No
license or role can bypass the Safety Kernel, authorize external targeting,
enable hack-back, promote a model automatically or infer a criminal identity.

## 1.1.0 — Native Windows Desktop Foundation

- Replaced the browser-launch workflow with `aegis.desktop`, which presents the
  complete analyst console inside a dedicated native WebView2 window with no
  browser chrome, public listener or internet dependency.
- Added automatic attachment to a matching `AEGISNode` resident service and a
  portable fallback that owns an ephemeral loopback runtime for the lifetime of
  the desktop window.
- Added a per-session mutation token, loopback Host validation, same-origin
  isolation headers, private WebView storage, disabled downloads, disabled
  external navigation and clean close-time shutdown.
- Added reproducible PyInstaller specifications for `AEGIS.exe` and the
  always-on `AEGISNode.exe` service, with Windows version metadata and pinned
  packaging dependencies.
- Added a one-click Windows builder that runs the full suite, packages both
  executables, smoke-tests the frozen desktop runtime, creates an installable
  bundle and records its SHA-256 digest.
- Added a UAC installer with delayed-auto-start service registration, bounded
  recovery, per-install token creation, ACL application, Start-menu integration
  and health verification, plus a data-preserving uninstaller.
- Added a Windows CI build workflow and Desktop Product Guide.
- Expanded the complete suite from 68 to 74 tests.

Boundaries retained: the current deliverable is an unsigned research build.
Packaging does not establish production security, enterprise performance,
code-signing trust, Windows qualification, patentability, human attribution or
authorization for external pursuit or hack-back.

## 1.0.0 — Safety-Gated Diagnostic Steering

- Added a Bayesian expected-information-gain controller that selects among four
  equal-contract synthetic decoy probes under a bounded cost penalty.
- Added a mandatory execution order in which every selected probe becomes a
  complete proposed action and must receive a Safety Kernel `PERMIT` before an
  outcome can exist or update the posterior.
- Added a deterministic corpus of five environment families, four intent
  hypotheses and 24 variants per intent/family: 480 episodes per policy, with
  all 96 family-4 episodes reserved for held-out evaluation.
- Added static, seeded-random and leading-intent expert baselines. On the seeded
  held-out family, the EIG policy reaches correct confidence ≥ 0.86 in 59.38%
  of episodes versus 18.75% for static selection, saves 1.30 penalized
  interactions and lowers final entropy by 0.387 bits.
- Added Brier, calibration, entropy, cost, abstention, wrong-confidence,
  interaction-interval, action-distribution and safety measurements. The expert
  rule's 10.42% wrong-confidence rate is retained as a negative result.
- Registered the diagnostic corpus and EIG decision policy with dataset and
  Safety-Kernel lineage, increasing the built-in registry to ten artifacts.
- Added Steering Lab as the fifteenth analyst workspace, plus cached read/rerun
  APIs and a dedicated diagnostic-steering technical guide.
- Expanded the complete suite from 60 to 68 tests.

Boundaries retained: the result is a deterministic synthetic research
checkpoint; the likelihoods, costs, labels and family shifts are design
assumptions. The policy is `HOLD_SHADOW`; there is no external target, person or
state attribution, protected-data access, hack-back, packet effect, automatic
promotion, enterprise-accuracy claim or patentability claim.

## 0.9.0 — Attested Artifact Governance

- Added an immutable registry for dataset, model, policy, evaluator and rollback
  descriptors with content digests, lineage and per-install HMAC-SHA256
  attestations.
- Materialized three deterministic research datasets, four evaluated models and
  the Safety Kernel policy as eight linked built-in artifacts.
- Added SQL triggers that reject artifact or promotion-record update/delete
  operations instead of silently relying on interface convention.
- Added a hash-linked, locally attested promotion ledger with complete gate
  evidence, candidate/champion identities and tamper verification.
- Added a candidate evaluator that separates quality gates from production
  release evidence. The loopback API cannot create enterprise validation,
  shadow volume, reviewer sign-off, rollback readiness or promotion authority.
- Added Governance Ledger APIs and a fourteenth analyst workspace with artifact
  inventory, attestation scope, candidate selection, gate evidence, chain
  verification and decision history.
- Added a Model Governance Guide and expanded the suite from 52 to 60 tests.

Boundaries retained: HMAC is a per-install integrity/authenticity mechanism—not
an external digital signature, trusted timestamp or non-repudiation proof. The
Research Edition is unsigned, candidates remain `HOLD_SHADOW`, no model can
self-promote or actuate, and production requires platform code signing,
organization signatures, reviewer workflow and a registered rollback artifact.

## 0.8.0 — Transitivity-Safe Campaign Graph

- Added a deterministic all-pairs campaign-clustering protocol with grouped
  training, validation and held-out environment families.
- Added B³, pairwise, purity, false-merge, split-campaign and largest-cluster
  measurements with a manifested dataset and deterministic run identifier.
- Added source-reference and naive learned-edge connected-component baselines.
- Added a cohort-supported merge guard requiring evidence diversity,
  validation-selected seed/association thresholds, cross-cluster support and a
  maximum cluster size before accepting transitive closure.
- Added a seven-edge adversarial bridge chain. Naive closure merges all 48
  held-out sessions; the shadow guard rejects every injected bridge and
  recovers eight synthetic campaign cohorts with zero false merges.
- Added Graph Lab as the thirteenth analyst workspace and exposed reproducible
  graph experiment APIs, merge audit, method comparison and cluster output.
- Added a Graph Research Guide and expanded the suite from 45 to 52 tests.

Boundaries retained: the result is deterministic and synthetic, the graph
contains activity sessions rather than entities, the candidate remains in
`HOLD_SHADOW`, and there is no raw IP, person label, automatic attribution,
external target, outbound pursuit, hack-back or packet effect.

## 0.7.0 — Privacy-Bounded Evidence Gateway

- Added strict offline import adapters for selected Suricata EVE JSON and Zeek
  `conn.log` JSON fields.
- Added in-memory validation, per-install HMAC pseudonymization, byte bucketing,
  raw-endpoint/content refusal and record/request limits.
- Added separate preview and commit operations, safe per-record disposition,
  import manifests and telemetry deduplication.
- Added a hard boundary preventing imported network evidence from automatically
  creating a case, training label, response or external connection.
- Added Evidence Gateway APIs and a twelfth analyst workspace with local-file
  loading, connector contracts, privacy airlock and normalized-output inspection.
- Added an Evidence Gateway guide and expanded the suite from 38 to 45 tests.

Boundaries retained: adapters are fixture-tested offline importers, not certified
live integrations; no raw IP/domain/content persistence, sensor control,
automatic accusation, outbound transport, hack-back or packet enforcement.

## 0.6.0 — Evidence-Diverse Threat Trace

- Added `aegis.threat-trace.v1`, which refuses raw IP literals and links
  authorized activity across six reliability/spoofability-aware evidence
  families.
- Added diversity gates, contradiction penalties, calibration metadata,
  alternative explanations, an activity graph, cross-session timeline and a
  manifested JSON trace with `identity_claim: false`.
- Added a deterministic grouped corpus of 240 sessions and 240 balanced pairs,
  including rotating-source positives and shared-infrastructure hard negatives.
- Added source-only, single-profile and fixed-fusion baselines plus a learned
  logistic shadow candidate. The current synthetic held-out result is F1 0.979;
  the candidate remains `HOLD_SHADOW`.
- Added Threat Trace APIs and an eleventh premium analyst workspace with graph,
  signal contribution, alternatives, timeline, experiment comparison and trace
  export.
- Added a dedicated Threat Trace learning/research guide and updated the paper,
  architecture and invention records.
- Expanded the suite from 29 to 38 passing tests.

Boundaries retained: activity linkage is not human identity; no raw IP storage,
outbound pursuit, external scanning, geolocation claim, hack-back, packet effect
or patentability claim.

## 0.5.0 — Resident Signal Plane

- Added a durable local telemetry store, collector-run ledger and bounded
  background scheduler.
- Added real host-health sampling and a SHA-256 runtime-integrity manifest.
- Added a privacy-bounded Windows Event Log collector for selected Security and
  System event IDs. Identifiers are HMAC-pseudonymized before storage; raw
  command lines and all non-allowlisted fields are discarded.
- Added overlap-safe telemetry deduplication, status/event APIs and manual
  collection.
- Added a resident control-plane lifecycle and a native Windows Service host
  using the Windows Service Control Manager contract.
- Added reversible PowerShell installation and uninstallation scripts. The
  Research Edition remains unsigned and is not represented as production-ready.
- Expanded the analyst application to ten workspaces with Telemetry Nexus,
  collector execution, privacy envelope and live signal-stream views.
- Expanded the automated suite from 21 to 29 passing tests.

Boundaries retained: no outbound telemetry, no raw usernames/IP addresses or
command lines in the telemetry store, no external targets, no hack-back, no
human attribution, no packet effects, and no patentability claim.

## 0.4.0 — Governed Learning Fabric

- Added a real passive local-node runtime with host heartbeat and resource
  envelope reporting.
- Added an honest collector registry distinguishing active, adapter-ready,
  simulated, disabled and non-applicable capabilities.
- Added three complementary calibrated intent learners and a probability-fusion
  ablation under one family-grouped research protocol.
- Added a continual-learning promotion gate. The current candidate remains in
  `HOLD_SHADOW`; model weights cannot self-promote.
- Added `/api/models/fabric`, `/api/models/fabric/evaluate`, and
  `/api/system/agents`.
- Expanded the analyst application to nine workspaces, including Learning
  Fabric and System & Agents.
- Reframed Policy Centre as Enforcement & Trust so the Safety Kernel's purpose,
  certificates and deny path are explicit.
- Reworked the interface toward an obsidian, restrained enterprise visual
  system with reduced neon and denser operational information.
- Added the living Learning Guide and Research and Invention Register.
- Expanded the automated suite from 16 to 21 passing tests.

Boundaries retained: synthetic threat scenarios, no external targets, no
hack-back, no human attribution, no packet effects, and no patentability claim.

## 0.3.0 — Research Vertical Slice

- Added calibrated intent baseline, campaign linkage, case export, model
  observatory and the zero-packet-effect Hardware Enforcement Profile.
