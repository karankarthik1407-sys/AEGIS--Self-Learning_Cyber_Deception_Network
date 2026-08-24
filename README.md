# AEGIS

AEGIS is a local-first defensive cyber-deception, investigation and governed-learning platform.
The v1.2 Desktop Research Edition implements a safe end-to-end vertical slice:
normalized synthetic telemetry, uncertainty-calibrated intent beliefs,
behavioural campaign linkage, a hash-chained evidence ledger, a deterministic
action-safety gate, a reproducible multi-model intent benchmark, a continual-
learning promotion gate, a resident endpoint runtime, real host-health and
runtime-integrity telemetry, a privacy-bounded Windows Event Log collector, a
future hardware-enforcement protocol simulator, an evidence-diverse Threat Trace
engine with a grouped source-only versus multi-signal experiment, a privacy-bounded
Suricata/Zeek Evidence Gateway, a transitivity-safe campaign-graph research
layer, an attested artifact/promotion ledger, a safety-gated expected-information-
gain steering experiment, signed offline commercial-entitlement verification,
server-assigned operator roles, a tamper-evident command journal, a sixteen-
workspace analyst console, a native Windows desktop host, and a reproducible
dual-executable packaging path.

The threat and enforcement paths remain deliberately defensive and simulation-
only. The endpoint health and integrity observations are real. On Windows, the
resident collector queries an allowlist of Security/System events when the
service account has permission. AEGIS does not
scan external systems, deploy malware, identify a human from a model score, or
permit hack-back. Its host heartbeat and resource readings are real; the threat
scenarios, deception nodes and enforcement effects remain synthetic in this
release. AEGIS correlates authorized-range activity to help an investigator
form and test hypotheses; real-world attribution requires independently verified
technical, legal, and contextual evidence.

## Application boundary

AEGIS is not a hosted website. Version 1.2 opens the analyst console inside the
native `AEGIS.exe` window using the Windows WebView2 component; there is no
browser tab, address bar, public listener or internet dependency. `AEGIS.exe`
attaches to the `AEGISNode` delayed-auto-start Windows Service when installed,
or starts an isolated window-owned runtime for portable use. The service keeps
collecting after the desktop window closes. Both paths bind only to loopback,
and mutating desktop requests require a per-install session token. Every
mutation must also satisfy a server-assigned role, route entitlement and audit
preflight; accepted and completed/failed receipts are HMAC-linked in an
append-only local journal.

This Research Edition is unsigned. Production still requires organization code
signing, hardened identity and ACLs, a signed upgrade channel, SBOM and
independent Windows deployment validation.

## Run the desktop application from source

The research engine remains standard-library Python. The native window adds the
pinned `pywebview` desktop dependency:

```powershell
py -3 -m pip install -e ".[desktop]"
py -3 -m aegis.desktop
```

After installing the desktop extra, Windows users can double-click
`START_AEGIS.bat`.

## Build AEGIS.exe

On Windows, double-click `BUILD_AEGIS_EXE.bat`. The builder executes all tests,
packages `AEGIS.exe` and `AEGISNode.exe`, runs a packaged-runtime smoke check,
and produces a ZIP and SHA-256 checksum under `release`.

The low-level browser-accessible server remains available only for development
and automated testing:

```bash
python -m aegis.server --port 8765
```

The SQLite database remains local. The desktop build stores data in the user or
machine AEGIS data directory rather than beside the executable.

The generated package contains `INSTALL_AEGIS.bat`, which installs the resident
service and Start-menu application after an administrator approval. Source-mode
service installation remains available for development:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install\Install-AEGIS.ps1
```

The service listens only on `127.0.0.1` by default and stores its database and
per-install pseudonymization and registry-attestation keys under
`%ProgramData%\AEGIS`. See
`docs/ENDPOINT_DEPLOYMENT.md` before installation.

## Verify

```bash
python -m unittest discover -s tests -v
```

The repository also carries dependency-free contract checks used by GitHub CI:

```bash
python tools/ci/check_repository_hygiene.py
python tools/ci/check_version_contract.py
python tools/ci/check_ui_contract.py
```

## Repository workflow

The canonical repository is private while patent-sensitive research is under
development. Normal work uses a focused branch and pull request; `main` is the
reviewable release line. CI runs the full unit suite on Python 3.10–3.13 and
checks repository confidentiality, release-version consistency, Python/JS
syntax and the bundled sixteen-workspace UI contract.

See `CONTRIBUTING.md`, `SECURITY.md`, `ROADMAP.md`,
`docs/GITHUB_GOVERNANCE.md` and `docs/IP_DISCLOSURE_POLICY.md` before changing,
sharing or publishing the project. Public disclosure is a separate decision
and is not authorized by possession of this repository.

## Research documentation

- `docs/LEARNING_GUIDE.md` — concepts, models, telemetry, code map and next work
- `docs/ARCHITECTURE.md` — contracts, trust boundaries and deployment shapes
- `docs/ENDPOINT_DEPLOYMENT.md` — resident collector, privacy and service guide
- `docs/PAPER_BLUEPRINT.md` — falsifiable thesis, RQs, experiments and paper plan
- `docs/THREAT_TRACE_GUIDE.md` — IP-versus-identity boundary, signal fusion,
  experiment, investigator workflow and enterprise adapters
- `docs/EVIDENCE_GATEWAY_GUIDE.md` — Suricata/Zeek schemas, minimization,
  preview/commit workflow, provenance, limits and validation boundary
- `docs/GRAPH_RESEARCH_GUIDE.md` — clustering protocol, B³ metrics, adversarial
  bridge-chain experiment, merge guard and non-attribution boundary
- `docs/MODEL_GOVERNANCE_GUIDE.md` — immutable artifact identities, local
  attestations, lineage, promotion chain and production signing gap
- `docs/DIAGNOSTIC_STEERING_GUIDE.md` — Bayesian steering objective, Safety
  Kernel order, four-policy experiment, results, limitations and prior-art gate
- `docs/PRELIMINARY_PRIOR_ART_MATRIX.md` — non-exhaustive limitation/reference
  map, crowding risks and questions for professional claim-chart review
- `docs/PAPER_DRAFT_v1.0.md` — internal full paper draft with implemented method,
  preliminary results, limitations and external-validation requirements
- `docs/RESEARCH_IP_REGISTER.md` — confidential invention candidates, evidence
  ledger, disclosure control and claim boundaries
- `docs/DESKTOP_PRODUCT_GUIDE.md` — native process topology, Windows build,
  installation, security controls and commercial-release gaps
- `docs/ACCESS_AUDIT_GUIDE.md` — signed-license schema, roles, command decision
  order, audit chain, APIs, tests and production trust gaps
- `docs/LICENSE_AUTHORITY_RUNBOOK.md` — offline encrypted key generation,
  license issuance, verification, installation and rotation boundaries
- `docs/V1.2_VALIDATION_REPORT.md` — executed source/wheel/control checks and
  the exact remaining Windows acceptance procedure
- `docs/V1.1_VALIDATION_REPORT.md` — historical native-desktop checkpoint
- `docs/GITHUB_GOVERNANCE.md` — branch, review, CI and release rules
- `docs/IP_DISCLOSURE_POLICY.md` — confidential/patent-sensitive disclosure gate
- `ROADMAP.md` — completed checkpoint and ordered research/product milestones

## Investigation workspaces

- Mission Canvas — system state, topology, beliefs, policy, and evidence health
- Live Cases — switch between investigations and reconstruct event narratives
- Campaign Constellation — link related activity with explicit uncertainty
- Threat Trace — follow activity across rotated/shared source context using six
  evidence families, alternatives and a manifested non-identity graph
- Graph Lab — compare source-only, naive transitive and cohort-guarded campaign
  clustering under a reproducible adversarial bridge-chain stress test
- Steering Lab — compare static, random, expert-rule and expected-information-
  gain probe selection, then inspect every verified Bayesian update
- Deception Fabric — inspect isolated, synthetic assets and engagement state
- Evidence Vault — verify hash chains and export manifested case bundles
- Enforcement & Trust — inspect permit/deny certificates against eight invariants
- Research Lab — track baselines, experiments, tests, and external-target count
- Learning Fabric — compare complementary models, inspect promotion gates,
  calibration, failure structure, deep-learning candidates and hardware horizon
- Telemetry Nexus — inspect real local observations, collector executions,
  privacy controls, deduplication and resident-runtime state
- Evidence Gateway — preview and explicitly import minimized Suricata EVE or
  Zeek connection evidence without retaining raw endpoints or content
- Governance Ledger — verify dataset/model/policy attestations and lineage,
  inspect non-bypassable release gates and audit every promotion decision
- Access & Audit — inspect offline license verification, effective operator
  scopes, route contracts and the sealed preflight/outcome command chain
- System & Agents — inspect the real local heartbeat, resource envelope,
  collector truth state, and licensed deployment shapes

## What is real in v1.2.0

- A native `AEGIS.exe` window with no browser chrome or public web deployment
- A separately packaged `AEGISNode.exe` resident Windows Service executable
- Automatic desktop attachment to a matching installed resident service, with
  a safe embedded-runtime fallback for portable use
- Random loopback port selection for the portable runtime, strict loopback host
  checks, per-session mutation tokens, disabled downloads/external navigation,
  private WebView storage and orderly runtime shutdown
- Pinned Windows packaging inputs, executable version resources, an isolated
  one-click build, packaged-runtime smoke test, UAC installer, Start-menu
  shortcut, service recovery policy, release ZIP and SHA-256 checksum
- Canonical `AEGIS-LICENSE-1` envelopes with offline Ed25519 verification,
  strict claims, bounded validity, explicit entitlements and fail-closed handling
  for present-but-invalid licenses
- An offline authority utility that generates encrypted PKCS#8 Ed25519 private
  keys, issues signed envelopes and independently verifies delivery material;
  private keys are never packaged with endpoint executables
- Monotonic viewer/analyst/administrator scopes assigned by the local host,
  with no browser-controlled role header and no raw session-token persistence
- A two-stage command journal that seals `ACCEPTED` before route execution and
  `COMPLETED` or `FAILED` afterward using a per-install HMAC-SHA256 hash chain
- SQL-enforced append-only audit rows, full-chain verification, request-digest-
  only retention and mutation lockout if an existing journal loses its key

- Event ingestion into a versioned internal contract
- Bayesian intent-belief updates with explicit uncertainty
- Pairwise campaign linkage across ATT&CK techniques, sequence, target family,
  and pseudonymous fingerprint features
- A raw-IP-refusing Threat Trace contract with reliability/spoofability-weighted
  source, infrastructure, transport, tooling, behaviour and deception evidence;
  single-family evidence cannot create a high-confidence activity link
- A deterministic corpus of 240 synthetic sessions and 240 balanced trace pairs
  with rotating-source positives and shared-infrastructure hard negatives under
  a 144/48/48 environment-family-grouped split
- Four trace comparators. For seed `26082026`, source-only test F1 is 0.286
  with false-link rate 1.000, while the diversity-feature logistic shadow
  candidate reaches F1 0.979, Brier 0.041 and false-link rate 0.000. These are
  synthetic research results, not enterprise accuracy or human attribution.
- Strict offline Suricata EVE JSON and Zeek `conn.log` JSON adapters with
  record/count limits, timestamp validation, local HMAC pseudonymization,
  content discard, safe preview and explicit commit
- A manifested gateway import ledger and telemetry-level deduplication; imported
  observations cannot automatically create cases, labels or responses
- A deterministic campaign-graph corpus protocol: the pair model trains on 144
  balanced hard-negative pairs from environment families 0–2, calibration and
  merge-guard selection use all 1,128 pairs from family 3, and final evaluation
  uses all 1,128 pairs among 48 held-out sessions from family 4
- Source-reference connected components, naive learned-edge connected
  components and the AEGIS cohort-supported graph guard compared under the same
  held-out graph
- An adversarial bridge-chain stress protocol that injects seven locally
  plausible cross-campaign edges. For seed `26082026`, naive transitive closure
  collapses all 48 sessions into one cluster (B³-F1 0.222, false-merge rate
  0.894), while the shadow graph guard rejects all seven bridges and recovers
  eight six-session clusters (B³-F1 1.000, false-merge rate 0.000). These are
  synthetic stress results, not operational accuracy or attribution.
- A deterministic diagnostic-steering protocol with four intent hypotheses,
  four equal-contract probes, four policies, five environment families and 480
  episodes per policy. On 96 held-out family-4 episodes, the EIG shadow policy
  reaches correct posterior confidence ≥ 0.86 in 0.5938 of episodes versus
  0.1875 for static selection, saves 1.3021 penalized interactions, and records
  zero unsafe acceptances. These are synthetic results, not attacker-behaviour
  or enterprise-performance estimates.
- Every steering proposal is evaluated by the real eight-invariant Safety Kernel
  before an outcome can exist or enter the Bayesian update; the candidate still
  remains `HOLD_SHADOW` and cannot actuate a deployed system.
- An immutable artifact registry containing four manifested synthetic datasets,
  five evaluated model/decision-policy descriptors and the Safety Kernel policy, with
  SHA-256 identities, explicit lineage and per-install HMAC-SHA256 attestations
- SQL-enforced update/delete refusal for registry and promotion tables, plus a
  hash-linked decision chain that verifies previous hashes, record hashes,
  column consistency, key identity and local attestations
- A non-bypassable lifecycle evaluator that separates offline quality gates
  from enterprise validation, authorized shadow volume, offline named-reviewer
  sign-off and rollback evidence. Public API attempts to supply those trusted
  facts are ignored and recorded; candidates remain `HOLD_SHADOW`.
- An explicit trust statement: local HMAC is not external code signing, a
  public-key organization signature, a trusted timestamp or non-repudiation
  proof
- Per-case SHA-256 evidence chaining and integrity verification
- Manifested JSON case export with ATT&CK mappings and a non-attribution boundary
- Machine-readable safety certificates for proposed deception actions
- Safe permit and deliberate-deny demonstrations for the policy boundary
- Two synthetic authorized-range scenarios that can be replayed safely
- A deterministic corpus of 240 harmless event sequences across four intent
  hypotheses and twenty grouped scenario families
- Leakage-resistant train/validation/test partitions of 144/48/48 sequences
- A calibrated multinomial sequence baseline with accuracy 0.854, macro-F1
  0.854, multiclass Brier 0.210, and expected calibration error 0.094 on the
  held-out family split for seed `26082026`
- Three complementary calibrated intent learners: ordered n-gram, event-set,
  and relative-position views, plus a validation-selected probability-fusion
  ablation under exactly the same family-grouped split
- A shadow candidate with held-out macro-F1 0.937 and Brier 0.086 on the current
  synthetic corpus; these values are reproducible research results, not claims
  of live-enterprise performance
- A governed continual-learning decision that keeps the candidate in
  `HOLD_SHADOW` because production shadow volume and human release approval are
  intentionally unsatisfied; no endpoint can manufacture either condition
- A live local-node heartbeat with real OS, architecture, CPU, memory, storage,
  process uptime and collector-state reporting
- A durable local telemetry spool and bounded background collector scheduler
- Real host-health sampling and a SHA-256 runtime-integrity manifest
- A Windows Event Log collector for allowlisted event IDs 4624, 4625, 4688,
  4719, 4720, 4740, 1102 and 7045, using the operating system's `wevtutil`
  interface; identity fields are HMAC-pseudonymized before persistence and raw
  command lines are discarded
- Overlap-safe observation deduplication across periodic event-log windows
- A pure-Python Windows Service host plus reversible PowerShell install and
  uninstall scripts; the service implementation is fixture-tested but this
  release has not yet been signed or validated on a production Windows host
- A software-only Hardware Enforcement Profile state machine that verifies a
  Safety Gate certificate, stages an atomic rule manifest, models expiry
  rollback, and records a tamper-evident receipt with zero packet effects
- Eighty-eight automated access, licensing, audit, desktop, governance, model,
  steering, trace, graph,
  gateway, agent, evidence, safety, hardware, telemetry, resident-runtime, API,
  and integration tests

The benchmark is intentionally not perfect. It contains ambiguous early-stage
traces so that the confusion matrix and calibration measurements expose real
failure structure. These synthetic results validate the experimental pipeline;
they do not establish performance on live enterprise telemetry.

## What is intentionally deferred

- Real Zeek, Suricata, Cowrie, identity, SIEM, and SOAR connectors
- Containerized SSH/HTTP decoys
- Code-signed Windows installer/runtime and Linux-daemon installation
- Privileged ETW/WFP/eBPF collection and enforcement adapters; v1.2 uses the
  read-only Windows Event Log command interface, not ETW or WFP
- Temporal Transformer, temporal graph neural network, novelty, contextual-bandit, and
  language-assisted models evaluated against the current calibrated baselines
- Calibrated entity resolution over approved enterprise telemetry
- Enterprise OIDC/Windows-integrated identity, multi-user session issuance,
  multi-tenancy, embedded vendor trust anchors, license revocation, HSM/TPM key
  protection, trusted time, remote audit anchoring, HA, and upgrade orchestration
- Physical DPU/SmartNIC/FPGA enforcement, measured boot, hardware-protected
  receipt signing, and independently verified data-plane isolation
- External pilot deployment

These are extension points, not reasons to change the event, evidence, policy,
or API contracts established here.
