# AEGIS Research and Invention Register

Version 1.2.0 · confidential working record · 23 August 2026

This is an engineering and research record, not a legal opinion or a patentability
determination. Patent claims and publication timing must be reviewed by a
qualified patent professional in the relevant jurisdictions.

## Confidentiality control

Do not publicly release enabling technical details of an intended claim set
until a filing strategy has been reviewed. WIPO advises filing before public
disclosure because disclosure can become prior art, subject to jurisdiction-
specific exceptions or grace periods. See the official [WIPO patent FAQ](https://www.wipo.int/en/web/patents/faq_patents)
and [WIPO invention-protection guidance](https://www.wipo.int/en/web/patents/protection).

Until that review, public demos and papers should describe measured outcomes and
system boundaries without publishing secret implementation details selected for
the patent specification.

## Invention thesis under investigation

The strongest AEGIS direction is not “AI plus honeypots.” That phrase is broad,
crowded and unlikely to define a defensible invention by itself. The invention
candidate is the cooperation between learning, diagnostic deception, proof-
carrying authorization, evidence, and an optional hardware enforcement boundary.

### Candidate A — proof-carrying adaptive deception

**Hypothesis:** a cyber-deception controller in which an uncertainty-aware model
selects a bounded diagnostic world change, while an independent deterministic
verifier produces a machine-checkable certificate containing scope, provenance,
resource, reversibility, lifetime and containment proofs before actuation.

Evidence still needed:

- precise action, certificate and failure-state definitions;
- comparison against orchestration systems using ordinary policy checks;
- proof that the certificate changes measurable safety/audit outcomes;
- prior-art search across adaptive honeypots, policy-as-code and proof-carrying
  authorization.

### Candidate B — governed adversary-resilient continual learning

**Hypothesis:** a security-learning lifecycle that separates online belief
updates from weight updates and requires grouped generalization, calibration,
poisoning checks, shadow volume, human approval, signed promotion and rollback
before an adaptive deception model gains decision authority.

Evidence still needed:

- formal threat model for data poisoning and catastrophic forgetting;
- organization-signed champion/challenger manifests, trusted reviewer identity,
  revocation and hardware-backed keys;
- live shadow study across more than one authorized environment;
- comparison with ordinary MLOps approval pipelines.

Implemented v1.0 embodiment: ten immutable dataset/model/policy descriptors,
explicit model-to-dataset lineage, per-install HMAC attestations, SQL-enforced
append-only tables and a hash-linked promotion record. The API cannot create
trusted enterprise-validation, shadow-volume, reviewer-signature or rollback
facts. This advances enablement for Candidate B but is not a public-key signed
registry, production promotion mechanism or novelty determination. Model
registries, ML provenance, supply-chain attestations, transparency logs and
MLOps approval systems are directly relevant prior art.

### Candidate C — attested deception enforcement module

**Hypothesis:** a DPU/SmartNIC/FPGA boundary that accepts only certified,
short-lived deception-rule manifests, preserves protected-core and egress-denial
invariants, commits atomically, expires automatically and returns a tamper-
evident receipt linked to the investigation ledger.

Evidence still needed:

- physical prototype and measured boot/attestation design;
- packet-path and failure-isolation measurements;
- host-compromise experiment;
- prior-art search across SmartNIC security, P4 control, service meshes and
  hardware policy enforcement.

### Candidate D — information-gain deception steering

**Hypothesis:** constrained selection of a synthetic interaction based on the
expected reduction in uncertainty between competing adversary-intent hypotheses,
not merely engagement duration or alert probability.

Implemented v1.0 embodiment: a declared Bayesian entropy objective, cost-penalized
expected-information-gain selector, four equal-contract synthetic probes, a
Safety-Kernel-before-observation order, static/random/expert comparators, five
environment families, a held-out family, explicit abstention, calibration and
wrong-confidence metrics, and dataset/policy lineage. The EIG candidate improves
correct high confidence by 0.4063 over static selection and records zero unsafe
acceptances in the seeded synthetic protocol; it remains `HOLD_SHADOW`.

Evidence still needed:

- robust, contextual-bandit, POMDP and constrained-RL comparators;
- ablation of information gain, risk cost, threshold, realism and likelihood
  misspecification without tuning on the final held-out family;
- real elapsed-time, analyst-cost and containment-risk measurements;
- adversarial response, replay, poisoning and decoy-fingerprinting tests; and
- authorized multi-environment external evaluation with repeated seeds and
  environment-level confidence intervals.

Preliminary prior-art warning: observation-driven adaptive deception and
hypothesis-test adaptation appear in
[US11934948B1](https://patents.google.com/patent/US11934948B1/en); optimized
deception planning using machine learning and information theory appears in
[US12425417B2](https://patents.google.com/patent/US12425417B2/en); and generated
honeypot content with interaction-based retraining appears in
[US20240333765A1](https://patents.google.com/patent/US20240333765A1/en).
Generic “self-learning deception” is therefore not treated as novel. Candidate
D survives only as a narrow hypothesis about the specific cooperation among
information-gain selection, certificate-before-observation ordering,
wrong-confidence/abstention constraints, governed lineage and a future attested
enforcement boundary. Professional claim charts may still reject that thesis.

### Candidate E — privacy-bounded observation-to-deception provenance

**Hypothesis:** a resident deception-security node that minimizes and
pseudonymizes endpoint observations before persistence, preserves stable local
linkability and collector provenance, and permits only explicitly governed
promotion of those observations into an investigation or adaptive-deception
decision.

The individual use of event allowlists, HMAC pseudonyms, local stores and audit
logs is likely crowded prior art. Any defensible claim would need to arise from
a specific technical cooperation with uncertainty-aware deception, evidence
provenance or proof-carrying action—not from privacy filtering alone.

Evidence still needed:

- formal raw-field-to-persisted-field information-flow model;
- measured privacy/utility tradeoff against raw and fully anonymized telemetry;
- governed observation-to-case promotion and deletion/key-rotation semantics;
- prior-art search across privacy-preserving SIEM, endpoint telemetry,
  pseudonymous linkage and forensic provenance.

Implemented v0.7 embodiment: strict Suricata/Zeek offline adapters now perform
bounded validation, in-memory pseudonymization, content discard, preview,
explicit commit, telemetry deduplication and manifested safe-output provenance.
This advances enablement but does not establish novelty: commercial log
normalizers, privacy gateways and SIEM pipelines remain highly relevant prior
art.

### Candidate F — evidence-diversity-constrained threat tracing

**Hypothesis:** an authorized activity-correlation system that refuses raw
network identifiers at the correlation boundary, scores multiple technical and
controlled-deception signal families according to reliability and spoofability,
requires cross-family diversity before a high-confidence link, preserves
contradictions and machine-readable alternative explanations, and exports the
relationship as a manifested non-identity trace.

Address reputation, device fingerprinting, entity resolution, graph
correlation, probabilistic record linkage and attack-campaign clustering are
crowded fields. Individual elements such as Jaccard overlap, logistic
calibration, weighted evidence and pseudonyms are not presumed novel. Any
defensible claim would need a narrow, enabled technical cooperation—potentially
the diversity gate plus controlled-deception responses, raw-identifier refusal,
explicit contradiction handling and proof-carrying downstream action safety.

Evidence still needed:

- a professional patent and non-patent prior-art search with element-by-element
  claim charts;
- formal treatment of dependent evidence families and adversarial signal
  mimicry;
- authorized multi-environment and temporal validation with benign hard
  negatives, realistic prevalence and confidence intervals;
- comparison with commercial SIEM/XDR entity resolution, CTI knowledge graphs,
  probabilistic record linkage and campaign clustering;
- enterprise graph-level false-merge/split evaluation beyond the implemented
  synthetic bridge-chain foundation; and
- alternative embodiments covering on-premises software and an attested
  DPU/SmartNIC/FPGA enforcement boundary without overclaiming either.

### Candidate G — cohort-supported transitivity control

**Hypothesis:** a campaign-correlation graph that prevents local relationship
scores from gaining unconditional transitive force by requiring a combination
of evidence-family diversity, a stronger cohort seed, cross-component pair
support, a bounded merge size and an auditable abstention/rejection record.

Graph clustering, correlation clustering, constrained agglomeration, entity
resolution, link prediction and bridge/outlier detection are crowded fields.
Union-find, B³ metrics, logistic edge scores, thresholds and cluster-size caps
are individually conventional. No novelty is presumed. A potentially relevant
narrow cooperation would need to be distinguished from these fields—for
example, a deception-derived evidence-diversity constraint combined with
cohort-level transitivity verification and a proof-carrying downstream action
boundary.

Implemented v0.8 embodiment: a family-grouped all-pairs protocol, two graph
baselines, a validation-selected guard, a seven-edge bridge-chain perturbation,
per-bridge decision evidence and a manifested non-identity result. On the seeded
synthetic test graph, naive closure collapses all 48 nodes while the guard
rejects all seven injected bridges. This is enablement evidence only, not a
patentability determination or enterprise result.

Evidence still needed:

- professional search across constrained/correlation clustering, record
  linkage, knowledge-graph completion and cyber-campaign graphs;
- element-by-element comparison against cohort/cluster consistency gates and
  anti-chaining entity-resolution techniques;
- formal invariants, adversarial complexity and alternative guard embodiments;
- authorized longitudinal datasets with natural—not only injected—bridges;
- comparisons with hierarchical, correlation-clustering and temporal-GNN
  baselines under equal calibration and abstention budgets; and
- proof that the guard's cooperation with deception response and certified
  action control yields a technical effect beyond ordinary analytics policy.

### Product control boundary — recorded, not asserted as Candidate H

Version 1.2 implements offline Ed25519 license verification, monotonic local
roles and a two-stage HMAC-linked command journal. These are important product
and research-governance controls, but digital licensing, RBAC, append-only logs,
hash chains and pre/post audit events are crowded security engineering fields.
AEGIS does not presently assert that this layer is independently inventive.

Its relevance to the invention program is evidentiary: experiments, governance
evaluations and future defensive actions can be tied to a scoped operator and a
tamper-evident command history. Any future claim would need a professionally
searched, narrow technical cooperation with the deception-learning and proof-
carrying action architecture—not the generic presence of licensing or audit.

## Claims we should not make

- “AEGIS identifies a cybercriminal.” It links authorized observations and
  produces investigative hypotheses; human attribution requires other evidence.
- “AEGIS is fully autonomous.” The system deliberately retains deterministic
  enforcement and human release gates.
- “Multiple models make it revolutionary.” Only measured improvement and a
  novel technical interaction can support that argument.
- “The patent is guaranteed.” Novelty, inventive step, enablement, ownership and
  jurisdictional exclusions must all be examined.
- “Synthetic accuracy predicts enterprise accuracy.” It does not.

## Paper program

### Paper 1 — publishable foundation

Provisional title:

> AEGIS: Governed Continual Learning and Proof-Carrying Action Safety for
> Adaptive Cyber Deception

Research questions:

1. Does diagnostic adaptive deception reduce intent uncertainty faster than
   static or randomly selected decoys?
2. Do complementary temporal and graph models improve calibration and campaign
   linkage under environment-grouped evaluation?
3. Can an independent certificate verifier prevent unsafe model proposals
   without eliminating useful defensive actions?
4. How much latency, analyst workload and attacker dwell time does the safety
   architecture introduce?

Required experiments:

| Experiment | Baselines | Primary metrics |
| --- | --- | --- |
| Intent inference | Uniform, rules, sequence NB, event-set NB | Macro-F1, Brier, ECE, NLL, abstention coverage |
| Temporal candidate | NB champion, TCN/GRU, Transformer | Same metrics plus latency and memory |
| Campaign/activity linkage | Source-only, single-profile, fixed diversity fusion, tabular model, temporal GNN | Pairwise F1, Brier, ECE, false-link/missed-link rate, cluster stability |
| Deception steering | Static, random, rule-based, constrained bandit | Information gain, time-to-confidence, safety cost |
| Safety Kernel | Unverified action path, ordinary policy, certificate verifier | Unsafe acceptance, safe rejection, verification latency |
| Continual learning | Frozen model, blind online update, governed lifecycle | Drift recovery, poisoning success, forgetting, rollback time |

Minimum validity conditions:

- multiple scenario families and at least one external authorized environment;
- temporal/environment-grouped splits;
- hard benign negatives and class imbalance;
- confidence intervals over repeated seeds;
- ablations and negative results;
- explicit ethics, authorization and non-attribution boundary;
- artifact manifest sufficient for independent reproduction.

## v1.2 evidence ledger

| Evidence | Current result | Interpretation |
| --- | --- | --- |
| Sequence champion | Macro-F1 0.854; Brier 0.210 | Serious reproducible baseline |
| Event-set candidate | Macro-F1 0.937; Brier 0.086 | Promising synthetic challenger |
| Fusion ablation | Macro-F1 0.937; Brier 0.108 | Complexity did not beat the candidate's probability quality |
| Promotion gate | `HOLD_SHADOW` | Self-learning remains governed |
| Safety suite | Zero expected invariant violations in current tests | Foundation result, not external certification |
| Hardware profile | Zero packet effects | Contract simulation only |
| Host telemetry | Real health and runtime-integrity observations | Resident data-plane checkpoint; not threat accuracy |
| Windows event collector | Eight event types; allowlist + local HMAC | Fixture-tested privacy contract; Windows qualification pending |
| Overlap deduplication | Canonical observation digest | Repeated lookback queries do not multiply identical evidence |
| Resident lifecycle | Loopback API, background collection, clean stop | Service-shaped application rather than UI-only process |
| Windows Service host | SCM callbacks and reversible scripts implemented | Unsigned Research Edition; actual Windows validation pending |
| Threat Trace corpus | 240 sessions; 120 positive and 120 hard-negative pairs; grouped 144/48/48 | First reproducible activity-linkage foundation |
| Source-only trace baseline | F1 0.286; Brier 0.566; false-link rate 1.000 | Deliberately difficult synthetic evidence that source context cannot stand in for identity |
| Logistic trace candidate | F1 0.979; Brier 0.041; false-link rate 0.000; missed-link rate 0.042 | Promising synthetic shadow result; no enterprise or identity claim |
| Trace export | Six-family contributions, alternatives, graph, identity boundary and SHA-256 manifest | Investigator-facing provenance checkpoint |
| Evidence Gateway | Strict Suricata/Zeek preview and explicit commit; raw endpoints/content discarded | Implemented privacy-boundary embodiment for Candidate E |
| Gateway provenance | Input digest, safe dispositions, explicit assertions and manifested import ledger | Foundation only; not a digital signature or custody certification |
| Gateway case boundary | Zero automatic case events or labels | Sensor ingestion cannot silently become an accusation |
| Graph held-out protocol | 48 family-4 nodes and all 1,128 unordered pairs | Global clustering test remains disjoint from training and validation families |
| Bridge-chain stress | Seven locally plausible cross-campaign edges | Directly tests transitive error amplification |
| Naive learned-edge closure | B³-F1 0.222; false-merge 0.894; largest cluster 48 | Strong local edges can still produce catastrophic global structure |
| Cohort-supported graph guard | B³-F1 1.000; false-merge 0.000; 7/7 bridges rejected | Promising synthetic embodiment for Candidate G; `HOLD_SHADOW` |
| Diagnostic steering corpus | 480 episodes per policy; 96 held-out family-4 episodes | Balanced, manifested synthetic foundation; not real attacker behaviour |
| EIG steering candidate | Correct confidence 0.5938 vs static 0.1875; 1.3021 interactions saved; wrong confidence 0.0313 | Candidate D embodiment; synthetic and `HOLD_SHADOW` |
| Steering Safety Kernel order | 13,271 permitted actions across all policies/families; zero unsafe acceptances | Defined-contract evidence only; not formal or deployment certification |
| Expert-rule negative result | Wrong high confidence 0.1042 | More decisive adaptation can be less trustworthy; preserve abstention |
| Artifact registry | Four datasets, five model/decision-policy descriptors and one policy; all local attestations verify | Concrete lineage/provenance embodiment for Candidate B; not external signing |
| Registry immutability | SQL update/delete triggers plus descriptor-copy tamper detection | Ordinary application paths cannot rewrite artifact history |
| Promotion ledger | Hash-linked decisions with previous hash, record hash, column checks and local HMAC | Modification detection inside one installation; not non-repudiation |
| Release-fact boundary | API-supplied sign-off/shadow claims ignored; result remains `HOLD_SHADOW` | Browser input cannot manufacture promotion authority |
| Offline license verifier | Canonical Ed25519 signature, key identity, strict claim/time validation and entitlement lock | Commercial-control foundation; not asserted as patent novelty or tamper-proof DRM |
| Operator role boundary | Viewer/analyst/administrator scopes assigned by the host; browser cannot self-elevate | Local least-privilege embodiment; enterprise identity binding still absent |
| Command journal | `ACCEPTED` before route plus `COMPLETED`/`FAILED` after route; request digest only | Route execution leaves paired local integrity evidence |
| Audit integrity | HMAC chain, key identity, SQL update/delete refusal and out-of-band tamper test | Per-install modification detection; not public non-repudiation or trusted time |
| Audit fail-closed case | Existing records plus missing key lock every mutation | Prevents silent replacement of a broken command history |
| Test suite | 88 passing tests | Reproducible checkpoint including desktop lifecycle, signed licensing, scoped roles and command-audit controls |
| External targets | Zero | Authorized defensive boundary preserved |

## Prior-art workflow

1. Freeze a dated invention disclosure with diagrams, inventors, experiments and
   alternative embodiments.
2. Search patent and non-patent literature separately for each candidate, not
   only the full AEGIS product phrase.
3. Build a claim chart mapping every proposed claim limitation to each reference.
4. Mark each element as disclosed, arguably disclosed, absent or dependent on a
   combination of references.
5. Revise the technical design where the search reveals crowded elements.
6. Ask a patent professional to assess patent-eligible subject matter, novelty,
   inventive step, enablement, ownership and filing geography.
7. Decide the filing order before submitting an enabling paper, poster, public
   repository, competition deck or demo.

Suggested search concept groups:

- adaptive honeypot or moving-target deception plus reinforcement learning;
- uncertainty reduction or information gain in cyber deception;
- proof-carrying authorization, policy certificates and verified orchestration;
- continual learning with poisoning-resistant promotion in security systems;
- DPU/SmartNIC/P4 attestation, atomic rule update and rollback;
- forensic evidence chains linked to automated defensive actions;
- model registries, ML metadata/provenance, in-toto/SLSA-style supply-chain
  attestations, transparency logs and signed MLOps promotion workflows;
- multi-signal entity resolution, probabilistic record linkage and cyber
  campaign clustering with uncertainty, contradiction and abstention;
- deception-response fingerprints combined with privacy-preserving correlation.

## Decision log

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-08-20 | Keep the product name AEGIS | One name across paper, product and invention record |
| 2026-08-20 | Treat the console as an interface, not the runtime | Licensed systems require a resident service/daemon |
| 2026-08-20 | Use multiple models only under shared ablations | Prevent unmeasured “model soup” claims |
| 2026-08-20 | Prohibit automatic weight promotion | Reduce poisoning, drift and silent-regression risk |
| 2026-08-20 | Rename Policy Centre to Enforcement & Trust | Make the Safety Kernel's product value understandable |
| 2026-08-20 | Prefer PCIe DPU/SmartNIC/FPGA over a RAM-like DIMM | Correct compute, network and control interfaces for future enforcement |
| 2026-08-20 | Separate `TelemetryObservation` from case `SecurityEvent` | Prevent an operating-system signal from silently becoming an accusation or training label |
| 2026-08-20 | Pseudonymize before persistence and provide no outbound telemetry path | Minimize resident data exposure while retaining local correlation utility |
| 2026-08-20 | Implement an unsigned Windows Service host but label qualification honestly | Establish the product shape without claiming production assurance |
| 2026-08-20 | Treat IP/source context as the weakest trace family and reject raw IPs in the trace contract | Shared/rotating infrastructure cannot support identity inference |
| 2026-08-20 | Hold the learned trace candidate in shadow despite F1 0.979 | Synthetic grouped performance is insufficient for enterprise promotion |
| 2026-08-20 | Require sensor preview and explicit commit; prohibit automatic case promotion | Ingestion, investigative judgment and model labeling are separate trust decisions |
| 2026-08-20 | Require cohort support before transitive graph merges | A locally plausible relationship must not contaminate an entire campaign hypothesis |
| 2026-08-20 | Separate local artifact attestation from production signing | HMAC provides useful per-install integrity but cannot support external trust or non-repudiation |
| 2026-08-20 | Make release evidence non-writable by the loopback API | Candidate evaluation must not manufacture shadow volume or reviewer authority |
| 2026-08-20 | Require Safety Kernel verification before a steering outcome can exist | Unsafe or out-of-scope proposals must not influence the posterior through simulated evidence |
| 2026-08-20 | Keep EIG steering in shadow despite its held-out synthetic gain | Simulator-coupled performance is not enterprise evidence or release authority |
| 2026-08-20 | Narrow the IP thesis after preliminary patent review | Broad adaptive/hypothesis-driven cyber deception is already crowded prior art |
| 2026-08-23 | Replace ordinary-browser launch with a native Windows shell and independent resident executable | Match the licensed endpoint-product requirement while preserving the validated UI and control contracts |
| 2026-08-23 | Require a session token for every desktop mutation | Loopback binding alone does not prevent an unrelated web origin from attempting local side effects |
| 2026-08-23 | Put role and entitlement checks before every mutation route | The interface must not be able to manufacture its own authority |
| 2026-08-23 | Seal an audit preflight before execution and fail closed if the journal is unavailable | A successful side effect must not occur without at least durable command-intent evidence |
| 2026-08-23 | Treat licensing/RBAC/hash-chain logging as product controls, not a new patent candidate | These fields are crowded; novelty must remain focused on narrower technical cooperation supported by evidence |

## Next register update

Update this file when any of the following happens:

- a new dataset or experiment changes a reported metric;
- a candidate claim is narrowed, rejected or supported by prior art;
- a public disclosure is planned;
- another contributor joins or inventorship facts change;
- a prototype begins touching real authorized telemetry or packet paths;
- a patent professional gives filing or confidentiality guidance.
