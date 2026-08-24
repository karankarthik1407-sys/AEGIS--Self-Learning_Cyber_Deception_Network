# AEGIS paper blueprint

Version 1.2.0 · working research protocol · 23 August 2026

## Working title

**AEGIS: Governed Multi-Model Learning and Proof-Carrying Diagnostic Deception
from Privacy-Bounded Endpoint Evidence**

Short title: **AEGIS: Proof-Carrying Adaptive Cyber Deception**

The title is intentionally about the technical interaction being tested. “AI
cybersecurity platform” and “self-learning honeypot” are too generic to make a
strong scientific contribution.

## Central falsifiable thesis

Compared with static, random and ordinary rule-selected deception, an AEGIS
controller can reduce uncertainty over competing adversary-intent hypotheses
with fewer interactions while an independent verifier prevents unsafe model-
proposed actions. Governed champion/challenger learning should recover from
distribution shift with lower poisoning success and catastrophic forgetting
than blind online updating.

The paper fails its central thesis if diagnostic steering does not improve
time-to-calibrated-confidence, if the verifier admits unsafe actions, if safe
rejection makes the system unusable, or if governed learning provides no
measurable robustness advantage over simpler lifecycle controls.

## Proposed contributions

1. **Diagnostic deception objective.** A constrained objective that balances
   expected information gain, operational cost, realism and safety rather than
   optimizing attacker dwell time alone.
2. **Uncertainty-aware multi-model fabric.** Complementary temporal, set, graph
   and novelty views evaluated through one environment-grouped calibration
   protocol with explicit disagreement and abstention.
3. **Proof-carrying action boundary.** A deterministic verifier that issues a
   machine-checkable certificate for scope, containment, provenance,
   reversibility, lifetime and resources before any adaptive action may execute.
4. **Governed adversary-resilient learning.** Separation of online belief
   updates from weight updates, followed by isolated training, grouped
   validation, poisoning tests, shadow evaluation, signed approval, canary and
   rollback.
5. **Privacy-bounded evidence plane.** A resident endpoint contract that
   minimizes and pseudonymizes observations before persistence while preserving
   local linkability, provenance and overlap-safe deduplication.
6. **Reproducible defensive artifact.** A safe range, event contracts, baselines,
   ablations, negative results, evidence manifests and an adversarial safety
   suite that never targets an external system.
7. **Evidence-diverse activity linkage.** A raw-IP-refusing trace contract that
   weights signal reliability/spoofability, requires independent-family
   diversity, exposes contradictions and alternatives, and forbids identity
   inference from a technical relationship score.
8. **Transitivity-safe campaign clustering.** An interpretable graph merge
   guard that requires diverse local evidence and cohort-level cross-support,
   preserves abstention and records why every adversarial bridge was rejected.
9. **Attested learning lifecycle evidence.** Immutable dataset/model identities,
   explicit lineage and a hash-linked promotion record that separates measured
   quality from trusted release authorization and rollback readiness.
10. **Scoped experimental accountability.** A local command boundary that ties
    each mutation to a server-assigned role, technical entitlement and paired
    preflight/outcome integrity receipts without retaining the request body.

Contributions 1–4 are the main paper and invention candidates. Contribution 5
is supporting system evidence unless a prior-art review identifies a narrower
novel technical cooperation. Contribution 10 is currently product/reproducibility
infrastructure and is not asserted as independently novel.

## Research questions and hypotheses

| ID | Research question | Testable hypothesis |
| --- | --- | --- |
| RQ1 | Does diagnostic deception distinguish intent faster? | Information-gain steering reduces interactions and elapsed time to a calibrated confidence threshold versus static, random and rules |
| RQ2 | Do complementary models improve reliable inference? | A validation-selected candidate improves held-out macro-F1/Brier or abstention risk under unseen environment families; extra models are rejected when they do not |
| RQ3 | Does proof-carrying verification improve action safety? | The verifier yields zero unsafe acceptance in the defined adversarial suite with bounded safe-rejection and latency costs |
| RQ4 | Does governance resist poisoned adaptation? | Governed promotion lowers poisoning success and forgetting versus blind online and periodic ungoverned updates |
| RQ5 | What privacy utility is lost by minimizing telemetry? | Pseudonymous allowlisted telemetry preserves useful case-linkage/inference performance within a pre-registered tolerance while materially reducing retained sensitive fields |
| RQ6 | Can the design operate at endpoint scale? | Compressed inference and verification satisfy defined memory, latency, availability and recovery budgets on low/mid-range endpoints |
| RQ7 | Can activity be linked safely across rotated/shared source infrastructure? | Evidence-diverse linkage lowers false-link and missed-link rates versus source-only and single-profile baselines under grouped environments while remaining calibrated and non-attributive |
| RQ8 | Can campaign clustering resist transitive error amplification? | A cohort-supported merge guard lowers false merges and catastrophic component growth versus source-only and ordinary learned-edge connected components under bridge-chain perturbation |
| RQ9 | Does attested lifecycle evidence make unsafe model changes more detectable? | Immutable artifact identity and chained promotion evidence detect descriptor/decision modification and prevent API-supplied release facts from changing authority compared with a mutable registry |

## Experimental program

| Experiment | Current status | Comparators | Primary outcomes |
| --- | --- | --- | --- |
| E0 — calibrated intent foundation | Reproducible v0.5 | Uniform, sequence NB, event-set NB, position NB, probability fusion | Macro-F1, Brier, ECE, NLL, per-class recall |
| E1 — temporal neural candidate | Next | Champion NB, TCN/GRU, compact Transformer | Same plus latency, memory, seeds and abstention risk |
| E2 — activity-trace linkage | Reproducible v0.6 foundation | Source-only, single-profile, fixed diversity fusion, diversity-feature logistic model; temporal GNN remains future work | Pairwise F1, Brier, ECE, false-link/missed-link rate, then cluster stability |
| E3 — diagnostic steering | Reproducible v1.0 synthetic foundation | Static, seeded random, leading-intent expert rule, expected-information-gain policy; contextual-bandit and robust-policy extensions remain pending | Correct/wrong high confidence, interactions, entropy, Brier, ECE, cost, safety |
| E4 — Safety Kernel adversarial suite | Foundation exists | No verifier, ordinary policy check, proof-carrying verifier | Unsafe acceptance, safe rejection, latency, recovery |
| E5 — continual-learning attack study | Planned | Frozen, blind online, periodic batch, governed AEGIS | Poison success, drift recovery, forgetting, rollback time |
| E6 — privacy/utility ablation | Gateway foundation reproducible v0.7; comparative study pending | Raw approved fields, allowlisted raw, pseudonymous allowlist, aggregate-only | Sensitive fields retained, linkage/inference delta, storage cost |
| E7 — resident performance | Runtime exists | Foreground vs service; 10/30/60-second cadence | CPU, RSS, database growth, query latency, stop/restart loss |
| E8 — transitive graph safety | Reproducible v0.8 synthetic foundation | Source components, naive learned-edge closure, cohort-supported guard | B³-F1, pairwise F1, false merges, split campaigns, largest cluster, bridge rejection |
| E9 — lifecycle integrity | v0.9 software foundation; adversarial study pending | Mutable metadata, hash-only records, local attestation, organization-signed release | Tamper detection, unauthorized-promotion success, verification latency, rollback evidence completeness |
| E10 — operator command integrity | v1.2 software foundation | No audit, terminal-only log, two-stage local chain, future externally anchored chain | unaudited side-effect rate, tamper detection, denial coverage, preflight/verification latency |

## Dataset and range protocol

- Use only owned or explicitly authorized environments.
- Represent benign administration, maintenance, automation and failed-user
  behaviour as hard negatives—not only attacks.
- Separate scenario generation, labels, collection and evaluation manifests.
- Split by complete environment/scenario family and time. Never allow one family
  or cloned route template to cross train, calibration and test partitions.
- Reserve at least one independently operated authorized environment for external
  validation before making an enterprise-performance claim.
- Preserve class prevalence and report both balanced research metrics and
  operational metrics at realistic prevalence.
- Store raw evidence, minimized AEGIS observations and model-ready features as
  separately governed tiers so the privacy ablation remains measurable.

Current E0 contains 240 synthetic sequences, four intent hypotheses and twenty
grouped scenario families with a 144/48/48 train/calibration/test partition. It
is a pipeline checkpoint, not sufficient evidence for the final paper.

Current E2 contains 240 synthetic sessions and 240 balanced pairs. Positives
rotate source context; hard negatives deliberately share provider/source/toolkit
context. Complete environment families produce a 144/48/48 train/validation/test
split. The source-only baseline obtains F1 0.286 and false-link rate 1.000 on
the held-out family; the logistic shadow candidate obtains F1 0.979, Brier
0.041 and false-link rate 0.000. These values establish a reproducible research
foundation only. The headline paper requires repeated seeds, temporal drift,
realistic prevalence, benign operations and an external authorized environment.

Current E3 contains 480 balanced synthetic episodes per policy across five
environment families; all 96 family-4 episodes are held out. Every selected
probe is verified by the Safety Kernel before an outcome exists. At seed
`26082026`, the EIG policy reaches correct posterior confidence ≥ 0.86 in 0.5938
of held-out episodes versus 0.1875 for static selection, while wrong confidence
is 0.0313, mean penalized interactions are 7.0208 versus 8.3229, and unsafe
acceptances are zero. The likelihood model, costs and family shift are synthetic,
so these values establish implementation and protocol evidence—not real-world
adversary behaviour, deployment safety or patent novelty.

## Statistical analysis plan

1. Pre-register the primary metric and decision threshold for each RQ.
2. Use repeated seeds and environment-level bootstrap confidence intervals;
   sequences from one environment are not independent bootstrap units.
3. Report effect sizes and interval estimates, not only p-values.
4. Calibrate only on the validation partition. Do not retune after viewing the
   held-out test result.
5. Compare paired systems on identical scenario executions where possible.
6. Report failed replications, regressions and ablations that do not help.
7. Include resource/error bars and missing-telemetry conditions.

## Mandatory ablations

- Remove information gain while retaining cost/safety terms.
- Sweep the cost coefficient and confidence threshold without selecting either
  from the final held-out family.
- Replace the nominal response likelihoods with misspecified, adversarial and
  learned likelihood models; compare explicit abstention with forced choice.
- Remove each model view and inter-model disagreement.
- Replace grouped splitting with a random split only to quantify leakage—not as
  a headline result.
- Disable calibration and abstention separately.
- Replace proof-carrying verification with ordinary boolean policy checks.
- Remove shadow volume, human approval, signed artifact and rollback gates one at
  a time in an isolated simulation.
- Compare raw approved telemetry, pseudonymous allowlist and aggregate-only data.
- Vary collector loss, delay, duplication and clock skew.
- Remove each Threat Trace family, then remove the diversity gate,
  reliability/spoofability adjustment and contradiction penalty separately.
- Compare pairwise scores with graph-level clustering and measure transitive
  false merges rather than assuming pairwise quality guarantees a valid cluster.

## Paper structure

1. **Introduction:** threat, gap, thesis and contributions.
2. **Problem and threat model:** authorized defender, attacker-controlled input,
   compromised model/host assumptions, non-goals and attribution boundary.
3. **AEGIS design:** belief state, model fabric, information-gain steering,
   certificate verifier, evidence plane and governance.
4. **Implementation:** resident runtime, range, telemetry contract, registry and
   future hardware boundary.
5. **Methodology:** datasets, grouped splits, baselines, metrics, attacks,
   statistical protocol and ethics.
6. **Results:** RQ order, calibration/reliability, ablations, negative results and
   resource measurements.
7. **Security/privacy analysis:** poisoning, evasion, prompt injection, service
   compromise, telemetry minimization and failure containment.
8. **Limitations and validity threats:** synthetic-to-real gap, attribution,
   label quality, service qualification and jurisdictional limits.
9. **Related work:** adaptive honeypots, moving-target defense, active learning,
   continual security ML, proof-carrying authorization, privacy-preserving
   telemetry and programmable enforcement.
10. **Conclusion and artifact statement.**

## Figure and table inventory

- F1: end-to-end control/trust-boundary architecture.
- F2: belief update and diagnostic action loop.
- F3: governed champion/challenger state machine.
- F4: proof-carrying certificate and enforcement handshake.
- F5: environment-grouped dataset split.
- F6: calibration/reliability and abstention curves.
- F7: information gain versus interactions/time.
- F8: poisoning/drift recovery trajectories.
- F9: source-only versus evidence-diverse trace reliability and error tradeoff.
- T1: threat model and non-goals.
- T2: datasets and environment families.
- T3: model and steering baselines.
- T4: primary results with confidence intervals.
- T5: safety adversarial suite.
- T6: privacy/utility and endpoint resource tradeoffs.

## Current evidence available to cite internally

- Sequence baseline: held-out macro-F1 0.854, multiclass Brier 0.210.
- Event-set challenger: macro-F1 0.937, Brier 0.086 on the current synthetic
  family split.
- Fusion negative result: same macro-F1 0.937 but worse Brier 0.108.
- Promotion decision: `HOLD_SHADOW`; selected offline quality passes while
  enterprise validation, trusted shadow volume, reviewer signature and rollback
  artifact remain unsatisfied.
- Safety/hardware foundation: deterministic certificates and zero-packet-effect
  attested-commit/rollback simulation.
- Resident evidence: real health/integrity collection, local privacy contract,
  overlap deduplication and clean lifecycle.
- Activity-trace foundation: 240 grouped pairs; source-only F1 0.286/Brier
  0.566 versus logistic shadow F1 0.979/Brier 0.041, with zero external targets
  and an explicit non-identity contract.
- Sensor-gateway foundation: strict Suricata/Zeek offline adapters, preview and
  explicit commit, content discard, local pseudonymization, import manifests,
  deduplication and no automatic case promotion; 45 tests pass.
- Graph-safety foundation: all-pairs family-grouped clustering evaluation and a
  seven-edge bridge chain; naive closure produces one 48-node component with
  B³-F1 0.222/false-merge 0.894, while the shadow guard rejects all bridges and
  reaches B³-F1 1.000/false-merge 0.000 on the synthetic held-out graph; 52
  tests pass in the complete v0.8 suite.
- Diagnostic-steering foundation: four equal-action policies, 480 episodes per
  policy, 96 held-out family-4 episodes, correct high-confidence rate 0.5938 for
  EIG versus 0.1875 for static, 1.3021 penalized interactions saved, wrong
  confidence 0.0313, and zero unsafe acceptances. The result remains synthetic
  and `HOLD_SHADOW`.
- Governance foundation: ten immutable dataset/model/policy descriptors with
  valid lineage and per-install HMAC attestations; a hash-linked promotion
  ledger detects modified copies and rejects SQL update/delete; API-supplied
  release claims are ignored and recorded. The v1.0 paper checkpoint had 68
  passing tests; the v1.2 enterprise-control checkpoint has 88. This is local
  integrity evidence, not external code signing or
  non-repudiation.
- Operator-control foundation: offline Ed25519 envelope verification, monotonic
  local roles and paired `ACCEPTED`/outcome receipts; invalid licenses, role
  escalation, row tampering and audit-key loss fail closed in the 88-test suite.
  This is local control evidence, not enterprise IAM, trusted time, DRM or an
  asserted patent contribution.

None of these results supports a claim of live-enterprise accuracy, criminal
identity attribution, real packet enforcement or patent novelty.

## Patent/publication sequencing

Adaptive deception, observation-driven decoy changes, hypothesis-test
adaptation, optimized deception planning and ML-generated honeypots already
appear in patent literature, including US11934948B1, US12425417B2 and
US20240333765A1. The paper must not describe generic adaptive deception as the
novelty. Any invention thesis requires an element-by-element professional search
focused on the narrower cooperation among information-gain selection,
certificate-before-observation ordering, abstention, artifact lineage and the
future attested enforcement boundary.

Freeze dated invention disclosures and complete professional filing-strategy
review before releasing an enabling paper, repository, poster or public demo.
The paper should disclose enough for scientific reproducibility only after the
intended claim scope and filing sequence are settled. This is a workflow control,
not legal advice.

## Submission readiness gate

The paper is not submission-ready until E1, the external/temporal extension of
E2 and E3, E4, E5 and E6 are complete,
the external authorized environment has been evaluated, confidence intervals and
ablations are frozen, the artifact reproduces from a clean machine, the ethics
statement is approved, and the patent/public-disclosure decision is recorded.
