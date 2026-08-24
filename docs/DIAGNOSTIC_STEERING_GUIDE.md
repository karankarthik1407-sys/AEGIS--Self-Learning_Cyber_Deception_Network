# AEGIS diagnostic steering guide

Version 1.0.0 · reproducible synthetic foundation · 20 August 2026

This is the technical and learning companion for AEGIS's first complete
diagnostic-deception experiment. It explains the implemented mechanism, its
mathematics, its falsifiable comparison, and the gap between a promising
synthetic result and a defensible enterprise or patent claim.

## 1. What changed in v1.0

Earlier releases could update intent beliefs and verify a proposed decoy action.
Version 1.0 closes the loop in a controlled research setting:

1. maintain a probability distribution over four intent hypotheses;
2. score four pre-authorized synthetic probes by expected information gain;
3. select a probe under a bounded cost penalty;
4. submit the complete proposed action to the independent Safety Kernel;
5. generate an observation only after a `PERMIT` certificate;
6. update the posterior with Bayes' rule;
7. stop at a declared confidence threshold or abstain at the interaction cap;
8. compare the policy against static, random, and expert-rule baselines on an
   environment family excluded from policy development.

The mechanism is active and reproducible in the Research Edition. The decoys,
intent labels, response distributions, and environment shifts are synthetic.
No network target is contacted and no production asset is changed.

## 2. Why “self-learning” needs two different loops

AEGIS deliberately separates fast belief adaptation from slow model adaptation.

| Loop | Changes | Frequency | Authority |
| --- | --- | --- | --- |
| Online inference | Case-local probabilities over existing hypotheses | After a permitted observation | Automatic within the bounded case model |
| Offline learning | Model weights, likelihoods, thresholds, and policy artifacts | After isolated training and evaluation | Shadow candidate only; release requires external approval |

This distinction matters. Updating a posterior is not the same as retraining a
model, and an attacker-controlled interaction must not be allowed to rewrite the
production policy directly. The v1.0 steering policy is frozen before held-out
evaluation and is registered as a `SHADOW` artifact.

## 3. The inference state

The current hypothesis set is:

- reconnaissance;
- credential access;
- lateral movement; and
- collection.

Let the prior probability of intent \(h\) be \(p(h)\), a candidate probe be
\(a\), and its observed outcome be \(y\). The implemented update is:

\[
p(h \mid y,a)=\frac{p(y\mid h,a)p(h)}
{\sum_{h'}p(y\mid h',a)p(h')}.
\]

The uncertainty of a distribution is Shannon entropy:

\[
H[p]= -\sum_h p(h)\log_2 p(h).
\]

For each safe candidate probe, AEGIS calculates the expected reduction in that
entropy before observing the outcome:

\[
\operatorname{EIG}(a)=H[p(h)]-
\sum_y p(y\mid a)H[p(h\mid y,a)].
\]

The v1.0 decision score is \(\operatorname{EIG}(a)-0.035c(a)\), where \(c(a)\)
is the declared probe cost. The coefficient is a design setting, not a learned
or universally valid constant. Modern Bayesian experimental design treats
expected information gain as a principled way to choose informative experiments;
the AEGIS research question is whether that idea can cooperate usefully with a
strict cyber-deception action boundary. See the primary research overviews
[Modern Bayesian Experimental Design](https://arxiv.org/abs/2302.14545) and
[Targeted Active Learning for Bayesian Decision-Making](https://arxiv.org/abs/2106.04193).

## 4. Equal candidate-action contract

Every comparator chooses from the same four actions. No policy receives a more
powerful probe set.

| Probe | Synthetic target | Intended diagnostic contrast | Cost |
| --- | --- | --- | ---: |
| Selective service map | `decoy-edge-service-map` | Reconnaissance response | 0.75 |
| Synthetic credential note | `decoy-credential-note` | Credential-access response | 1.00 |
| Isolated pivot route | `decoy-pivot-route` | Lateral-movement response | 1.15 |
| Synthetic archive index | `decoy-archive-index` | Collection response | 1.25 |

Each probe supports three outcomes: `engage`, `inspect`, and `decline`. The
complete likelihood table is stored in the source and included in the dataset
digest. The held-out environment flattens response strength, while the policy
continues to use the nominal table. This creates a declared observation-model
shift instead of evaluating on an exact clone of the development environment.

MITRE Engage describes deception as an adversary-engagement process rather than
a fire-and-forget technology. AEGIS uses that planning idea only within owned or
explicitly authorized environments and narrows it further to isolated,
synthetic actions. See the official [MITRE Engage framework](https://engage.mitre.org/).

## 5. Safety order is part of the algorithm

For every selected action, the following order is mandatory:

```text
select candidate → construct action → Safety Kernel → PERMIT → observe → update
                                               ↘ DENY → no observation
```

The Safety Kernel verifies eight invariants:

1. exact authorized namespace;
2. decoy-only target with a `decoy-` identifier;
3. no network egress;
4. synthetic data only;
5. reversibility;
6. bounded memory;
7. bounded CPU; and
8. bounded lifetime.

This order prevents the simulator—and a future runtime adapter—from pretending
an unsafe probe occurred and learning from the fabricated consequence. In v1.0,
all 13,271 executed research actions across the four policies and five families
were evaluated first; zero unsafe acceptances occurred. This is a test result
under the defined action schema, not a formal proof of all possible software or
deployment failures.

## 6. Experimental protocol

| Item | Frozen v1.0 value |
| --- | --- |
| Generator | `aegis.synthetic-diagnostic-steering.v1` |
| Seed | `26082026` |
| Intent hypotheses | 4 |
| Environment families | 5 |
| Variants per intent/family | 24 |
| Episodes per policy | 480 |
| Held-out family | Family 4; 96 episodes per policy |
| Maximum executed interactions | 8 |
| Failure penalty | 9 interactions |
| Confidence threshold | posterior probability at least 0.86 |
| Primary metric | correct high-confidence rate |
| Safety requirement | zero unsafe acceptances |

Four policies are compared:

- `STEER-STATIC`: always presents the service-map probe;
- `STEER-RANDOM`: seeded uniform selection from the same action set;
- `STEER-RULE`: presents the probe corresponding to the current leading intent;
- `STEER-EIG`: selects the highest expected information gain after cost penalty.

The primary decision gate declares the candidate `PASSING` only when it is the
best held-out policy, improves correct high confidence by at least 0.20 over the
static baseline, keeps wrong high confidence at or below 0.05, and has zero
unsafe acceptances. A passing research result still receives
`promotion: HOLD_SHADOW`.

## 7. Reproducible result

Run: `STEER-RUN-1B7760DA3CCDAF3A`

| Held-out policy | Correct ≥ 0.86 | Wrong ≥ 0.86 | Mean penalized interactions | Final entropy (bits) | Multiclass Brier |
| --- | ---: | ---: | ---: | ---: | ---: |
| Static service map | 0.1875 | 0.0104 | 8.3229 | 1.2354 | 0.4749 |
| Seeded random | 0.3438 | 0.0521 | 7.9167 | 0.9504 | 0.4556 |
| Leading-intent rule | 0.4479 | 0.1042 | 7.6354 | 0.9265 | 0.4570 |
| AEGIS EIG | **0.5938** | **0.0313** | **7.0208** | **0.8486** | **0.2966** |

Relative to the static policy, EIG improves correct high confidence by 0.4063,
saves 1.3021 penalized interactions, and lowers final entropy by 0.3868 bits.
The expert rule reaches high confidence more often than random, but it is also
wrong with high confidence in 10.4% of held-out episodes. This is an important
negative result: decisive-looking adaptation can be less trustworthy than a
policy that preserves uncertainty.

## 8. What this result does and does not establish

It establishes that:

- the implementation is deterministic for a fixed seed and manifested schema;
- the four policies use balanced episodes and the same action contract;
- the EIG candidate beats all included baselines under the declared synthetic
  family shift;
- the confidence threshold and safety gate are actually exercised; and
- the candidate can be represented as a governed artifact with dataset and
  Safety-Kernel lineage.

It does not establish that:

- the synthetic likelihood table matches real intruder behaviour;
- 59.4% is an enterprise detection or attribution accuracy;
- the chosen cost coefficient is operationally optimal;
- a person, group, location, or state can be identified;
- a deployed decoy is impossible to fingerprint or escape;
- an adaptive-deception patent is novel or will be granted; or
- the policy may actuate on a customer system without qualification.

## 9. The strongest validity threats

1. **Model–simulator coupling.** The policy and posterior use the nominal
   likelihood family from which the shifted simulator is derived. More severe
   misspecification could reverse the result.
2. **Synthetic outcomes.** Real adversaries are strategic, non-stationary, and
   may intentionally poison the observation loop.
3. **One deterministic seed.** The artifact proves reproducibility, not
   variability across generators or environments.
4. **Simplified costs.** Cost is a scalar rather than measured deployment,
   analyst, detection, and containment risk.
5. **No live latency.** Interactions are simulation steps, not elapsed time.
6. **Limited baselines.** Contextual bandits, POMDP policies, robust Bayesian
   design, and reinforcement-learning deception controllers remain to be
   compared.
7. **Normal-approximation interval.** The current interaction interval describes
   simulation variability and is not an environment-level uncertainty estimate.

## 10. Required external extension

The next defensible study should pre-register and then execute:

- at least three independently configured owned/authorized ranges;
- benign administrator and automation sessions as realistic hard negatives;
- time-separated training, calibration, and final test periods;
- repeated generator and model seeds with environment-level bootstrap intervals;
- likelihood misspecification and adversarial mimicry sweeps;
- static, random, expert, contextual-bandit, robust-EIG, and constrained-RL
  policies under equal actions and equal safety budgets;
- calibration, abstention, safe rejection, latency, compute, dwell time, analyst
  workload, and decoy-fingerprinting measurements;
- poisoning, replay, missing telemetry, delayed telemetry, and compromised-node
  tests; and
- an external evaluator who freezes the final manifest before results are read.

## 11. Multiple ML and deep-learning models

Multiple models can help only when they add measured information. The sensible
AEGIS sequence is:

1. retain the current calibrated Naive Bayes and logistic models as serious,
   CPU-light baselines;
2. train a compact temporal convolution or GRU on event sequences;
3. train a temporal graph model on session relationships;
4. train a novelty model on benign/known activity embeddings;
5. optionally use a small language model to structure already-authorized text
   artifacts, never as an unrestricted actuator;
6. compare every model on grouped data, calibration, resource use, poisoning,
   abstention, and safety—not accuracy alone;
7. export only compressed, signed inference artifacts to the endpoint.

The Victus laptop can run the v1.0 standard-library experiments and small-model
prototypes. Larger temporal/GNN training should use a reproducible remote GPU
job; this does not change the endpoint target, which should receive a compact
validated artifact rather than a training stack.

## 12. Patent checkpoint and crowded prior art

“Adaptive cyber deception” is already a crowded concept. A preliminary search
found, among other references:

- [US11934948B1, Adaptive deception system](https://patents.google.com/patent/US11934948B1/en),
  which includes observation-driven adaptation and hypothesis-test embodiments;
- [US12425417B2, Generation and implementation of cyber deception strategies](https://patents.google.com/patent/US12425417B2/en),
  which discusses machine learning, information theory, and optimized deception
  planning;
- [US20240333765A1, LLM cybersecurity deception and honeypots](https://patents.google.com/patent/US20240333765A1/en),
  which covers generated deceptive content and learning from interactions; and
- [US20250254196A1, Adaptive deception orchestration](https://patents.google.com/patent/US20250254196A1/en),
  which describes orchestrated behavioural honeypots and activity-path tracking.

Therefore, neither “AI honeypot,” “self-learning deception,” nor generic
observation-driven adaptation should be treated as the AEGIS invention. The
narrow candidate worth professional claim-chart analysis is the technical
cooperation among:

- uncertainty-reduction selection over an equal pre-authorized probe set;
- mandatory certificate verification before an observation can enter the
  belief update;
- explicit abstention and wrong-confidence constraints;
- artifact lineage binding the policy to its dataset and safety policy; and
- a later attested enforcement boundary that accepts only the certificate-bound,
  short-lived decoy manifest.

Even that combination may be obvious or already disclosed. A patent
professional must perform jurisdiction-specific novelty, inventive-step,
eligibility, enablement, ownership, and filing-sequence analysis before an
enabling public disclosure. This guide is an engineering record, not legal
advice or a patentability opinion.

## 13. Governance alignment

The v1.0 registry contains ten built-in artifacts: four datasets, five model or
decision-policy descriptors, and one Safety Kernel policy. The steering model
has two parents: its manifested diagnostic corpus and the exact Safety Kernel
policy. Per-install HMAC attestations detect local modification, and the
promotion ledger remains append-only. These are useful controls but not an
organization signature, trusted timestamp, or non-repudiation proof.

The governance approach follows the risk-management direction of NIST AI RMF:
govern, map, measure, and manage risk across the lifecycle rather than treating
one benchmark as deployment approval. See the official
[NIST AI RMF 1.0](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf).

## 14. Code and API map

| Surface | Location |
| --- | --- |
| Probe definitions, Bayes update, EIG, policies, simulator | `aegis/steering_research.py` |
| Independent action verification | `aegis/safety.py` |
| Service cache and governed artifact bootstrap | `aegis/service.py` |
| Read/rerun endpoints | `aegis/server.py` |
| Steering Lab | `web/index.html`, `web/app.js`, `web/styles.css` |
| Experiment tests | `tests/test_steering_research.py` |

API endpoints:

- `GET /api/steering/experiment` returns the cached default manifested run;
- `POST /api/steering/experiment/run` reruns a bounded integer seed; and
- `GET /api/governance/status` exposes the steering dataset/model lineage.

Reproduce everything with:

```bash
python -m unittest discover -s tests -v
```

The release gate is intentionally simple: if any test fails, any artifact fails
attestation, the steering result changes unexpectedly, or an unsafe acceptance
is nonzero, v1.0 is not a valid research checkpoint.
