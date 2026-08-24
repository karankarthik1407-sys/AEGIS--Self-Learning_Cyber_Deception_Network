# AEGIS: Safety-Gated Information-Gain Steering for Governed Cyber Deception

Working paper draft 0.1 · AEGIS Research Edition 1.0.0 · 20 August 2026

**Author:** K. Karan Murugan  
**Status:** internal pre-submission draft; not externally validated  
**Disclosure control:** obtain patent/publication-sequence advice before public
release of enabling implementation details.

## Abstract

Cyber deception is often evaluated by engagement duration or alert production,
even though an adaptive defender may need a different objective: selecting the
next bounded interaction that most efficiently separates competing explanations
of observed activity. We present AEGIS, a local-first research architecture for
safety-gated diagnostic deception. AEGIS maintains a calibrated belief state
over intent hypotheses, ranks a fixed set of synthetic decoy probes by expected
information gain under an interaction-cost penalty, and requires an independent
deterministic Safety Kernel to authorize every proposal before an observation
can exist or update the posterior. The learning and release planes are separated:
online posterior updates may occur inside a case, while model or policy artifacts
remain in a governed shadow lifecycle with immutable lineage and a hash-linked
promotion record.

We implement a deterministic synthetic protocol with four intent hypotheses,
four equal-contract probes, four policies, five environment families, and 480
episodes per policy. All 96 episodes in family 4 are held out. At seed 26082026,
the expected-information-gain policy reaches correct posterior confidence of at
least 0.86 in 59.38% of held-out episodes, compared with 18.75% for a static
policy, while reducing the mean failure-penalized interaction count from 8.32 to
7.02. Wrong high confidence is 3.13%, and none of the 13,271 executed actions
across the complete experiment bypasses or violates the defined Safety Kernel
contract. These results establish reproducible implementation evidence only.
The likelihoods, labels, costs, and environment shift are synthetic; no claim is
made about enterprise accuracy, real adversary behaviour, person attribution,
deployment certification, or patent novelty.

**Keywords:** cyber deception; Bayesian experimental design; active learning;
expected information gain; uncertainty; safety kernel; model governance;
honeypot; adversary engagement.

## 1. Introduction

Defensive deception can expose attacker choices that ordinary monitoring cannot
observe directly. A defender can present a synthetic service, credential,
route, or archive and examine whether the observed session engages, inspects, or
declines it. The hard question is not merely whether to deploy a decoy, but which
authorized decoy is most useful now, given the defender's uncertainty and the
risk of changing an environment in response to attacker-controlled input.

Three problems make this question technically important.

First, a source address is neither a stable activity identity nor a human
identity. Shared, proxied, translated, compromised, and rotating infrastructure
requires uncertainty-aware correlation across multiple evidence families.
Second, an adaptive policy can become overconfident under model misspecification
or adversarial responses. A decisive policy may be less reliable than one that
abstains. Third, allowing a learned policy to actuate directly creates a control
hazard: the same hostile observations that influence the model may drive a
world-changing action.

AEGIS addresses these problems by treating a deception action as a constrained
diagnostic experiment. A proposal is useful only if it is expected to reduce
uncertainty; it is executable only if a separate verifier proves that it satisfies
the fixed authorization contract. A model may propose, but it cannot define its
own safety boundary, generate trusted release evidence, or promote itself.

This paper focuses on the smallest falsifiable form of that thesis. It asks:

- **RQ1:** Does expected-information-gain steering reach correct high confidence
  more often and with fewer interactions than static, random, and expert-rule
  selection under a held-out synthetic environment shift?
- **RQ2:** Does the policy preserve probability quality and limit wrong high
  confidence rather than optimizing decisiveness alone?
- **RQ3:** Can the action path enforce a verify-before-observe invariant with
  zero unsafe acceptances under the declared action schema?

The contributions of this artifact are:

1. a declared Bayesian diagnostic-deception objective over an equal action set;
2. a non-bypassable verify-before-observe-and-update execution order;
3. a grouped synthetic protocol with static, random, expert, and adaptive
   comparators plus calibration, abstention, cost, and safety measurements;
4. an artifact-governance embodiment that binds the steering policy to both its
   manifested corpus and Safety Kernel policy; and
5. a reproducible, local-first software artifact with no external target or
   packet effect.

## 2. Scope, threat model, and non-goals

### 2.1 Authorized defensive scope

The operator is assumed to own or have explicit permission to operate the
endpoint, telemetry source, deception namespace, and synthetic assets. The v1.0
experiment does not open a socket to a sensor, scan a target, exploit a host,
route traffic, or deploy a decoy container. It simulates only responses to
declared synthetic probes.

### 2.2 Adversarial influence

The observed party may choose deceptive, noisy, repeated, delayed, or strategic
responses. Therefore, its interaction is evidence—not authority. Online input
may update a case-local posterior, but it cannot rewrite model weights, alter the
Safety Kernel, create a human approval, or satisfy a production-release gate.

### 2.3 Non-goals

AEGIS v1.0 does not:

- identify a person, criminal group, organization, location, or state;
- treat an IP address as an identity;
- pursue an observed party outside the authorized environment;
- generate real credentials or use protected customer data as bait;
- perform hack-back or external disruption;
- claim that synthetic metrics estimate enterprise performance;
- claim formal verification or production certification; or
- claim that any described mechanism is patentable.

## 3. AEGIS system design

### 3.1 Resident product boundary

AEGIS is an installed local control plane, not a hosted website. A resident node
maintains the local evidence and telemetry stores, collectors, inference
services, Safety Kernel, research runners, and loopback API. The browser console
is an analyst view and can close without terminating a Windows Service
installation. Production deployment remains blocked on signing, authenticated
local access, least-privilege service configuration, independent qualification,
and customer-specific legal/privacy review.

### 3.2 Evidence and belief state

Case events use a versioned contract and a per-case SHA-256 chain. Intent
inference retains a distribution over:

\[
\mathcal{H}=\{\text{reconnaissance},\text{credential access},
\text{lateral movement},\text{collection}\}.
\]

For prior \(p(h)\), probe \(a\), and outcome \(y\), the posterior is:

\[
p(h\mid y,a)=\frac{p(y\mid h,a)p(h)}
{\sum_{h'\in\mathcal{H}}p(y\mid h',a)p(h')}.
\]

This belief is an analytical hypothesis distribution. It is not a probability
that a named individual committed an act.

### 3.3 Expected-information-gain steering

The entropy of the current belief is:

\[
H[p]=-\sum_{h\in\mathcal{H}}p(h)\log_2p(h).
\]

Each candidate probe has a declared three-outcome likelihood table. The expected
information gain is:

\[
\operatorname{EIG}(a)=H[p(h)]-
\sum_{y\in\{engage,inspect,decline\}}p(y\mid a)H[p(h\mid y,a)].
\]

The implemented adaptive policy selects:

\[
a^*=\arg\max_{a\in\mathcal{A}}
\left(\operatorname{EIG}(a)-0.035c(a)\right),
\]

where \(c(a)\) is a fixed synthetic interaction cost. Neither 0.035 nor the
costs are claimed to be operationally optimal.

### 3.4 Deterministic Safety Kernel

The proposed action includes its type, target, namespace, decoy-only flag,
egress flag, data classification, reversibility, CPU, memory, time-to-live,
rationale, and identifier. The Safety Kernel separately verifies:

- exact authorized namespace;
- a decoy-only target;
- no network egress;
- synthetic data only;
- reversibility;
- memory, CPU, and lifetime ceilings.

The execution order is:

\[
\text{select}\rightarrow\text{construct}\rightarrow\text{verify}
\rightarrow\text{observe}\rightarrow\text{update}.
\]

A denial produces no outcome and therefore no posterior update. The proposal
policy cannot change the invariant set.

### 3.5 Governed learning

Online posterior adaptation and offline model learning are different state
transitions. Candidate weights or policies must be trained outside the action
path, evaluated on grouped data, run in shadow, and associated with a registered
rollback artifact and independently authorized release evidence. The loopback
API cannot create enterprise validation, shadow volume, or named-reviewer
sign-off. Version 1.0 registers four datasets, five model/decision-policy
descriptors, and one Safety Kernel policy. Local HMAC attestations detect
modification within one installation; they are not organization signatures or
non-repudiation evidence.

## 4. Experimental methodology

### 4.1 Synthetic action set

All policies choose from the same set:

| ID | Probe | Target | Cost |
| --- | --- | --- | ---: |
| P1 | Selective service map | `decoy-edge-service-map` | 0.75 |
| P2 | Synthetic credential note | `decoy-credential-note` | 1.00 |
| P3 | Isolated pivot route | `decoy-pivot-route` | 1.15 |
| P4 | Synthetic archive index | `decoy-archive-index` | 1.25 |

Every target is synthetic, decoy-only, isolated, reversible, time-bounded, and
non-egressing under the action contract.

### 4.2 Environment families

The generator defines five environment families. For family \(f\), the actual
response distribution is flattened relative to the nominal table by
\(0.03f\). The policy and Bayesian update retain the nominal table. Family 4 is
therefore a modest declared observation-model shift, but not an independent
real-world data source.

Each family contains 24 variants for each of four hidden intents, producing 96
episodes per family and 480 episodes per policy. The policy is frozen before
family-4 evaluation.

### 4.3 Comparators

- **Static:** repeatedly selects P1.
- **Seeded random:** samples uniformly from P1–P4.
- **Leading-intent expert rule:** selects the probe mapped to the current
  maximum-posterior hypothesis.
- **AEGIS EIG:** maximizes expected information gain after cost penalty.

The experiment does not yet include a contextual bandit, POMDP, robust Bayesian
design, or constrained reinforcement-learning policy.

### 4.4 Stop, abstention, and failure penalty

An episode stops when the maximum posterior reaches 0.86 or when eight actions
have executed. A correct threshold crossing is a success. A wrong threshold
crossing is wrong high confidence. A non-crossing is an abstention. For the
primary efficiency mean, failure receives an interaction count of nine so that
a policy is not rewarded for failing to decide early.

### 4.5 Metrics

The primary metric is held-out correct high-confidence rate. Secondary metrics
are wrong high-confidence rate, final correctness, abstention, mean penalized
interactions, successful-episode interactions, final entropy, entropy reduction,
expected and observed information gain, probe cost, multiclass Brier score,
expected calibration error, safety permits/denials, unsafe acceptances, and
action distribution.

The v1.0 95% interaction interval uses a normal approximation over episodes.
It is descriptive simulation evidence, not an environment-level uncertainty
estimate. A submission study must use repeated seeds and environment-level
resampling.

### 4.6 Decision gate

The artifact reports `PASSING` only when EIG is the best composite policy, its
correct high-confidence rate exceeds static by at least 0.20, wrong high
confidence is at most 0.05, and unsafe acceptances equal zero. Passing this gate
does not change its `HOLD_SHADOW` promotion status.

## 5. Results

### 5.1 Held-out family

| Policy | Correct ≥ .86 | Wrong ≥ .86 | Final correct | Abstain | Penalized interactions | Final entropy | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Static | 0.1875 | 0.0104 | 0.6146 | 0.8021 | 8.3229 | 1.2354 | 0.4749 | 0.0543 |
| Random | 0.3438 | 0.0521 | 0.6458 | 0.6042 | 7.9167 | 0.9504 | 0.4556 | 0.1101 |
| Expert rule | 0.4479 | 0.1042 | 0.6771 | 0.4479 | 7.6354 | 0.9265 | 0.4570 | 0.0914 |
| AEGIS EIG | **0.5938** | **0.0313** | **0.7813** | **0.3750** | **7.0208** | **0.8486** | **0.2966** | **0.0727** |

The EIG policy improves correct high confidence over static by 0.4063, saves
1.3021 mean penalized interactions, and lowers final entropy by 0.3868 bits.
Its interaction interval is [6.6166, 7.4251].

### 5.2 Probability honesty

The expert rule is more frequently decisive than random, but its wrong high-
confidence rate reaches 0.1042. This exceeds the predeclared 0.05 candidate
limit and is more than three times the EIG rate. The result supports measuring
wrong confidence and abstention alongside success; a controller that forces a
plausible next action around its current leading hypothesis can reinforce an
early error.

### 5.3 Safety path

Across the complete five-family comparison, the Safety Kernel issued 13,271
permits and zero denials because every candidate action was intentionally
contract-valid. No unsafe acceptance was recorded. This result confirms that the
experiment actually invokes the verifier for each executed probe. It does not
measure rejection quality against malformed/adversarial proposals; that remains
a separate expanded Safety Kernel study.

### 5.4 Reproducibility

The manifested run is `STEER-RUN-1B7760DA3CCDAF3A`. The corpus descriptor binds
the generator version, seed, family count, hypotheses, episode count, maximum
interactions, threshold, outcomes, complete probe likelihoods, policy IDs, and
Safety Kernel contract. The complete AEGIS v1.0 suite contains 68 passing tests.

## 6. Discussion

The result supports the limited proposition that diagnostic selection can be
measured separately from engagement and that expected uncertainty reduction is
a useful baseline objective. It also demonstrates a control cooperation:
information value does not grant execution authority, and execution does not
grant model-release authority.

The result does not yet show that EIG is the best operational controller. Its
advantage is evaluated under a simulator related to its nominal likelihood
table. Robust policies may perform better under misspecification; a contextual
bandit or POMDP may capture delayed and strategic responses; and an expert may
assign costs that reverse the synthetic ranking. The current result should be
used to justify the external experiment, not to market a finished autonomous
defense.

The failure-penalized interaction metric is intentionally conservative, but it
also embeds a design choice. Future work should separately report elapsed time,
attacker dwell, analyst effort, decoy resource cost, safe-rejection delay, and
business impact.

## 7. Security, privacy, and ethics

AEGIS adopts five mandatory boundaries:

1. owned or explicitly authorized environments only;
2. synthetic decoys and no protected records or real credentials;
3. no external pursuit, exploitation, disruption, or hack-back;
4. activity correlation is not person or state attribution; and
5. no learned model may bypass the deterministic action or release gates.

Resident telemetry is local-first and minimized. Identity-like fields in the
implemented Windows and sensor import paths are HMAC-pseudonymized before
persistence, command lines and content are discarded, and imported observations
cannot automatically become case allegations or training labels. These choices
reduce retained sensitive data but do not replace deployment-specific privacy,
employment, evidence, or data-residency review.

## 8. Limitations and threats to validity

- **Construct validity:** four intent classes simplify real campaigns and may
  confound means, opportunity, automation, and benign administration.
- **Internal validity:** the simulator is derived from the same nominal
  likelihood family used for policy scoring and posterior updates.
- **External validity:** no live adversary, production workload, external
  authorized range, or independently collected corpus is used.
- **Statistical conclusion validity:** one deterministic seed and episode-level
  intervals do not estimate environment-level uncertainty.
- **Baseline completeness:** modern bandit, POMDP, robust-BED, and RL policies
  are absent.
- **Safety completeness:** valid proposals exercise the permit path, while a
  broader malformed, compromised-policy, and runtime-failure suite is pending.
- **Operational validity:** there is no real decoy deployment, packet action,
  elapsed-time measurement, or Windows qualification in this result.
- **Adversarial validity:** strategic mimicry, poisoning, replay, decoy
  fingerprinting, and compromised-node behaviour remain untested.

## 9. Related work and prior art

Expected information gain is a standard Bayesian experimental-design objective;
AEGIS does not claim to invent it. Rainforth et al. survey modern Bayesian
experimental design, including sequential and deep adaptive methods. Sundin et
al. apply expected information gain to decision-targeted active learning.

MITRE Engage provides a planning framework for cyber denial, deception, and
adversary engagement and emphasizes that deception is an ongoing process. Cyber
deception literature includes adaptive honeynets, moving-target defense, game-
theoretic planning, reinforcement learning, and dynamic orchestration. A proper
submission must compare those mechanisms at the level of objectives, action
sets, safety boundaries, and evaluation conditions.

Patent literature is also material. US11934948B1 describes observation-driven
adaptive deception and hypothesis-test adaptation; US12425417B2 describes cyber-
deception strategy generation involving machine learning and information theory;
and US20240333765A1 describes LLM-generated honeypot content and interaction-based
retraining. These references make broad “adaptive” or “self-learning” deception
an unsuitable novelty claim. Any AEGIS invention hypothesis must be evaluated
against individual claim limitations and combinations by a qualified
professional before an enabling public disclosure.

NIST AI RMF motivates lifecycle-wide governance, measurement, and management of
AI risks. AEGIS uses it as engineering guidance and does not claim certification.

## 10. Required submission extension

Before this draft can become a submission, the study should:

1. pre-register thresholds, metrics, failure gates, and analysis;
2. collect time-separated data from at least three independently configured
   owned/authorized ranges;
3. include benign operators, maintenance tools, automation, and realistic class
   prevalence;
4. compare static, random, expert, contextual-bandit, robust-EIG, POMDP, and
   constrained-RL policies under equal actions and safety budgets;
5. evaluate likelihood misspecification, strategic mimicry, poisoning, replay,
   missing/delayed telemetry, and decoy fingerprinting;
6. report repeated seeds, environment-level bootstrap intervals, effect sizes,
   calibration, abstention, latency, resource use, and safe rejection;
7. independently freeze and reproduce the artifact on a clean machine;
8. qualify the resident runtime and isolated decoy adapters; and
9. complete ethics, legal, privacy, and patent/publication-sequence review.

## 11. Artifact statement

The v1.0 Research Edition uses Python 3.10 or newer and the standard library.
The steering implementation is in `aegis/steering_research.py`; safety checks
are in `aegis/safety.py`; governance is in `aegis/registry.py`; the service/API
surface is in `aegis/service.py` and `aegis/server.py`; and the experiment tests
are in `tests/test_steering_research.py`. Reproduce with:

```bash
python -m unittest discover -s tests -v
```

The Research Edition contains no external target configuration and no packet-
effecting adapter. All built-in threat/steering results are synthetic. AEGIS
must remain in shadow until external authorization, validation, signing,
rollback, and human-release evidence exists.

## References

1. T. Rainforth et al., “Modern Bayesian Experimental Design,” 2023.
   <https://arxiv.org/abs/2302.14545>
2. I. Sundin et al., “Targeted Active Learning for Bayesian Decision-Making,”
   2022. <https://arxiv.org/abs/2106.04193>
3. MITRE, “Engage: An Adversary Engagement Framework.”
   <https://engage.mitre.org/>
4. NIST, “Artificial Intelligence Risk Management Framework (AI RMF 1.0),”
   NIST AI 100-1, 2023.
   <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf>
5. U.S. Patent No. 11,934,948, “Adaptive deception system.”
   <https://patents.google.com/patent/US11934948B1/en>
6. U.S. Patent No. 12,425,417, “Systems and methods for generation and
   implementation of cyber deception strategies.”
   <https://patents.google.com/patent/US12425417B2/en>
7. U.S. Patent Application Pub. No. 2024/0333765, “Method for using generative
   large language models for cybersecurity deception and honeypots.”
   <https://patents.google.com/patent/US20240333765A1/en>
