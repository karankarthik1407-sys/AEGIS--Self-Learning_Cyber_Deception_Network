# AEGIS Graph Research Guide

Version 0.8.0 · transitivity-safety checkpoint · 20 August 2026

## Purpose

Threat Trace estimates whether two authorized activity sessions may belong to
the same campaign. A graph layer has a harder job: it must turn many local pair
scores into coherent campaign hypotheses. Ordinary connected components are
unsafe for this purpose. If A links to B and B links to C, the algorithm merges
A, B and C even when A and C have no supporting relationship.

Version 0.8 establishes an interpretable safety baseline for that problem. It
does not identify a person, organization, location or state. Its nodes are
synthetic activity sessions and its reference labels are synthetic campaigns.

## Implemented experiment

`aegis.trace-graph.v1` is represented by the deterministic function
`run_trace_graph_experiment`. It reuses the v0.6 synthetic session generator and
the evidence-diversity pair features, then evaluates the full held-out graph.

| Partition | Environment families | Pair use | Count |
| --- | --- | --- | ---: |
| Training | 0, 1, 2 | Balanced rotating-source positives and shared-infrastructure hard negatives | 144 |
| Validation | 3 | Every unordered pair among 48 sessions | 1,128 |
| Test | 4 | Every unordered pair among 48 sessions | 1,128 |

No test-family session is used to fit the logistic edge model, temperature,
classification threshold, graph seed threshold, association threshold or
minimum cross-support. The complete corpus, split and selected settings are
hashed into a dataset digest and deterministic run ID.

## Why all-pairs evaluation matters

The earlier pair experiment uses a balanced diagnostic set so model differences
are visible. A campaign graph is naturally imbalanced: among 48 test sessions,
only 120 of the 1,128 possible pairs are same-campaign pairs. Evaluating all
pairs exposes false positives that would be hidden by a small paired sample and
shows their global effect under transitive closure.

## Three methods

### 1. Source-reference connected components

An edge exists whenever two sessions share a pseudonymous source reference.
This is deliberately weak. Addresses can be shared, relayed, reassigned,
proxied or imitated, so the baseline both merges unrelated campaigns and splits
campaigns that rotate infrastructure.

### 2. Naive learned-edge connected components

The diversity-feature logistic linker produces a calibrated local probability.
Every edge above the validation-selected pair threshold is accepted, then
ordinary union-find computes connected components. Local classification can be
good while the global graph is catastrophically wrong: one false edge can join
two otherwise correct cohorts.

### 3. AEGIS cohort-supported graph guard

The candidate processes edges from strongest to weakest and applies four
interpretable checks before merging two components:

1. The proposed edge must match at least three evidence families.
2. A singleton-to-singleton seed must clear a high seed threshold.
3. A merge involving an existing cohort must have sufficient support across
   all cross-component pair scores—not only the proposed bridge.
4. The resulting cluster cannot exceed the configured research size cap.

The association threshold, seed threshold and cross-support requirement are
selected using family 3 only. They are frozen before family 4 is evaluated.
Every injected stress edge receives an explicit `MERGE` or `REJECT` record with
its local probability, cross-support, mean cross probability, proposed size and
reason.

## Adversarial bridge-chain protocol

Seven cross-campaign edges join campaign 0 to 1, 1 to 2, and so on through
campaign 7. Each injected edge has three apparent evidence families and a local
probability high enough for naive pair-threshold closure. The chain therefore
tests the exact claim: can cluster-level evidence stop a plausible local error
from becoming a graph-wide false conclusion?

For seed `26082026`:

| Method | Stress B³-F1 | False-merge rate | Split-campaign rate | Largest cluster |
| --- | ---: | ---: | ---: | ---: |
| Source-reference components | 0.438 | 0.636 | 1.000 | 6 |
| Naive learned-edge components | 0.222 | 0.894 | 0.000 | 48 |
| AEGIS cohort-supported guard | 1.000 | 0.000 | 0.000 | 6 |

The guard rejects all seven injected bridges and returns eight six-session
cohorts. This is a result on a deterministic synthetic stress corpus. It is not
an enterprise performance estimate and must not be quoted as real-world
attribution accuracy.

## Metrics

Pairwise metrics count all unordered session pairs. A false merge is a pair
placed in the same predicted cluster despite different reference campaigns.

B³ evaluates each session independently. For session `i`:

\[
P_i = \frac{|C(i) \cap L(i)|}{|C(i)|}, \qquad
R_i = \frac{|C(i) \cap L(i)|}{|L(i)|}
\]

where `C(i)` is the predicted cluster and `L(i)` is the reference-label set.
The experiment averages member precision and recall, then takes their harmonic
mean. This exposes both over-merging and over-splitting without requiring
predicted cluster identifiers to match reference identifiers.

The report also includes purity, split-campaign rate, number of clusters,
largest-cluster size and a pair confusion matrix. A single headline score is
never sufficient to judge a security clustering system.

## What the result proves—and does not prove

It proves that the implementation is deterministic, that grouped leakage
controls are enforced, that the bridge audit is inspectable, and that this
specific cohort guard survives this specific synthetic stress protocol better
than the two implemented baselines.

It does not prove:

- that the synthetic generator reflects operational campaign prevalence;
- that a cluster corresponds to a human, criminal group or government;
- that the current thresholds generalize across enterprises;
- that a temporal graph neural network would not perform better;
- that the system is ready to promote graph output into automatic response;
- that the mechanism is novel or patentable.

The candidate remains `HOLD_SHADOW`. Operational use requires authorized,
multi-environment longitudinal evidence, analyst adjudication, calibration
drift monitoring and a signed model/data registry.

## How to reproduce

```bash
python -m unittest tests.test_trace_graph_research -v
python -m unittest discover -s tests -v
```

From the installed loopback application:

- `GET /api/trace/graph-experiment` returns the cached default run.
- `POST /api/trace/graph-experiment/run` reruns a bounded integer seed.
- Graph Lab renders the method comparison, guard settings, bridge decisions,
  dataset digest and guarded clusters.

## Code map

| File | Responsibility |
| --- | --- |
| `aegis/trace_graph_research.py` | all-pairs construction, pair scoring, union-find baselines, cohort guard, stress injection, metrics and manifest |
| `aegis/trace_research.py` | synthetic sessions, grouped hard-negative pair corpus and logistic edge model |
| `aegis/trace.py` | evidence-family scoring and raw-IP-refusing trace contract |
| `aegis/service.py` | cached experiment service boundary |
| `aegis/server.py` | loopback graph experiment APIs |
| `web/index.html`, `web/app.js`, `web/styles.css` | Graph Lab workspace |
| `tests/test_trace_graph_research.py` | split, metric, determinism, bridge, comparative and safety contracts |

## Next graph research

The next scientific comparator should preserve this interpretable guard as a
baseline. Candidate work includes time-respecting edge construction, rolling
evaluation, calibrated abstention, graph perturbation tests, label-delay
simulation and compact temporal graph models. Temporal Graph Networks and TGAT
are relevant primary research starting points:

- [Temporal Graph Networks](https://arxiv.org/abs/2006.10637)
- [Inductive Representation Learning on Temporal Graphs (TGAT)](https://arxiv.org/abs/2002.07962)

MITRE ATT&CK campaign data may inform schema design and evaluator terminology,
but any operational dataset must respect its provenance and licensing, and
ATT&CK mappings must not be treated as identity proof:

- [MITRE ATT&CK campaigns](https://attack.mitre.org/campaigns/)
- [MITRE ATT&CK data and tools](https://attack.mitre.org/resources/attack-data-and-tools/)
