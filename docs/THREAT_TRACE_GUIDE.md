# AEGIS Threat Trace Guide

Version 0.6.0 · research and product companion · 20 August 2026

## 1. What AEGIS is tracking

AEGIS does not “lock onto a cybercriminal.” It constructs a defensible,
uncertainty-aware relationship between observations gathered inside systems the
defender is authorized to monitor. The output is an **activity cluster**: a set
of sessions that may share control, tooling, infrastructure or a playbook.

That distinction is essential:

| Question | v0.6 answer |
| --- | --- |
| Are these two authorized observations technically related? | AEGIS estimates this, with calibrated uncertainty and alternatives. |
| Did the apparent source reference rotate? | AEGIS can show that the references differ and evaluate other evidence. |
| Which evidence supports the relationship? | The report exposes every available family, overlap score and contradiction. |
| Is a particular person behind the activity? | Not inferred. That requires independent, lawfully obtained evidence. |
| Will AEGIS scan or pursue the source? | No. There is no outbound tracking, external scanning, exploitation or hack-back path. |

This is useful to incident responders because one operation may appear across
different addresses, accounts, hosts or time windows, while one address may be
shared by unrelated activity.

## 2. Why an IP address is context, not identity

An address may represent a carrier-grade NAT gateway, VPN exit, cloud instance,
forward proxy, compromised relay, shared office, mobile connection or reassigned
lease. Attackers can rotate it, and unrelated users can share it. AEGIS therefore
uses an address only after an approved adapter converts it to an opaque local
reference. The trace layer rejects a raw IPv4 or IPv6 value even if a faulty
adapter places it in another signal field.

The source family has the smallest configured weight, lower reliability and the
highest spoofability. A source match alone is capped below high confidence. A
source mismatch is a small contradiction—not proof that the sessions are
unrelated.

RFC 5737 documentation-address semantics are used when a paper, fixture or
diagram needs an address example. No experiment contacts those ranges or any
external target.

## 3. Threat Trace contract

The contract is `aegis.threat-trace.v1`. It consumes ordered, authorized case
events and produces:

- canonical per-session signal profiles;
- pairwise activity-link probabilities;
- evidence-family contributions and contradictions;
- alternative explanations;
- an activity-cluster graph and cross-session timeline;
- a hard `identity_claim: false` boundary;
- a source policy that forbids raw IPs, single-signal high confidence, external
  scanning, outbound pursuit and hack-back; and
- a SHA-256 manifest over the complete report.

The report borrows observed-data and relationship ideas from STIX 2.1 but does
not claim to be a complete STIX bundle. ATT&CK technique metadata remains attached
to timeline observations. A later connector can produce strict STIX objects
after conformance tests are added.

## 4. Signal families

| Family | Examples retained as opaque references | Base weight | Reliability | Spoofability | Failure mode |
| --- | --- | ---: | ---: | ---: | --- |
| Source | Locally pseudonymized source reference | 0.06 | 0.45 | 0.78 | Rotation, NAT, VPN, relay, reassignment |
| Infrastructure | Provider, ASN, domain cluster, certificate relationship | 0.13 | 0.58 | 0.58 | Shared hosting, rented infrastructure, copied certificate |
| Transport | TLS/SSH/client-transport profile | 0.20 | 0.78 | 0.34 | Common libraries, deliberate mimicry |
| Tooling | Client, user-agent or toolchain profile | 0.17 | 0.68 | 0.46 | Commodity kits, forks, stolen tooling |
| Behaviour | Technique, target family, route choice and ordered sequence | 0.24 | 0.72 | 0.40 | Common objective or copied playbook |
| Deception | Response to a controlled lure or canary family | 0.20 | 0.90 | 0.14 | Range construction or leaked lure knowledge |

The configured values are research priors, not universal truth. An enterprise
must recalibrate them on authorized data from multiple environments and time
periods.

## 5. How the evidence-diversity linker works

For each family, AEGIS computes Jaccard overlap between the two sets of retained
references. Behaviour also includes longest-common-subsequence similarity over
the ordered event types:

\[
s_{behaviour}=0.65J(A,B)+0.35\frac{LCS(A,B)}{\max(|A|,|B|)}
\]

Each family has an effective weight:

\[
w'_f=w_f r_f(1-0.5q_f)
\]

where \(w_f\) is the configured weight, \(r_f\) is reliability and \(q_f\) is
spoofability. Available evidence is fused as:

\[
z=\frac{\sum_f w'_f s_f}{\sum_f w'_f}
  +b_{diversity}-p_{contradiction}
\]

The current diversity bonus rises as independent families agree and is capped
at 0.10. A complete non-source contradiction costs 0.04; a source-reference
change costs only 0.012. A logistic transform maps the bounded score to a
research probability. Diversity gates then cap fewer than two matching families
at 0.49 and fewer than three at 0.69.

These gates prevent one address, certificate or fingerprint from creating a
high-confidence link. They are deterministic and inspectable. The calibration
metadata travels with every result.

## 6. The learned shadow candidate

The second implementation is a dependency-free binary logistic model over nine
pair features:

- six family similarities;
- matched-family diversity;
- divergent-family fraction; and
- the weighted evidence score.

It is trained only on grouped training environments. Temperature and decision
threshold are selected only on the validation environment. It has no authority
to replace the deterministic linker or control an actuator; its promotion state
is `HOLD_SHADOW`.

This is the present ML step. Future neural candidates—Siamese temporal encoders,
temporal graph networks or calibrated metric-learning models—must run under the
same grouped split, hard negatives, calibration measures and identity boundary.
“Deep learning” is not accepted as an improvement unless an ablation proves it.

## 7. Reproducible experiment EXP-TRACE-LINK-001

The seeded generator creates 240 synthetic sessions: eight campaign labels,
five environment families and six variants. It creates 240 balanced pairs:

- 120 positives with rotating source references; and
- 120 hard negatives that deliberately share a provider, source slot or toolkit.

Environment families 0–2 train, family 3 validates and family 4 tests. No family
crosses a partition. The split is 144/48/48 pairs.

Seed `26082026` currently produces:

| Model | Test F1 | Brier | False-link rate | Missed-link rate | Interpretation |
| --- | ---: | ---: | ---: | ---: | --- |
| Source-reference only | 0.286 | 0.566 | 1.000 | 0.667 | Demonstrates why one address/reference is unsafe as identity |
| Single transport/tool profile | 0.800 | 0.146 | 0.000 | 0.333 | Useful but misses rotated/mimicked profiles |
| Fixed evidence-diversity fusion | 0.769 | 0.152 | 0.000 | 0.375 | Conservative, inspectable research linker |
| Diversity-feature logistic candidate | 0.979 | 0.041 | 0.000 | 0.042 | Best synthetic result; held in shadow |

The source baseline’s 1.000 false-link rate is a property of this deliberately
difficult synthetic test set, not a measurement of the Internet. The learned
candidate’s strong result is also synthetic and must not be presented as live
enterprise accuracy.

Reproduce both the experiment and all quality gates:

```bash
python -m unittest tests.test_trace tests.test_trace_research -v
python - <<'PY'
from aegis.trace_research import run_trace_experiment
report = run_trace_experiment()
print(report["run_id"], report["winner"]["test"])
PY
```

## 8. Analyst workflow

1. Confirm the monitored assets, evidence sources and investigation are
   authorized.
2. Inspect source references as context; never copy the displayed score into an
   identity claim.
3. Require multiple independent families before treating sessions as related.
4. Review divergent families and every alternative explanation.
5. Inspect chronology, clock quality, collector provenance and missing evidence.
6. Export the manifested trace and preserve the underlying case evidence.
7. If lawful human identification is necessary, hand the technical hypothesis
   to authorized investigators. Provider records, warrants, account ownership,
   endpoint forensics and other legal/contextual evidence remain outside AEGIS.
8. Record whether the link was confirmed, rejected or unresolved so it can
   become governed feedback—not an automatic live label.

## 9. Enterprise adapter path

The trace engine is deliberately independent of any one sensor. Planned,
read-only adapters can normalize approved fields from:

- Suricata EVE JSON flows and alerts, using `flow_id` only as local correlation
  context;
- Zeek protocol logs and analyzer output;
- identity-provider authentication events;
- endpoint-detection and response events;
- DNS, certificate and cloud-control-plane audit evidence; and
- AEGIS-controlled lures and canaries.

Raw sensor records should stay in the organization’s approved forensic system.
The AEGIS adapter should emit bounded references and provenance. This preserves
local linkage utility while reducing the sensitive material copied into the
learning and correlation plane.

## 10. Threats to validity and abuse resistance

- Synthetic campaign labels encode assumptions made by the generator.
- Tooling, certificates, transport profiles and behaviours can all be copied.
- Deception responses can be biased if lure design leaks campaign structure.
- Correlated signal families can create false diversity; future work must model
  conditional dependence.
- Missing or delayed sensors can create false contradictions.
- A compromised adapter could forge opaque references; production needs signed
  node identity, schema validation, provenance and replay protection.
- Pairwise linkage does not automatically yield correct multi-session clusters.
- Dataset shift can destroy calibration even when ranking performance remains.
- Analyst confirmation can introduce feedback bias and should not become an
  unquestioned training label.

## 11. Standards and primary references

- NIST SP 800-61 Rev. 3, *Incident Response Recommendations and Considerations
  for Cybersecurity Risk Management*: <https://csrc.nist.gov/pubs/sp/800/61/r3/final>
- OASIS STIX 2.1 specification: <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html>
- MITRE ATT&CK Data Sources: <https://attack.mitre.org/datasources/>
- MITRE ATT&CK Network Traffic Flow data component:
  <https://attack.mitre.org/datacomponents/DC0078/>
- MITRE ATT&CK User Account Authentication data component:
  <https://attack.mitre.org/datacomponents/DC0002/>
- Suricata 8 EVE JSON output: <https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-output.html>
- Zeek protocol analyzer reference: <https://docs.zeek.org/en/current/reference/zeekscript/proto-analyzers.html>
- RFC 5737 IPv4 documentation blocks: <https://www.rfc-editor.org/info/rfc5737/>

These references guide terminology and future connector design. They do not
certify AEGIS, establish STIX conformance, prove scientific validity or support
a patentability conclusion.

## 12. Learning checkpoints

You should be able to explain the following before treating v0.6 as complete:

1. Why can two different source references still describe related activity?
2. Why can one shared source reference create a false link?
3. What is the difference between evidence ranking, activity linkage and human
   attribution?
4. Why are grouped environment splits stronger than a random pair split?
5. What do Brier score, false-link rate and calibration error reveal that F1
   does not?
6. Why must a learned linker remain in shadow even after a strong synthetic
   result?
7. Which signals are likely conditionally dependent, and how would that affect
   the diversity bonus?
8. What evidence must an enterprise collect before recalibrating the model?
