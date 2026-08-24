# AEGIS preliminary prior-art matrix

Version 1.0.0 · engineering search checkpoint · 20 August 2026

This matrix records a preliminary, non-exhaustive engineering review. It is not
a legal search, claim construction, freedom-to-operate opinion, validity opinion,
or patentability determination. “Not located” means only that the feature was
not found in the limited passages reviewed; it does not mean the feature is
absent from the full reference, its family, cited art, or other literature.

## Candidate cooperation under review

| ID | Proposed AEGIS limitation |
| --- | --- |
| L1 | Maintain explicit uncertainty over multiple cyber-activity intent hypotheses |
| L2 | Select from an equal, pre-authorized decoy action set by expected reduction in intent entropy under bounded cost |
| L3 | Convert the selected probe into a complete action and require an independent machine-checkable safety certificate before an outcome may exist |
| L4 | On denial, create no synthetic observation and perform no posterior update |
| L5 | Stop at a declared calibrated-confidence threshold and preserve abstention; constrain wrong high confidence |
| L6 | Bind the shadow steering artifact to both a manifested experiment dataset and the exact Safety Kernel policy through immutable lineage |
| L7 | Keep production release facts outside the model/browser authority and record every promotion evaluation in an immutable chain |
| L8 | Future embodiment: an attested hardware boundary accepts only certificate-bound, short-lived, reversible decoy manifests and returns a linked receipt |

The candidate is the cooperation, not any individual item. Entropy, Bayes' rule,
HMAC, hash chains, decoys, policy checks, hardware attestation, and model
registries are all established concepts.

## Reference matrix

| Reference | Clearly relevant disclosure located | AEGIS limitations requiring deeper claim-chart review |
| --- | --- | --- |
| [US11934948B1 — Adaptive deception system](https://patents.google.com/patent/US11934948B1/en) | Observation-driven adaptation; a control system; hypothesis-test adaptation; new hypotheses; actuators implementing deception changes | L1 is closely related. L2 may be implicated by hypothesis-test selection. L3–L8 were not established as absent; full claims/specification and cited family must be charted. |
| [US12425417B2 — Generation and implementation of cyber deception strategies](https://patents.google.com/patent/US12425417B2/en) | Surveillance inputs; latent-parameter model; multi-stage ML; game-theoretic/ probabilistic/information-theoretic planning; ranked deception plans and possible deployment | L2 may be implicated by optimized/information-theoretic selection. Examine plan constraints, verification, deployment ordering, lineage and temporal operation against L2–L8. |
| [US20240333765A1 — LLM cybersecurity deception and honeypots](https://patents.google.com/patent/US20240333765A1/en) | LLM-generated deceptive content; interaction monitoring; behavioural extraction; retraining from interactions | Crowds generic “AI-generated/self-learning honeypot” language. Examine whether safety gating, release governance or bounded probe selection appears in dependent claims. |
| [US20250254196A1 — Adaptive deception orchestration](https://patents.google.com/patent/US20250254196A1/en) | Behavioural honeypot network; orchestrated attack paths; near-real-time activity tracking; camouflaged collection | Crowds behavioural tracking and orchestration. Compare isolation, action selection, data transport, safety ordering and TTP-path construction. |
| [US20170134423A1 — Decoy and deceptive data objects](https://patents.google.com/patent/US20170134423A1/en) | Deceptive data objects, breadcrumbs, decoy systems and monitoring interactions in a protected environment | Crowds decoy artifacts and monitored use. Examine adaptive selection, placement and interaction-triggered changes. |
| [Targeted Active Learning for Bayesian Decision-Making](https://arxiv.org/abs/2106.04193) | Sequential expected-information-gain selection for uncertainty over an optimal downstream decision | Strong non-patent prior art for generic L2 mathematics outside cyber deception. Any claim must require a technical cyber/safety cooperation rather than EIG itself. |
| [Modern Bayesian Experimental Design](https://arxiv.org/abs/2302.14545) | Broad treatment of EIG, sequential design, robust design and deep adaptive design | Confirms that EIG, cost-aware experimental selection and learned design policies are established. |
| [MITRE Engage](https://engage.mitre.org/) | Planning framework for denial, deception and adversary engagement; deception as a continuing process | Crowds broad process framing. Compare operational planning and safeguards, but do not imply a patent reference establishes all limitations. |
| [NIST AI RMF 1.0](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf) | Lifecycle governance, mapping, measurement and management of AI risk with defined human roles | Strong governance background; L6–L7 must be technically specific beyond ordinary responsible-AI lifecycle controls. |

## Initial risk assessment

| Area | Preliminary crowding | Engineering consequence |
| --- | --- | --- |
| Adaptive/feedback-driven deception | Very high | Do not use as the novelty statement. |
| ML or LLM honeypot generation | Very high | Keep generated content outside the primary claim thesis. |
| Information-gain action selection | High in general active learning; unresolved in exact cyber cooperation | Treat EIG as known mathematics and focus only on a non-obvious technical combination, if any. |
| Safety/policy checks before actuation | High across control and policy systems | Ordinary boolean checks are not enough; define certificate structure, temporal ordering, failure semantics and measurable effect. |
| Artifact lineage and promotion governance | High across MLOps/supply-chain systems | Tie any candidate narrowly to the deception action/evidence lifecycle and compare against standard registries. |
| Attested SmartNIC/DPU/FPGA enforcement | High but implementation-specific | A future physical prototype and separate network/hardware search are mandatory. |
| Person/criminal attribution | Outside the designed claim and unsafe analytical scope | Maintain an explicit non-identity boundary. |

## Narrow questions for counsel and professional search

1. Does any reference or combination disclose a verifier that must certify a
   diagnostic deception action before the system is permitted to create the
   observation used for the next inference update?
2. Is “no observation/no update on denial” a technical control effect or merely
   an obvious consequence of ordinary authorization?
3. Does binding the steering policy to both its experiment dataset and exact
   safety policy produce a non-obvious technical effect beyond standard MLOps
   lineage?
4. Are wrong-confidence and abstention constraints part of the controller or
   only evaluation criteria, and how does that affect claim scope?
5. Does a hardware embodiment add a patentable technical limitation, or is it an
   obvious placement of known verification/rollback mechanisms on a DPU/FPGA?
6. Which jurisdictions treat the software/algorithm portions as eligible subject
   matter, and what concrete network/computer effect must be demonstrated?
7. What disclosure has already occurred, to whom, under what confidentiality,
   and how does that affect filing options?

## Required next search actions

- retrieve full patent families, prosecution histories, classifications,
  backward citations and forward citations for each reference;
- search CPC/IPC classes rather than relying on keywords;
- add non-patent literature on adaptive honeypots, POMDP/cyber-deception games,
  policy-as-code, proof-carrying authorization, MLOps lineage, transparency logs,
  and attested network enforcement;
- chart every independent claim and the most relevant dependent claims against
  L1–L8 with direct quotations and page/claim citations;
- separate novelty, inventive step/non-obviousness, eligibility, enablement and
  freedom-to-operate analyses; and
- record a filing/publication decision before releasing an enabling paper,
  repository, poster, demo, or competition submission.
