# Confidential research and IP disclosure policy

This document is an engineering control, not legal advice. A qualified patent
professional must assess inventorship, ownership, prior art, enablement and
filing strategy before any public disclosure.

## Default classification

All AEGIS source, model designs, experiment protocols, unpublished results,
research notebooks, diagrams and invention records are **confidential —
patent-sensitive** unless explicitly reclassified in writing.

| Class | Examples | Allowed destination |
|---|---|---|
| Public | Approved overview with no enabling detail | Approved public channel |
| Internal | Build instructions and ordinary product operations | Private repository |
| Confidential | Unpublished results, architecture details, model artifacts | Named authorized collaborators |
| Patent-sensitive | Candidate mechanisms, claim maps, enabling experiments | Restricted private records and counsel |

## Disclosure gate

Before a repository, release, paper, poster, preprint, presentation, demo video
or competition submission becomes public, record all of the following:

- the exact material and commit or artifact hash;
- candidate invention(s) and named human inventor(s);
- completed prior-art and claim-scope review;
- written approval from the owner and patent professional;
- the applicable filing reference and filing date, when a filing is chosen;
- third-party data, code, license and confidentiality review; and
- the approved publication date and channel.

Until that record exists, the GitHub repository stays private and no enabling
implementation detail is copied into public issues, gists, discussions, model
hubs, package indexes or AI benchmark leaderboards.

## Invention evidence

For each candidate, preserve dated human conception notes, the technical
problem, mechanism, alternatives considered, experimental evidence, code and
artifact hashes, contributors, negative results and disclosure history. Git
history supports provenance but does not itself determine legal inventorship.

## Operational data boundary

Never use the repository for customer telemetry, raw IP addresses, packet
payloads, authentication data, personal information, private keys or issued
licenses. Experiments use synthetic, properly licensed or explicitly authorized
data and retain only the minimum necessary evidence.
