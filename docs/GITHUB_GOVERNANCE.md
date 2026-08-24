# GitHub governance

## Repository status

`karankarthik1407-sys/AEGIS` is the canonical private engineering repository.
It must remain private until the disclosure gate in
`IP_DISCLOSURE_POLICY.md` is satisfied. Downloadable release archives are
outputs of a tagged, verified source revision; they are not the source of truth.

## Branch model

- `main` — reviewable, releasable source; never force-push.
- `feature/*` — product capability.
- `research/*` — experiment or model work.
- `fix/*` — defect or security correction.
- `docs/*` — documentation-only change.
- `release/*` — bounded release preparation.

All normal changes enter `main` through a pull request. Squash merge is the
default so the mainline remains easy to audit. A release tag is created only
from a passing `main` revision and uses `vMAJOR.MINOR.PATCH`.

## Required review evidence

Every pull request records:

- purpose and affected trust boundary;
- tests and validation commands actually executed;
- security, privacy and authorization impact;
- model/data/provenance impact when applicable;
- compatibility, rollback and migration notes; and
- public-disclosure/IP classification.

Research changes additionally record a falsifiable hypothesis, baselines,
split policy, seeds, metrics, failure analysis and output hashes. Negative
results are retained when they alter a design or research conclusion.

## Recommended `main` ruleset

The repository owner should configure the following GitHub rules after the
initial CI workflow has completed once:

1. require a pull request before merging;
2. require `Unit tests`, `Repository contracts` and `UI contract` checks;
3. require conversations to be resolved;
4. block force pushes and branch deletion;
5. require linear history;
6. allow squash merges and disable merge commits; and
7. include administrators, with an emergency bypass recorded in an issue.

The initial import is deliberately staged on a feature branch so these checks
can run before `main` receives the source.

## Release discipline

1. Update the single version contract across Python, Windows metadata and
   installer declarations.
2. Run the full source suite and clean-install test.
3. Build Windows executables on a clean Windows runner.
4. Verify the executable smoke check and checksum manifest.
5. Update the changelog and validation report.
6. Tag the reviewed `main` commit.
7. Keep private keys, issued licenses and code-signing credentials outside the
   repository and outside workflow logs.

## Ownership

The current owner and required reviewer is `@karankarthik1407-sys`. Future
collaborators receive the minimum repository role required and must accept the
confidentiality, contribution and disclosure terms established for that work.
