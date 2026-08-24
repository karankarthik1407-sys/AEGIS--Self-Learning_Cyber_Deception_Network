# Contributing to AEGIS

AEGIS is presently a private, solo-maintainer research and product-development
repository. Contributions are accepted only through an explicitly authorized
collaboration.

## Working agreement

1. Create a focused branch from `main`: `feature/...`, `fix/...`,
   `research/...`, `docs/...` or `release/...`.
2. Keep commits small and use Conventional Commit prefixes such as `feat:`,
   `fix:`, `test:`, `docs:`, `research:` or `build:`.
3. Open a pull request. Do not push a release directly to `main`.
4. Complete the test, security, research-integrity and disclosure sections in
   the pull-request template.
5. Merge only after required checks pass and the change is reviewable from its
   recorded evidence.

## Local verification

```bash
python -m pip install -e .
python -m compileall -q aegis tests tools
python tools/ci/check_repository_hygiene.py
python tools/ci/check_version_contract.py
python tools/ci/check_ui_contract.py
python -m unittest discover -s tests -v
```

Windows packaging changes must additionally pass
`packaging/windows/Build-AEGIS-Desktop.ps1` on a clean Windows runner.

## Research changes

A research pull request must identify the hypothesis, comparator, dataset
contract, split boundary, random seeds, metrics, expected failure modes and
artifact hashes. Test data must be synthetic, public under compatible terms, or
covered by documented authorization. A single favourable run is not evidence
of generalization.

Models remain shadow candidates until the promotion gate records calibration,
safety, regression, provenance and rollback evidence. Learned output never
bypasses the deterministic Safety Kernel.

## Material that must never be committed

- credentials, tokens, passwords, private keys or code-signing material;
- issued customer licenses or the offline license-authority private key;
- runtime databases, raw telemetry, packet payloads or personal data;
- production endpoints, exploit payloads or unauthorized target information;
- generated release packages, model weights or evidence exports; and
- patent-sensitive disclosure not approved under `docs/IP_DISCLOSURE_POLICY.md`.

Use GitHub's private vulnerability-reporting path for security findings. Do not
place exploit details in a normal issue or pull request.
