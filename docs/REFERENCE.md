# Reference

Details moved out of the README. For the measured results and their limits see [STUDY.md](STUDY.md).

## Common reporting model

Integrated scanners are normalized into a shared `Finding` model so downstream automation can consume results consistently.

Supported outputs include terminal reports, normalized JSON, SARIF 2.1.0, Markdown summaries, severity gates, and reusable baselines. Every normalized finding carries a stable fingerprint plus confidence, target, evidence, and remediation metadata where available.

```bash
aisec scan . --write-baseline .aisec-baseline.json
aisec scan . --baseline .aisec-baseline.json --fail-on high
```

## Finding lifecycle

Baselines are fingerprint-based and remain stable across line-number shifts. When a baseline is supplied, the scanner classifies findings as **new**, **existing**, or **resolved**:

```bash
aisec scan . --baseline .aisec-baseline.json --json findings.json
# lifecycle: new=2 existing=5 resolved=1
```

Only new findings remain in the active finding output, so `--fail-on` evaluates newly introduced risk rather than repeatedly failing on already-accepted findings. Resolved fingerprints are reported for cleanup and audit visibility.

## Policy as code

Use a versioned JSON policy to define enforcement and narrowly scoped finding exclusions:

```bash
aisec scan . --all --policy examples/security-policy.json
```

Policy version 1 supports:
- `fail_on`: `low`, `medium`, `high`, or `critical`
- `exclude`: selectors for `scanner`, `rule`, `file`, and `severity`
- shell-style glob matching for selectors

Exclusions are explicit and visible in scan warnings; default behavior is unchanged without a policy file. Keep policy files in version control and review exclusions like code.

## Policy profiles

For teams that do not need a checked-in policy file, the CLI provides deterministic enforcement profiles:

| Profile | Fails at | Intended use |
|---|---|---|
| `strict` | low | release/security validation |
| `balanced` | high | normal CI |
| `dev` | critical | local development |

```bash
aisec scan . --all --policy-profile balanced
aisec policy init examples/security-policy.json --profile balanced
aisec policy show balanced
aisec policy validate examples/security-policy.json
```

`aisec policy init` creates a reviewable policy from a deterministic profile and refuses to overwrite an existing file unless `--force` is supplied.

A checked-in `--policy` file and `--policy-profile` are mutually exclusive. A policy file's `fail_on` value overrides the CLI threshold, while exclusions are always surfaced in warnings.

`aisec policy validate` rejects unknown top-level fields, unsupported versions, malformed exclusions, and invalid severities so policy drift fails closed.

## Security reporting and triage

When `GITHUB_STEP_SUMMARY` is available, every scan writes a concise security report to the GitHub Actions job summary. The report includes severity counts, baseline lifecycle state, warnings, and a prioritized triage queue.

Priority mapping is deterministic: **P0 = critical**, **P1 = high**, **P2 = medium**, **P3 = low**. Findings with scanner-provided remediation guidance display it directly in the queue.

```bash
aisec scan . --all --summary scan-summary.md
```

JSON and SARIF remain the machine-readable integrations; the Markdown report is designed for human review and pull-request workflows.

## Controlled benchmark

Run the end-to-end regression corpus through the umbrella CLI (the corpus, `agent-test-range`, is currently private):

```bash
aisec benchmark ../agent-test-range --json benchmark/metrics.json
```

The command delegates execution to the real scanner regression harness and validates its versioned metrics contract. It reports overall and per-scanner precision, recall, F1, false-positive rate, and the underlying confusion-matrix counts.

This benchmark is intentionally a **controlled regression corpus**, not a universal claim about production detection accuracy.

## Detection quality

The suite exposes reusable precision, recall, F1, and false-positive-rate calculations for controlled regression corpora. These metrics are intended for reproducible benchmark cases—not claims of universal real-world detection rates.

## CI security gate

Every push and pull request scans this repository with the published scanners (`aisec scan . --all`, private adapters skipped) under the checked-in policy. The security workflow gates on the checked-in policy and uploads SARIF results to GitHub code scanning. GitHub Actions dependencies are pinned to immutable commit SHAs and checkout disables persisted credentials.

## Release pipeline

Version tags (`vX.Y.Z`) build and validate both wheel and source distributions. The release workflow verifies that the pushed tag exactly matches the version in `pyproject.toml` and publishes through PyPI trusted publishing (OIDC); no long-lived PyPI API token is stored in the repository.
