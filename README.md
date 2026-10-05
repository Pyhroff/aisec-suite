# 🛡️ aisec-suite

<div align="center">

**Unified security tooling for AI agents, MCP, memory, RAG, training data, and software supply chains.**

[![CI](https://github.com/Pyhroff/aisec-suite/actions/workflows/tests.yml/badge.svg)](https://github.com/Pyhroff/aisec-suite/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

### Security signals for the inputs your AI agent actually trusts.

</div>

---

## Overview

Traditional application scanners focus on source code, dependencies, and runtime behavior. AI systems also consume **tool descriptions, memory files, retrieved documents, training data, and agent traces** that can influence decisions without looking like ordinary executable code.

**aisec-suite** brings those surfaces into one product-level workflow with a shared CLI, normalized findings, CI-friendly exit codes, JSON/SARIF output, and reusable baselines.

The individual scanner repositories remain independently versioned and testable. This repository is the **umbrella product**.

## Coverage

| Surface | Module | Primary capability |
|---|---|---|
| MCP | [mcpaudit](https://github.com/Pyhroff/mcpaudit) | Tool poisoning, permission scope, rug pulls, confused-deputy testing |
| Memory | [memsentry](https://github.com/Pyhroff/memsentry) | Persistent instruction injection, provenance manipulation, goal hijacking |
| RAG | [ragsentry](https://github.com/Pyhroff/ragsentry) | Document injection, hidden payloads, fake remediation, retrieval manipulation |
| Training data | [trainsentry](https://github.com/Pyhroff/trainsentry) | Fine-tuning poisoning, trigger patterns, goal hijacking, duplicate flooding |
| Supply chain | [agent-install-guardrail](https://github.com/Pyhroff/agent-install-guardrail) | Pre-install decisions, dependency analysis, policy, SBOM |
| Agent behavior | [loopcheck](https://github.com/Pyhroff/loopcheck) | Duplicate calls, thrashing, stale retries, regression and waste analysis |
| Package worms | [wormsentry](https://github.com/Pyhroff/wormsentry) | Risky install scripts, credential harvesting, self-propagation patterns |
| Adversarial research | [adversagen](https://github.com/Pyhroff/adversagen) | Adaptive evasion experiments against scanner-style defenses |

## One CLI

### Repository-wide scan

```bash
pip install "aisec-suite[all]"
aisec scan .
aisec scan . --rag ./docs
aisec scan . --sarif aisec.sarif --json findings.json --fail-on high
# Run every native module that has a compatible target in the repository
# (training_data.jsonl, trace.json, pyproject.toml, etc.)
aisec scan . --all --sarif aisec.sarif
```

### Dedicated module commands

```bash
aisec training dataset.jsonl --json training-findings.json
aisec behavior trace.json --json behavior-findings.json
aisec supply-chain pypi:httpx --json supply-chain-findings.json
aisec worm ./package --json worm-findings.json
```

### Discover capabilities

```bash
aisec modules
```

## Reusable GitHub Action

Use the bundled composite action to standardize the scanner in another workflow:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - uses: Pyhroff/aisec-suite/.github/actions/aisec-scan@v1
    with:
      fail-on: high
      sarif: aisec.sarif
      json: aisec.json
      policy-profile: balanced
  - uses: github/codeql-action/upload-sarif@87ef0dc97def48aa960fbf026a2563ee9dbdb470 # v3
    with:
      sarif_file: aisec.sarif
```

For maximum reproducibility in production, pin the `aisec-suite` action reference to an immutable commit SHA rather than a moving tag. All first-party workflow action dependencies in this repository are pinned to immutable SHAs.

## Release pipeline

Version tags (`vX.Y.Z`) build and validate both wheel and source distributions. The release workflow verifies that the tag matches the package version and publishes through PyPI trusted publishing (OIDC); no PyPI API token is stored in the repository.

## CI security gate

Every push and pull request runs the full native scanner suite through `aisec scan . --all` with the repository policy applied. The security workflow gates on the checked-in policy and uploads SARIF results to GitHub code scanning. GitHub Actions dependencies are pinned to immutable commit SHAs and checkout disables persisted credentials.

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

## Architecture

```text
                           ┌──────────────────────────┐
                           │       aisec-suite        │
                           │ unified CLI + findings   │
                           └────────────┬─────────────┘
                                        │
          ┌───────────────┬─────────────┼───────────────┬──────────────┐
          ▼               ▼             ▼               ▼              ▼
        MCP             Memory          RAG         Training data   Supply chain
     mcpaudit         memsentry      ragsentry      trainsentry      guardrail
          │               │             │               │              │
          └───────────────┴─────────────┼───────────────┴──────────────┘
                                        │
                           ┌────────────┴────────────┐
                           ▼                         ▼
                       Behavior                 Package worms
                       loopcheck                 wormsentry
```

`adversagen` remains the attack-side research layer rather than another static scanner.

## Design principles

**Static-first** · **Fail closed** · **Composable** · **CI-native** · **Honest about uncertainty**

## Project status

Native umbrella adapters now cover **MCP, memory, RAG, training data, supply-chain inspection, agent-loop behavior, and package-worm detection**.

The adversarial research runner remains intentionally separate because it is an experiment engine rather than a static artifact scanner.

## Controlled benchmark

Run the end-to-end regression corpus through the umbrella CLI:

```bash
aisec benchmark ../agent-test-range --json benchmark/metrics.json
```

The command delegates execution to the real scanner regression harness and validates its versioned metrics contract. It reports overall and per-scanner precision, recall, F1, false-positive rate, and the underlying confusion-matrix counts.

This benchmark is intentionally a **controlled regression corpus**, not a universal claim about production detection accuracy.

## Detection quality

The suite exposes reusable precision, recall, F1, and false-positive-rate calculations for controlled regression corpora. These metrics are intended for reproducible benchmark cases—not claims of universal real-world detection rates.

## Research

Benchmark methodology and evaluation results live in [`docs/STUDY.md`](docs/STUDY.md). Treat measured results as evidence for the documented corpus and experimental design, not as universal guarantees.

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

`aisec policy init` creates a reviewable policy from a deterministic profile and refuses to overwrite an existing file unless `--force` is supplied.\n\nA checked-in `--policy` file and `--policy-profile` are mutually exclusive. A policy file's `fail_on` value overrides the CLI threshold, while exclusions are always surfaced in warnings.

`aisec policy validate` rejects unknown top-level fields, unsupported versions, malformed exclusions, and invalid severities so policy drift fails closed.

## Security reporting and triage

When `GITHUB_STEP_SUMMARY` is available, every scan writes a concise security report to the GitHub Actions job summary. The report includes severity counts, baseline lifecycle state, warnings, and a prioritized triage queue.

Priority mapping is deterministic: **P0 = critical**, **P1 = high**, **P2 = medium**, **P3 = low**. Findings with scanner-provided remediation guidance display it directly in the queue.

```bash
aisec scan . --all --summary scan-summary.md
```

JSON and SARIF remain the machine-readable integrations; the Markdown report is designed for human review and pull-request workflows.

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

## Portfolio

[mcpaudit](https://github.com/Pyhroff/mcpaudit) · [memsentry](https://github.com/Pyhroff/memsentry) · [ragsentry](https://github.com/Pyhroff/ragsentry) · [trainsentry](https://github.com/Pyhroff/trainsentry) · [agent-install-guardrail](https://github.com/Pyhroff/agent-install-guardrail) · [loopcheck](https://github.com/Pyhroff/loopcheck) · [wormsentry](https://github.com/Pyhroff/wormsentry) · [adversagen](https://github.com/Pyhroff/adversagen) · [agent-security-ci](https://github.com/Pyhroff/agent-security-ci) · [agent-test-range](https://github.com/Pyhroff/agent-test-range)

## License

MIT
