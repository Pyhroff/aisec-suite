#  aisec-suite

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

The individual scanner packages remain independently versioned and testable. This repository is the **umbrella product**; the scanner packages are installed as optional dependencies.

## Coverage (12 Specialist Modules across 5 Mathematical Security Planes)

| Plane / Surface | Module | Primary Mathematical / Security Capability |
|---|---|---|
| **Plane 1: Model Weights & Supply Chain** | `weightspecter` v2.0 *(native `--weights`)* | Marchenko-Pastur RMT spectral law, BBP phase-transition outlier spike detection, Tracy-Widom $\text{TW}_1$ $p$-values, blind trigger inversion & surgical rank-1 spike excision |
| **Plane 1: Fine-Tuning & Supply Chain** | `trainsentry` · `agent-install-guardrail` · `wormsentry` | Fine-tuning dataset poisoning, pre-install dependency SBOM policy, self-propagating package worm detection |
| **Plane 2: Verifiable Compute** | `attestinfer` v2.0 *(native `--attest`)* | 16-round Rademacher Freivalds matmul prover ($2^{-16}$ soundness), Fiat-Shamir bilinear sumcheck, SHA-256 Merkle activation roots, non-linear RMSNorm/SiLU/Softmax checks & speculative draft fraud detection |
| **Plane 3: Residual & Refusal Subspace** | `circuitshield` v2.0 *(native `--circuit`)* | Mechanistic refusal-subspace directional ablation ($\cos\theta_l$), Sparse Autoencoder (SAE) monosemantic feature disentanglement, Kalman-filter Crescendo trajectory forecasting & homeostatic clamping |
| **Plane 4: Protocol, MCP & Memory** | `specprove-sec` *(native `--formal`)* · `mcpaudit` · `memsentry` · `ragsentry` · `loopcheck` | Z3 SMT bounded model checking, unbounded $k$-induction, Houdini invariant synthesis, CEGIS AST auto-patching, Lean 4 proof certificates, MCP tool poisoning, RAG & persistent memory hygiene |
| **Plane 5: Encrypted Network Wire** | `tokenspecter` v2.0 *(native `--sidechannel`)* | Encrypted SSE token-length & inter-arrival timing Bayesian Viterbi cryptanalysis, speculative-decoding burst entropy & 64-byte constant-rate ring-buffer shaping |
| **Adversarial Red-Team Layer** | `adversagen` *(specialist CLI)* | Adaptive genetic/white-box evasion experiments against static and runtime defenses |

## One CLI

### Repository-wide scan

```bash
pip install "aisec-suite[all]"
aisec scan .
aisec scan . --rag ./docs
aisec scan . --sarif aisec.sarif --json findings.json --fail-on high
# Run every native module (MCP, Memory, RAG, Z3 Formal, RMT Weights, Verifiable Compute, Refusal Circuit, SSE Side-Channel)
aisec scan . --all --sarif aisec.sarif
```

### Closed-Loop Auto-Remediation, 5-Plane Wargame & Zero-Trust Runtime Guard-Proxy

```bash
# Automatically repair vulnerable Python ASTs (Z3 CEGIS), .safetensors (BBP excision), .proof.json (FP32 re-attestation), .act.json (homeostatic clamping), and .stream.json (64B shaping)
aisec remediate . --html reports/aisec-command-center.html

# Launch the Unified 12-Module Command Center HTML5 Dashboard
aisec dashboard . --html reports/aisec-command-center.html

# Execute the 5-Stage Autonomous Red-vs-Blue Cyber-Range Wargame Simulator
aisec wargame --html reports/aisec-wargame-arena.html

# Run the sub-millisecond Zero-Trust Runtime Interceptor Sidecar verification suite
aisec guard-proxy --json reports/guard-proxy-tx.json
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

Use the bundled composite action to standardize the scanner in another workflow. The example pins the action itself to an immutable commit; update that SHA only when intentionally upgrading the action:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      persist-credentials: false
  - uses: Pyhroff/aisec-suite/.github/actions/aisec-scan@7b355445867cde3724365c6e9a132e4875a78569 # pinned action revision
    with:
      fail-on: high
      sarif: aisec.sarif
      json: aisec.json
      policy-profile: balanced
  - uses: github/codeql-action/upload-sarif@87ef0dc97def48aa960fbf026a2563ee9dbdb470 # v3
    with:
      sarif_file: aisec.sarif
```

For maximum reproducibility in production, pin both the `aisec-suite` action reference and its GitHub Action dependencies to immutable commit SHAs. The bundled composite action validates its dependency-extra input before using it in a shell command.

## Release pipeline

Version tags (`vX.Y.Z`) build and validate both wheel and source distributions. The release workflow verifies that the tag matches the package version and publishes through PyPI trusted publishing (OIDC); no PyPI API token is stored in the repository.

## CI security gate

Every push and pull request runs the full native scanner suite through `aisec scan . --all` with the repository policy applied. The security workflow gates on the checked-in policy and uploads SARIF results to GitHub code scanning. GitHub Actions dependencies are pinned to immutable commit SHAs and checkout disables persisted credentials.

## Package and release status

The repository may contain unreleased development changes ahead of the latest PyPI publication. For reproducible installs, pin the aisec-suite package version and specialist package versions in deployment and CI configuration rather than assuming the repository development version is the published release.

The release workflow enforces an important invariant: a pushed vX.Y.Z tag must exactly match the version declared in pyproject.toml before publication. PyPI publishing uses trusted publishing (OIDC), so no long-lived PyPI API token is required.

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

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

## Portfolio

mcpaudit · memsentry · ragsentry · trainsentry · agent-install-guardrail · loopcheck · wormsentry · adversagen · agent-security-ci · agent-test-range



## Portfolio / research architecture

See [docs/PORTFOLIO.md](docs/PORTFOLIO.md) for the portfolio-level threat-model and evaluation standard. The intended flagship path is **PromptStrike → ModelHawk → Adversagen → mcpaudit → aisec-suite**, with RAG, memory, loop and supply-chain scanners providing supporting coverage.

## Portfolio visibility

The umbrella intentionally separates public proof from private R&D. The public repositories are the reproducible, recruiter-facing subset; specialist components that remain private are not required to use this README as a navigational link.

For the current public entry points, start with **aisec-suite**, **mcp-scan-study**, **promptstrike**, and **ModelHawk**. Private specialist implementations are exercised through the controlled regression layer when access is available.

## License

MIT
