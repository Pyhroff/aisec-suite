# aisec-suite

[![CI](https://github.com/Pyhroff/aisec-suite/actions/workflows/tests.yml/badge.svg)](https://github.com/Pyhroff/aisec-suite/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**A CI security gate for the inputs an AI agent trusts but code scanners ignore: MCP tool metadata, agent memory files and RAG documents.**

## Headline result

I scanned **135 public MCP server repositories** (pinned commits, findings hand-labelled) and built a tool-poisoning detector that I evaluated on attacks it was not developed against:

| detector | recall, seen attacks | recall, held-out attacks | false-positive rate (3,974 real tool descriptions) |
|---|---|---|---|
| naive regex | 42.6% | **0.0%** | 0.0% |
| **aisec structural detector** | 61.1% | **48.1%** | **0.03%** (1 / 3,974) |

Pattern matching memorises its own examples and finds almost nothing new. Scoring decoded text structurally (hidden Unicode, base64/hex/entity decoding, co-occurrence of model-directed, data-flow and concealment cues) generalises much better, but it still misses about half of unseen attacks, so it is a review aid, not a security boundary. The same study raised mcpaudit's precision from 38.8% to 69.4% at 80.6% recall.

Across 135 real MCP servers I found **no tool poisoning in the wild**. Unconstrained-scope findings were by-design capabilities, not vulnerabilities, which is why the gate is a review aid rather than a vulnerability scanner.

Full method, confidence intervals and the caveats (including that the held-out set was evaluated twice) are in [`docs/STUDY.md`](docs/STUDY.md).

## Try it in two minutes

```bash
pip install "aisec-suite[core]"
bash examples/demo-mcp-server/run_demo.sh
```

The demo scans a small MCP server whose `add` tool hides an instruction to read `~/.ssh/id_rsa` and leak it through a parameter. The gate fails on it, then passes on the fixed version. See [`examples/demo-mcp-server`](examples/demo-mcp-server).

## What it scans

| Surface | Scanner | Status |
|---|---|---|
| MCP tool descriptions, schemas, permission scope | `mcpaudit` + built-in structural detector and reachability (`--reach`) | **Published** (`pip install "aisec-suite[core]"`) |
| Agent memory / context files (`CLAUDE.md`, `.cursorrules`, ...) | `memsentry` | **Published** |
| RAG source documents | `ragsentry` | **Published** |
| Fine-tuning datasets, agent traces, package installs, package worms | `trainsentry`, `loopcheck`, `agent-install-guardrail`, `wormsentry` | Private, adapters included, not on PyPI |
| Model weights, inference receipts, activation traces, streaming side channels, formal checks of tool state machines | `weightspecter`, `attestinfer`, `circuitshield`, `tokenspecter`, `specprove-sec` | Research preview, private, evaluated only on synthetic fixtures |

Only the published row is installable from PyPI today. Adapters for the other scanners activate when those packages are installed from source; otherwise the CLI reports them as unavailable instead of failing.

## Usage

```bash
aisec scan .                                    # MCP + memory
aisec scan . --rag ./docs                       # add RAG documents
aisec scan . --reach annotate                   # add handler reachability evidence
aisec scan . --sarif aisec.sarif --json findings.json --fail-on high
aisec modules                                   # list scanners and whether each is installed
```

Exit codes with `--fail-on`: `0` nothing at or above the threshold, `1` findings at or above it, `2` a scanner crashed (reported as a warning, never mistaken for a finding).

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

Every push and pull request scans this repository with the published scanners (`aisec scan . --all`, private adapters skipped) under the checked-in policy. The security workflow gates on the checked-in policy and uploads SARIF results to GitHub code scanning. GitHub Actions dependencies are pinned to immutable commit SHAs and checkout disables persisted credentials.

## Package and release status

Latest release: **0.4.0**. Earlier development builds were labelled 2.x in the repository but never published; PyPI releases are 0.2.0, 0.3.0 and 0.4.0. Pin versions in CI rather than tracking the default branch.

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

## Controlled benchmark


Run the end-to-end regression corpus through the umbrella CLI (the corpus, `agent-test-range`, is currently private):

```bash
aisec benchmark ../agent-test-range --json benchmark/metrics.json
```

The command delegates execution to the real scanner regression harness and validates its versioned metrics contract. It reports overall and per-scanner precision, recall, F1, false-positive rate, and the underlying confusion-matrix counts.

This benchmark is intentionally a **controlled regression corpus**, not a universal claim about production detection accuracy.

## Detection quality

The suite exposes reusable precision, recall, F1, and false-positive-rate calculations for controlled regression corpora. These metrics are intended for reproducible benchmark cases—not claims of universal real-world detection rates.

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

## Experimental demos

`aisec experimental wargame | guard-proxy | dashboard | remediate` are **scripted walkthroughs** of the research-preview modules. They run on fixed, synthetic inputs and their outcomes are pre-determined. They do not intercept traffic and are not detection results. They live in `aisec/experimental/` and need the private packages.

## Architecture

```text
            files in a repository / PR
                        │
      ┌─────────────────┼─────────────────┐
      ▼                 ▼                 ▼
   mcpaudit         memsentry         ragsentry        (+ optional private adapters)
  + structural
    detector
  + reachability
      │                 │                 │
      └─────────────────┼─────────────────┘
                        ▼
          normalized Finding (fingerprint, severity, evidence)
                        │
        policy / baseline lifecycle (new · existing · resolved)
                        │
        terminal · JSON · SARIF 2.1.0 · Markdown job summary · exit code
```

Design principles: static-first, never execute the scanned code, never follow symlinks out of the repo, fail closed on scanner crashes, and state measured limits next to every number.

## Development

```bash
pip install -e ".[core,dev]"
ruff check .
pytest -q -rs     # -rs lists tests skipped because private scanners are absent
```

CI runs the unit tests on Python 3.10-3.12 with in-memory fake scanners, plus an integration job that installs the published scanners from PyPI. Tests for the private research modules skip in CI because those packages are not public.

## Upstream security work

- **BerriAI/litellm**:
  - [PR #47312](https://github.com/BerriAI/litellm/pull/47312) (open): scope /v1/mcp/access_groups to caller-accessible servers for non-admin callers
  - [PR #47105](https://github.com/BerriAI/litellm/pull/47105) (open): authorization check on proxy endpoints when model lists are empty
- **PrefectHQ/fastmcp**:
  - [PR #6063](https://github.com/PrefectHQ/fastmcp/pull/6063) (closed; reopen pending linked issue): wall-clock timeout and external callback limit in MontySandboxProvider and CodeMode

## Related projects

`mcpaudit`, `memsentry`, `ragsentry` (published) · `adversagen` (attack-side research used to test the detectors) · `agent-security-ci` (CI wiring example). See [`docs/PORTFOLIO.md`](docs/PORTFOLIO.md).

## License

MIT
