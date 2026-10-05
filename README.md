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

## Common reporting model

Integrated scanners are normalized into a shared `Finding` model so downstream automation can consume results consistently.

Supported outputs include terminal reports, normalized JSON, SARIF 2.1.0, Markdown summaries, severity gates, and reusable baselines. Every normalized finding carries a stable fingerprint plus confidence, target, evidence, and remediation metadata where available.

```bash
aisec scan . --write-baseline .aisec-baseline.json
aisec scan . --baseline .aisec-baseline.json --fail-on high
```

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

## Detection quality

The suite exposes reusable precision, recall, F1, and false-positive-rate calculations for controlled regression corpora. These metrics are intended for reproducible benchmark cases—not claims of universal real-world detection rates.

## Research

Benchmark methodology and evaluation results live in [`docs/STUDY.md`](docs/STUDY.md). Treat measured results as evidence for the documented corpus and experimental design, not as universal guarantees.

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
