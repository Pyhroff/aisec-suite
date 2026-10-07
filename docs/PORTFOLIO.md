# AI Security Portfolio Architecture

This repository is the umbrella for a portfolio of focused AI-security tools. The goal is not maximum repository count; it is composable coverage of distinct trust boundaries.

## Flagship narrative

```
Prompt / jailbreak security
        │
        ▼
   promptstrike
        │
        ▼
Model artifact security ──> ModelHawk
        │
        ▼
Agent / adversarial evaluation ──> adversagen
        │
        ▼
MCP tool-surface security ──> mcpaudit
        │
        ▼
Memory / RAG / supply-chain surfaces
        │
        ▼
      aisec-suite
```

## Portfolio evidence model

Each specialist should ideally expose the same evidence chain:

**Threat model → attack/fixture → detection/defense → benchmark → results → limitations**

This makes the repositories comparable and turns the collection into a coherent security-engineering body of work.

## Recommended flagship set

### mcpaudit
MCP tool-surface scanning, manifest drift detection, permission-scope analysis and controlled confused-deputy experiments.

### ModelHawk
Static inspection of serialized ML artifacts, with a strong safety invariant: inspection must not deserialize the untrusted artifact.

### PromptStrike
Reproducible jailbreak and indirect-injection research with multiple attack algorithms, adapters and a defensive shield.

### adversagen
Adaptive attacker-side research for testing scanner resilience.

## Supporting surfaces

- RAG injection: ragsentry
- Agent memory: memsentry
- Agent loops/behavior: loopcheck
- Training-data poisoning: trainsentry
- Supply-chain controls: agent-install-guardrail
- Regression corpus: agent-test-range

## Portfolio rule

A project should be promoted to flagship status only when it has:

- a precise threat model
- reproducible fixtures
- automated tests
- quantitative evaluation
- documented limitations
- a clear security boundary
- a usable interface or integration path

The objective is **depth over project count**.
