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

## 5-Plane Mathematical Security Architecture (v2.2.0)

| Defense Plane | Repository | Core Mathematical Primitive |
|---|---|---|
| **Plane 1: Supply Chain & Model Weights** | `weightspecter` v2.0 | Random Matrix Theory (Marchenko-Pastur, BBP phase transition, Tracy-Widom $\text{TW}_1$), blind trigger coordinate inversion, zero-execution Pickle VM static disassembly |
| **Plane 2: Cryptographic Verifiable Inference** | `attestinfer` v2.0 | 16-round Rademacher Freivalds matmul prover ($2^{-16}$ soundness), Fiat-Shamir bilinear sumcheck, SHA-256 Merkle activation trees, RMSNorm/SiLU/Softmax algebraic invariants & speculative decoding Wald audit |
| **Plane 3: Mechanistic Circuit Firewall** | `circuitshield` v2.0 | Refusal-subspace directional ablation detection, Sparse Autoencoder (SAE) monosemantic feature disentanglement, 2D Kalman-filter Crescendo trajectory forecasting & homeostatic clamping |
| **Plane 4: Formal Protocol Verification** | `specprove-sec` v0.4 | Z3 SMT bounded model checking, unbounded $k$-induction, Houdini invariant synthesis, CEGIS AST auto-patcher & machine-checkable Lean 4 proof certificates |
| **Plane 5: Encrypted Wire Side-Channel Defense** | `tokenspecter` v2.0 | Bayesian Viterbi token-length/timing cryptanalysis, Shannon mutual information auditor, speculative burst entropy detector & 64-byte constant-rate ring-buffer shaper |

## Supporting surfaces

- RAG injection: ragsentry
- Agent memory: memsentry
- Agent loops/behavior: loopcheck
- Training-data poisoning: trainsentry
- Supply-chain controls: agent-install-guardrail
- Package-worm detection: wormsentry
- Controlled regression & CI gating: agent-test-range · agent-security-ci

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

