"""Unified AI security toolkit.

One public product with independently versioned specialist scanners behind a
common CLI and finding model.
"""
__version__ = "2.0.0"

MODULES = {
    "mcp": "MCP tool-surface poisoning and privilege analysis (mcpaudit)",
    "memory": "persistent agent-memory/context poisoning (memsentry)",
    "rag": "RAG document poisoning and retrieval manipulation (ragsentry)",
    "training": "fine-tuning dataset poisoning (trainsentry)",
    "supply-chain": "agent package/install supply-chain risk (agent-install-guardrail)",
    "behavior": "agent-loop waste and regression analysis (loopcheck)",
    "adversarial": "adaptive red-team/evasion experiments (adversagen)",
    "worm": "self-propagating package/supply-chain behavior (wormsentry)",
    "formal": "Z3 SMT formal state-machine verification, CEGIS patch synthesis & Lean 4 proof certificates (specprove-sec)",
    "weights": "RMT spectral & topological LoRA/safetensors backdoor detection & surgical sanitization (weightspecter)",
    "sidechannel": "encrypted streaming SSE token-length & timing Viterbi cryptanalysis & constant-rate shaping (tokenspecter)",
    "circuit": "mechanistic interpretability refusal-subspace & activation-steering firewall (circuitshield)",
}


