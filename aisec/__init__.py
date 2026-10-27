"""Unified AI security toolkit.

One public product with independently versioned specialist scanners behind a
common CLI and finding model.
"""
__version__ = "0.4.0"

MODULES = {
    "mcp": "MCP tool-surface poisoning and privilege analysis (mcpaudit)",
    "memory": "persistent agent-memory/context poisoning (memsentry)",
    "rag": "RAG document poisoning and retrieval manipulation (ragsentry)",
    "training": "fine-tuning dataset poisoning (trainsentry)",
    "supply-chain": "agent package/install supply-chain risk (agent-install-guardrail)",
    "behavior": "agent-loop waste and regression analysis (loopcheck)",
    "adversarial": "adaptive red-team/evasion experiments (adversagen)",
    "worm": "self-propagating package/supply-chain behavior (wormsentry)",
    "formal": "[research preview] Z3 model checking of MCP tool state machines (specprove-sec)",
    "weights": "[research preview] spectral outlier check for backdoored LoRA/safetensors weights (weightspecter)",
    "sidechannel": "[research preview] token-length/timing leakage check for streamed responses (tokenspecter)",
    "circuit": "[research preview] refusal-direction ablation check on activation traces (circuitshield)",
    "attest": "[research preview] Freivalds-style spot check of inference receipts (attestinfer)",
}


