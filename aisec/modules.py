"""Optional module registry for aisec-suite."""
from __future__ import annotations
from dataclasses import dataclass
from aisec import MODULES

@dataclass(frozen=True)
class ModuleSpec:
    name: str
    description: str
    package: str

REGISTRY = {
    "mcp": ModuleSpec("mcp", MODULES["mcp"], "pyhroff-mcpaudit"),
    "memory": ModuleSpec("memory", MODULES["memory"], "memsentry"),
    "rag": ModuleSpec("rag", MODULES["rag"], "pyhroff-ragsentry"),
    "training": ModuleSpec("training", MODULES["training"], "trainsentry"),
    "supply-chain": ModuleSpec("supply-chain", MODULES["supply-chain"], "agent-install-guardrail"),
    "behavior": ModuleSpec("behavior", MODULES["behavior"], "loopcheck"),
    "adversarial": ModuleSpec("adversarial", MODULES["adversarial"], "adversagen"),
    "worm": ModuleSpec("worm", MODULES["worm"], "wormsentry"),
}

def available_modules():
    return list(REGISTRY.values())

def resolve_module(name: str):
    return REGISTRY.get(name)
