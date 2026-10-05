"""Module registry and adapter capability metadata."""
from __future__ import annotations
from dataclasses import dataclass
from aisec import MODULES

@dataclass(frozen=True)
class ModuleSpec:
    name: str
    description: str
    package: str
    native: bool = False
    mode: str = ""

REGISTRY = {
    "mcp": ModuleSpec("mcp", MODULES["mcp"], "pyhroff-mcpaudit", True, "scan PATH"),
    "memory": ModuleSpec("memory", MODULES["memory"], "memsentry", True, "scan PATH"),
    "rag": ModuleSpec("rag", MODULES["rag"], "pyhroff-ragsentry", True, "scan PATH --rag DIR"),
    "training": ModuleSpec("training", MODULES["training"], "trainsentry", True, "training DATASET"),
    "supply-chain": ModuleSpec("supply-chain", MODULES["supply-chain"], "agent-install-guardrail", True, "supply-chain TARGET"),
    "behavior": ModuleSpec("behavior", MODULES["behavior"], "loopcheck", True, "behavior TRACE"),
    "adversarial": ModuleSpec("adversarial", MODULES["adversarial"], "adversagen", False, "specialist CLI"),
    "worm": ModuleSpec("worm", MODULES["worm"], "wormsentry", True, "worm PATH"),
}

def available_modules():
    return list(REGISTRY.values())

def resolve_module(name: str):
    return REGISTRY.get(name)
