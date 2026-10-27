"""Module registry and adapter capability metadata."""
from __future__ import annotations
import importlib.util
from dataclasses import dataclass
from aisec import MODULES

@dataclass(frozen=True)
class ModuleSpec:
    name: str
    description: str
    package: str
    native: bool = False
    mode: str = ""
    import_name: str = ""

    def installed(self) -> bool:
        try:
            return importlib.util.find_spec(self.import_name or self.name) is not None
        except (ImportError, ValueError):
            return False

REGISTRY = {
    "mcp": ModuleSpec("mcp", MODULES["mcp"], "pyhroff-mcpaudit", True, "scan PATH", "mcpaudit"),
    "memory": ModuleSpec("memory", MODULES["memory"], "memsentry", True, "scan PATH", "memsentry"),
    "rag": ModuleSpec("rag", MODULES["rag"], "pyhroff-ragsentry", True, "scan PATH --rag DIR", "ragsentry"),
    "training": ModuleSpec("training", MODULES["training"], "trainsentry", True, "training DATASET", "trainsentry"),
    "supply-chain": ModuleSpec("supply-chain", MODULES["supply-chain"], "agent-install-guardrail", True, "supply-chain TARGET", "guardrail"),
    "behavior": ModuleSpec("behavior", MODULES["behavior"], "loopcheck", True, "behavior TRACE", "loopcheck"),
    "adversarial": ModuleSpec("adversarial", MODULES["adversarial"], "adversagen", False, "specialist CLI", "adversagen"),
    "worm": ModuleSpec("worm", MODULES["worm"], "wormsentry", True, "worm PATH", "wormsentry"),
    "formal": ModuleSpec("formal", MODULES["formal"], "pyhroff-specprove-sec", True, "scan PATH --formal", "specprove"),
    "weights": ModuleSpec("weights", MODULES["weights"], "pyhroff-weightspecter", True, "scan PATH --weights", "weightspecter"),
    "sidechannel": ModuleSpec("sidechannel", MODULES["sidechannel"], "pyhroff-tokenspecter", True, "scan PATH --sidechannel", "tokenspecter"),
    "circuit": ModuleSpec("circuit", MODULES["circuit"], "pyhroff-circuitshield", True, "scan PATH --circuit", "circuitshield"),
    "attest": ModuleSpec("attest", MODULES["attest"], "pyhroff-attestinfer", True, "scan PATH --attest", "attestinfer"),
}

def available_modules():
    return list(REGISTRY.values())

def resolve_module(name: str):
    return REGISTRY.get(name)
