from __future__ import annotations

from dataclasses import dataclass, asdict

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Finding:
    scanner: str      # mcpaudit | memsentry | ragsentry
    rule: str         # e.g. "permission_scope: Unscoped filesystem access"
    severity: str     # low | medium | high | critical
    message: str
    file: str         # path relative to the scan root
    line: int = 1

    def to_dict(self) -> dict:
        return asdict(self)


def at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]
