from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Finding:
    scanner: str  # mcpaudit | memsentry | ragsentry
    rule: str  # e.g. "permission_scope: Unscoped filesystem access"
    severity: str  # low | medium | high | critical
    message: str
    file: str  # path relative to the scan root
    line: int = 1
    evidence: str = ""  # why severity was adjusted; not part of fingerprint
    confidence: float = 1.0
    target: str = ""
    remediation: str = ""

    @property
    def fingerprint(self) -> str:
        """Stable across line shifts, so baselines survive unrelated edits."""
        raw = "\x1f".join(
            (
                self.scanner,
                self.rule,
                self.file.replace("\\", "/"),
                self.message,
            )
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def to_dict(self) -> dict:
        data = {**asdict(self), "fingerprint": self.fingerprint}
        data["confidence"] = max(0.0, min(1.0, float(self.confidence)))
        return data


def at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]
