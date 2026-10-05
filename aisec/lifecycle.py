"""Finding lifecycle helpers for reusable baseline comparisons."""

from __future__ import annotations

from dataclasses import dataclass

from aisec.model import Finding


@dataclass(frozen=True)
class FindingDiff:
    """Classification of findings relative to an accepted baseline."""

    new: tuple[Finding, ...]
    existing: tuple[Finding, ...]
    resolved: tuple[str, ...]

    @property
    def new_count(self) -> int:
        return len(self.new)

    @property
    def existing_count(self) -> int:
        return len(self.existing)

    @property
    def resolved_count(self) -> int:
        return len(self.resolved)

    def to_dict(self) -> dict:
        return {
            "new": [f.to_dict() for f in self.new],
            "existing": [f.to_dict() for f in self.existing],
            "resolved": list(self.resolved),
            "counts": {
                "new": self.new_count,
                "existing": self.existing_count,
                "resolved": self.resolved_count,
            },
        }


def classify(findings: list[Finding], baseline: set[str]) -> FindingDiff:
    """Classify current findings against fingerprint-only baseline state."""
    current = {f.fingerprint: f for f in findings}
    baseline = set(baseline)
    new = tuple(f for fingerprint, f in current.items() if fingerprint not in baseline)
    existing = tuple(f for fingerprint, f in current.items() if fingerprint in baseline)
    resolved = tuple(sorted(baseline - current.keys()))
    return FindingDiff(new=new, existing=existing, resolved=resolved)


def load_baseline(path) -> set[str]:
    """Load the legacy JSON fingerprint-list baseline format."""
    import json

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
        raise ValueError("baseline must be a JSON list of finding fingerprints")
    return set(payload)
