"""Policy-as-code support for deterministic finding enforcement.

Policy files are JSON so the CLI has no extra dependency:
{
  "version": 1,
  "fail_on": "high",
  "exclude": [
    {"scanner": "mcpaudit", "rule": "example-rule", "file": "tests/**"}
  ]
}
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path

from aisec.model import Finding, SEVERITY_ORDER


@dataclass(frozen=True)
class Policy:
    fail_on: str | None = None
    excludes: tuple[dict[str, str], ...] = ()


def load_policy(path: Path) -> Policy:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("policy must be a JSON object with version=1")
    fail_on = payload.get("fail_on")
    if fail_on is not None and fail_on not in SEVERITY_ORDER:
        raise ValueError("policy fail_on must be low|medium|high|critical")
    excludes = payload.get("exclude", [])
    if not isinstance(excludes, list) or not all(isinstance(item, dict) for item in excludes):
        raise ValueError("policy exclude must be a list of objects")
    allowed = {"scanner", "rule", "file", "severity"}
    normalized = []
    for item in excludes:
        unknown = set(item) - allowed
        if unknown:
            raise ValueError("unsupported policy fields: " + ", ".join(sorted(unknown)))
        normalized.append({str(k): str(v) for k, v in item.items()})
    return Policy(fail_on=fail_on, excludes=tuple(normalized))


def _matches(finding: Finding, selector: dict[str, str]) -> bool:
    values = {
        "scanner": finding.scanner,
        "rule": finding.rule,
        "file": finding.file.replace("\\", "/"),
        "severity": finding.severity,
    }
    return all(fnmatch.fnmatchcase(values[key], pattern) for key, pattern in selector.items())


def apply_policy(findings: list[Finding], policy: Policy) -> tuple[list[Finding], int]:
    kept = [finding for finding in findings if not any(_matches(finding, selector) for selector in policy.excludes)]
    return kept, len(findings) - len(kept)
