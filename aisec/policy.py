"""Versioned policy-as-code support for deterministic finding enforcement.

Policy files are JSON so the CLI has no extra dependency.
Built-in profiles provide predictable CI defaults without requiring a file.
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path

from aisec.model import Finding, SEVERITY_ORDER

PROFILE_NAMES = ("strict", "balanced", "dev")
PROFILES = {
    "strict": "low",
    "balanced": "high",
    "dev": "critical",
}


@dataclass(frozen=True)
class Policy:
    fail_on: str | None = None
    excludes: tuple[dict[str, str], ...] = ()


def validate_policy(policy: Policy) -> dict:
    """Return the normalized, machine-readable policy contract."""
    if policy.fail_on is not None and policy.fail_on not in SEVERITY_ORDER:
        raise ValueError("policy fail_on must be low|medium|high|critical")
    return {
        "version": 1,
        "fail_on": policy.fail_on,
        "exclude": [dict(item) for item in policy.excludes],
    }


def load_policy(path: Path) -> Policy:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("policy must be a JSON object with version=1")
    unknown_top = set(payload) - {"version", "fail_on", "exclude"}
    if unknown_top:
        raise ValueError("unsupported policy fields: " + ", ".join(sorted(unknown_top)))

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
        if not item:
            raise ValueError("policy exclusions must select at least one field")
        normalized.append({str(k): str(v) for k, v in item.items()})
    return Policy(fail_on=fail_on, excludes=tuple(normalized))


def profile_policy(name: str) -> Policy:
    """Return a deterministic built-in enforcement profile."""
    if name not in PROFILES:
        raise ValueError(f"unknown policy profile: {name}; use strict, balanced, or dev")
    return Policy(fail_on=PROFILES[name])


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
