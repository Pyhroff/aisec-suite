"""Minimal SARIF 2.1.0 writer so findings show up in GitHub code scanning."""
from __future__ import annotations

import re

from aisec import __version__
from aisec.model import Finding

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
# GitHub ranks code-scanning alerts by this CVSS-like number (>=9 critical, 7-8.9 high, 4-6.9 medium, <4 low).
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0"}
_HELP = {"mcpaudit": "https://github.com/Pyhroff/mcpaudit", "memsentry": "https://github.com/Pyhroff/memsentry",
         "ragsentry": "https://github.com/Pyhroff/ragsentry"}


def _rule_id(f: Finding) -> str:
    return f"{f.scanner}/" + re.sub(r"[^A-Za-z0-9_.-]+", "-", f.rule).strip("-").lower()


def to_sarif(findings: list[Finding]) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = _rule_id(f)
        rules.setdefault(rid, {"id": rid, "name": rid, "shortDescription": {"text": f.rule},
                               "helpUri": _HELP.get(f.scanner, "https://github.com/Pyhroff/aisec-suite"),
                               "properties": {"scanner": f.scanner, "security-severity": _SECURITY_SEVERITY[f.severity],
                                              "tags": ["security", "ai-security", f.scanner]}})
        results.append({
            "ruleId": rid,
            "level": _LEVEL[f.severity],
            "message": {"text": f.message + (f" [{f.evidence}]" if f.evidence else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file.replace("\\", "/")},
                                                "region": {"startLine": max(1, f.line)}}}],
            "partialFingerprints": {"aisec/v1": f.fingerprint},
            "properties": {"severity": f.severity, "scanner": f.scanner},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "aisec-suite", "version": __version__,
                                      "informationUri": "https://github.com/Pyhroff", "rules": list(rules.values())}},
                  "results": results}],
    }
