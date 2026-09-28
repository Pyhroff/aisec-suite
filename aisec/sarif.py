"""Minimal SARIF 2.1.0 writer so findings show up in GitHub code scanning."""
from __future__ import annotations

import re

from aisec import __version__
from aisec.model import Finding

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _rule_id(f: Finding) -> str:
    return f"{f.scanner}/" + re.sub(r"[^A-Za-z0-9_.-]+", "-", f.rule).strip("-").lower()


def to_sarif(findings: list[Finding]) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = _rule_id(f)
        rules.setdefault(rid, {"id": rid, "name": rid, "shortDescription": {"text": f.rule},
                               "properties": {"scanner": f.scanner}})
        results.append({
            "ruleId": rid,
            "level": _LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file.replace("\\", "/")},
                                                "region": {"startLine": max(1, f.line)}}}],
            "properties": {"severity": f.severity},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "aisec-suite", "version": __version__,
                                      "informationUri": "https://github.com/Pyhroff", "rules": list(rules.values())}},
                  "results": results}],
    }
