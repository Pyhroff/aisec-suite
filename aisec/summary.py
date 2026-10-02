"""Markdown job summary (GitHub renders $GITHUB_STEP_SUMMARY on the run page)."""
from __future__ import annotations

import collections

from aisec.model import Finding

_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "⬜"}


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")[:160]


def to_markdown(findings: list[Finding], n_tools: int, warnings: list[str], suppressed: int = 0) -> str:
    by = collections.Counter(f.severity for f in findings)
    out = ["## aisec-suite scan\n",
           f"**{len(findings)} finding(s)** · critical {by['critical']} · high {by['high']} · "
           f"medium {by['medium']} · low {by['low']} · MCP tools extracted: {n_tools}"
           + (f" · {suppressed} accepted via baseline" if suppressed else "") + "\n"]
    if n_tools == 0:
        out.append("> No MCP tools were found statically. That means *unknown*, not *safe*.\n")
    for w in warnings:
        out.append(f"> ⚠️ {_cell(w)}\n")
    if findings:
        out.append("| Severity | Scanner | Rule | Location |\n|---|---|---|---|")
        for f in findings[:50]:
            out.append(f"| {_ICON[f.severity]} {f.severity} | {f.scanner} | {_cell(f.rule)} | `{_cell(f.file)}:{f.line}` |")
        if len(findings) > 50:
            out.append(f"\n…and {len(findings) - 50} more in the SARIF/JSON output.")
    return "\n".join(out) + "\n"
