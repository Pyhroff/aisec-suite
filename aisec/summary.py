"""Markdown job summary and triage report."""

from __future__ import annotations

import collections

from aisec.model import Finding

_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "⬜"}
_PRIORITY = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3"}

def _cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")[:180]

def to_markdown(findings: list[Finding], n_tools: int, warnings: list[str], suppressed: int = 0, lifecycle=None) -> str:
    by = collections.Counter(f.severity for f in findings)
    out = ["## 🛡️ aisec-suite security report\n",
           f"**{len(findings)} active finding(s)** · 🟥 {by['critical']} critical · 🟧 {by['high']} high · "
           f"🟨 {by['medium']} medium · ⬜ {by['low']} low · MCP tools extracted: {n_tools}"]
    if suppressed:
        out.append(f"\n> ℹ️ {suppressed} finding(s) accepted by the baseline.")
    if lifecycle:
        out.append(f"\n**Lifecycle:** `{lifecycle.new_count}` new · `{lifecycle.existing_count}` existing · `{lifecycle.resolved_count}` resolved")
    if n_tools == 0:
        out.append("\n> ⚠️ No MCP tools were found statically. That means *unknown*, not *safe*.")
    for warning in warnings:
        out.append(f"\n> ⚠️ {_cell(warning)}")
    if findings:
        out.extend(["\n### Triage queue", "| Priority | Severity | Scanner | Rule | Location | Remediation |", "|---|---|---|---|---|---|"])
        for finding in findings[:50]:
            remediation = finding.remediation or "Review the finding and validate the affected trust boundary."
            out.append(f"| **{_PRIORITY[finding.severity]}** | {_ICON[finding.severity]} {finding.severity} | {_cell(finding.scanner)} | {_cell(finding.rule)} | `{_cell(finding.file)}:{finding.line}` | {_cell(remediation)} |")
        if len(findings) > 50:
            out.append(f"\n…and {len(findings) - 50} more in the SARIF/JSON output.")
    else:
        out.append("\n### Result\n✅ No active findings.")
    return "\n".join(out) + "\n"