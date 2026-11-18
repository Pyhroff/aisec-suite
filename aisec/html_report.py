"""Self-contained HTML executive report writer for aisec scan."""
from __future__ import annotations

import html
from collections import Counter

from aisec import __version__
from aisec.model import Finding

_SEV_ORDER = ("critical", "high", "medium", "low")
_SEV_COLOR = {
    "critical": "#f85149",
    "high": "#db6d28",
    "medium": "#d29922",
    "low": "#58a6ff",
}


def to_html(findings: list[Finding], target: str = ".") -> str:
    counts = Counter(f.severity for f in findings)
    cards = "".join(
        f'<div class="card"><div class="num" style="color:{_SEV_COLOR[s]}">{counts.get(s, 0)}</div>'
        f'<div class="lbl">{s.upper()}</div></div>'
        for s in _SEV_ORDER
    )
    rows = []
    for f in findings:
        color = _SEV_COLOR.get(f.severity, "#8b949e")
        rows.append(
            "<tr>"
            f'<td><span class="badge" style="background:{color}">{html.escape(f.severity.upper())}</span></td>'
            f"<td><code>{html.escape(f.scanner)}</code></td>"
            f"<td><code>{html.escape(f.rule)}</code></td>"
            f"<td><code>{html.escape(f.file)}:{f.line}</code></td>"
            f"<td>{html.escape(f.message)}</td>"
            f"<td>{html.escape(f.remediation or '')}</td>"
            "</tr>"
        )
    table_body = "\n".join(rows) if rows else '<tr><td colspan="6" class="empty">No findings detected.</td></tr>'
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>aisec-suite v{html.escape(__version__)} Scan Report</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; }}
  h1 {{ margin: 0 0 6px; font-size: 20px; color: #f0f6fc; }}
  .meta {{ color: #8b949e; font-size: 13px; margin-bottom: 20px; }}
  .grid {{ display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 12px; margin-bottom: 24px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px; text-align: center; }}
  .num {{ font-size: 28px; font-weight: 700; }}
  .lbl {{ font-size: 11px; color: #8b949e; letter-spacing: 0.08em; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }}
  th, td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; text-align: left; font-size: 13px; vertical-align: top; }}
  th {{ background: #21262d; color: #f0f6fc; font-weight: 600; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; color: #0d1117; font-weight: 700; font-size: 11px; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: #79c0ff; }}
  .empty {{ text-align: center; color: #8b949e; padding: 24px; }}
</style>
</head>
<body>
  <h1>aisec-suite Scan Report</h1>
  <div class="meta">Version {html.escape(__version__)} · Target: <code>{html.escape(target)}</code> · Total findings: {len(findings)}</div>
  <div class="grid">{cards}</div>
  <table>
    <thead><tr><th>Severity</th><th>Scanner</th><th>Rule</th><th>Location</th><th>Message</th><th>Remediation</th></tr></thead>
    <tbody>
      {table_body}
    </tbody>
  </table>
</body>
</html>
"""
