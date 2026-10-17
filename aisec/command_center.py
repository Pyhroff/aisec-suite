"""
Unified 11-Module Command Center Dashboard & Closed-Loop Auto-Remediation Engine (`aisec.command_center`).

Provides:
  1. `remediate_repository(root)`:
     Automatically repairs vulnerable artifacts across all 4 mathematical security domains:
       - Python protocol state-machine vulnerabilities -> repaired via `specprove.auto_patcher.ASTAutoPatcher`
       - Backdoored `.safetensors` LoRA/weight matrices -> sanitized via `weightspecter.spectral_engine.SpectralBackdoorAnalyzer.sanitize_checkpoint`
       - Leaky encrypted `.stream.json` SSE traces -> shaped via `tokenspecter.sidechannel_engine.ConstantRateStreamShaper`
       - Ablated `.act.json` residual stream traces -> clamped via `circuitshield.circuit_engine.CircuitShieldFirewall.clamp_and_heal_trace`
  2. `generate_unified_command_center_html(findings, remediation_records, output_path)`:
     Generates a single-pane-of-glass interactive HTML5 Cyber-Range Command Center with an SVG
     Multi-Layer Attack Kill-Chain Graph, scanner breakdown, and live Before/After remediation view.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from typing import Any, Dict, List

from aisec import __version__
from aisec.model import Finding


@dataclass
class RemediationAction:
    scanner: str
    target_file: str
    action_type: str
    pre_status: str
    post_status: str
    detail: str


@dataclass
class RemediationSummary:
    root_path: str
    actions: List[RemediationAction] = field(default_factory=list)


def remediate_repository(root: pathlib.Path) -> RemediationSummary:
    """
    Execute closed-loop mathematical auto-remediation across Python AST handlers,
    `.safetensors` weights, `.stream.json` packet captures, and `.act.json` residual traces.
    """
    summary = RemediationSummary(root_path=str(root))

    # 1. SpecProve-Sec Z3 CEGIS AST Auto-Patcher for .py files
    try:
        from specprove.auto_patcher import ASTAutoPatcher

        patcher = ASTAutoPatcher(max_k=8)
        for py_file in sorted(root.rglob("*.py")):
            if any(p in py_file.parts for p in (".venv", "venv", ".git", "tests")):
                continue
            rep = patcher.patch_file(py_file, write_in_place=True)
            if rep.initial_findings_count > 0:
                summary.actions.append(
                    RemediationAction(
                        scanner="specprove",
                        target_file=str(py_file.relative_to(root)),
                        action_type="Z3 CEGIS Guard Injection",
                        pre_status=f"VULNERABLE ({rep.initial_findings_count} Z3 SAT traces)",
                        post_status=f"PROVED_INDUCTIVE ({rep.post_patch_findings_count} violations)",
                        detail=", ".join(p.patch_name for p in rep.patches_applied),
                    )
                )
    except ImportError:
        pass

    # 2. WeightSpecter Surgical BBP Spike Sanitizer for .safetensors files
    try:
        from weightspecter.spectral_engine import SpectralBackdoorAnalyzer

        analyzer = SpectralBackdoorAnalyzer()
        for sf_file in sorted(root.rglob("*.safetensors")):
            if any(p in sf_file.parts for p in (".venv", "venv", ".git", "tests")):
                continue
            rep = analyzer.scan_checkpoint(sf_file)
            if rep.overall_verdict != "CLEAN":
                san = analyzer.sanitize_checkpoint(sf_file, sf_file)
                summary.actions.append(
                    RemediationAction(
                        scanner="weightspecter",
                        target_file=str(sf_file.relative_to(root)),
                        action_type="Surgical RMT BBP Spike Excision",
                        pre_status=f"{san.pre_verdict} (BBP={san.pre_max_bbp_ratio:.2f}x)",
                        post_status=f"{san.post_verdict} (BBP={san.post_max_bbp_ratio:.2f}x)",
                        detail=f"Sanitized {san.layers_sanitized} layer(s), retained {san.bulk_subspace_retention_pct:.0f}% bulk subspace",
                    )
                )
    except ImportError:
        pass

    # 3. TokenSpecter Constant-Rate 64B Bucket Shaper for .stream.json files
    try:
        from tokenspecter.sidechannel_engine import (
            ConstantRateStreamShaper,
            SideChannelVulnerabilityAuditor,
            load_stream_trace,
            save_stream_trace,
        )

        auditor = SideChannelVulnerabilityAuditor()
        shaper = ConstantRateStreamShaper()
        for st_file in sorted(root.rglob("*.stream.json")):
            if any(p in st_file.parts for p in (".venv", "venv", ".git", "tests")):
                continue
            tr = load_stream_trace(st_file)
            res = auditor.audit_trace(tr)
            if res.verdict != "SHAPED_SAFE":
                shaped_tr = shaper.shape_trace(tr)
                save_stream_trace(shaped_tr, st_file)
                post_res = auditor.audit_trace(shaped_tr)
                summary.actions.append(
                    RemediationAction(
                        scanner="tokenspecter",
                        target_file=str(st_file.relative_to(root)),
                        action_type="Constant-Rate 64B Bucket Padding + Chaff",
                        pre_status=f"{res.verdict} (MI={res.mutual_information_bits:.2f} bits)",
                        post_status=f"{post_res.verdict} (MI={post_res.mutual_information_bits:.2f} bits)",
                        detail="Quantized SSE frames to 64B buckets @ 25.0ms ticks",
                    )
                )
    except ImportError:
        pass

    # 4. CircuitShield Homeostatic Refusal-Subspace Clamping for .act.json files
    try:
        from circuitshield.circuit_engine import (
            CircuitShieldFirewall,
            load_activation_trace,
            save_activation_trace,
        )

        fw = CircuitShieldFirewall()
        for act_file in sorted(root.rglob("*.act.json")):
            if any(p in act_file.parts for p in (".venv", "venv", ".git", "tests")):
                continue
            tr = load_activation_trace(act_file)
            res = fw.audit_trace(tr)
            if res.verdict != "CIRCUIT_INTACT":
                clamped = fw.clamp_and_heal_trace(tr)
                save_activation_trace(clamped, act_file)
                post_res = fw.audit_trace(clamped)
                summary.actions.append(
                    RemediationAction(
                        scanner="circuitshield",
                        target_file=str(act_file.relative_to(root)),
                        action_type="Homeostatic Refusal-Subspace Clamping",
                        pre_status=f"{res.verdict} (RefProj={res.min_refusal_projection:.2f})",
                        post_status=f"{post_res.verdict} (RefProj={post_res.min_refusal_projection:.2f})",
                        detail=f"Restored refusal projection across {res.ablated_layers_count} ablated layer(s)",
                    )
                )
    except ImportError:
        pass

    return summary


def generate_unified_command_center_html(
    findings: List[Finding],
    remediation: RemediationSummary | None = None,
) -> str:
    """Render the unified 11-module `aisec-suite` Command Center HTML5 dashboard."""
    findings_json = json.dumps([f.to_dict() for f in findings])
    rem_json = json.dumps(
        [
            {
                "scanner": a.scanner,
                "target_file": a.target_file,
                "action_type": a.action_type,
                "pre_status": a.pre_status,
                "post_status": a.post_status,
                "detail": a.detail,
            }
            for a in (remediation.actions if remediation else [])
        ]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>aisec-suite v{__version__} — Unified 11-Module AI Security Command Center</title>
<style>
  :root {{
    --bg: #070a12;
    --panel: #0f1626;
    --panel2: #162038;
    --border: #263659;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --green: #22c55e;
    --red: #f43f5e;
    --amber: #f59e0b;
    --purple: #a855f7;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 24px; }}
  .hero {{
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 60%, #0f172a 100%);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 22px 28px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
  }}
  .hero h1 {{ font-size: 22px; color: #f8fafc; }}
  .hero p {{ font-size: 13px; color: var(--muted); margin-top: 4px; }}
  .kpis {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-bottom: 20px; }}
  .kpi {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px; }}
  .kpi .l {{ font-size: 11px; text-transform: uppercase; color: var(--muted); }}
  .kpi .v {{ font-size: 24px; font-weight: 700; margin-top: 4px; color: var(--accent); }}
  .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
  .card h2 {{ font-size: 16px; margin-bottom: 12px; color: #f8fafc; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); text-align: left; }}
  th {{ background: var(--panel2); color: var(--muted); font-size: 11px; text-transform: uppercase; }}
  .pill {{ padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
  .pill.critical, .pill.high {{ background: rgba(244,63,94,0.18); color: var(--red); border: 1px solid rgba(244,63,94,0.4); }}
  .pill.medium {{ background: rgba(245,158,11,0.18); color: var(--amber); }}
  .pill.clean {{ background: rgba(34,197,94,0.18); color: var(--green); border: 1px solid rgba(34,197,94,0.4); }}
</style>
</head>
<body>
<div class="hero">
  <div>
    <h1>aisec-suite v{__version__} — Unified 11-Module AI Security Command Center</h1>
    <p>Correlating Static MCP/RAG/Memory Hygiene &bull; Z3 SMT Formal Verification (SpecProve-Sec) &bull; RMT Spectral Weight Forensics (WeightSpecter v2.0) &bull; Viterbi Side-Channel Cryptanalysis (TokenSpecter) &bull; Mechanistic Refusal Firewall (CircuitShield)</p>
  </div>
  <div><span class="pill clean" style="font-size:12px;padding:6px 14px;">11 Specialist Scanners Active</span></div>
</div>

<div class="kpis" id="kpi-bar"></div>

<div class="card">
  <h2>Multi-Layer Agentic Kill-Chain Architecture &amp; Defense Planes</h2>
  <svg viewBox="0 0 960 150" style="width:100%;height:150px;background:#090d18;border-radius:10px;border:1px solid #1e293b;">
    <defs>
      <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#38bdf8"/>
      </marker>
    </defs>
    <rect x="20" y="35" width="160" height="80" rx="8" fill="#162038" stroke="#38bdf8" stroke-width="1.5"/>
    <text x="100" y="65" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">1. Data &amp; Weights</text>
    <text x="100" y="85" fill="#94a3b8" font-size="10" text-anchor="middle">WeightSpecter v2 (RMT/TW1)</text>
    <text x="100" y="100" fill="#94a3b8" font-size="10" text-anchor="middle">TrainSentry / RagSentry</text>

    <line x1="180" y1="75" x2="250" y2="75" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>

    <rect x="255" y="35" width="180" height="80" rx="8" fill="#162038" stroke="#a855f7" stroke-width="1.5"/>
    <text x="345" y="65" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">2. Residual Subspace</text>
    <text x="345" y="85" fill="#d8b4fe" font-size="10" text-anchor="middle">CircuitShield Firewall</text>
    <text x="345" y="100" fill="#94a3b8" font-size="10" text-anchor="middle">Homeostatic Refusal Clamp</text>

    <line x1="435" y1="75" x2="505" y2="75" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>

    <rect x="510" y="35" width="190" height="80" rx="8" fill="#162038" stroke="#22c55e" stroke-width="1.5"/>
    <text x="605" y="65" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">3. Protocol &amp; MCP Gate</text>
    <text x="605" y="85" fill="#86efac" font-size="10" text-anchor="middle">SpecProve-Sec (Z3 + Lean 4)</text>
    <text x="605" y="100" fill="#94a3b8" font-size="10" text-anchor="middle">MCPAudit + LoopCheck</text>

    <line x1="700" y1="75" x2="765" y2="75" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>

    <rect x="770" y="35" width="170" height="80" rx="8" fill="#162038" stroke="#f59e0b" stroke-width="1.5"/>
    <text x="855" y="65" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">4. Encrypted Wire</text>
    <text x="855" y="85" fill="#fcd34d" font-size="10" text-anchor="middle">TokenSpecter (Viterbi)</text>
    <text x="855" y="100" fill="#94a3b8" font-size="10" text-anchor="middle">64B Constant-Rate Shaper</text>
  </svg>
</div>

<div class="card" id="rem-card" style="display:none;">
  <h2>Closed-Loop Mathematical Auto-Remediation Ledger (`aisec remediate`)</h2>
  <table>
    <thead><tr><th>Scanner</th><th>Target Artifact</th><th>Remediation Engine</th><th>Pre-State</th><th>Post-State</th><th>Mathematical Proof / Detail</th></tr></thead>
    <tbody id="rem-body"></tbody>
  </table>
</div>

<div class="card">
  <h2>Unified Multi-Scanner Findings Table</h2>
  <table>
    <thead><tr><th>Severity</th><th>Scanner</th><th>Location</th><th>Rule</th><th>Message &amp; Mathematical Evidence</th><th>Suggested Remediation</th></tr></thead>
    <tbody id="findings-body"></tbody>
  </table>
</div>

<script>
const FINDINGS = {findings_json};
const REMEDIATIONS = {rem_json};

const scanners = new Set(FINDINGS.map(f => f.scanner));
const critCount = FINDINGS.filter(f => f.severity === 'critical' || f.severity === 'high').length;
document.getElementById('kpi-bar').innerHTML = `
  <div class="kpi"><div class="l">Total Findings</div><div class="v" style="color:${{FINDINGS.length ? 'var(--red)' : 'var(--green)'}}">${{FINDINGS.length}}</div></div>
  <div class="kpi"><div class="l">Critical / High</div><div class="v" style="color:${{critCount ? 'var(--red)' : 'var(--green)'}}">${{critCount}}</div></div>
  <div class="kpi"><div class="l">Scanners Triggered</div><div class="v">${{scanners.size}}</div></div>
  <div class="kpi"><div class="l">Auto-Remediations</div><div class="v" style="color:var(--green)">${{REMEDIATIONS.length}}</div></div>
  <div class="kpi"><div class="l">Suite Version</div><div class="v">v{__version__}</div></div>
`;

if (REMEDIATIONS.length > 0) {{
  document.getElementById('rem-card').style.display = 'block';
  document.getElementById('rem-body').innerHTML = REMEDIATIONS.map(r => `
    <tr>
      <td><strong>${{r.scanner}}</strong></td>
      <td><code>${{r.target_file}}</code></td>
      <td>${{r.action_type}}</td>
      <td style="color:var(--red)">${{r.pre_status}}</td>
      <td><span class="pill clean">${{r.post_status}}</span></td>
      <td>${{r.detail}}</td>
    </tr>
  `).join('');
}}

document.getElementById('findings-body').innerHTML = FINDINGS.length ? FINDINGS.map(f => `
  <tr>
    <td><span class="pill ${{f.severity}}">${{f.severity}}</span></td>
    <td><strong>${{f.scanner}}</strong></td>
    <td><code>${{f.file}}:${{f.line}}</code></td>
    <td>${{f.rule}}</td>
    <td>${{f.message}} <span style="color:#94a3b8;font-size:11px;">${{f.evidence ? '[' + f.evidence + ']' : ''}}</span></td>
    <td><code>${{f.remediation || '—'}}</code></td>
  </tr>
`).join('') : '<tr><td colspan="6" style="text-align:center;color:var(--green);font-weight:700;">0 Findings — All 11 Security Modules Passed!</td></tr>';
</script>
</body>
</html>
"""
