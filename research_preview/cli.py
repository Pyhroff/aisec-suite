"""CLI for the research-preview demos (``python -m research_preview``).

These commands are scripted walkthroughs on fixed synthetic inputs with pre-determined outcomes. They are not part of
the published ``aisec-suite`` wheel and are not detection results or runtime controls. They need the private scanner
packages and numpy.
"""
from __future__ import annotations

import json
import pathlib
from typing import Optional

import typer

from aisec.adapters import (
    scan_attestinfer_proofs,
    scan_circuitshield_traces,
    scan_context_files,
    scan_manifest_files,
    scan_mcp_source,
    scan_specprove_formal,
    scan_tokenspecter_streams,
    scan_weightspecter_checkpoints,
)

app = typer.Typer(
    name="research-preview",
    help=(
        "Scripted demos of the private research modules. They run on fixed synthetic inputs "
        "and report pre-determined outcomes; they are not detection results or runtime controls."
    ),
    no_args_is_help=True,
)

_DEMO_NOTICE = "NOTE: scripted demo on fixed synthetic inputs; outcomes are pre-determined, not measured."


@app.command("remediate")
def remediate(
    path: pathlib.Path = typer.Argument(..., exists=True, file_okay=False, help="Repository root to auto-remediate."),
    html_out: Optional[pathlib.Path] = typer.Option(None, "--html", help="Write Command Center HTML5 report after remediation."),
) -> None:
    """Demo: apply the private modules' repair routines to their fixture artifact formats."""
    typer.echo(_DEMO_NOTICE, err=True)
    from research_preview.command_center import (
        generate_unified_command_center_html,
        remediate_repository,
    )

    root = path.resolve()
    rem = remediate_repository(root)
    typer.echo(f"remediated {len(rem.actions)} artifact(s) under {root}")
    for act in rem.actions:
        typer.echo(f"  [{act.scanner}] {act.target_file}: {act.pre_status} -> {act.post_status} ({act.action_type})")

    if html_out is not None:
        warnings: list[str] = []
        post_findings = (
            scan_specprove_formal(root, warnings=warnings)
            + scan_weightspecter_checkpoints(root, warnings=warnings)
            + scan_tokenspecter_streams(root, warnings=warnings)
            + scan_circuitshield_traces(root, warnings=warnings)
            + scan_attestinfer_proofs(root, warnings=warnings)
        )
        html_out.parent.mkdir(parents=True, exist_ok=True)
        html_out.write_text(
            generate_unified_command_center_html(post_findings, rem),
            encoding="utf-8",
        )
        typer.echo(f"command center HTML written -> {html_out}")


@app.command("dashboard")
def dashboard(
    path: pathlib.Path = typer.Argument(..., exists=True, file_okay=False, help="Repository root to audit."),
    html_out: pathlib.Path = typer.Option(
        pathlib.Path("reports/aisec-command-center.html"),
        "--html",
        "-o",
        help="Output path for the demo HTML dashboard.",
    ),
    include_tests: bool = typer.Option(False, "--include-tests", help="Include test/sample directories."),
) -> None:
    """Demo: render an HTML dashboard of findings from the private research modules."""
    typer.echo(_DEMO_NOTICE, err=True)
    from research_preview.command_center import generate_unified_command_center_html

    root = path.resolve()
    warnings: list[str] = []
    mcp_findings, _ = scan_mcp_source(root, include_tests, warnings)
    findings = (
        list(mcp_findings)
        + scan_manifest_files(root, warnings)
        + scan_context_files(root, warnings)
        + scan_specprove_formal(root, include_tests, warnings)
        + scan_weightspecter_checkpoints(root, include_tests, warnings)
        + scan_tokenspecter_streams(root, include_tests, warnings)
        + scan_circuitshield_traces(root, include_tests, warnings)
        + scan_attestinfer_proofs(root, include_tests, warnings)
    )
    html_out.parent.mkdir(parents=True, exist_ok=True)
    html_out.write_text(
        generate_unified_command_center_html(findings, None),
        encoding="utf-8",
    )
    typer.echo(f"command center dashboard written ({len(findings)} findings) -> {html_out}")


@app.command("wargame")
def wargame(
    work_dir: pathlib.Path = typer.Option(
        pathlib.Path("reports/wargame_arena"),
        "--work-dir",
        help="Working directory for demo fixture artifacts.",
    ),
    html_out: pathlib.Path = typer.Option(
        pathlib.Path("reports/aisec-wargame-arena.html"),
        "--html",
        "-o",
        help="Output path for the demo HTML report.",
    ),
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json", help="Write JSON campaign report."),
) -> None:
    """Demo: replay a scripted five-stage attack/defence walkthrough on synthetic fixtures."""
    typer.echo(_DEMO_NOTICE, err=True)
    from dataclasses import asdict

    from research_preview.wargame import export_wargame_html, run_five_plane_wargame

    report = run_five_plane_wargame(work_dir.resolve())
    export_wargame_html(report, html_out.resolve())
    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")

    typer.echo(
        f"wargame campaign={report.campaign_id} | stages={report.stages_intercepted}/{report.total_stages} blocked | "
        f"blue_survival={report.blue_team_survival_prob*100:.1f}% | latency={report.total_latency_ms}ms"
    )
    for s in report.stages:
        typer.echo(
            f"  [Stage {s.stage_num}] {s.plane_name} :: {s.red_attack_name} -> {s.blue_interception_verdict}"
        )
    typer.echo(f"wargame arena HTML written -> {html_out}")


@app.command("guard-proxy")
def guard_proxy(
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json", help="Write Guard-Proxy transaction log as JSON."),
) -> None:
    """Demo: run the private modules' runtime checks on fixed sample inputs (no traffic is intercepted)."""
    typer.echo(_DEMO_NOTICE, err=True)
    from dataclasses import asdict

    from research_preview.wargame import ZeroTrustGuardProxy

    proxy = ZeroTrustGuardProxy()
    txs = proxy.inspect_and_shape_all()
    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps([asdict(t) for t in txs], indent=2), encoding="utf-8")

    typer.echo(f"guard-proxy demo ran {len(txs)} scripted sample check(s):")
    for t in txs:
        typer.echo(
            f"  [{t.tx_id}] {t.endpoint} | {t.verdict} | {t.action_taken} ({t.latency_ms}ms)"
        )


if __name__ == "__main__":
    app()
