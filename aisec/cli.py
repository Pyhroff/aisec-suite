from __future__ import annotations

import collections
import json
import os
import pathlib
from typing import Optional

import typer

from aisec import __version__
from aisec.adapters import scan_context_files, scan_manifest_files, scan_mcp_source, scan_rag_dir
from aisec.model import SEVERITY_ORDER, at_least
from aisec.sarif import to_sarif
from aisec.summary import to_markdown

app = typer.Typer(name="aisec", help="Run mcpaudit, memsentry and ragsentry on a repository in one command.", no_args_is_help=True)


@app.callback()
def _main(version: bool = typer.Option(False, "--version", is_eager=True)) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command()
def scan(
    path: pathlib.Path = typer.Argument(..., exists=True, file_okay=False, help="Repository root to scan."),
    rag: Optional[pathlib.Path] = typer.Option(None, "--rag", help="Directory of RAG source documents to scan with ragsentry."),
    sarif: Optional[pathlib.Path] = typer.Option(None, "--sarif", help="Write SARIF 2.1.0 here (for GitHub code scanning)."),
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json", help="Write findings as JSON here."),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit 1 if any finding is at or above: low|medium|high|critical."),
    include_tests: bool = typer.Option(False, "--include-tests", help="Also extract tools from tests/examples/fixtures."),
    baseline: Optional[pathlib.Path] = typer.Option(None, "--baseline", help="JSON file of accepted findings; they are hidden and never fail the run."),
    write_baseline: Optional[pathlib.Path] = typer.Option(None, "--write-baseline", help="Write current findings as a baseline (accept everything seen today)."),
    summary: Optional[pathlib.Path] = typer.Option(None, "--summary", help="Write a Markdown summary here (defaults to $GITHUB_STEP_SUMMARY when set)."),
) -> None:
    if fail_on and fail_on not in SEVERITY_ORDER:
        raise typer.BadParameter("must be one of low|medium|high|critical")
    root = path.resolve()
    warnings: list[str] = []
    crashed: list[str] = []

    def guarded(label, fn, default, *args):
        """A scanner bug must not masquerade as 'findings exist' (exit 1) nor as a clean pass."""
        try:
            return fn(*args)
        except Exception as e:  # noqa: BLE001 - third-party scanners; report, don't die
            crashed.append(label)
            warnings.append(f"{label} crashed ({type(e).__name__}: {e}); its results are missing")
            return default

    findings, n_tools = guarded("mcpaudit (source)", scan_mcp_source, ([], 0), root, include_tests, warnings)
    findings = list(findings)
    findings += guarded("mcpaudit (manifests)", scan_manifest_files, [], root, warnings)
    findings += guarded("memsentry", scan_context_files, [], root, warnings)
    if rag:
        findings += guarded("ragsentry", scan_rag_dir, [], rag.resolve(), root, warnings)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))

    if write_baseline:
        write_baseline.write_text(json.dumps(sorted({f.fingerprint for f in findings}), indent=2))
        typer.echo(f"baseline written: {len(findings)} findings accepted -> {write_baseline}")
    suppressed = 0
    if baseline:
        try:
            accepted = set(json.loads(baseline.read_text()))
        except (OSError, ValueError) as e:
            raise typer.BadParameter(f"cannot read baseline: {e}")
        kept = [f for f in findings if f.fingerprint not in accepted]
        suppressed, findings = len(findings) - len(kept), kept

    if sarif:
        sarif.write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")
    if json_out:
        json_out.write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")

    summary = summary or (pathlib.Path(os.environ["GITHUB_STEP_SUMMARY"]) if os.environ.get("GITHUB_STEP_SUMMARY") else None)
    if summary:
        with summary.open("a", encoding="utf-8") as fh:
            fh.write(to_markdown(findings, n_tools, warnings, suppressed))

    for w in warnings:
        typer.echo(f"warning: {w}", err=True)
    by_sev = collections.Counter(f.severity for f in findings)
    typer.echo(f"tools extracted: {n_tools} | findings: {len(findings)} "
               f"(critical {by_sev['critical']}, high {by_sev['high']}, medium {by_sev['medium']}, low {by_sev['low']})"
               + (f" | baseline-suppressed: {suppressed}" if suppressed else ""))
    if n_tools == 0:
        typer.echo("note: no MCP tools were found statically; that means 'unknown', not 'safe'.")
    for f in findings[:25]:
        typer.echo(f"  [{f.severity:8}] {f.file}:{f.line}  {f.scanner}  {f.rule}")
    if len(findings) > 25:
        typer.echo(f"  ... and {len(findings) - 25} more (use --json or --sarif for all)")
    if fail_on and crashed and not any(at_least(f.severity, fail_on) for f in findings):
        typer.echo(f"error: {len(crashed)} scanner(s) crashed, so a clean result can't be trusted (exit 2)", err=True)
        raise typer.Exit(2)
    if fail_on and any(at_least(f.severity, fail_on) for f in findings):
        raise typer.Exit(1)
