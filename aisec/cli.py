from __future__ import annotations

import collections
import json
import pathlib
from typing import Optional

import typer

from aisec import __version__
from aisec.adapters import scan_context_files, scan_manifest_files, scan_mcp_source, scan_rag_dir
from aisec.model import SEVERITY_ORDER, at_least
from aisec.sarif import to_sarif

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
) -> None:
    if fail_on and fail_on not in SEVERITY_ORDER:
        raise typer.BadParameter("must be one of low|medium|high|critical")
    root = path.resolve()
    warnings: list[str] = []
    findings, n_tools = scan_mcp_source(root, include_tests, warnings)
    findings += scan_manifest_files(root, warnings)
    findings += scan_context_files(root, warnings)
    if rag:
        findings += scan_rag_dir(rag.resolve(), root, warnings)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))

    if sarif:
        sarif.write_text(json.dumps(to_sarif(findings), indent=2))
    if json_out:
        json_out.write_text(json.dumps([f.to_dict() for f in findings], indent=2))

    for w in warnings:
        typer.echo(f"warning: {w}", err=True)
    by_sev = collections.Counter(f.severity for f in findings)
    typer.echo(f"tools extracted: {n_tools} | findings: {len(findings)} "
               f"(critical {by_sev['critical']}, high {by_sev['high']}, medium {by_sev['medium']}, low {by_sev['low']})")
    if n_tools == 0:
        typer.echo("note: no MCP tools were found statically; that means 'unknown', not 'safe'.")
    for f in findings[:25]:
        typer.echo(f"  [{f.severity:8}] {f.file}:{f.line}  {f.scanner}  {f.rule}")
    if len(findings) > 25:
        typer.echo(f"  ... and {len(findings) - 25} more (use --json or --sarif for all)")
    if fail_on and any(at_least(f.severity, fail_on) for f in findings):
        raise typer.Exit(1)
