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
from aisec.modules import available_modules
from aisec.sarif import to_sarif
from aisec.summary import to_markdown

app = typer.Typer(name="aisec", help="Unified AI security toolkit.", no_args_is_help=True)


@app.callback()
def _main(version: bool = typer.Option(False, "--version", is_eager=True)) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command("modules")
def modules() -> None:
    """List all suite modules and their optional specialist packages."""
    for spec in available_modules():
        typer.echo(f"{spec.name:13} {spec.package:30} {spec.description}")


@app.command()
def scan(
    path: pathlib.Path = typer.Argument(..., exists=True, file_okay=False, help="Repository root to scan."),
    only: Optional[str] = typer.Option(None, "--only", help="Comma-separated modules: mcp,memory,rag. Other portfolio modules are exposed by aisec modules and remain specialist commands until native adapters exist."),
    rag: Optional[pathlib.Path] = typer.Option(None, "--rag", help="Directory of RAG source documents."),
    sarif: Optional[pathlib.Path] = typer.Option(None, "--sarif", help="Write SARIF 2.1.0 here."),
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json", help="Write normalized findings as JSON."),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit 1 at low|medium|high|critical."),
    include_tests: bool = typer.Option(False, "--include-tests", help="Also inspect tests/examples/fixtures."),
    reach: str = typer.Option("annotate", "--reach", help="off | annotate | strict."),
    structural: bool = typer.Option(True, "--structural/--no-structural", help="Enable structural MCP poisoning detector."),
    baseline: Optional[pathlib.Path] = typer.Option(None, "--baseline", help="Accepted finding fingerprints."),
    write_baseline: Optional[pathlib.Path] = typer.Option(None, "--write-baseline", help="Accept all current findings."),
    summary: Optional[pathlib.Path] = typer.Option(None, "--summary", help="Write Markdown summary."),
) -> None:
    if reach not in ("off", "annotate", "strict"):
        raise typer.BadParameter("--reach must be off, annotate or strict")
    if fail_on and fail_on not in SEVERITY_ORDER:
        raise typer.BadParameter("must be one of low|medium|high|critical")
    root = path.resolve()
    warnings: list[str] = []
    crashed: list[str] = []

    def guarded(label, fn, default, *args):
        try:
            return fn(*args)
        except Exception as e:  # noqa: BLE001
            crashed.append(label)
            warnings.append(f"{label} crashed ({type(e).__name__}: {e}); its results are missing")
            return default

    findings: list = []
    n_tools = 0
    selected = {"mcp", "memory"}
    if rag:
        selected.add("rag")
    if only:
        requested = {x.strip() for x in only.split(",") if x.strip()}
        unknown = requested - {"mcp", "memory", "rag"}
        if unknown:
            raise typer.BadParameter("unsupported inline modules: " + ", ".join(sorted(unknown)) + "; use the specialist CLI until a native adapter is added")
        selected = requested
    if not selected:
        raise typer.BadParameter("no runnable static modules selected")

    if "mcp" in selected:
        findings, n_tools = guarded("mcpaudit (source)", scan_mcp_source, ([], 0), root, include_tests, warnings, reach, structural)
        findings = list(findings)
        findings += guarded("mcpaudit (manifests)", scan_manifest_files, [], root, warnings)
    if "memory" in selected:
        findings += guarded("memsentry", scan_context_files, [], root, warnings)
    if "rag" in selected and rag:
        findings += guarded("ragsentry", scan_rag_dir, [], rag.resolve(), root, warnings)

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line, f.scanner, f.rule))
    if write_baseline:
        write_baseline.write_text(json.dumps(sorted({f.fingerprint for f in findings}), indent=2), encoding="utf-8")
        typer.echo(f"baseline written: {len(findings)} findings accepted -> {write_baseline}")
    suppressed = 0
    if baseline:
        try:
            accepted = set(json.loads(baseline.read_text(encoding="utf-8")))
        except (OSError, ValueError) as e:
            raise typer.BadParameter(f"cannot read baseline: {e}")
        kept = [f for f in findings if f.fingerprint not in accepted]
        suppressed, findings = len(findings) - len(kept), kept
    if sarif:
        sarif.write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")
    if json_out:
        json_out.write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")
    summary_path = summary or (pathlib.Path(os.environ["GITHUB_STEP_SUMMARY"]) if os.environ.get("GITHUB_STEP_SUMMARY") else None)
    if summary_path:
        with summary_path.open("a", encoding="utf-8") as fh:
            fh.write(to_markdown(findings, n_tools, warnings, suppressed))
    for w in warnings:
        typer.echo(f"warning: {w}", err=True)
    by_sev = collections.Counter(f.severity for f in findings)
    typer.echo(
        f"tools extracted: {n_tools} | findings: {len(findings)} "
        f"(critical {by_sev['critical']}, high {by_sev['high']}, medium {by_sev['medium']}, low {by_sev['low']})"
    )
    if suppressed:
        typer.echo(f"baseline-suppressed: {suppressed}")
    for f in findings[:25]:
        typer.echo(f"  [{f.severity:8}] {f.file}:{f.line}  {f.scanner}  {f.rule}")
    if len(findings) > 25:
        typer.echo(f"  ... and {len(findings) - 25} more")
    if fail_on and crashed and not any(at_least(f.severity, fail_on) for f in findings):
        typer.echo(f"error: {len(crashed)} scanner(s) crashed; result is incomplete (exit 2)", err=True)
        raise typer.Exit(2)
    if fail_on and any(at_least(f.severity, fail_on) for f in findings):
        raise typer.Exit(1)
