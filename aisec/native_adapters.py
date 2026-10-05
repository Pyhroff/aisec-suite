"""Native adapters for the specialist scanners exposed by the umbrella CLI.
The specialist projects remain source-of-truth; these adapters normalize their
library findings into aisec.model.Finding when the package is installed.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
from typing import Any

from aisec.model import Finding

def _run_json(scanner: str, args: list[str], *, root: pathlib.Path) -> tuple[int, Any, str]:
    proc = subprocess.run(
        [sys.executable, "-m", scanner, *args],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return proc.returncode, None, (proc.stderr or proc.stdout).strip()
    return proc.returncode, payload, proc.stderr.strip()

def scan_training_dataset(dataset: pathlib.Path, warnings: list[str] | None = None) -> list[Finding]:
    """Run trainsentry's JSON output through its installed CLI."""
    if not dataset.is_file():
        raise ValueError(f"dataset does not exist: {dataset}")
    try:
        rc, payload, err = _run_json("trainsentry.cli", ["scan", str(dataset), "--json", "-"], root=dataset.parent)
    except Exception as exc:
        if warnings is not None:
            warnings.append(f"trainsentry unavailable: {exc}")
        return []
    if payload is None:
        if warnings is not None:
            warnings.append(f"trainsentry returned no JSON (exit {rc}): {err}")
        return []
    return _findings_from_payload("trainsentry", payload, dataset.parent)

def scan_agent_trace(trace: pathlib.Path, warnings: list[str] | None = None) -> list[Finding]:
    """Run loopcheck analyze in JSON mode against a trace."""
    if not trace.is_file():
        raise ValueError(f"trace does not exist: {trace}")
    try:
        rc, payload, err = _run_json("loopcheck.cli", ["analyze", str(trace), "--json", "-"], root=trace.parent)
    except Exception as exc:
        if warnings is not None:
            warnings.append(f"loopcheck unavailable: {exc}")
        return []
    if payload is None:
        if warnings is not None:
            warnings.append(f"loopcheck returned no JSON (exit {rc}): {err}")
        return []
    return _findings_from_payload("loopcheck", payload, trace.parent)

def scan_supply_chain(target: str, warnings: list[str] | None = None) -> list[Finding]:
    """Run the guardrail inspection CLI and normalize its JSON finding list."""
    try:
        rc, payload, err = _run_json("guardrail.cli", ["inspect", target, "--format", "json"], root=pathlib.Path.cwd())
    except Exception as exc:
        if warnings is not None:
            warnings.append(f"agent-install-guardrail unavailable: {exc}")
        return []
    if payload is None:
        if warnings is not None:
            warnings.append(f"agent-install-guardrail returned no JSON (exit {rc}): {err}")
        return []
    return _findings_from_payload("agent-install-guardrail", payload, pathlib.Path.cwd())

def scan_worm_tree(root: pathlib.Path, warnings: list[str] | None = None) -> list[Finding]:
    """Run wormsentry's library checks directly."""
    try:
        from wormsentry.package import Package
        from wormsentry.checks.install_script_risk import check_install_script_risk
        from wormsentry.checks.credential_harvesting import check_credential_harvesting
        from wormsentry.checks.self_propagation import check_self_propagation
    except ImportError as exc:
        if warnings is not None:
            warnings.append(f"wormsentry unavailable: {exc}")
        return []
    pkg = Package.load(str(root))
    out: list[Finding] = []
    for finding in (
        *check_install_script_risk(pkg),
        *check_credential_harvesting(pkg),
        *check_self_propagation(pkg),
    ):
        out.append(Finding("wormsentry", f"{finding.check}: {finding.title}", finding.severity.value,
                           finding.detail, finding.file, finding.line))
    return out

def _findings_from_payload(scanner: str, payload: Any, root: pathlib.Path) -> list[Finding]:
    """Best-effort normalization for common specialist JSON report shapes."""
    if isinstance(payload, dict):
        raw = payload.get("findings", payload.get("results", []))
    elif isinstance(payload, list):
        raw = payload
    else:
        raw = []
    out: list[Finding] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "low")).lower()
        if severity not in {"low", "medium", "high", "critical"}:
            severity = "low"
        file_name = str(item.get("file", item.get("path", root)))
        try:
            line = int(item.get("line", 1))
        except (TypeError, ValueError):
            line = 1
        title = str(item.get("title", item.get("rule", item.get("check", "finding"))))
        detail = str(item.get("detail", item.get("message", "")))
        check = str(item.get("check", title))
        out.append(Finding(scanner, f"{check}: {title}", severity, detail, file_name, line))
    return out
