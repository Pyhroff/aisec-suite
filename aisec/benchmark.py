"""Orchestration helpers for controlled aisec-suite regression benchmarks."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from aisec.metrics import evaluate


def run_range(range_dir: Path, metrics_json: Path | None = None) -> tuple[int, str]:
    """Run an agent-test-range checkout using its own CI harness."""
    script = range_dir / "scripts" / "run_range.py"
    if not script.is_file():
        raise FileNotFoundError(f"benchmark harness not found: {script}")
    cmd = [sys.executable, str(script)]
    if metrics_json:
        cmd += ["--metrics-json", str(metrics_json)]
    proc = subprocess.run(cmd, cwd=range_dir, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def load_metrics(path: Path) -> dict:
    """Load and validate the versioned benchmark JSON contract."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported benchmark metrics schema")
    for key in ("cases", "overall", "by_scanner"):
        if key not in payload:
            raise ValueError(f"benchmark metrics missing required field: {key}")
    return payload


def evaluate_cases(expected_vulnerable: set[str], detected: set[str], expected_clean: set[str]) -> dict:
    """Expose the shared metric contract for callers with their own corpora."""
    return evaluate(expected_vulnerable, detected, expected_clean).to_dict()
