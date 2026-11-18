from pathlib import Path

from typer.testing import CliRunner

from aisec.cli import app
from aisec.html_report import to_html
from aisec.model import Finding


def test_to_html_renders_counts_and_escaped_findings():
    f = Finding(
        scanner="mcpaudit",
        rule="description_scan",
        severity="high",
        file="server.py",
        line=12,
        message="Injected <script>alert(1)</script> tag",
        remediation="Remove hidden instructions",
    )
    out = to_html([f], target="demo/")
    assert "<!DOCTYPE html>" in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "Remove hidden instructions" in out
    assert "mcpaudit" in out


def test_cli_scan_writes_html_report(tmp_path: Path):
    report = tmp_path / "report.html"
    res = CliRunner().invoke(app, ["scan", "examples/demo-mcp-server/fixed", "--html", str(report)])
    assert res.exit_code == 0
    assert report.exists()
    content = report.read_text(encoding="utf-8")
    assert "aisec-suite Scan Report" in content
