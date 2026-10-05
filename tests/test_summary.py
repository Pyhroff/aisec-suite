from aisec.model import Finding
from aisec.summary import to_markdown


def test_markdown_report_contains_triage_and_remediation():
    finding = Finding(
        scanner="mcpaudit",
        rule="permission_scope",
        severity="high",
        message="tool has excessive access",
        file="server.py",
        line=12,
        remediation="Restrict the tool to its required path.",
    )
    report = to_markdown([finding], 2, [], 1)
    assert "Triage queue" in report
    assert "P1" in report
    assert "Restrict the tool" in report
    assert "2" in report


def test_markdown_report_is_safe_for_table_cells():
    finding = Finding(
        scanner="test|scanner",
        rule="bad|rule",
        severity="medium",
        message="line\nvalue",
        file="demo.py",
    )
    report = to_markdown([finding], 0, ["warning|value"])
    assert "test\\|scanner" in report
    assert "bad\\|rule" in report
    assert "warning\\|value" in report
