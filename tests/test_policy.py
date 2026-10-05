import json

from aisec.model import Finding
from aisec.policy import apply_policy, load_policy


def test_policy_excludes_matching_findings(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "version": 1,
        "fail_on": "high",
        "exclude": [{"scanner": "mcpaudit", "rule": "demo-*", "file": "tests/**"}],
    }))
    policy = load_policy(path)
    findings = [
        Finding("mcpaudit", "demo-rule", "high", "x", "tests/demo.py"),
        Finding("mcpaudit", "real-rule", "high", "x", "app.py"),
    ]
    kept, excluded = apply_policy(findings, policy)
    assert excluded == 1
    assert len(kept) == 1
    assert kept[0].rule == "real-rule"
    assert policy.fail_on == "high"


def test_policy_rejects_unknown_version(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 2}))
    try:
        load_policy(path)
    except ValueError as exc:
        assert "version=1" in str(exc)
    else:
        raise AssertionError("expected policy validation failure")
