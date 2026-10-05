import json

from aisec.model import Finding
from aisec.policy import apply_policy, load_policy, profile_policy, validate_policy


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


def test_policy_rejects_unknown_top_level_field(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 1, "wat": True}))
    try:
        load_policy(path)
    except ValueError as exc:
        assert "unsupported policy fields" in str(exc)
    else:
        raise AssertionError("expected policy validation failure")


def test_policy_rejects_empty_exclusion(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 1, "exclude": [{}]}))
    try:
        load_policy(path)
    except ValueError as exc:
        assert "at least one field" in str(exc)
    else:
        raise AssertionError("expected policy validation failure")


def test_builtin_profiles_are_deterministic():
    assert profile_policy("strict").fail_on == "low"
    assert profile_policy("balanced").fail_on == "high"
    assert profile_policy("dev").fail_on == "critical"
    assert validate_policy(profile_policy("balanced"))["version"] == 1
