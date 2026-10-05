from aisec.model import Finding
from aisec.sarif import to_sarif


def test_sarif_shape_and_levels():
    fs = [Finding("mcpaudit", "permission_scope: Unscoped filesystem access", "high", "msg", "a/b.py", 12),
          Finding("memsentry", "hidden_payload: Abnormally long line", "medium", "m2", "CLAUDE.md", 0)]
    s = to_sarif(fs)
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert [r["level"] for r in run["results"]] == ["error", "warning"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
    assert run["results"][1]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1  # SARIF lines are 1-based
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"mcpaudit/permission_scope-unscoped-filesystem-access", "memsentry/hidden_payload-abnormally-long-line"}


def test_sarif_has_ranking_and_fingerprints():
    f = Finding("mcpaudit", "permission_scope: X", "high", "m", "a.py", 3)
    run = to_sarif([f])["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "8.0"
    assert run["results"][0]["partialFingerprints"]["aisec/v1"] == f.fingerprint
    assert Finding("mcpaudit", "permission_scope: X", "high", "m", "a.py", 99).fingerprint == f.fingerprint  # line-independent


def test_enriched_finding_metadata_is_exported():
    f = Finding("mcpaudit", "scope", "high", "msg", "a.py", 2, confidence=0.82, target="tool.read", remediation="Restrict the path scope")
    d = f.to_dict()
    assert d["confidence"] == 0.82
    assert d["target"] == "tool.read"
    assert d["remediation"] == "Restrict the path scope"
    result = to_sarif([f])["runs"][0]["results"][0]
    assert result["properties"]["confidence"] == 0.82
