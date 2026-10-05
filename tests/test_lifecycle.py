from aisec.lifecycle import classify, load_baseline
from aisec.model import Finding


def _finding(message: str) -> Finding:
    return Finding(
        scanner="test",
        rule="rule",
        severity="high",
        message=message,
        file="demo.py",
    )


def test_classify_reports_new_existing_and_resolved():
    existing = _finding("existing")
    new = _finding("new")
    resolved = _finding("resolved")
    diff = classify([existing, new], {existing.fingerprint, resolved.fingerprint})

    assert [f.message for f in diff.existing] == ["existing"]
    assert [f.message for f in diff.new] == ["new"]
    assert diff.resolved == (resolved.fingerprint,)
    assert diff.to_dict()["counts"] == {"new": 1, "existing": 1, "resolved": 1}


def test_load_baseline_rejects_non_fingerprint_payload(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text('{"fingerprints": []}', encoding="utf-8")
    try:
        load_baseline(path)
    except ValueError as exc:
        assert "JSON list" in str(exc)
    else:
        raise AssertionError("expected baseline validation failure")
