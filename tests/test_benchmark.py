import json

from aisec.benchmark import evaluate_cases, load_metrics


def test_load_metrics_requires_versioned_contract(tmp_path):
    path = tmp_path / "metrics.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "cases": 1,
        "overall": {},
        "by_scanner": {},
    }))
    assert load_metrics(path)["schema_version"] == 1


def test_load_metrics_rejects_unknown_schema(tmp_path):
    path = tmp_path / "metrics.json"
    path.write_text(json.dumps({"schema_version": 99}))
    try:
        load_metrics(path)
    except ValueError as exc:
        assert "unsupported benchmark metrics schema" in str(exc)
    else:
        raise AssertionError("expected schema validation failure")


def test_evaluate_cases_uses_shared_metrics_contract():
    metrics = evaluate_cases({"vuln"}, {"vuln", "clean"}, {"clean"})
    assert metrics["true_positive"] == 1
    assert metrics["false_positive"] == 1
    assert metrics["false_negative"] == 0
    assert metrics["precision"] == 0.5
