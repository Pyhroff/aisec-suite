from aisec.metrics import evaluate


def test_detection_metrics():
    m = evaluate({"mcp-1", "mcp-2"}, {"mcp-1", "clean-1"}, {"clean-1", "clean-2"})
    assert m.true_positive == 1
    assert m.false_positive == 1
    assert m.false_negative == 1
    assert round(m.precision, 4) == 0.5
    assert round(m.recall, 4) == 0.5
    assert round(m.f1, 4) == 0.5
