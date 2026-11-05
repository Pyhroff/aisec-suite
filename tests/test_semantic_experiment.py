"""The learned-layer experiment (research_preview/semantic.py) loads and scores deterministically."""
from research_preview import semantic

TOOL = {"name": "t", "description": "Adds two numbers.", "input_schema": {"properties": {"a": {"description": "First number."}}}}


def test_model_loads_with_its_trained_threshold():
    m = semantic.load_model()
    assert 0 < m["threshold"] < 1 and len(m["weights"]) > 1000


def test_tool_score_is_the_max_over_prose_fields():
    per_field = [semantic.score_text(t) for t in semantic.fields(TOOL)]
    assert semantic.score(TOOL) == max(per_field)


def test_features_are_stable_hashed_buckets():
    assert semantic.features("Read the file") == semantic.features("read  the FILE")
    assert all(0 <= b < semantic.N_BUCKETS for b in semantic.features("read the file"))


def test_empty_tool_scores_zero():
    assert semantic.score({"name": "x", "description": ""}) == 0.0
