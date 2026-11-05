"""The benchmark gate must fail on any regression and on any unrecorded improvement."""
from benchmarks.check import DIRECTION, compare


def test_identical_runs_pass():
    base = {"poison.seen_medium": 40, "poison.test_fp_medium": 2}
    assert compare(base, dict(base)) == ([], [])


def test_fewer_detections_is_a_regression():
    worse, better = compare({"poison.seen_medium": 40}, {"poison.seen_medium": 39})
    assert worse == ["poison.seen_medium: 40 -> 39"] and better == []


def test_more_false_positives_is_a_regression():
    worse, _ = compare({"poison.test_fp_medium": 2}, {"poison.test_fp_medium": 3})
    assert worse == ["poison.test_fp_medium: 2 -> 3"]


def test_any_wrong_refutation_is_a_regression():
    worse, _ = compare({"reach.wrong_refutations": 0}, {"reach.wrong_refutations": 1})
    assert worse


def test_improvement_is_reported_so_the_baseline_and_docs_get_updated():
    worse, better = compare({"reach.fp_removed.unseen": 4, "poison.test_fp_medium": 2},
                            {"reach.fp_removed.unseen": 5, "poison.test_fp_medium": 1})
    assert worse == [] and len(better) == 2


def test_missing_metric_fails():
    worse, _ = compare({"poison.seen_medium": 40}, {})
    assert worse


def test_lower_is_better_metrics_are_declared():
    assert DIRECTION["poison.test_fp_medium"] == -1 and DIRECTION["reach.wrong_refutations"] == -1


def test_fetch_refuses_unexpected_corpus_entries(tmp_path):
    import pytest

    from benchmarks.fetch_corpus import fetch

    for repo, url, sha in [
        ("a/b", "https://evil.example/a/b.git", "0" * 40),
        ("a/b", "https://github.com/a/b.git", "HEAD; rm -rf /"),
        ("../x", "https://github.com/a/b.git", "0" * 40),
        ("a/b", "--upload-pack=touch /tmp/x", "0" * 40),
    ]:
        with pytest.raises(ValueError):
            fetch(repo, url, sha, tmp_path)
