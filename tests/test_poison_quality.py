"""Quality regression gate for the structural tool-poisoning detector.

Locks in the measured behaviour documented in README.md / docs/STUDY.md using only data committed to this repo:

* recall on the 108 synthetic positives in ``benchmarks/poison/attacks.py`` (54 "seen", 54 "held-out"), and
* false positives on ``tests/fixtures/benign_tools.json`` (66 realistic, deliberately hard benign descriptions).

The 3,974-description real-world corpus from the study is not in the repo, so the 0.03% FPR headline is checked by
``python -m benchmarks.poison.run``; this test guards against regressions that CI can see. If you improve the detector,
raise the floors; if you lower one, explain why in the PR.
"""
import json
import pathlib

from aisec import poison
from benchmarks.poison.attacks import POSITIVES

BENIGN = json.loads((pathlib.Path(__file__).parent / "fixtures" / "benign_tools.json").read_text(encoding="utf-8"))

# Measured at the time of writing: seen 34/54, held-out 26/54 (medium or higher).
MIN_RECALL = {"seen": 34, "heldout": 26}
MIN_HIGH_RECALL = {"seen": 11, "heldout": 7}
# Benign descriptions that are known to be flagged today (they quote credential/URL handling guidance). The set may
# shrink but must never grow.
KNOWN_FALSE_POSITIVES = {"http_request", "oauth_connect"}


def _hits(register, high=False):
    want = ("high",) if high else ("medium", "high")
    return sum(poison.detect(p["tool"])[1] in want for p in POSITIVES if p["register"] == register)


def test_corpus_sizes_are_what_the_docs_claim():
    assert sum(p["register"] == "seen" for p in POSITIVES) == 54
    assert sum(p["register"] == "heldout" for p in POSITIVES) == 54
    assert len(BENIGN) >= 60


def test_seen_recall_does_not_regress():
    assert _hits("seen") >= MIN_RECALL["seen"]


def test_heldout_recall_does_not_regress():
    assert _hits("heldout") >= MIN_RECALL["heldout"]


def test_high_severity_recall_does_not_regress():
    assert _hits("seen", high=True) >= MIN_HIGH_RECALL["seen"]
    assert _hits("heldout", high=True) >= MIN_HIGH_RECALL["heldout"]


def test_no_new_false_positives_on_benign_fixture():
    flagged = {t["name"] for t in BENIGN if poison.detect(t)[1]}
    assert flagged <= KNOWN_FALSE_POSITIVES, f"new false positives: {sorted(flagged - KNOWN_FALSE_POSITIVES)}"


def test_benign_false_positive_rate_budget():
    flagged = sum(poison.detect(t)[1] is not None for t in BENIGN)
    assert flagged / len(BENIGN) <= 0.035


def test_no_benign_description_reaches_high_severity():
    assert [t["name"] for t in BENIGN if poison.detect(t)[1] == "high"] == []


def test_baseline_regex_is_beaten_on_heldout():
    """The reason the detector exists: naive keyword matching scores ~0% on paraphrased attacks."""
    from benchmarks.poison.run import det_naive

    naive = sum(det_naive(p["tool"])[1] is not None for p in POSITIVES if p["register"] == "heldout")
    assert _hits("heldout") > naive + 15
