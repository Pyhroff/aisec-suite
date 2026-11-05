"""Train the learned tool-poisoning layer (protocol: docs/SEMANTIC_LAYER_PROTOCOL.md). Training data only.

Positives: every MCP-Poison-Bench payload (injection text alone) and the seen register of attacks.py.
Negatives: the calibration half of the study's real tool descriptions and tests/fixtures/benign_tools.json.
Threshold: 99.5th percentile of 5-fold out-of-fold scores on the training negatives.

Usage: python -m benchmarks.poison.semantic_train --study ../mcp-scan-study --mpb DIR/MCP-Poison-Bench
Needs scikit-learn (training only; the shipped model is plain JSON).
"""
from __future__ import annotations

import argparse
import json
import pathlib

from benchmarks.poison.attacks import POSITIVES
from benchmarks.poison.external import mpb_payloads
from benchmarks.poison.run import load_negatives
from research_preview import semantic

ROOT = pathlib.Path(__file__).resolve().parents[2]


def training_set(study: pathlib.Path, mpb: pathlib.Path) -> tuple[list[str], list[int]]:
    texts: list[str] = []
    labels: list[int] = []
    for p in mpb_payloads(mpb):
        texts.append(p["injection"])
        labels.append(1)
    for p in POSITIVES:
        if p["register"] == "seen":
            for t in semantic.fields(p["tool"]):
                texts.append(t)
                labels.append(1)
    negs = [n for n in load_negatives(study) if n["half"] == "calib"]
    negs += json.loads((ROOT / "tests" / "fixtures" / "benign_tools.json").read_text(encoding="utf-8"))
    for n in negs:
        for t in semantic.fields(n):
            texts.append(t)
            labels.append(0)
    return texts, labels


def train(texts: list[str], labels: list[int]) -> dict:
    import numpy as np
    from scipy.sparse import csr_matrix
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold

    rows, cols, vals = [], [], []
    for i, t in enumerate(texts):
        idx = semantic.features(t)
        rows += [i] * len(idx)
        cols += idx
        vals += [1.0 / max(len(idx), 1) ** 0.5] * len(idx)
    x = csr_matrix((vals, (rows, cols)), shape=(len(texts), semantic.N_BUCKETS))
    y = np.array(labels)

    def fit(xs, ys):
        return LogisticRegression(C=1.0, class_weight="balanced", max_iter=5000).fit(xs, ys)

    oof = np.zeros(len(y))
    for tr, te in StratifiedKFold(n_splits=5, shuffle=True, random_state=0).split(x, y):
        oof[te] = fit(x[tr], y[tr]).predict_proba(x[te])[:, 1]
    threshold = float(np.percentile(oof[y == 0], 99.5))
    clf = fit(x, y)
    w = clf.coef_[0]
    nz = np.nonzero(np.abs(w) >= 1e-4)[0]
    return {
        "format": "aisec-semantic-v1",
        "features": "canonical lower-case word 1-2grams, blake2b-8 % 2^18, binary, l2-normalised",
        "bias": round(float(clf.intercept_[0]), 6),
        "threshold": round(threshold, 6),
        "training": {"texts": len(y), "positives": int(y.sum()), "negatives": int((y == 0).sum()),
                     "oof_recall_at_threshold": round(float((oof[y == 1] >= threshold).mean()), 4)},
        "weights": {str(int(i)): round(float(w[i]), 5) for i in nz},
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--study", required=True)
    ap.add_argument("--mpb", required=True)
    ap.add_argument("--out", default=str(semantic.MODEL_PATH))
    a = ap.parse_args()
    model = train(*training_set(pathlib.Path(a.study), pathlib.Path(a.mpb)))
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(model, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    print(json.dumps({k: v for k, v in model.items() if k != "weights"}, indent=1), f"\nweights: {len(model['weights'])}")
