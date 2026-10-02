"""Choose the detector's two thresholds from the CALIBRATION half of real tool descriptions only (no positives).

medium = lowest score whose calibration false-positive rate is <= 1%;  high = lowest with <= 0.1%.
Usage: python -m benchmarks.poison.calibrate --study ../mcp-scan-study
"""
from __future__ import annotations

import argparse
import collections
import pathlib

from aisec import poison
from benchmarks.poison.run import load_negatives

ap = argparse.ArgumentParser()
ap.add_argument("--study", required=True)
a = ap.parse_args()
negs = [n for n in load_negatives(pathlib.Path(a.study)) if n["half"] == "calib"]
scores = [poison.detect(n)[0] for n in negs]
print(f"calibration negatives: {len(negs)}")
hist = collections.Counter(int(s) for s in scores)
print("score histogram (floor):", dict(sorted(hist.items())))
for target, label in ((0.005, "medium (<=0.5%)"), (0.001, "high (<=0.1%)")):
    t = next(x for x in [i / 2 for i in range(1, 60)] if sum(s >= x for s in scores) / len(scores) <= target)
    print(f"{label}: threshold {t} -> calibration FPR {100 * sum(s >= t for s in scores) / len(scores):.2f}%")
