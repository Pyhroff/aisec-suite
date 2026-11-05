"""Benchmark regression gate: re-run every measured claim in docs/STUDY.md and compare with benchmarks/baseline.json.

Fails (exit 1) when any metric gets worse: fewer attacks caught, more false positives, fewer accurate findings kept,
any wrong refutation. When a metric improves it also fails, asking for the baseline (and the docs quoting it) to be
updated in the same change, so published numbers cannot drift silently in either direction.

Usage:
  python -m benchmarks.fetch_corpus --study ../mcp-scan-study --out corpus
  python -m benchmarks.check --study ../mcp-scan-study --corpus corpus [--write-baseline]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from benchmarks import eval_reach
from benchmarks.poison import evasion
from benchmarks.poison import run as poison_run

BASELINE = pathlib.Path(__file__).with_name("baseline.json")

# metric -> +1 if higher is better, -1 if lower is better
DIRECTION = {
    "poison.seen_medium": 1, "poison.heldout_medium": 1, "poison.seen_high": 1, "poison.heldout_high": 1,
    "poison.test_fp_medium": -1, "poison.test_fp_high": -1,
    "reach.fp_removed.dev": 1, "reach.fp_removed.unseen": 1, "reach.accurate_kept.all": 1,
    "reach.wrong_refutations": -1, "reach.decided": 1,
}


def measure(study: pathlib.Path, corpus: pathlib.Path) -> dict[str, int]:
    m: dict[str, int] = {}
    det = poison_run.evaluate(study)["detectors"]["aisec-structural"]
    for level in ("medium", "high"):
        m[f"poison.seen_{level}"] = det[level]["recall"]["seen/all"]["hit"]
        m[f"poison.heldout_{level}"] = det[level]["recall"]["heldout/all"]["hit"]
        m[f"poison.test_fp_{level}"] = det[level]["false_positives"]["hit"]
    ev = evasion.evaluate()["transforms"]
    for name, row in ev.items():
        m[f"evasion.{name}"] = row["kept"]
        DIRECTION.setdefault(f"evasion.{name}", 1)
    rs = eval_reach.evaluate(study, corpus)["summary"]
    m["reach.fp_removed.dev"] = int(rs["dev"]["false_positives_removed"].split("/")[0])
    m["reach.fp_removed.unseen"] = int(rs["unseen (heldout+fresh)"]["false_positives_removed"].split("/")[0])
    m["reach.accurate_kept.all"] = int(rs["all"]["accurate_retained"].split("/")[0])
    m["reach.wrong_refutations"] = rs["wrong_refutations"]
    m["reach.decided"] = rs["decided"]
    return m


def compare(base: dict[str, int], now: dict[str, int]) -> tuple[list[str], list[str]]:
    worse, better = [], []
    for key in sorted(set(base) | set(now)):
        if key not in base or key not in now:
            worse.append(f"{key}: present in only one of baseline/current run")
            continue
        delta = (now[key] - base[key]) * DIRECTION.get(key, 1)
        line = f"{key}: {base[key]} -> {now[key]}"
        if delta < 0:
            worse.append(line)
        elif delta > 0:
            better.append(line)
    return worse, better


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--study", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--write-baseline", action="store_true")
    a = ap.parse_args()
    now = measure(pathlib.Path(a.study), pathlib.Path(a.corpus))
    if a.write_baseline:
        BASELINE.write_text(json.dumps(now, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {BASELINE}")
        return 0
    worse, better = compare(json.loads(BASELINE.read_text(encoding="utf-8")), now)
    for title, items in (("REGRESSED", worse), ("IMPROVED (update baseline.json and the docs that quote it)", better)):
        if items:
            print(title)
            print("\n".join(f"  {x}" for x in items))
    if not worse and not better:
        print(f"all {len(now)} benchmark metrics match baseline.json")
    return 1 if worse or better else 0


if __name__ == "__main__":
    sys.exit(main())
