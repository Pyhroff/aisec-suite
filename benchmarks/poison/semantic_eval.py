"""Test run for the learned layer (protocol: docs/SEMANTIC_LAYER_PROTOCOL.md). Run once, after training.

Test sets: MCPTox (485 poisoned / 362 legitimate), the held-out register of attacks.py (54), and the test half of the
study's real tool descriptions. Detectors: structural alone, semantic alone, combined (structural medium+ OR semantic).

Usage: python -m benchmarks.poison.semantic_eval --study ../mcp-scan-study --mcptox DIR/MCPTox-Benchmark [--json out]
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib

from aisec import poison
from benchmarks.poison.attacks import POSITIVES
from benchmarks.poison.external import load as load_mcptox
from benchmarks.poison.run import load_negatives, wilson
from research_preview import semantic

MEDIUM = ("medium", "high", "critical")


def flags(tool: dict) -> dict[str, bool]:
    structural = poison.detect(tool)[1] in MEDIUM
    sem = semantic.detect(tool)[1] is not None
    return {"structural": structural, "semantic": sem, "combined": structural or sem}


def rate(hits: int, n: int) -> dict:
    return {"hit": hits, "n": n, "pct": round(100 * hits / n, 2) if n else 0.0, "ci95": wilson(hits, n)}


def evaluate(study: pathlib.Path, mcptox: pathlib.Path) -> dict:
    pos, neg = load_mcptox(mcptox)
    pf = [(p, flags(p["tool"])) for p in pos]
    nf = [flags(n["tool"]) for n in neg]
    held = [flags(p["tool"]) for p in POSITIVES if p["register"] == "heldout"]
    test_negs = [flags(n) for n in load_negatives(study) if n["half"] == "test"]
    out: dict = {}
    for d in ("structural", "semantic", "combined"):
        groups = {}
        for field in ("paradigm", "risk"):
            tot = collections.Counter(p[field] for p in pos)
            got = collections.Counter(p[field] for p, f in pf if f[d])
            groups[field] = {k: rate(got[k], tot[k]) for k in sorted(tot)}
        out[d] = {
            "mcptox_recall": rate(sum(f[d] for _p, f in pf), len(pf)),
            "mcptox_false_positives": rate(sum(f[d] for f in nf), len(nf)),
            "heldout_recall": rate(sum(f[d] for f in held), len(held)),
            "study_test_false_positives": rate(sum(f[d] for f in test_negs), len(test_negs)),
            **groups,
        }
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--study", required=True)
    ap.add_argument("--mcptox", required=True)
    ap.add_argument("--json")
    a = ap.parse_args()
    res = evaluate(pathlib.Path(a.study), pathlib.Path(a.mcptox))
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(res, indent=1), encoding="utf-8")
    for d, r in res.items():
        print(f"{d:11} MCPTox recall {r['mcptox_recall']['pct']:>6}% ({r['mcptox_recall']['hit']}/{r['mcptox_recall']['n']})"
              f"  MCPTox FP {r['mcptox_false_positives']['hit']}/{r['mcptox_false_positives']['n']}"
              f"  held-out {r['heldout_recall']['hit']}/{r['heldout_recall']['n']}"
              f"  study FP {r['study_test_false_positives']['pct']}% ({r['study_test_false_positives']['hit']}/{r['study_test_false_positives']['n']})")
