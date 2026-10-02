"""Poison benchmark runner: recall on synthetic positives (two registers) vs false-positive rate on REAL tool metadata.

Negatives: every tool description extracted from the study's 135 public MCP-server repos (not hand-checked tool by tool;
the study found no genuine poisoning among the ones its scanners flagged, so treat negatives as 'presumed clean').
Negatives are split by repo into a calibration half (used ONLY to set thresholds) and a test half (used for the
reported false-positive rate). Positives never influence thresholds.

Usage: python -m benchmarks.poison.run --study ../mcp-scan-study [--json out.json]
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import pathlib
import re

from benchmarks.poison.attacks import POSITIVES

NAIVE = re.compile(r"ignore (?:all )?(?:previous|prior) instructions|<important>|do not (?:tell|mention|inform)|don't (?:tell|mention)|"
                   r"never (?:mention|reveal)|\.ssh|id_rsa", re.I)


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    p, d = k / n, 1 + z * z / n
    c, m = p + z * z / (2 * n), z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round(100 * (c - m) / d, 1), round(100 * (c + m) / d, 1)]


def load_negatives(study: pathlib.Path) -> list[dict]:
    out, seen = [], set()
    for fname in ("manifests.json", "manifests_fresh.json"):
        for repo, v in json.loads((study / "data" / fname).read_text()).items():
            for t in v["tools"]:
                key = (t["name"], t["description"][:80])
                if key in seen or not t["description"].strip():
                    continue
                seen.add(key)
                half = "calib" if int(hashlib.sha256(repo.encode()).hexdigest(), 16) % 2 == 0 else "test"
                out.append({"name": t["name"], "description": t["description"], "input_schema": t.get("input_schema", {}), "repo": repo, "half": half})
    return out


# ---- detectors: tool dict -> (score, severity|None) ------------------------------------------------------------------
def det_naive(t: dict):
    return (1.0, "high") if NAIVE.search(t["description"]) else (0.0, None)


def det_mcpaudit(t: dict):
    from mcpaudit.checks.description_scan import scan_descriptions
    from mcpaudit.manifest import ServerManifest, ToolManifest
    fs = scan_descriptions(ServerManifest(server_name="bench", tools=[ToolManifest(t["name"], t["description"], t["input_schema"])]))
    if not fs:
        return (0.0, None)
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    top = max(fs, key=lambda f: order[f.severity.value])
    return (float(order[top.severity.value]), top.severity.value)


DETECTORS = {"naive-regex": det_naive, "mcpaudit-descriptions": det_mcpaudit}
try:  # structural detector (aisec-suite); optional so the harness runs without it
    from aisec import poison as _poison
    DETECTORS["aisec-structural"] = _poison.detect
except ImportError:
    pass


def evaluate(study: pathlib.Path) -> dict:
    negs = load_negatives(study)
    res: dict = {"negatives": {"total": len(negs), "calib": sum(n["half"] == "calib" for n in negs),
                               "test": sum(n["half"] == "test" for n in negs)},
                 "positives": {"total": len(POSITIVES)}, "detectors": {}}
    test_negs = [n for n in negs if n["half"] == "test"]
    for dname, det in DETECTORS.items():
        npos = [(p, det(p["tool"])) for p in POSITIVES]
        nneg = [(n, det(n)) for n in test_negs]
        d: dict = {}
        for level in ("any", "medium", "high"):
            rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            thr = 0 if level == "any" else rank[level]
            hit = lambda r: r[1] is not None and (level == "any" or rank[r[1]] >= thr)  # noqa: E731
            by = collections.defaultdict(lambda: [0, 0])
            for p, r in npos:
                by[(p["register"], "all")][1] += 1
                by[(p["register"], "all")][0] += hit(r)
                by[(p["register"], p["category"])][1] += 1
                by[(p["register"], p["category"])][0] += hit(r)
            fp = sum(hit(r) for _, r in nneg)
            d[level] = {
                "recall": {f"{reg}/{cat}": {"hit": k, "n": n, "pct": round(100 * k / n, 1), "ci95": wilson(k, n)}
                           for (reg, cat), (k, n) in sorted(by.items())},
                "false_positives": {"hit": fp, "n": len(nneg), "pct": round(100 * fp / len(nneg), 2), "ci95": wilson(fp, len(nneg))},
            }
        res["detectors"][dname] = d
    return res


def show(res: dict) -> None:
    print(f"negatives: {res['negatives']}  positives: {res['positives']['total']} (54 seen + 54 held-out)\n")
    print(f"{'detector':24} {'level':7} {'recall seen':>14} {'recall held-out':>17} {'FPR (test negatives)':>24}")
    for dname, d in res["detectors"].items():
        for level, v in d.items():
            s, h, fp = v["recall"]["seen/all"], v["recall"]["heldout/all"], v["false_positives"]
            print(f"{dname:24} {level:7} {s['pct']:>7}% ({s['hit']}/{s['n']}) {h['pct']:>8}% ({h['hit']}/{h['n']}) "
                  f"{fp['pct']:>8}% ({fp['hit']}/{fp['n']})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--study", required=True)
    ap.add_argument("--json")
    a = ap.parse_args()
    r = evaluate(pathlib.Path(a.study))
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(r, indent=1))
    show(r)
