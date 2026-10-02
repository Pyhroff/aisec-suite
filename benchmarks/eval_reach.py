"""Evaluate sink-aware reachability against the hand-labelled permission_scope findings from the 90+45 repo study.

Usage: python -m benchmarks.eval_reach --study mcp-scan-study --corpus path/to/clones [--json out.json]
  study/data/labels.json + the three samples; corpus/<owner>__<repo>/ are checkouts pinned to the study SHAs.

Labels (one reviewer): accurate | weak | false_positive. "Strict precision" = accurate / raised.
A finding counts as still raised at HIGH when the verdict is sink_unguarded or unknown (annotate mode) or only sink_unguarded (--strict); guarded verdicts drop one
level (to MEDIUM) and no_sink drops to LOW, so both stop being HIGH.
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import pathlib

from aisec import reach
from aisec.extract import extract_tools

SETS = {  # label key -> sample file
    "dev": ("permission_scope_high_sample40", "review_sample_permission_scope.json"),
    "heldout": ("permission_scope_high_heldout40", "heldout_sample_permission_scope.json"),
    "fresh": ("permission_scope_high_fresh40", "fresh_sample.json"),
}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (round(100 * (c - m) / d, 1), round(100 * (c + m) / d, 1))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--study", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--json")
    ap.add_argument("--strict", action="store_true", help="count only proven (sink_unguarded) findings as still HIGH")
    a = ap.parse_args()
    study, corpus = pathlib.Path(a.study) / "data", pathlib.Path(a.corpus)
    labels = json.loads((study / "labels.json").read_text())
    cache: dict[str, list[dict]] = {}
    rows = []
    for setname, (lkey, fname) in SETS.items():
        sample = json.loads((study / fname).read_text())
        for i, s in enumerate(sample):
            repo = s["repo"]
            if repo not in cache:
                d = corpus / repo.replace("/", "__")
                cache[repo] = extract_tools(d) if d.is_dir() else []
            cands = [t for t in cache[repo] if t["name"] == s["tool"]]
            t = cands[0] if cands else None
            r = reach.assess(t) if t else reach.Reach("unknown")
            rows.append(dict(set=setname, repo=repo, tool=s["tool"], label=labels[lkey][str(i)], found=t is not None,
                             verdict=r.verdict, kinds=r.kinds, evidence=r.evidence[:2]))
    out = {"n": len(rows), "not_extracted": sum(not r["found"] for r in rows)}
    for scope, sel in (("all", rows), ("unseen (heldout+fresh)", [r for r in rows if r["set"] != "dev"]),
                       *((k, [r for r in rows if r["set"] == k]) for k in SETS)):
        before = collections.Counter(r["label"] for r in sel)
        keep_verdicts = ("sink_unguarded",) if a.strict else ("sink_unguarded", "unknown")
        kept = [r for r in sel if r["verdict"] in keep_verdicts]
        after = collections.Counter(r["label"] for r in kept)
        acc_b, acc_a = before["accurate"], after["accurate"]
        out[scope] = {
            "n": len(sel), "verdicts": dict(collections.Counter(r["verdict"] for r in sel)),
            "precision_before_pct": round(100 * acc_b / len(sel), 1), "ci_before": wilson(acc_b, len(sel)),
            "still_high": len(kept), "precision_after_pct": round(100 * acc_a / len(kept), 1) if kept else None,
            "ci_after": wilson(acc_a, len(kept)),
            "false_positives_removed": f"{before['false_positive'] - after['false_positive']}/{before['false_positive']}",
            "accurate_retained": f"{acc_a}/{acc_b}",
            "recall_of_accurate_pct": round(100 * acc_a / acc_b, 1) if acc_b else None,
        }
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps({"summary": out, "rows": rows}, indent=1))
    print(json.dumps(out, indent=1))
    print("\nper-verdict x label:")
    tab = collections.Counter((r["verdict"], r["label"]) for r in rows)
    for v in ("no_sink", "sink_guarded", "sink_unguarded", "unknown"):
        print(f"  {v:15}", {lab: tab[(v, lab)] for lab in ("accurate", "weak", "false_positive")})


if __name__ == "__main__":
    main()
