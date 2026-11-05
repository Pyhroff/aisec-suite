"""EXPERIMENT, not part of the shipped detector: a learned tool-poisoning layer (hashed n-gram logistic regression).

Result (docs/STUDY.md section 3d): it did not generalise. Trained on MCP-Poison-Bench and the seen register, it caught
0.8% of MCPTox at a 2.9% false-positive rate on real tool metadata, so by the pre-registered rule it is left out of
the package. It is kept here, with its training and evaluation scripts, so the result can be reproduced.

The structural detector in ``aisec.poison`` keys on instruction structure (imperatives, authority claims, data flows),
so an attack phrased as ordinary documentation passes it. This layer scores the wording itself with a small linear
model trained offline (``benchmarks/poison/semantic_train.py``; protocol and results in docs/SEMANTIC_LAYER_PROTOCOL.md
and docs/STUDY.md section 3d). The model ships as JSON (non-zero weights only) and runs in pure Python: no pickle, no
new dependency.

Each prose field (the description and every parameter description) is scored on its own; the tool score is the
maximum. ``detect`` returns ``(score, "medium")`` at or above the trained threshold, else ``(score, None)``.
"""
from __future__ import annotations

import functools
import hashlib
import json
import math
import pathlib
import re

from aisec.poison import _canonical

N_BUCKETS = 2**18
MODEL_PATH = pathlib.Path(__file__).parent / "data" / "semantic_model.json"
_WORD = re.compile(r"[a-z0-9_']+")


def _bucket(token: str) -> int:
    return int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "big") % N_BUCKETS


def features(text: str) -> list[int]:
    """Hashed word 1- and 2-grams of the canonical, lower-cased text (binary: each bucket once)."""
    words = _WORD.findall(_canonical(text).lower())
    grams = set(words) | {f"{a} {b}" for a, b in zip(words, words[1:])}  # noqa: B905 - pairs of adjacent words
    return sorted({_bucket(g) for g in grams})


def fields(tool: dict) -> list[str]:
    out = [tool.get("description") or ""]
    props = (tool.get("input_schema") or {}).get("properties") or {}
    if isinstance(props, dict):
        out += [p.get("description") or "" for p in props.values() if isinstance(p, dict)]
    return [t for t in out if t.strip()]


@functools.lru_cache(maxsize=1)
def load_model(path: str = str(MODEL_PATH)) -> dict:
    raw = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return {"bias": float(raw["bias"]), "threshold": float(raw["threshold"]),
            "weights": {int(k): float(v) for k, v in raw["weights"].items()}}


def score_text(text: str, model: dict | None = None) -> float:
    m = model or load_model()
    idx = features(text)
    if not idx:
        return 0.0
    z = m["bias"] + sum(m["weights"].get(i, 0.0) for i in idx) / math.sqrt(len(idx))
    return 1.0 / (1.0 + math.exp(-z))


def score(tool: dict, model: dict | None = None) -> float:
    return max((score_text(t, model) for t in fields(tool)), default=0.0)


def detect(tool: dict, model: dict | None = None) -> tuple[float, str | None]:
    m = model or load_model()
    s = score(tool, m)
    return (s, "medium" if s >= m["threshold"] else None)
