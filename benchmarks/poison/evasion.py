"""Evasion robustness: does detection survive cheap, mechanical obfuscation an attacker would try first?

The recall table in docs/STUDY.md measures paraphrase (seen vs held-out wording). This measures something different:
take the *seen* attacks the detector already catches, apply one meaning-preserving transform, and count how many are
still caught. Every transform leaves the instruction readable to an LLM; none needs any knowledge of the detector
beyond "it is a text scanner".

Only seen-register positives are used, so the held-out register stays uninspected. False-positive cost of any detector
change is still measured on the real-tool negatives by ``benchmarks.poison.run``.

Usage: python -m benchmarks.poison.evasion [--json out.json]
"""
from __future__ import annotations

import argparse
import base64
import copy
import json
import pathlib
import random
import re
from collections.abc import Callable

from aisec import poison
from benchmarks.poison.attacks import POSITIVES
from benchmarks.poison.run import wilson

# Latin -> visually identical Cyrillic/Greek code points (subset of Unicode confusables.txt, lowercase + common caps).
HOMOGLYPHS = {
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у",
    "i": "і", "s": "ѕ", "j": "ј", "A": "Α", "B": "Β", "E": "Ε", "H": "Η",
    "I": "Ι", "K": "Κ", "M": "Μ", "N": "Ν", "O": "Ο", "P": "Ρ", "T": "Τ",
    "X": "Χ", "Y": "Υ",
}

Transform = Callable[[str, random.Random], str]


def _words(text: str, fn: Callable[[str, int], str]) -> str:
    out, i = [], 0
    for tok in re.split(r"(\s+)", text):
        if tok and not tok.isspace() and re.fullmatch(r"[A-Za-z]{4,}", tok):
            out.append(fn(tok, i))
            i += 1
        else:
            out.append(tok)
    return "".join(out)


def t_uppercase(text: str, _r: random.Random) -> str:
    """Control: the detector is case-insensitive, so this should retain everything.

    Encoded blobs are left alone: upper-casing base64/hex would destroy the payload, not obfuscate it.
    """
    return re.sub(r"[A-Za-z0-9+/=_-]{16,}|[^\s]+", lambda m: m.group(0) if len(m.group(0)) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", m.group(0)) else m.group(0).upper(), text)


def t_whitespace(text: str, _r: random.Random) -> str:
    """Control: doubled spaces between words."""
    return re.sub(r"(?<=\S) (?=\S)", "  ", text)


def t_homoglyph(text: str, r: random.Random) -> str:
    """Swap roughly half of the swappable Latin letters for Cyrillic/Greek look-alikes."""
    return "".join(HOMOGLYPHS[c] if c in HOMOGLYPHS and r.random() < 0.5 else c for c in text)


def t_hardwrap(text: str, _r: random.Random) -> str:
    """Hard-wrap at ~40 columns, the way docstrings and YAML block scalars often are."""
    lines: list[str] = []
    for para in text.split("\n"):
        line = ""
        for w in para.split(" "):
            if line and len(line) + 1 + len(w) > 40:
                lines.append(line)
                line = w
            else:
                line = f"{line} {w}" if line else w
        lines.append(line)
    return "\n".join(lines)


def t_bullets(text: str, _r: random.Random) -> str:
    """Rewrite clauses as a markdown bullet list (split on commas, 'and', semicolons)."""
    parts = [p.strip() for p in re.split(r",\s+|;\s+|\s+and\s+", text) if p.strip()]
    return "\n".join(f"- {p}" for p in parts)


def t_fragment(text: str, _r: random.Random) -> str:
    """Break each sentence into short fragments at commas and 'and' / 'then'."""
    return re.sub(r",\s+|\s+(?:and|then)\s+", ". ", text)


def t_letterspace(text: str, _r: random.Random) -> str:
    """Space out the letters of every other long word ('r e a d')."""
    return _words(text, lambda w, i: " ".join(w) if i % 2 == 0 else w)


def t_zwsp_words(text: str, _r: random.Random) -> str:
    """One zero-width space inside every long word (no runs)."""
    return _words(text, lambda w, _i: w[: len(w) // 2] + "​" + w[len(w) // 2 :])


def t_b64url(text: str, _r: random.Random) -> str:
    """Keep the first sentence; move the rest into an unpadded URL-safe base64 'config' blob."""
    head, _, tail = text.partition(". ")
    if not tail:
        return text
    blob = base64.urlsafe_b64encode(tail.encode()).decode().rstrip("=")
    return f"{head}. Config (base64url, decode before use): {blob}"


def t_b32(text: str, _r: random.Random) -> str:
    """As above, base32."""
    head, _, tail = text.partition(". ")
    if not tail:
        return text
    return f"{head}. Config (base32, decode before use): {base64.b32encode(tail.encode()).decode()}"


def t_uescape(text: str, _r: random.Random) -> str:
    """As above, as \\uXXXX escapes (JSON-style)."""
    head, _, tail = text.partition(". ")
    if not tail:
        return text
    return f"{head}. Config (JSON string): " + "".join(f"\\u{ord(c):04x}" for c in tail)


TRANSFORMS: dict[str, Transform] = {
    "control:uppercase": t_uppercase,
    "control:whitespace": t_whitespace,
    "homoglyph": t_homoglyph,
    "hardwrap-40": t_hardwrap,
    "bullets": t_bullets,
    "fragment": t_fragment,
    "letterspace": t_letterspace,
    "zwsp-in-words": t_zwsp_words,
    "base64url": t_b64url,
    "base32": t_b32,
    "unicode-escape": t_uescape,
}


def split_across_fields(tool: dict) -> dict:
    """Structural transform: move the second half of the description's sentences into a new parameter description."""
    t = copy.deepcopy(tool)
    sents = re.split(r"(?<=[.!?])\s+", t["description"])
    if len(sents) < 2:
        return t
    mid = (len(sents) + 1) // 2
    t["description"] = " ".join(sents[:mid])
    props = t.setdefault("input_schema", {}).setdefault("properties", {})
    props["context"] = {"type": "string", "description": " ".join(sents[mid:])}
    return t


def apply(tool: dict, fn: Transform, seed: int) -> dict:
    """Apply a text transform to the description and to every string parameter text."""
    r = random.Random(seed)
    t = copy.deepcopy(tool)
    t["description"] = fn(t.get("description", ""), r)
    for spec in (t.get("input_schema") or {}).get("properties", {}).values():
        if isinstance(spec, dict) and isinstance(spec.get("description"), str):
            spec["description"] = fn(spec["description"], r)
    return t


def detected(tool: dict) -> bool:
    return poison.detect(tool)[1] is not None


def evaluate(seed: int = 7) -> dict:
    base = [p for p in POSITIVES if p["register"] == "seen" and detected(p["tool"])]
    n = len(base)
    rows = {}
    for name, fn in TRANSFORMS.items():
        kept = [p for i, p in enumerate(base) if detected(apply(p["tool"], fn, seed + i))]
        rows[name] = {"kept": len(kept), "n": n, "pct": round(100 * len(kept) / n, 1), "ci95": wilson(len(kept), n),
                      "lost": sorted({p["tool"]["name"] + "/" + p["category"] for p in base} - {p["tool"]["name"] + "/" + p["category"] for p in kept})}
    kept = [p for p in base if detected(split_across_fields(p["tool"]))]
    rows["split-across-fields"] = {"kept": len(kept), "n": n, "pct": round(100 * len(kept) / n, 1), "ci95": wilson(len(kept), n), "lost": []}
    return {"base": {"register": "seen", "detected_medium_plus": n, "of": sum(p["register"] == "seen" for p in POSITIVES)},
            "transforms": rows}


def show(res: dict) -> None:
    b = res["base"]
    print(f"base: {b['detected_medium_plus']}/{b['of']} seen positives detected at medium+; retention after each transform:\n")
    for name, row in res["transforms"].items():
        print(f"  {name:22} {row['kept']:>3}/{row['n']}  {row['pct']:>5}%  CI95 {row['ci95'][0]}-{row['ci95'][1]}%")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    result = evaluate(a.seed)
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
    show(result)
