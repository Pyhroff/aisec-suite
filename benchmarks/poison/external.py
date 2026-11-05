"""External evaluation of the structural poisoning detector on MCPTox (protocol: docs/EXTERNAL_EVAL_PROTOCOL.md).

Positives are the 485 poisoned tool descriptions of MCPTox (Wang et al., AAAI 2026), written by other authors
against 45 real MCP servers. Negatives are those servers' own legitimate tools, parsed from the clean system
prompts the benchmark ships. The dataset is fetched at a pinned commit and read as JSON; nothing from it is
executed or redistributed (the repository has no licence file).

Usage:
  python -m benchmarks.poison.external --data DIR --fetch          # clone MCPTox at the pinned commit into DIR
  python -m benchmarks.poison.external --data DIR [--json out.json]
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import shutil
import subprocess  # nosec B404 - runs git with constant arguments only

from benchmarks.poison.run import DETECTORS, wilson

MCPTOX_URL = "https://github.com/zhiqiangwang4/MCPTox-Benchmark.git"
MCPTOX_SHA = "f85189f9ad12504c197c7f920ab818a40657b1fa"
LEVELS = {"medium": ("medium", "high", "critical"), "high": ("high", "critical")}

_TOOL_BLOCK = re.compile(r"Tool: (?P<name>[^\n]+)\nDescription: (?P<desc>.*?)\nArguments:\n(?P<args>.*?)(?:\n\n|\Z)", re.S)
_ARG = re.compile(r"^- (?P<name>[\w.-]+): (?P<desc>.*?)(?: \((?:required|optional)\))?$")


def fetch(data: pathlib.Path) -> pathlib.Path:
    dest = data / "MCPTox-Benchmark"
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required")
    if not (dest / ".git").is_dir():
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run([git, "init", "-q", str(dest)], check=True)  # noqa: S603
    subprocess.run([git, "-C", str(dest), "fetch", "-q", "--depth", "1", MCPTOX_URL, MCPTOX_SHA], check=True, timeout=600)  # noqa: S603
    subprocess.run([git, "-C", str(dest), "-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"], check=True)  # noqa: S603
    return dest


def parse_clean_tools(prompt: str) -> list[dict]:
    """Legitimate tools from a server's clean system prompt (Tool / Description / Arguments blocks)."""
    tools = []
    for m in _TOOL_BLOCK.finditer(prompt):
        props = {}
        for line in m.group("args").splitlines():
            a = _ARG.match(line.strip())
            if a:
                desc = a.group("desc").strip()
                props[a.group("name")] = {"type": "string", "description": "" if desc == "No description" else desc}
        tools.append({"name": m.group("name").strip(), "description": m.group("desc").strip(),
                      "input_schema": {"type": "object", "properties": props}})
    return tools


def load(root: pathlib.Path) -> tuple[list[dict], list[dict]]:
    pos = []
    for server in json.loads((root / "pure_tool.json").read_text(encoding="utf-8")):
        for key, v in server.items():
            pos.append({"id": key, "server": v["server_name"], "paradigm": v["paradigm"], "risk": v["security risk"],
                        "tool": {"name": v["tool_name"], "description": v["tool_content"], "input_schema": {}}})
    neg = []
    servers = json.loads((root / "response_all.json").read_text(encoding="utf-8"))["servers"]
    for name, s in servers.items():
        seen: set[str] = set()
        for t in parse_clean_tools(s["clean_system_promot"]):
            if t["name"] in seen:  # some prompts list a tool twice
                continue
            seen.add(t["name"])
            neg.append({"server": name, "tool": t})
    return pos, neg


def evaluate(root: pathlib.Path) -> dict:
    pos, neg = load(root)
    out: dict = {"dataset": {"name": "MCPTox", "commit": MCPTOX_SHA, "positives": len(pos), "negatives": len(neg),
                             "servers": len({p["server"] for p in pos})}, "detectors": {}}
    for dname, det in DETECTORS.items():
        pv = [(p, det(p["tool"])[1]) for p in pos]
        nv = [(n, det(n["tool"])[1]) for n in neg]
        res: dict = {}
        for level, sev in LEVELS.items():
            hit = [p for p, s in pv if s in sev]
            fp = [n for n, s in nv if s in sev]
            groups: dict[str, dict] = {}
            for field in ("paradigm", "risk"):
                tot = collections.Counter(p[field] for p in pos)
                got = collections.Counter(p[field] for p in hit)
                groups[field] = {k: {"hit": got[k], "n": tot[k], "pct": round(100 * got[k] / tot[k], 1), "ci95": wilson(got[k], tot[k])}
                                 for k in sorted(tot)}
            res[level] = {
                "recall": {"hit": len(hit), "n": len(pos), "pct": round(100 * len(hit) / len(pos), 1), "ci95": wilson(len(hit), len(pos))},
                "false_positives": {"hit": len(fp), "n": len(neg), "pct": round(100 * len(fp) / len(neg), 2), "ci95": wilson(len(fp), len(neg)),
                                    "tools": sorted(f"{n['server']}/{n['tool']['name']}" for n in fp)},
                **groups,
            }
        out["detectors"][dname] = res
    return out


def show(res: dict) -> None:
    d = res["dataset"]
    print(f"MCPTox @ {d['commit'][:10]}: {d['positives']} poisoned tools, {d['negatives']} legitimate tools, {d['servers']} servers\n")
    print(f"{'detector':24} {'level':7} {'recall':>22} {'false positives':>22}")
    for name, r in res["detectors"].items():
        for level, v in r.items():
            rc, fp = v["recall"], v["false_positives"]
            print(f"{name:24} {level:7} {rc['pct']:>6}% ({rc['hit']}/{rc['n']}) CI {rc['ci95'][0]}-{rc['ci95'][1]}"
                  f"   {fp['pct']:>5}% ({fp['hit']}/{fp['n']})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args()
    data = pathlib.Path(a.data)
    root = fetch(data) if a.fetch else data / "MCPTox-Benchmark"
    if not a.fetch:
        result = evaluate(root)
        if a.json:
            pathlib.Path(a.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
        show(result)
