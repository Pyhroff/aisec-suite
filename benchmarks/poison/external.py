"""External evaluation of the structural poisoning detector (protocol: docs/EXTERNAL_EVAL_PROTOCOL.md).

Two datasets written by other authors: MCPTox and MCP-Poison-Bench.

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
import ast
import collections
import json
import pathlib
import re
import shutil
import subprocess  # nosec B404 - runs git with constant arguments only

from benchmarks.poison.run import DETECTORS, wilson

MCPTOX_URL = "https://github.com/zhiqiangwang4/MCPTox-Benchmark.git"
MCPTOX_SHA = "f85189f9ad12504c197c7f920ab818a40657b1fa"
MPB_URL = "https://github.com/chirag-dewan/MCP-Poison-Bench.git"
MPB_SHA = "944ccbb6d8137c08ae1e0027ea525fd1b6b188a2"
LEVELS = {"medium": ("medium", "high", "critical"), "high": ("high", "critical")}

_TOOL_BLOCK = re.compile(r"Tool: (?P<name>[^\n]+)\nDescription: (?P<desc>.*?)\nArguments:\n(?P<args>.*?)(?:\n\n|\Z)", re.S)
_ARG = re.compile(r"^- (?P<name>[\w.-]+): (?P<desc>.*?)(?: \((?:required|optional)\))?$")


def fetch(data: pathlib.Path) -> pathlib.Path:
    _clone(data / "MCP-Poison-Bench", MPB_URL, MPB_SHA)
    return _clone(data / "MCPTox-Benchmark", MCPTOX_URL, MCPTOX_SHA)


def _clone(dest: pathlib.Path, url: str, sha: str) -> pathlib.Path:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required")
    if not (dest / ".git").is_dir():
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run([git, "init", "-q", str(dest)], check=True)  # noqa: S603
    subprocess.run([git, "-C", str(dest), "fetch", "-q", "--depth", "1", url, sha], check=True, timeout=600)  # noqa: S603
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


# --- MCP-Poison-Bench ---------------------------------------------------------------------------------------------------
# Its payloads are built in Python (string concatenation, f-strings, one register-building helper). The protocol said
# the file would be imported; the evaluation environment refused to execute third-party code, so the module is instead
# read with `ast` and a tiny evaluator that only understands literals, names, `+`, f-strings, `Payload(...)` and the
# `_objective_register(...)` helper (re-implemented below from its 15-line definition). Nothing from the file runs.

MPB_HOST_DOC = ("Perform an arithmetic operation on two numbers.\n\noperation must be one of: add, subtract, multiply, "
                "divide.\nReturns a human-readable string with the result.")
_MPB_CLASS_ABBREVIATION = {"tool_description": "td", "schema_field": "sf", "rug_pull": "rp", "cross_server": "xs",
                           "metadata_drift": "md"}
_MPB_CARRIER = {"tool_description": "description", "schema_field": "schema_field", "rug_pull": "tool_result",
                "cross_server": "shadow_description", "metadata_drift": "description"}


class _Unsupported(Exception):
    pass


def _ev(node: ast.AST, env: dict) -> object:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in env:
            raise _Unsupported(node.id)
        return env[node.id]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _ev(node.left, env) + _ev(node.right, env)  # type: ignore[operator]
    if isinstance(node, ast.JoinedStr):
        return "".join(str(_ev(v.value, env)) if isinstance(v, ast.FormattedValue) else str(_ev(v, env)) for v in node.values)
    if isinstance(node, (ast.Tuple, ast.List)):
        return [_ev(e, env) for e in node.elts]
    if isinstance(node, ast.Dict):
        return {_ev(k, env): _ev(v, env) for k, v in zip(node.keys, node.values, strict=True) if k is not None}
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        kw = {k.arg: _ev(k.value, env) for k in node.keywords}
        if node.func.id == "Payload":
            return {"objective": "exfil_sink", **kw}
        if node.func.id == "_objective_register":
            objective, prefix, variants = [_ev(a, env) for a in node.args]
            return {cls: [{"id": f"{prefix}-{_MPB_CLASS_ABBREVIATION[cls]}-{suffix}", "attack_class": cls,
                           "carrier": _MPB_CARRIER[cls], "note": note, "injection": inj, "objective": objective}
                          for suffix, note, inj in variants] for cls in env["ATTACK_CLASSES"]}
    raise _Unsupported(type(node).__name__)


def mpb_payloads(root: pathlib.Path) -> list[dict]:
    """Every payload of the seen and held-out registers of all objective sets, labelled with its register."""
    tree = ast.parse((root / "fixtures" / "payloads.py").read_text(encoding="utf-8"))
    env: dict = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            try:
                value = _ev(stmt.value, env)
            except _Unsupported:
                continue
            for t in targets:
                if isinstance(t, ast.Name):
                    env[t.id] = value
    out = []
    for objective, sets in env["OBJECTIVE_PAYLOAD_SETS"].items():
        for register in ("seen", "heldout"):
            for cls, items in sets[register].items():
                for p in items:
                    out.append({**p, "attack_class": cls, "objective": objective, "register": register})
    return out


def mpb_tool(p: dict) -> dict | None:
    """Render a payload the way the benchmark's poisoned server exposes it; None for runtime-only carriers."""
    if p["carrier"] == "description":
        return {"name": "calculate", "description": MPB_HOST_DOC + p["injection"], "input_schema": {
            "type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}, "operation": {"type": "string"}}}}
    if p["carrier"] == "schema_field":
        return {"name": "calculate", "description": "Perform an arithmetic operation on two numbers.", "input_schema": {
            "type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"},
                                             "operation": {"type": "string", "description": p["injection"]}}}}
    if p["carrier"] == "shadow_description":
        return {"name": "compliance_audit", "description": p["injection"],
                "input_schema": {"type": "object", "properties": {"note": {"type": "string"}}}}
    return None   # tool_result (rug pull): delivered at runtime, out of scope for a metadata scanner


def evaluate_mpb(root: pathlib.Path) -> dict:
    payloads = mpb_payloads(root)
    scored = [(p, t) for p in payloads if (t := mpb_tool(p)) is not None]
    out: dict = {"dataset": {"name": "MCP-Poison-Bench", "commit": MPB_SHA, "payloads": len(payloads),
                             "scored": len(scored), "excluded_runtime_only": len(payloads) - len(scored)}, "detectors": {}}
    for dname, det in DETECTORS.items():
        sev = [(p, det(t)[1]) for p, t in scored]
        res: dict = {}
        for level, levels in LEVELS.items():
            hit = [p for p, s in sev if s in levels]
            groups: dict[str, dict] = {}
            for field in ("attack_class", "objective", "register"):
                tot = collections.Counter(p[field] for p, _t in scored)
                got = collections.Counter(p[field] for p in hit)
                groups[field] = {k: {"hit": got[k], "n": tot[k], "pct": round(100 * got[k] / tot[k], 1), "ci95": wilson(got[k], tot[k])}
                                 for k in sorted(tot)}
            res[level] = {"recall": {"hit": len(hit), "n": len(scored), "pct": round(100 * len(hit) / len(scored), 1),
                                     "ci95": wilson(len(hit), len(scored))}, **groups}
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
        result = {"mcptox": evaluate(root), "mcp_poison_bench": evaluate_mpb(data / "MCP-Poison-Bench")}
        if a.json:
            pathlib.Path(a.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
        show(result["mcptox"])
        m = result["mcp_poison_bench"]
        print(f"\nMCP-Poison-Bench @ {MPB_SHA[:10]}: {m['dataset']['scored']} metadata payloads scored "
              f"({m['dataset']['excluded_runtime_only']} runtime-only excluded)")
        for name, r in m["detectors"].items():
            for level, v in r.items():
                rc = v["recall"]
                print(f"{name:24} {level:7} {rc['pct']:>6}% ({rc['hit']}/{rc['n']}) CI {rc['ci95'][0]}-{rc['ci95'][1]}")
