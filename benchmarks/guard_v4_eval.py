"""Guard v4 vs v3 vs v1 (protocol: docs/GUARD_V4_PROTOCOL.md). Run once.

Usage:
  python -m benchmarks.guard_v4_eval --injecagent DIR --asb DIR --mcptox DIR [--agentdojo] [--json out.json]
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib

from aisec.guard_v2 import _DEST_PARAM
from aisec.guard_v3 import GuardV3
from aisec.guard_v4 import GuardV4
from aisec.mcp_guard import infer_policy
from aisec.runtime_guard import RuntimeGuard
from benchmarks.guard_v2_eval import _first_destination, _rate
from benchmarks.poison.external import load as load_mcptox

GENERIC = "Summarise my notes"


def _lines(path: pathlib.Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def evaluate_injecagent(data: pathlib.Path) -> dict:
    d = data / "data"
    cases = [c for kind in ("dh", "ds") for c in json.loads((d / f"test_cases_{kind}_base.json").read_text(encoding="utf-8"))]
    meta, params = [], {}
    for tk in json.loads((d / "tools.json").read_text(encoding="utf-8")):
        for t in tk["tools"]:
            name = tk["toolkit"] + t["name"]
            params[name] = [p["name"] for p in t.get("parameters", [])]
            meta.append({"name": name, "description": t.get("summary", ""), "inputSchema": {"properties": {p: {} for p in params[name]}}})
    policy = infer_policy(meta)
    stopped: dict[str, set[int]] = {"v1": set(), "v3": set(), "v4": set()}
    for i, c in enumerate(cases):
        dest = _first_destination(c["Attacker Instruction"])
        gs = {"v1": RuntimeGuard(policy, c["User Instruction"]), "v3": GuardV3(c["User Instruction"]),
              "v4": GuardV4(c["User Instruction"], tools=meta)}
        for g in gs.values():
            g.observe_result(c["User Tool"])
        for tool in c["Attacker Tools"]:
            args = {p: dest for p in params[tool] if _DEST_PARAM.match(p)} if dest else {}
            for k, g in gs.items():
                if not g.check(tool, args).allow:
                    stopped[k].add(i)
                g.observe_result(tool)
    return {"cases": len(cases), **{k: _rate(len(v), len(cases)) for k, v in stopped.items()},
            "regressions_v3_to_v4": len(stopped["v3"] - stopped["v4"])}


def evaluate_asb(data: pathlib.Path) -> dict:
    d = data / "data"
    attacks, normal = _lines(d / "all_attack_tools.jsonl"), _lines(d / "all_normal_tools.jsonl")
    tasks = {r["agent_name"]: r["tasks"] for r in _lines(d / "agent_task.jsonl")}
    meta = [{"name": a["Attacker Tool"], "description": a["Description"]} for a in attacks] \
        + [{"name": n["Tool Name"], "description": n["Description"]} for n in normal]
    policy = infer_policy([{"name": m["name"], "inputSchema": {"properties": {}}} for m in meta])
    pairs = [(a, t) for a in attacks for t in tasks.get(a["Corresponding Agent"], [])]
    flags: dict[str, list[bool]] = {k: [] for k in ("v1", "v3", "v4")}
    for a, task in pairs:
        gs = {"v1": RuntimeGuard(policy, task), "v3": GuardV3(task), "v4": GuardV4(task, tools=meta)}
        for k, g in gs.items():
            g.observe_result("<normal tool output>")
            flags[k].append(not g.check(a["Attacker Tool"], {"request": a["Attacker Instruction"]}).allow)
    out: dict = {"pairs": len(pairs)}
    for k, f in flags.items():
        out[k] = {"overall": _rate(sum(f), len(f))}
        for field in ("Attack Type", "Aggressive"):
            for val in sorted({a[field] for a, _ in pairs}):
                idx = [i for i, (a, _) in enumerate(pairs) if a[field] == val]
                out[k][f"{field}={val}"] = _rate(sum(f[i] for i in idx), len(idx))
    out["regressions_v3_to_v4"] = sum(x and not y for x, y in zip(flags["v3"], flags["v4"], strict=True))
    held = {k: 0 for k in ("v1", "v3", "v4")}
    n = 0
    for agent, ts in tasks.items():
        mine = [x["Tool Name"] for x in normal if x["Corresponding Agent"] == agent]
        for task in ts:
            n += 1
            gs = {"v1": RuntimeGuard(policy, task), "v3": GuardV3(task), "v4": GuardV4(task, tools=meta)}
            for k, g in gs.items():
                g.observe_result("<normal tool output>")
                held[k] += any(not g.check(t, {}).allow for t in mine)
    out["benign"] = {k: _rate(v, n) for k, v in held.items()}
    never = collections.Counter(a["Attacker Tool"] for a, _ in pairs if not _held(a, pairs, meta))
    out["v4_unheld_attacker_tools_top"] = dict(never.most_common(15))
    return out


def _held(a: dict, pairs: list, meta: list) -> bool:
    task = next(t for x, t in pairs if x is a)
    g = GuardV4(task, tools=meta)
    g.observe_result("x")
    return not g.check(a["Attacker Tool"], {"request": a["Attacker Instruction"]}).allow


def evaluate_agentdojo(version: str = "v1.2.2") -> dict:
    from agentdojo.task_suite.load_suites import get_suites

    from aisec.runtime_guard import AGENTDOJO_POLICY

    tot: collections.Counter[str] = collections.Counter()
    suites: dict = {}
    for name, suite in sorted(get_suites(version).items()):
        env = suite.load_and_inject_default_environment({})
        meta = []
        for f in suite.tools:
            try:
                props = list(f.parameters.model_json_schema().get("properties", {}))
            except Exception:  # noqa: BLE001
                props = []
            meta.append({"name": f.name, "description": f.description, "inputSchema": {"properties": {p: {} for p in props}}})
        c: collections.Counter[str] = collections.Counter()
        for _u, task in sorted(suite.user_tasks.items()):
            g3, g4 = GuardV3(task.PROMPT), GuardV4(task.PROMPT, tools=meta)
            held = {"v3": 0, "v4": 0}
            for call in task.ground_truth(env.model_copy(deep=True)):
                for k, g in (("v3", g3), ("v4", g4)):
                    dd = g.check(call.function, dict(call.args))
                    if not dd.allow:
                        held[k] += 1
                        g.approve(dd)
                    g.observe_result(call.function)
            c["tasks"] += 1
            for k in held:
                c[f"{k}_tasks_held"] += held[k] > 0
                c[f"{k}_prompts"] += held[k]
        for _u, task in sorted(suite.user_tasks.items()):
            for _i, inj in sorted(suite.injection_tasks.items()):
                c["attacks"] += 1
                gs = {"v1": RuntimeGuard(AGENTDOJO_POLICY, task.PROMPT), "v3": GuardV3(task.PROMPT), "v4": GuardV4(task.PROMPT, tools=meta)}
                for g in gs.values():
                    g.observe_result("<tool output>")
                hit = dict.fromkeys(gs, False)
                for call in inj.ground_truth(env.model_copy(deep=True)):
                    for k, g in gs.items():
                        hit[k] |= not g.check(call.function, dict(call.args)).allow
                        g.observe_result(call.function)
                for k, v in hit.items():
                    c[f"{k}_stopped"] += v
                c["regress_v3_to_v4"] += hit["v3"] and not hit["v4"]
        suites[name] = dict(c)
        tot.update(c)
    return {"suites": suites, "overall": dict(tot)}


def evaluate_mcptox(root: pathlib.Path) -> dict:
    _pos, neg = load_mcptox(root)
    tools = [n["tool"] for n in neg]
    meta = [{"name": t["name"], "description": t["description"], "inputSchema": t["input_schema"]} for t in tools]
    held = {"v3": 0, "v4": 0}
    held_names: dict[str, list[str]] = {"v3": [], "v4": []}
    for t in tools:
        for k, g in (("v3", GuardV3(GENERIC)), ("v4", GuardV4(GENERIC, tools=meta))):
            g.observe_result("x")
            if not g.check(t["name"], {}).allow:
                held[k] += 1
                held_names[k].append(t["name"])
    return {"tools": len(tools), **{k: _rate(v, len(tools)) for k, v in held.items()}}


def show(res: dict) -> None:
    i = res["injecagent"]
    print(f"InjecAgent {i['cases']}: " + ", ".join(f"{k} {i[k]['pct']}% ({i[k]['hit']})" for k in ("v1", "v3", "v4")) + f"; regressions v3->v4 {i['regressions_v3_to_v4']}")
    a = res["asb"]
    print(f"ASB {a['pairs']} pairs: " + ", ".join(f"{k} {a[k]['overall']['pct']}% ({a[k]['overall']['hit']}) CI {a[k]['overall']['ci95']}" for k in ("v1", "v3", "v4"))
          + f"; regressions v3->v4 {a['regressions_v3_to_v4']}")
    for field in ("Attack Type=Stealthy Attack", "Attack Type=Disruptive Attack"):
        print(f"   {field}: " + ", ".join(f"{k} {a[k][field]['pct']}%" for k in ("v1", "v3", "v4")))
    print("   ASB benign pairs held:", {k: f"{v['pct']}% ({v['hit']}/{v['n']})" for k, v in a["benign"].items()})
    if "agentdojo" in res:
        o = res["agentdojo"]["overall"]
        print(f"AgentDojo: attacks stopped v1 {o['v1_stopped']} v3 {o['v3_stopped']} v4 {o['v4_stopped']} of {o['attacks']}; regressions {o['regress_v3_to_v4']}; "
              f"benign tasks held v3 {o['v3_tasks_held']} v4 {o['v4_tasks_held']} of {o['tasks']}; prompts v3 {o['v3_prompts']} v4 {o['v4_prompts']}")
    m = res["mcptox"]
    print(f"MCPTox legitimate tools held after a read ({m['tools']}): v3 {m['v3']['pct']}% ({m['v3']['hit']}), v4 {m['v4']['pct']}% ({m['v4']['hit']})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--injecagent", required=True)
    ap.add_argument("--asb", required=True)
    ap.add_argument("--mcptox", required=True)
    ap.add_argument("--agentdojo", action="store_true")
    ap.add_argument("--json")
    ns = ap.parse_args()
    result = {"injecagent": evaluate_injecagent(pathlib.Path(ns.injecagent)), "asb": evaluate_asb(pathlib.Path(ns.asb)),
              "mcptox": evaluate_mcptox(pathlib.Path(ns.mcptox))}
    if ns.agentdojo:
        result["agentdojo"] = evaluate_agentdojo()
    if ns.json:
        pathlib.Path(ns.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
    show(result)
