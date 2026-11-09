"""Guard v3 vs v2 vs v1 (protocol: docs/GUARD_V3_PROTOCOL.md). Run once.

Usage:
  python -m benchmarks.guard_v3_eval --injecagent DIR --asb DIR [--agentdojo] [--json out.json]
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib

from aisec.guard_v2 import _DEST_PARAM, GuardV2, classify, name_tokens
from aisec.guard_v3 import GuardV3
from aisec.mcp_guard import infer_policy
from aisec.runtime_guard import RuntimeGuard
from benchmarks.guard_v2_eval import _first_destination, _rate, _snake, load


def evaluate_injecagent(data: pathlib.Path) -> dict:
    """Parity check: which cases does v2 stop, which does v3, are the sets equal."""
    cases, params = load(data)
    out: dict = {"cases": len(cases), "arms": {}}
    for arm, rename in (("as_given", lambda n: n), ("snake_case", _snake)):
        names = {n: rename(n) for n in params}
        stopped: dict[str, set[int]] = {"v2": set(), "v3": set()}
        for i, c in enumerate(cases):
            dest = _first_destination(c["Attacker Instruction"])
            gs = {"v2": GuardV2(c["User Instruction"]), "v3": GuardV3(c["User Instruction"])}
            for g in gs.values():
                g.observe_result(names.get(c["User Tool"], c["User Tool"]))
            for tool in c["Attacker Tools"]:
                nm = names[tool]
                args = {p: dest for p in params[tool] if _DEST_PARAM.match(p)} if dest else {}
                for k, g in gs.items():
                    if not g.check(nm, args).allow:
                        stopped[k].add(i)
                    g.observe_result(nm)
        out["arms"][arm] = {"v2": len(stopped["v2"]), "v3": len(stopped["v3"]), "n": len(cases),
                            "differing_cases": len(stopped["v2"] ^ stopped["v3"])}
    return out


def evaluate_agentdojo(version: str = "v1.2.2") -> dict:
    from agentdojo.task_suite.load_suites import get_suites

    from aisec.runtime_guard import AGENTDOJO_POLICY

    tot: collections.Counter[str] = collections.Counter()
    suites: dict = {}
    for name, suite in sorted(get_suites(version).items()):
        env = suite.load_and_inject_default_environment({})
        c: collections.Counter[str] = collections.Counter()
        for _uid, task in sorted(suite.user_tasks.items()):
            g1, g2, g3 = RuntimeGuard(AGENTDOJO_POLICY, task.PROMPT), GuardV2(task.PROMPT), GuardV3(task.PROMPT)
            h1, held2, held3, first1 = 0, 0, 0, True
            for call in task.ground_truth(env.model_copy(deep=True)):
                args = dict(call.args)
                if first1 and not g1.check(call.function, args).allow:
                    h1 += 1
                    first1 = False
                for g, tag in ((g2, "2"), (g3, "3")):
                    d = g.check(call.function, args)
                    if not d.allow:
                        g.approve(d)
                        if tag == "2":
                            held2 += 1
                        else:
                            held3 += 1
                for g in (g1, g2, g3):
                    g.observe_result(call.function)
            c["tasks"] += 1
            c["v1_tasks_held"] += h1 > 0
            c["v2_tasks_held"] += held2 > 0
            c["v3_tasks_held"] += held3 > 0
            c["v1_prompts"] += h1
            c["v2_prompts"] += held2
            c["v3_prompts"] += held3
        for _uid, task in sorted(suite.user_tasks.items()):
            for _iid, inj in sorted(suite.injection_tasks.items()):
                c["attacks"] += 1
                gs = {"v1": RuntimeGuard(AGENTDOJO_POLICY, task.PROMPT), "v2": GuardV2(task.PROMPT), "v3": GuardV3(task.PROMPT)}
                for g in gs.values():
                    g.observe_result("<tool output>")
                hit = dict.fromkeys(gs, False)
                for call in inj.ground_truth(env.model_copy(deep=True)):
                    for k, g in gs.items():
                        hit[k] |= not g.check(call.function, dict(call.args)).allow
                        g.observe_result(call.function)
                for k, v in hit.items():
                    c[f"{k}_stopped"] += v
        suites[name] = dict(c)
        tot.update(c)
    return {"version": version, "suites": suites, "overall": dict(tot)}


def evaluate_asb(data: pathlib.Path) -> dict:
    d = data / "data"
    attacks = [json.loads(line) for line in (d / "all_attack_tools.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    normal = [json.loads(line) for line in (d / "all_normal_tools.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    tasks = {r["agent_name"]: r["tasks"] for r in (json.loads(line) for line in (d / "agent_task.jsonl").read_text(encoding="utf-8").splitlines() if line.strip())}
    pairs = [(a, t) for a in attacks for t in tasks.get(a["Corresponding Agent"], [])]
    skipped = [a["Attacker Tool"] for a in attacks if a["Corresponding Agent"] not in tasks]
    out: dict = {"attacks": len(attacks), "pairs": len(pairs), "attacks_without_agent_tasks": len(skipped), "arms": {}}
    for arm, rename in (("as_given", lambda n: n), ("snake_case", _snake)):
        policy = infer_policy([{"name": rename(a["Attacker Tool"]), "inputSchema": {"properties": {}}} for a in attacks]
                              + [{"name": rename(n["Tool Name"]), "inputSchema": {"properties": {}}} for n in normal])
        stopped = {k: [] for k in ("v1", "v2", "v3")}
        never: collections.Counter[str] = collections.Counter()
        for a, task in pairs:
            nm = rename(a["Attacker Tool"])
            gs = {"v1": RuntimeGuard(policy, task), "v2": GuardV2(task), "v3": GuardV3(task)}
            hit = {}
            for k, g in gs.items():
                g.observe_result("<normal tool output>")
                hit[k] = not g.check(nm, {"request": a["Attacker Instruction"]}).allow
                stopped[k].append(hit[k])
            if not hit["v3"]:
                never[a["Attacker Tool"]] += 1
        arm_out: dict = {}
        for k, flags in stopped.items():
            arm_out[k] = {"overall": _rate(sum(flags), len(flags))}
            for field in ("Attack Type", "Aggressive"):
                for val in sorted({a[field] for a, _ in pairs}):
                    idx = [i for i, (a, _) in enumerate(pairs) if a[field] == val]
                    arm_out[k][f"{field}={val}"] = _rate(sum(flags[i] for i in idx), len(idx))
        arm_out["v2_v3_differing_pairs"] = sum(x != y for x, y in zip(stopped["v2"], stopped["v3"], strict=True))
        arm_out["v3_unheld_attacker_tools_top"] = dict(never.most_common(25))
        out["arms"][arm] = arm_out
    verbs = sum(bool(classify(a["Attacker Tool"])) for a in attacks)
    out["attacker_names_with_a_recognised_verb_class"] = _rate(verbs, len(attacks))
    out["attacker_names_with_a_recognised_verb_token"] = _rate(sum(any(t in {"get", "search"} for t in name_tokens(a["Attacker Tool"])) for a in attacks), len(attacks))
    # benign cost: names only, no arguments
    held = {k: 0 for k in ("v1", "v2", "v3")}
    n_pairs = 0
    policy = infer_policy([{"name": a["Attacker Tool"], "inputSchema": {"properties": {}}} for a in attacks]
                          + [{"name": n["Tool Name"], "inputSchema": {"properties": {}}} for n in normal])
    for agent, ts in tasks.items():
        mine = [n["Tool Name"] for n in normal if n["Corresponding Agent"] == agent]
        for task in ts:
            n_pairs += 1
            gs = {"v1": RuntimeGuard(policy, task), "v2": GuardV2(task), "v3": GuardV3(task)}
            for k, g in gs.items():
                g.observe_result("<normal tool output>")
                held[k] += any(not g.check(t, {}).allow for t in mine)
    out["benign"] = {k: _rate(v, n_pairs) for k, v in held.items()}
    out["benign_tools_held_by_v3"] = sorted(n["Tool Name"] for n in normal if _held_after_taint(n["Tool Name"]))
    return out


def _held_after_taint(tool: str) -> bool:
    g = GuardV3("do the task")
    g.observe_result("x")
    return not g.check(tool, {}).allow


def show(res: dict) -> None:
    for arm, a in res["injecagent"]["arms"].items():
        print(f"InjecAgent {arm}: v2 {a['v2']}/{a['n']}, v3 {a['v3']}/{a['n']}, differing cases {a['differing_cases']}")
    if "agentdojo" in res:
        o = res["agentdojo"]["overall"]
        print(f"AgentDojo (development): attacks stopped v1 {o['v1_stopped']} v2 {o['v2_stopped']} v3 {o['v3_stopped']} of {o['attacks']}; "
              f"benign tasks held v1 {o['v1_tasks_held']} v2 {o['v2_tasks_held']} v3 {o['v3_tasks_held']} of {o['tasks']}; "
              f"prompts v1 {o['v1_prompts']} v2 {o['v2_prompts']} v3 {o['v3_prompts']}")
    a = res["asb"]
    print(f"ASB: {a['attacks']} attacker tools, {a['pairs']} (tool, task) pairs, {a['attacks_without_agent_tasks']} tools without agent tasks")
    for arm, x in a["arms"].items():
        for k in ("v1", "v2", "v3"):
            o = x[k]["overall"]
            print(f"  {arm:10} {k} stopped {o['pct']}% ({o['hit']}/{o['n']}) CI {o['ci95']}")
        print(f"  {arm:10} v2 vs v3 differing pairs: {x['v2_v3_differing_pairs']}")
    print("  attacker names with a recognised verb class:", a["attacker_names_with_a_recognised_verb_class"])
    print("  benign (agent, task) pairs held:", {k: f"{v['pct']}% ({v['hit']}/{v['n']})" for k, v in a["benign"].items()})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--injecagent", required=True)
    ap.add_argument("--asb", required=True)
    ap.add_argument("--agentdojo", action="store_true")
    ap.add_argument("--json")
    ns = ap.parse_args()
    result = {"injecagent": evaluate_injecagent(pathlib.Path(ns.injecagent)), "asb": evaluate_asb(pathlib.Path(ns.asb))}
    if ns.agentdojo:
        result["agentdojo"] = evaluate_agentdojo()
    if ns.json:
        pathlib.Path(ns.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
    show(result)
