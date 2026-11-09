"""Guard v2 vs v1 on InjecAgent, plus a development replay on AgentDojo (protocol: docs/GUARD_V2_PROTOCOL.md). Run once.

Usage:
  python -m benchmarks.guard_v2_eval --injecagent DIR [--agentdojo] [--json out.json]
DIR holds a checkout of InjecAgent at the pinned commit (see benchmarks/context_external.py: INJECAGENT). Nothing from it is executed.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib

from aisec.guard_v2 import _DEST_PARAM, _EMAIL, _PHONE, _URL, GuardV2, name_tokens
from aisec.mcp_guard import infer_policy
from aisec.runtime_guard import RuntimeGuard
from benchmarks.poison.run import wilson


def _rate(hit: int, n: int) -> dict:
    return {"hit": hit, "n": n, "pct": round(100 * hit / n, 1) if n else 0.0, "ci95": wilson(hit, n)}


def _snake(name: str) -> str:
    return "_".join(name_tokens(name))


def _first_destination(text: str) -> str | None:
    for rx in (_EMAIL, _URL, _PHONE):
        m = rx.search(text)
        if m:
            return m.group(0)
    return None


def load(data: pathlib.Path) -> tuple[list[dict], dict[str, list[str]]]:
    d = data / "data"
    cases = [{**c, "kind": kind} for kind in ("dh", "ds")
             for c in json.loads((d / f"test_cases_{kind}_base.json").read_text(encoding="utf-8"))]
    params: dict[str, list[str]] = {}
    for tk in json.loads((d / "tools.json").read_text(encoding="utf-8")):
        for t in tk["tools"]:
            params[tk["toolkit"] + t["name"]] = [p["name"] for p in t.get("parameters", [])]
    return cases, params


def evaluate_injecagent(data: pathlib.Path) -> dict:
    cases, params = load(data)
    out: dict = {"cases": len(cases), "arms": {}}
    for arm, rename in (("as_given", lambda n: n), ("snake_case", _snake)):
        names = {n: rename(n) for n in params}
        schemas = [{"name": names[n], "inputSchema": {"properties": {p: {} for p in ps}}} for n, ps in params.items()]
        policy = infer_policy(schemas)
        stopped = {"v1": set(), "v2": set()}
        reasons: collections.Counter[str] = collections.Counter()
        never_v2: collections.Counter[str] = collections.Counter()
        for i, c in enumerate(cases):
            dest = _first_destination(c["Attacker Instruction"])
            g1 = RuntimeGuard(policy, c["User Instruction"])
            g2 = GuardV2(c["User Instruction"])
            for g in (g1, g2):
                g.observe_result(names.get(c["User Tool"], c["User Tool"]))
            held = {"v1": False, "v2": False}
            for tool in c["Attacker Tools"]:
                nm = names[tool]
                args = {p: dest for p in params[tool] if _DEST_PARAM.match(p)} if dest else {}
                d1 = g1.check(nm, args)
                d2 = g2.check(nm, args)
                if not d1.allow:
                    held["v1"] = True
                if not d2.allow:
                    held["v2"] = True
                    reasons[d2.kind] += 1
                if held["v1"] and held["v2"]:
                    break
                g1.observe_result(nm)
                g2.observe_result(nm)
            for k in ("v1", "v2"):
                if held[k]:
                    stopped[k].add(i)
            if not held["v2"]:
                never_v2.update(c["Attacker Tools"])
        arm_out: dict = {"names": arm}
        for k in ("v1", "v2"):
            arm_out[k] = {"overall": _rate(len(stopped[k]), len(cases))}
            for kind in ("dh", "ds"):
                idx = [i for i, c in enumerate(cases) if c["kind"] == kind]
                arm_out[k][kind] = _rate(sum(i in stopped[k] for i in idx), len(idx))
        arm_out["regressions_v1_stopped_v2_allowed"] = len(stopped["v1"] - stopped["v2"])
        arm_out["v2_hold_reasons"] = dict(reasons)
        arm_out["v2_unheld_attacker_tools"] = dict(never_v2.most_common())
        out["arms"][arm] = arm_out
    return out


def evaluate_agentdojo(version: str = "v1.2.2") -> dict:
    from agentdojo.task_suite.load_suites import get_suites

    from aisec.runtime_guard import AGENTDOJO_POLICY

    res: dict = {"version": version, "suites": {}}
    tot = collections.Counter()
    for name, suite in sorted(get_suites(version).items()):
        env = suite.load_and_inject_default_environment({})
        c = collections.Counter()
        for _uid, task in sorted(suite.user_tasks.items()):
            g1, g2 = RuntimeGuard(AGENTDOJO_POLICY, task.PROMPT), GuardV2(task.PROMPT)
            h1 = h2 = 0
            first1 = True
            for call in task.ground_truth(env.model_copy(deep=True)):
                if first1 and not g1.check(call.function, dict(call.args)).allow:
                    h1 += 1
                    first1 = False
                d = g2.check(call.function, dict(call.args))
                if not d.allow:
                    h2 += 1
                    g2.approve(d)
                g1.observe_result(call.function)
                g2.observe_result(call.function)
            c["tasks"] += 1
            c["v1_tasks_held"] += h1 > 0
            c["v2_tasks_held"] += h2 > 0
            c["v1_prompts"] += h1
            c["v2_prompts"] += h2
        for _uid, task in sorted(suite.user_tasks.items()):
            for _iid, inj in sorted(suite.injection_tasks.items()):
                c["attacks"] += 1
                g1, g2 = RuntimeGuard(AGENTDOJO_POLICY, task.PROMPT), GuardV2(task.PROMPT)
                g1.observe_result("<tool output>")
                g2.observe_result("<tool output>")
                s1 = s2 = False
                for call in inj.ground_truth(env.model_copy(deep=True)):
                    s1 |= not g1.check(call.function, dict(call.args)).allow
                    s2 |= not g2.check(call.function, dict(call.args)).allow
                    g1.observe_result(call.function)
                    g2.observe_result(call.function)
                c["v1_stopped"] += s1
                c["v2_stopped"] += s2
        res["suites"][name] = dict(c)
        tot.update(c)
    res["overall"] = dict(tot)
    return res


def show(res: dict) -> None:
    ia = res["injecagent"]
    print(f"InjecAgent base, {ia['cases']} cases (stopped = at least one attacker call held)")
    for arm, a in ia["arms"].items():
        for k in ("v1", "v2"):
            o, dh, ds = a[k]["overall"], a[k]["dh"], a[k]["ds"]
            print(f"  {arm:10} {k}  overall {o['pct']:>5}% ({o['hit']}/{o['n']})  direct harm {dh['pct']:>5}% ({dh['hit']}/{dh['n']})"
                  f"  data stealing {ds['pct']:>5}% ({ds['hit']}/{ds['n']})")
        print(f"  {arm:10} regressions (v1 stops, v2 allows): {a['regressions_v1_stopped_v2_allowed']}; v2 hold reasons: {a['v2_hold_reasons']}")
    if "agentdojo" in res:
        o = res["agentdojo"]["overall"]
        print(f"AgentDojo (development replay, not held out): attacks {o['v1_stopped']}/{o['attacks']} (v1) vs {o['v2_stopped']}/{o['attacks']} (v2);"
              f" benign tasks held {o['v1_tasks_held']}/{o['tasks']} (v1) vs {o['v2_tasks_held']}/{o['tasks']} (v2);"
              f" prompts {o['v1_prompts']} (v1) vs {o['v2_prompts']} (v2)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--injecagent", required=True)
    ap.add_argument("--agentdojo", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args()
    result = {"injecagent": evaluate_injecagent(pathlib.Path(a.injecagent))}
    if a.agentdojo:
        result["agentdojo"] = evaluate_agentdojo()
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
    show(result)
