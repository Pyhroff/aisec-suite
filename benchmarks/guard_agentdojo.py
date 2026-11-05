"""Replay AgentDojo's ground-truth tool calls through the runtime guard (protocol: docs/GUARD_EVAL_PROTOCOL.md).

No model is called. AgentDojo ships, for every user task, the tool calls that complete it, and for every injection
task, the tool calls the attacker wants. Replaying them through ``aisec.runtime_guard`` measures:

* **attacks stopped**: (user task, injection task) pairs where the guard holds at least one of the attacker's calls,
  issued after the agent has read tool output (that is where the injection arrives);
* **utility cost**: user tasks where the guard holds at least one of the task's own calls, replayed in order with
  every tool result marking the conversation as having read untrusted content.

Run in a separate environment with ``agentdojo==0.1.35`` installed; this file never imports AgentDojo at module level.

Usage: python -m benchmarks.guard_agentdojo [--version v1.2.2] [--json out.json]
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib

from aisec.runtime_guard import AGENTDOJO_POLICY, RuntimeGuard
from benchmarks.poison.run import wilson


def _rate(hit: int, n: int) -> dict:
    return {"hit": hit, "n": n, "pct": round(100 * hit / n, 1) if n else 0.0, "ci95": wilson(hit, n)}


def evaluate(version: str) -> dict:
    from agentdojo.task_suite.load_suites import get_suites

    out: dict = {"version": version, "suites": {}}
    tot_att = tot_stop = tot_ben = tot_broken = 0
    for name, suite in sorted(get_suites(version).items()):
        env = suite.load_and_inject_default_environment({})
        held_by_tool: collections.Counter[str] = collections.Counter()
        broken = []
        for uid, task in sorted(suite.user_tasks.items()):
            g = RuntimeGuard(AGENTDOJO_POLICY, task.PROMPT)
            for call in task.ground_truth(env.model_copy(deep=True)):
                d = g.check(call.function, dict(call.args))
                if not d.allow:
                    broken.append({"task": uid, "reason": d.reason})
                    held_by_tool[call.function] += 1
                    break
                g.observe_result(call.function)
        attacks = stopped = 0
        missed: collections.Counter[str] = collections.Counter()
        for uid, task in sorted(suite.user_tasks.items()):
            for iid, inj in sorted(suite.injection_tasks.items()):
                attacks += 1
                g = RuntimeGuard(AGENTDOJO_POLICY, task.PROMPT)
                g.observe_result("<tool output carrying the injection>")
                held = False
                for call in inj.ground_truth(env.model_copy(deep=True)):
                    if not g.check(call.function, dict(call.args)).allow:
                        held = True
                        break
                    g.observe_result(call.function)
                stopped += held
                if not held:
                    missed[iid] += 1
        n_user = len(suite.user_tasks)
        out["suites"][name] = {
            "attacks_stopped": _rate(stopped, attacks),
            "utility_cost": _rate(len(broken), n_user),
            "injection_tasks_never_stopped": sorted(k for k, v in missed.items() if v == n_user),
            "benign_held": broken,
            "benign_held_by_tool": dict(held_by_tool),
        }
        tot_att += attacks
        tot_stop += stopped
        tot_ben += n_user
        tot_broken += len(broken)
    out["overall"] = {"attacks_stopped": _rate(tot_stop, tot_att), "utility_cost": _rate(tot_broken, tot_ben)}
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1.2.2")
    ap.add_argument("--json")
    a = ap.parse_args()
    res = evaluate(a.version)
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(res, indent=1), encoding="utf-8")
    for name, r in res["suites"].items():
        print(f"{name:10} attacks stopped {r['attacks_stopped']['pct']:>5}% ({r['attacks_stopped']['hit']}/{r['attacks_stopped']['n']})"
              f"   benign tasks held {r['utility_cost']['pct']:>5}% ({r['utility_cost']['hit']}/{r['utility_cost']['n']})")
    o = res["overall"]
    print(f"{'overall':10} attacks stopped {o['attacks_stopped']['pct']:>5}%   benign tasks held {o['utility_cost']['pct']:>5}%")
