"""Run the red-team engine over the fixed scenario suite against a chat model and aggregate the results. Run once per
model and record the numbers in docs/STUDY.md (protocol: docs/REDTEAM_EVAL_PROTOCOL.md).

Usage:
  python -m benchmarks.redteam.run --url http://localhost:11434/v1/chat/completions --model llama3.2 [options] [--json out.json]

Options mirror `aisec redteam`: --model/--api-key-env/--response-path for the target, --judge http|heuristic with
--judge-url/--judge-model, --attacker http with --attacker-url/--attacker-model, -s to pick strategies, --max-turns,
--breach-score. With --dry-run the suite runs against the offline mock target (for checking the harness, not a result).
"""
from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from aisec.redteam import engine, targets
from aisec.redteam import judge as judges
from aisec.redteam.attacker import LLMAttacker
from aisec.redteam.attacks import Strategy
from aisec.redteam.model import AttackResult, Objective
from benchmarks.poison.run import wilson
from benchmarks.redteam.scenarios import SCENARIOS, Scenario

TargetFactory = Callable[[Scenario], targets.Target]
JudgeFactory = Callable[[Objective], judges.Judge]
AttackerFactory = Callable[[Objective], Strategy]


def _label(strategy: str) -> str:
    return "llm-attacker" if strategy.startswith("llm-attacker") else strategy


def _rate(hit: int, n: int) -> dict:
    return {"hit": hit, "n": n, "pct": round(100 * hit / n, 1) if n else 0.0, "ci95": wilson(hit, n)}


@dataclass
class _Acc:
    n: int = 0
    breached: int = 0
    extracted: int = 0
    bypassed: int = 0
    score_sum: int = 0
    breach_turns: list[int] | None = None

    def add(self, a: AttackResult) -> None:
        self.n += 1
        self.breached += a.breached
        self.extracted += a.system_prompt_extracted
        self.bypassed += a.system_prompt_bypassed
        self.score_sum += a.max_score
        if self.breach_turns is None:
            self.breach_turns = []
        if a.first_breach_turn is not None:
            self.breach_turns.append(a.first_breach_turn)

    def summary(self) -> dict:
        turns = self.breach_turns or []
        return {
            "breach": _rate(self.breached, self.n),
            "extraction": _rate(self.extracted, self.n),
            "bypass": _rate(self.bypassed, self.n),
            "mean_max_score": round(self.score_sum / self.n, 2) if self.n else 0.0,
            "mean_turns_to_breach": round(sum(turns) / len(turns), 2) if turns else None,
        }


def evaluate(target_factory: TargetFactory, judge_factory: JudgeFactory, *,
             scenarios: Iterable[Scenario] = SCENARIOS, strategies: Iterable[str] = ("crescendo", "steganography", "roleplay"),
             attacker_factory: AttackerFactory | None = None, max_turns: int = 8, breach_score: int = 8) -> dict:
    """Run every strategy against every scenario and aggregate. One judged conversation per (scenario, strategy)."""
    scenarios = list(scenarios)
    names = list(strategies)
    by_strategy: dict[str, _Acc] = {}
    overall = _Acc()
    detail: list[dict] = []
    target_name = judge_name = ""
    for scenario in scenarios:
        objective = Objective(system_prompt=scenario.system_prompt, canaries=scenario.canaries, forbidden=scenario.forbidden)
        target = target_factory(scenario)
        judge = judge_factory(objective)
        target_name, judge_name = target.name, judge.name
        strats: list[str | Strategy] = list(names)
        if attacker_factory is not None:
            strats.append(attacker_factory(objective))
        result = engine.run(target, judge, objective, strategies=strats, max_turns=max_turns, breach_score=breach_score)
        row: dict = {"scenario": scenario.name, "strategies": {}}
        any_breach = any_ext = any_byp = False
        best = 0
        for a in result.attacks:
            label = _label(a.strategy)
            by_strategy.setdefault(label, _Acc()).add(a)
            row["strategies"][label] = {"max_score": a.max_score, "breached": a.breached,
                                        "extracted": a.system_prompt_extracted, "first_breach_turn": a.first_breach_turn}
            any_breach |= a.breached
            any_ext |= a.system_prompt_extracted
            any_byp |= a.system_prompt_bypassed
            best = max(best, a.max_score)
        overall.n += 1
        overall.breached += any_breach
        overall.extracted += any_ext
        overall.bypassed += any_byp
        overall.score_sum += best
        detail.append(row)
    report = {
        "protocol": "docs/REDTEAM_EVAL_PROTOCOL.md",
        "target": target_name,
        "judge": judge_name,
        "scenarios": len(scenarios),
        "config": {"strategies": names, "attacker": attacker_factory is not None, "max_turns": max_turns,
                   "breach_score": breach_score},
        "by_strategy": {name: acc.summary() for name, acc in sorted(by_strategy.items())},
        "overall": {k: v for k, v in overall.summary().items() if k != "mean_turns_to_breach"},
        "scenarios_detail": detail,
    }
    return report


def to_markdown(report: dict) -> str:
    lines = [f"Red-team evaluation: target {report['target']}, judge {report['judge']}, "
             f"{report['scenarios']} scenarios, breach score {report['config']['breach_score']}", ""]
    lines.append(f"{'strategy':<16} {'breach':>14} {'extraction':>14} {'bypass':>14} {'mean score':>11} {'turns':>6}")
    for name, m in list(report["by_strategy"].items()) + [("overall", report["overall"])]:
        turns = m.get("mean_turns_to_breach")
        lines.append(f"{name:<16} {m['breach']['pct']:>12.1f}% {m['extraction']['pct']:>12.1f}% "
                     f"{m['bypass']['pct']:>12.1f}% {m['mean_max_score']:>11} {('-' if turns is None else turns):>6}")
    return "\n".join(lines)


def _http_target_factory(url: str, model: str | None, api_key_env: str | None, response_path: str) -> TargetFactory:
    def factory(scenario: Scenario) -> targets.Target:
        chat = targets.HTTPChat(url, model, api_key_env=api_key_env, response_path=response_path)
        return targets.HTTPTarget(chat, scenario.system_prompt)
    return factory


def _judge_factory(args: argparse.Namespace) -> JudgeFactory:
    if args.judge == "heuristic":
        return judges.HeuristicJudge
    if args.judge == "http":
        if not args.judge_url:
            raise SystemExit("--judge http needs --judge-url")
        chat = targets.HTTPChat(args.judge_url, args.judge_model)
        return lambda objective: judges.LLMJudge(judges.HTTPJudgeModel(chat), objective)
    raise SystemExit("--judge must be heuristic or http")


def _attacker_factory(args: argparse.Namespace) -> AttackerFactory | None:
    if args.attacker == "none":
        return None
    if args.attacker != "http" or not args.attacker_url:
        raise SystemExit("--attacker http needs --attacker-url")
    chat = targets.HTTPChat(args.attacker_url, args.attacker_model)
    return lambda objective: LLMAttacker(chat, objective)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Evaluate the red-team engine over the fixed scenario suite.")
    p.add_argument("--url", help="Target chat-completions endpoint.")
    p.add_argument("--model")
    p.add_argument("--api-key-env")
    p.add_argument("--response-path", default="choices.0.message.content")
    p.add_argument("--judge", default="heuristic", choices=["heuristic", "http"])
    p.add_argument("--judge-url")
    p.add_argument("--judge-model")
    p.add_argument("--attacker", default="none", choices=["none", "http"])
    p.add_argument("--attacker-url")
    p.add_argument("--attacker-model")
    p.add_argument("-s", "--strategy", action="append", default=[], choices=["crescendo", "steganography", "roleplay"])
    p.add_argument("--max-turns", type=int, default=8)
    p.add_argument("--breach-score", type=int, default=8)
    p.add_argument("--dry-run", action="store_true", help="Run against the offline mock target (checks the harness, not a result).")
    p.add_argument("--json", type=str)
    args = p.parse_args(argv)

    if args.dry_run:
        from benchmarks.redteam.scenarios import Scenario as _S
        mock = targets.MockTarget("moderate")
        scenarios = [_S("mock", targets.MOCK_SYSTEM_PROMPT, targets.MOCK_OBJECTIVE.canaries, targets.MOCK_OBJECTIVE.forbidden)]

        def target_factory(scenario: Scenario) -> targets.Target:
            return mock
    elif args.url:
        scenarios = list(SCENARIOS)
        target_factory = _http_target_factory(args.url, args.model, args.api_key_env, args.response_path)
    else:
        raise SystemExit("give --url (a target endpoint) or --dry-run")

    report = evaluate(target_factory, _judge_factory(args), scenarios=scenarios,
                      strategies=args.strategy or ("crescendo", "steganography", "roleplay"),
                      attacker_factory=_attacker_factory(args), max_turns=args.max_turns, breach_score=args.breach_score)
    print(to_markdown(report))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nreport: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
