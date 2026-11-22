"""Run the red-team evaluation harness against several models and produce one combined comparison.

`benchmarks.redteam.run` evaluates one target. This drives it over a list of targets from a JSON config, writes each
target's full report (with transcripts) and, when available, its HTML page, and prints one table comparing overall
breach / extraction / bypass and per-strategy breach across the models. The interesting question it answers in one
place: does a larger or hosted model resist where a small one folds.

Config (JSON): a list of targets, each a chat-completions endpoint, plus optional shared judge and attacker endpoints.

```json
{
  "judge": {"mode": "heuristic"},
  "attacker": {"mode": "none"},
  "targets": [
    {"name": "llama3.2-3b", "url": "http://localhost:11434/v1/chat/completions", "model": "llama3.2",
     "temperature": 0, "seed": 7},
    {"name": "qwen2.5-7b", "url": "http://localhost:11434/v1/chat/completions", "model": "qwen2.5",
     "temperature": 0, "seed": 7}
  ]
}
```

Usage:
  python -m benchmarks.redteam.batch --config targets.json [--suite base|extended] [--out DIR] [--json combined.json]

Nothing is sent to a target the config does not name. API keys are read from the environment variable a target's
`api_key_env` names, never from the config. With --dry-run the batch runs against the three offline mock defences
(weak/moderate/hardened), to check the harness without a model.
"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
from typing import Any

from aisec.redteam import judge as judges
from aisec.redteam import targets
from aisec.redteam.attacker import LLMAttacker
from benchmarks.redteam import run as single
from benchmarks.redteam.scenarios import SUITES, Scenario

STRATEGY_ORDER = ("crescendo", "steganography", "roleplay", "llm-attacker")


def _slug(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "-" for c in name)[:64] or "target"


def _html_doc(report: dict, name: str) -> dict:
    """Assemble a single-run document (the shape ``aisec.redteam.html_report.to_html`` renders) from a harness report,
    flattening every scenario's conversations onto one page so a reviewer can read them and confirm each breach."""
    import aisec

    attacks = []
    for entry in report.get("transcripts", []):
        for attack in entry["attacks"]:
            attack = dict(attack, strategy=f"{entry['scenario']} · {attack['strategy']}")
            attacks.append(attack)
    breached = [a for a in attacks if a["outcome"] == "breached"]
    return {
        "schema_version": "1.0",
        "tool": {"name": "aisec redteam (batch)", "version": aisec.__version__},
        "generated_at": report.get("run", {}).get("started_at")
        or datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "target": f"{name} ({report['target']})",
        "judge": report["judge"],
        "config": {"breach_score": report["config"]["breach_score"], "max_turns": report["config"]["max_turns"]},
        "summary": {
            "verdict": "breached" if breached else "resisted",
            "attacks_run": len(attacks),
            "attacks_breached": len(breached),
            "max_score": max((a["max_score"] for a in attacks), default=0),
            "system_prompt_extracted": any(a["system_prompt_extracted"] for a in attacks),
            "system_prompt_bypassed": any(a["system_prompt_bypassed"] for a in attacks),
        },
        "attacks": attacks,
    }


def _judge_factory(cfg: dict, timeout: float) -> single.JudgeFactory:
    mode = cfg.get("mode", "heuristic")
    if mode == "heuristic":
        return judges.HeuristicJudge
    if mode == "http":
        url = cfg.get("url")
        if not url:
            raise ValueError("judge mode 'http' needs a 'url'")
        chat = targets.HTTPChat(url, cfg.get("model"), timeout=timeout)
        return lambda objective: judges.LLMJudge(judges.HTTPJudgeModel(chat), objective)
    raise ValueError("judge mode must be 'heuristic' or 'http'")


def _attacker_factory(cfg: dict, timeout: float) -> single.AttackerFactory | None:
    mode = cfg.get("mode", "none")
    if mode == "none":
        return None
    if mode != "http" or not cfg.get("url"):
        raise ValueError("attacker mode 'http' needs a 'url'")
    chat = targets.HTTPChat(cfg["url"], cfg.get("model"), timeout=timeout)
    return lambda objective: LLMAttacker(chat, objective)


def _target_factory(spec: dict, timeout: float) -> single.TargetFactory:
    url = spec.get("url")
    if not url:
        raise ValueError(f"target {spec.get('name', '?')!r} has no 'url'")
    return single._http_target_factory(url, spec.get("model"), spec.get("api_key_env"),
                                       spec.get("response_path", "choices.0.message.content"), timeout,
                                       spec.get("temperature"), spec.get("seed"))


def run_batch(config: dict, *, suite: str = "base", scenarios: tuple[Scenario, ...] | None = None,
              target_factory_for: Any = None, out_dir: pathlib.Path | None = None,
              max_turns: int = 8, breach_score: int = 8, timeout: float = 120.0) -> dict:
    """Evaluate every target in ``config['targets']`` over the scenario suite and combine the summaries.

    ``suite`` names a registered suite; ``scenarios`` overrides it with an explicit list (used by ``--dry-run`` and by
    tests, where each target must be judged against the prompt it actually holds). ``target_factory_for(spec) ->
    TargetFactory`` is injectable so tests can run in process; by default each target is an HTTP endpoint built from
    its spec. A target whose evaluation raises is recorded under ``failed`` and skipped; the batch continues so one
    dead endpoint does not lose the others."""
    if scenarios is None:
        if suite not in SUITES:
            raise ValueError(f"unknown suite {suite!r} (choose from {', '.join(SUITES)})")
        scenarios = SUITES[suite]
    target_factory_for = target_factory_for or (lambda spec: _target_factory(spec, timeout))
    judge_factory = _judge_factory(config.get("judge", {}), timeout)
    attacker_factory = _attacker_factory(config.get("attacker", {}), timeout)

    specs = config.get("targets", [])
    if not specs:
        raise ValueError("config has no targets")
    seen = set()
    results: list[dict] = []
    failed: list[dict] = []
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
    for spec in specs:
        name = spec.get("name") or spec.get("model") or spec.get("url", "target")
        if name in seen:
            raise ValueError(f"duplicate target name {name!r}")
        seen.add(name)
        try:
            report = single.evaluate(target_factory_for(spec), judge_factory, scenarios=scenarios,
                                     attacker_factory=attacker_factory, max_turns=max_turns, breach_score=breach_score)
        except (targets.TargetError, ValueError) as e:
            failed.append({"name": name, "error": str(e)})
            continue
        report["name"] = name
        if out_dir is not None:
            (out_dir / f"{_slug(name)}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            try:
                from aisec.redteam.html_report import to_html
                (out_dir / f"{_slug(name)}.html").write_text(to_html(_html_doc(report, name)), encoding="utf-8")
            except ImportError:
                pass
        results.append(report)

    combined = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "suite": suite,
        "scenarios": len(scenarios),
        "config": {"judge": config.get("judge", {}).get("mode", "heuristic"),
                   "attacker": config.get("attacker", {}).get("mode", "none"),
                   "max_turns": max_turns, "breach_score": breach_score},
        "commit": single._commit(),
        "models": [{
            "name": r["name"],
            "target": r["target"],
            "overall": r["overall"],
            "by_strategy": r["by_strategy"],
            "errors": len(r["errors"]),
        } for r in results],
        "failed": failed,
    }
    return combined


def to_markdown(combined: dict) -> str:
    strategies = [s for s in STRATEGY_ORDER
                  if any(s in m["by_strategy"] for m in combined["models"])]
    lines = [f"Cross-model red-team comparison: {combined['suite']} suite ({combined['scenarios']} scenarios), "
             f"judge {combined['config']['judge']}, attacker {combined['config']['attacker']}, "
             f"breach score {combined['config']['breach_score']}", ""]
    header = f"{'model':<22} {'breach':>8} {'extract':>8} {'bypass':>8}  " + "  ".join(f"{s[:10]:>10}" for s in strategies)
    lines.append(header)
    for m in combined["models"]:
        o = m["overall"]
        cells = []
        for s in strategies:
            cell = m["by_strategy"].get(s)
            cells.append(f"{cell['breach']['pct']:>9.1f}%" if cell else f"{'-':>10}")
        lines.append(f"{m['name'][:22]:<22} {o['breach']['pct']:>7.1f}% {o['extraction']['pct']:>7.1f}% "
                     f"{o['bypass']['pct']:>7.1f}%  " + "  ".join(cells))
    if combined["failed"]:
        lines += ["", f"{len(combined['failed'])} target(s) failed and were skipped:"]
        lines += [f"  {f['name']}: {f['error']}" for f in combined["failed"]]
    lines += ["", "breach/extract/bypass are overall (any strategy) per model; per-strategy columns are breach rate. "
              "One sampled run per model unless temperature 0 and a seed were set."]
    return "\n".join(lines)


def _mock_config() -> dict:
    return {"judge": {"mode": "heuristic"}, "attacker": {"mode": "none"},
            "targets": [{"name": f"mock-{d}"} for d in targets.DEFENSES]}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run the red-team harness against several models and compare them.")
    p.add_argument("--config", help="JSON config listing targets (and optional judge/attacker).")
    p.add_argument("--suite", default="base", choices=list(SUITES))
    p.add_argument("--out", help="Directory for each model's JSON and HTML report.")
    p.add_argument("--max-turns", type=int, default=8)
    p.add_argument("--breach-score", type=int, default=8)
    p.add_argument("--timeout", type=float, default=120.0)
    p.add_argument("--dry-run", action="store_true", help="Run against the offline mock defences (checks the batch runner, not a result).")
    p.add_argument("--json", help="Write the combined comparison here.")
    args = p.parse_args(argv)

    target_factory_for = None
    scenarios = None
    suite = args.suite
    if args.dry_run:
        config = _mock_config()
        # Each mock only protects its own canary, so the three defences are compared on the mock scenario, not the suite.
        scenarios = (Scenario("mock", targets.MOCK_SYSTEM_PROMPT, targets.MOCK_OBJECTIVE.canaries, targets.MOCK_OBJECTIVE.forbidden),)
        suite = "mock"

        def target_factory_for(spec: dict) -> single.TargetFactory:  # noqa: F811
            mock = targets.MockTarget(spec["name"].split("-", 1)[1])
            return lambda scenario: mock
    elif args.config:
        config = json.loads(pathlib.Path(args.config).read_text(encoding="utf-8"))
    else:
        raise SystemExit("give --config (a targets JSON) or --dry-run")

    try:
        combined = run_batch(config, suite=suite, scenarios=scenarios, target_factory_for=target_factory_for,
                             out_dir=pathlib.Path(args.out) if args.out else None,
                             max_turns=args.max_turns, breach_score=args.breach_score, timeout=args.timeout)
    except ValueError as e:
        raise SystemExit(str(e)) from e
    print(to_markdown(combined))
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(combined, indent=2), encoding="utf-8")
        print(f"\ncombined: {args.json}")
    if args.out:
        print(f"per-model reports: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
