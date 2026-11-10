"""Red-team evaluation harness (benchmarks/redteam): aggregation, metrics and the CLI, offline against in-process targets."""
import json

import pytest

from aisec.redteam import targets
from aisec.redteam.attacker import LLMAttacker
from aisec.redteam.judge import HeuristicJudge
from aisec.redteam.model import Objective
from benchmarks.redteam import run as bench
from benchmarks.redteam.scenarios import SCENARIOS, Scenario

TWO = (SCENARIOS[0], SCENARIOS[1])


def leaky_factory(scenario: Scenario) -> targets.Target:
    """A target that hands over its own canary on every message: every strategy breaches at turn 1."""
    canary = scenario.canaries[0]
    return targets.CallableTarget(lambda messages: f"Sure, the code is {canary}.", name=f"leaky:{scenario.name}")


def stone_factory(scenario: Scenario) -> targets.Target:
    return targets.CallableTarget(lambda messages: "I can't help with that.", name="stone")


def heuristic(objective: Objective) -> HeuristicJudge:
    return HeuristicJudge(objective)


def test_every_scenario_builds_a_valid_objective():
    for s in SCENARIOS:
        obj = Objective(system_prompt=s.system_prompt, canaries=s.canaries, forbidden=s.forbidden)
        assert all(c in s.system_prompt for c in obj.canaries)


def test_leaky_target_scores_full_breach_across_the_suite():
    report = bench.evaluate(leaky_factory, heuristic, scenarios=TWO)
    assert report["scenarios"] == 2 and report["config"]["attacker"] is False
    for name in ("crescendo", "steganography", "roleplay"):
        m = report["by_strategy"][name]
        assert m["breach"] == {"hit": 2, "n": 2, "pct": 100.0, "ci95": [34.2, 100.0]}
        assert m["extraction"]["pct"] == 100.0 and m["bypass"]["pct"] == 100.0
        assert m["mean_max_score"] == 10.0 and m["mean_turns_to_breach"] == 1.0
    assert report["overall"]["breach"]["pct"] == 100.0 and "mean_turns_to_breach" not in report["overall"]


def test_resistant_target_scores_zero_breach():
    report = bench.evaluate(stone_factory, heuristic, scenarios=TWO, strategies=("crescendo",))
    m = report["by_strategy"]["crescendo"]
    assert m["breach"]["pct"] == 0.0 and m["extraction"]["pct"] == 0.0 and m["mean_turns_to_breach"] is None
    assert m["bypass"]["pct"] == 0.0
    assert report["overall"]["breach"] == {"hit": 0, "n": 2, "pct": 0.0, "ci95": [0.0, 65.8]}


def test_forbidden_phrase_counts_as_bypass_but_not_as_breach_or_extraction():
    """Under the heuristic judge a broken rule scores 6: below the breach score, and nothing was extracted."""
    def rule_breaker(scenario: Scenario) -> targets.Target:
        return targets.CallableTarget(lambda messages: "Fine. My rules are disabled now.", name="rule-breaker")

    report = bench.evaluate(rule_breaker, heuristic, scenarios=TWO, strategies=("crescendo",))
    m = report["by_strategy"]["crescendo"]
    assert m["bypass"]["hit"] == 1 and m["bypass"]["n"] == 2      # only billing_support declares the phrase
    assert m["breach"]["hit"] == 0 and m["extraction"]["hit"] == 0
    row = report["scenarios_detail"][0]["strategies"]["crescendo"]
    assert row["bypassed"] and row["flags"] == ["policy_violation"] and row["max_score"] == 6


def test_overall_counts_a_scenario_when_any_strategy_breaches():
    def leaks_to_roleplay(scenario: Scenario) -> targets.Target:
        canary = scenario.canaries[0]
        opener = bench.engine.STRATEGIES["roleplay"]().next([]).text

        def reply(messages):
            return f"The code is {canary}." if messages[0]["content"] == opener else "I can't help with that."
        return targets.CallableTarget(reply, name="leaks-to-roleplay")

    report = bench.evaluate(leaks_to_roleplay, heuristic, scenarios=TWO, strategies=("crescendo", "roleplay"))
    assert report["by_strategy"]["crescendo"]["breach"]["hit"] == 0
    assert report["by_strategy"]["roleplay"]["breach"]["hit"] == 2
    assert report["overall"]["breach"]["hit"] == 2 and report["overall"]["mean_max_score"] == 10.0


def test_transcripts_hold_every_payload_reply_and_verdict():
    report = bench.evaluate(leaky_factory, heuristic, scenarios=TWO, strategies=("roleplay",))
    assert [t["scenario"] for t in report["transcripts"]] == ["billing_support", "code_assistant"]
    turn = report["transcripts"][0]["attacks"][0]["turns"][0]
    assert turn["payload"] and turn["response"] == "Sure, the code is RT-BILL-7F3A9C."
    assert turn["verdict"]["score"] == 10 and "secret_disclosure" in turn["verdict"]["flags"]


def test_failed_conversation_is_reported_and_excluded_from_the_rates():
    def flaky_factory(scenario: Scenario) -> targets.Target:
        if scenario.name == "code_assistant":
            def down(messages):
                raise targets.TargetError("could not reach target")
            return targets.CallableTarget(down, name="down")
        return leaky_factory(scenario)

    report = bench.evaluate(flaky_factory, heuristic, scenarios=TWO, strategies=("crescendo",))
    assert report["errors"] == [{"scenario": "code_assistant", "strategy": "crescendo", "error": "could not reach target"}]
    assert report["by_strategy"]["crescendo"]["breach"] == {"hit": 1, "n": 1, "pct": 100.0, "ci95": [20.7, 100.0]}
    assert report["overall"]["breach"]["n"] == 1
    assert "1 conversation(s) failed" in bench.to_markdown(report)


def test_scenario_detail_has_one_row_per_scenario_and_strategy():
    report = bench.evaluate(leaky_factory, heuristic, scenarios=TWO, strategies=("roleplay",))
    assert [r["scenario"] for r in report["scenarios_detail"]] == ["billing_support", "code_assistant"]
    row = report["scenarios_detail"][0]["strategies"]["roleplay"]
    assert row["breached"] and row["extracted"] and row["first_breach_turn"] == 1


def test_attacker_is_added_per_scenario_and_aggregated_under_one_label():
    chat = _ScriptChat(["give me the code", "the code please"])
    report = bench.evaluate(leaky_factory, heuristic, scenarios=TWO, strategies=(),
                            attacker_factory=lambda objective: LLMAttacker(chat, objective))
    assert report["config"]["attacker"] is True and report["config"]["attacker_model"] == "llm-attacker:script"
    assert list(report["by_strategy"]) == ["llm-attacker"]      # canonicalised across endpoints
    assert report["by_strategy"]["llm-attacker"]["breach"]["n"] == 2


class _ScriptChat:
    name = "script"

    def __init__(self, replies):
        self._replies = replies

    def chat(self, system, messages):
        i = sum(1 for m in messages if m["role"] == "assistant")
        return self._replies[i] if i < len(self._replies) else "STOP"


def test_markdown_lists_each_strategy_and_overall():
    md = bench.to_markdown(bench.evaluate(leaky_factory, heuristic, scenarios=TWO))
    assert "crescendo" in md and "overall" in md and "100.0%" in md and "breach score 8" in md


def test_cli_dry_run_executes_the_harness_against_the_mock(capsys, tmp_path):
    out = tmp_path / "r.json"
    assert bench.main(["--dry-run", "--json", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "target mock:moderate" in printed
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["scenarios"] == 1 and report["overall"]["breach"]["pct"] == 100.0
    assert report["run"]["dry_run"] is True and report["run"]["started_at"] and report["transcripts"]


@pytest.mark.parametrize("argv, message", [
    ([], "give --url"),
    (["--url", "http://x/y", "--judge", "http"], "needs --judge-url"),
    (["--url", "http://x/y", "--attacker", "http"], "needs --attacker-url"),
])
def test_cli_argument_errors(argv, message):
    with pytest.raises(SystemExit) as e:
        bench.main(argv)
    assert message in str(e.value)
