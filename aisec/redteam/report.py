"""Structured JSON report for a red-team run.

The report holds the full transcript, so it contains whatever the target leaked. Plant synthetic canaries rather than
real secrets, and handle the file with the same care as the system prompt it tested. The prompt itself is recorded
only as a SHA-256 digest.
"""
from __future__ import annotations

import datetime
import hashlib

from aisec import __version__
from aisec.redteam.engine import RunResult
from aisec.redteam.model import AttackResult, Turn

SCHEMA_VERSION = "1.0"


def _verdict(turn: Turn) -> dict:
    v = turn.verdict
    return {"score": v.score, "flags": list(v.flags), "rationale": v.rationale, "evidence": v.evidence, "judge": v.judge}


def _attack(a: AttackResult) -> dict:
    return {
        "strategy": a.strategy,
        "outcome": "breached" if a.breached else "resisted",
        "max_score": a.max_score,
        "turns_used": len(a.turns),
        "first_breach_turn": a.first_breach_turn,
        "system_prompt_extracted": a.system_prompt_extracted,
        "system_prompt_bypassed": a.system_prompt_bypassed,
        "flags": list(a.flags),
        "attack_path": [
            {"turn": t.index, "technique": t.payload.technique, "intent": t.payload.intent,
             "adapted_because": t.payload.adapted or None, "score": t.verdict.score}
            for t in a.turns
        ],
        "payloads": [{"turn": t.index, "technique": t.payload.technique, "text": t.payload.text} for t in a.turns],
        "turns": [
            {"turn": t.index, "technique": t.payload.technique, "payload": t.payload.text, "response": t.response,
             "verdict": _verdict(t)}
            for t in a.turns
        ],
    }


def to_report(result: RunResult) -> dict:
    prompt = result.objective.system_prompt
    attacks = [_attack(a) for a in result.attacks]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "aisec redteam", "version": __version__},
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "target": result.target,
        "judge": result.judge,
        "config": {"strategies": [a.strategy for a in result.attacks], "max_turns": result.max_turns,
                   "breach_score": result.breach_score},
        "objective": {
            "system_prompt_known": prompt is not None,
            "system_prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest() if prompt is not None else None,
            "canaries_planted": len(result.objective.canaries),
            "forbidden_patterns": list(result.objective.forbidden),
        },
        "summary": {
            "verdict": "breached" if result.breached else "resisted",
            "attacks_run": len(attacks),
            "attacks_breached": sum(a["outcome"] == "breached" for a in attacks),
            "max_score": max((a["max_score"] for a in attacks), default=0),
            "system_prompt_extracted": any(a["system_prompt_extracted"] for a in attacks),
            "system_prompt_bypassed": any(a["system_prompt_bypassed"] for a in attacks),
        },
        "attacks": attacks,
    }
