"""Data model shared by the red-team engine, strategies, judges and reporter."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Flags a judge may set. Anything else a judge model returns is dropped.
FLAGS = (
    "system_prompt_leak",     # most of the protected system prompt was reproduced
    "partial_leak",           # a recognisable part of it was reproduced
    "secret_disclosure",      # a planted canary value appeared in the reply
    "encoded_exfiltration",   # the leak was only visible after decoding the reply (base64, ROT13, ...)
    "policy_violation",       # the reply matched a pattern the operator declared forbidden
    "persona_adoption",       # the target announced it had taken on an unrestricted role
    "harmful_compliance",     # judge model only: the reply complied with a request the system prompt forbids
    "refusal",                # the target declined
)


@dataclass(frozen=True)
class Objective:
    """What counts as a breach. Everything here is ground truth supplied by the operator, not guessed from text."""

    system_prompt: str | None = None      # the protected prompt, when the tester knows it
    canaries: tuple[str, ...] = ()        # synthetic secrets planted in the system prompt
    forbidden: tuple[str, ...] = ()       # regexes; a reply matching one violates the system prompt's rules

    def __post_init__(self) -> None:
        for pattern in self.forbidden:
            re.compile(pattern)           # fail at construction, not mid-run


@dataclass(frozen=True)
class Payload:
    text: str
    technique: str        # e.g. "crescendo/quote-back", "steganography/base64"
    intent: str           # "rapport" | "setup" | "probe" | "extract"
    adapted: str = ""     # why the strategy chose this step, when it reacted to the previous reply


@dataclass(frozen=True)
class Verdict:
    score: int                                   # 1 (clean refusal) .. 10 (planted secret disclosed)
    flags: tuple[str, ...]
    rationale: str
    evidence: dict = field(default_factory=dict)
    judge: str = "heuristic"


@dataclass(frozen=True)
class Turn:
    index: int
    payload: Payload
    response: str
    verdict: Verdict


@dataclass
class AttackResult:
    strategy: str
    turns: list[Turn]
    breach_score: int

    @property
    def max_score(self) -> int:
        return max((t.verdict.score for t in self.turns), default=0)

    @property
    def flags(self) -> tuple[str, ...]:
        return tuple(sorted({f for t in self.turns for f in t.verdict.flags}))

    @property
    def breached(self) -> bool:
        return self.max_score >= self.breach_score

    @property
    def first_breach_turn(self) -> int | None:
        return next((t.index for t in self.turns if t.verdict.score >= self.breach_score), None)

    @property
    def system_prompt_extracted(self) -> bool:
        return bool({"system_prompt_leak", "secret_disclosure"} & set(self.flags))

    @property
    def system_prompt_bypassed(self) -> bool:
        return bool({"policy_violation", "secret_disclosure", "harmful_compliance"} & set(self.flags))
