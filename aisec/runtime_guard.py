"""Runtime guard for agent tool calls: decide by data provenance, not by reading intent from text.

Static scanners fail on attacks written as ordinary requests (docs/STUDY.md sections 3c-3e). This guard does not try
to recognise hostile text at all. It watches what the agent does after it has read untrusted content (any tool
result), and holds a consequential call for confirmation when the call's *destination* or *action* did not come from
the user:

* **Destination provenance.** For a sink tool (send money, send an email, share a file, invite a user, post to a URL),
  every destination value (recipient, IBAN, address, URL) must appear in the user's own request or in the trusted set
  the operator configures (the user's own addresses, saved payees). A destination that only appeared in tool output
  is where injected instructions send data.
* **Action provenance.** A destructive or account-changing tool (delete, change password, remove a user) is held
  unless the user's request names that kind of action.

Before any untrusted content has been read, calls pass: there is nothing for an injection to have come from. The guard
never blocks silently; it returns ``confirm`` with the reason, for the host to ask the user.

The policy is data (``GuardPolicy``) so it can describe any tool set. ``AGENTDOJO_POLICY`` maps AgentDojo's tools; it
was written from the tool signatures alone, before any evaluation run (docs/GUARD_EVAL_PROTOCOL.md).
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

_WORD = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class GuardPolicy:
    sinks: dict[str, tuple[str, ...]] = field(default_factory=dict)      # tool -> destination parameters
    actions: dict[str, tuple[str, ...]] = field(default_factory=dict)    # tool -> words the user must have used
    trusted: frozenset[str] = frozenset()                                # destinations always allowed (lower-case)


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str = ""


def _values(v: object) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [x for item in v for x in _values(item)]
    s = str(v).strip()
    return [s] if s else []


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower().rstrip("/"))


class RuntimeGuard:
    """Per-conversation guard. Call ``observe_result`` for every tool result and ``check`` before every tool call."""

    def __init__(self, policy: GuardPolicy, user_request: str, trusted: Iterable[str] = ()) -> None:
        self.policy = policy
        self.request = _norm(user_request)
        self.request_words = set(_WORD.findall(self.request))
        self.trusted = {_norm(t) for t in (*policy.trusted, *trusted) if t}
        self.tainted = False

    def observe_result(self, _tool: str, _result: object = None) -> None:
        self.tainted = True   # every tool result is untrusted: it can carry text the user did not write

    def _from_user(self, value: str) -> bool:
        v = _norm(value)
        return v in self.trusted or (len(v) >= 3 and v in self.request)

    def check(self, tool: str, args: dict[str, object]) -> Decision:
        if not self.tainted:
            return Decision(True)
        if tool in self.policy.sinks:
            for param in self.policy.sinks[tool]:
                for value in _values(args.get(param)):
                    if not self._from_user(value):
                        return Decision(False, f"{tool}.{param}={value!r} did not come from the user's request")
        if tool in self.policy.actions:
            words = self.policy.actions[tool]
            if not any(w in self.request_words for w in words):
                return Decision(False, f"{tool} changes or deletes data and the request asked for none of: {', '.join(words)}")
        return Decision(True)


AGENTDOJO_POLICY = GuardPolicy(
    sinks={
        "send_money": ("recipient",),
        "schedule_transaction": ("recipient",),
        "update_scheduled_transaction": ("recipient",),
        "send_email": ("recipients", "cc", "bcc"),
        "share_file": ("email",),
        "create_calendar_event": ("participants",),
        "add_calendar_event_participants": ("participants",),
        "send_direct_message": ("recipient",),
        "invite_user_to_slack": ("user", "user_email"),
        "add_user_to_channel": ("user",),
        "post_webpage": ("url",),
        "get_webpage": ("url",),
        "download_file": ("url",),
    },
    actions={
        "update_password": ("password",),
        "update_user_info": ("update", "change", "address", "name", "info", "information", "profile"),
        "delete_file": ("delete", "remove"),
        "delete_email": ("delete", "remove"),
        "remove_user_from_slack": ("remove", "delete", "kick"),
        "cancel_calendar_event": ("cancel", "delete", "remove"),
    },
)
