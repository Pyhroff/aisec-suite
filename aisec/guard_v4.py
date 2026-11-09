"""Runtime guard v4: v3 plus effect classes read from a tool's description and parameter names.

Section 3h found that name-based classes fail when a benchmark names its tools descriptively and without a verb
(ASB: 16.5% of attacker tool names contain a verb the class lists know). v4 adds two more sources of classes, both
**strictly additive**: whatever v3 holds, v4 holds, so an attacker who writes a misleading description can make the guard
stricter, never looser. Fixed in docs/GUARD_V4_PROTOCOL.md before the evaluation:

* **Description.** The first six content words of the description (articles and filler such as "a tool used for" removed).
  If the first of them is a read verb, the description adds nothing. Otherwise a stem match against a class's verbs adds
  that class. Word lists are v2's, unchanged.
* **Parameters.** Parameter names add a class: amount/price/currency/iban/account -> money, command/script/code -> exec,
  password/token/secret/api_key -> credential, recipient/to/cc/bcc/email -> publish.

The class a user's request authorises, destination detection, approvals and the decision logic are v3's.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from .guard_v2 import CLASSES, READ_VERBS, Decision, _stem, classify
from .guard_v3 import GuardV3, destinations

_WORD = re.compile(r"[a-z0-9]+")
_FILLER = frozenset("a an the tool used for to that which this is can be allows allow you your ability function api method it of "
                    "and or with by in on as are will helps help enables enable designed provides provide".split())
_READ_STEMS = frozenset(_stem(v) for v in READ_VERBS) | {"return", "display", "analyz", "analys"}
PARAM_CLASSES: dict[str, frozenset[str]] = {
    "money": frozenset({"amount", "price", "currency", "iban", "account", "account_number"}),
    "exec": frozenset({"command", "cmd", "script", "code", "shell"}),
    "credential": frozenset({"password", "passphrase", "secret", "token", "api_key", "apikey", "credential", "credentials"}),
    "publish": frozenset({"recipient", "recipients", "to", "cc", "bcc", "email", "emails"}),
}
_VERB_STEMS = {c: frozenset(_stem(v) for v in verbs) for c, (verbs, _) in CLASSES.items()}


def _stem4(word: str) -> str:
    s = _stem(word)
    return s[:-1] if len(s) > 3 and s[-1] == s[-2] and s[-1] not in "sl" else s


def text_classes(description: str) -> frozenset[str]:
    toks = [t for t in _WORD.findall(description[:300].lower()) if t not in _FILLER][:6]
    if not toks or _stem4(toks[0]) in _READ_STEMS:
        return frozenset()
    stems = {_stem4(t) for t in toks}
    return frozenset(c for c, vs in _VERB_STEMS.items() if stems & {_stem4(v) for v in vs})


def param_classes(params: Iterable[str]) -> frozenset[str]:
    names = {p.lower() for p in params}
    return frozenset(c for c, ps in PARAM_CLASSES.items() if names & ps)


def _param_names(tool: Mapping[str, Any]) -> list[str]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    return list(props) if isinstance(props, dict) else []


class GuardV4(GuardV3):
    def __init__(self, user_request: str, trusted: Iterable[str] = (), tools: Iterable[Mapping[str, Any]] = ()) -> None:
        super().__init__(user_request, trusted)
        self.meta: dict[str, frozenset[str]] = {}
        self.register(tools)

    def register(self, tools: Iterable[Mapping[str, Any]]) -> None:
        """Tool definitions as the agent sees them (``tools/list``): name, description, inputSchema."""
        for t in tools:
            name = str(t.get("name", ""))
            self.meta[name] = text_classes(str(t.get("description") or "")) | param_classes(_param_names(t))

    def classes_of(self, tool: str) -> frozenset[str]:
        return classify(tool) | self.meta.get(tool, frozenset())

    def check(self, tool: str, args: dict[str, object] | None = None) -> Decision:
        if not self.tainted:
            return Decision(True)
        args = args or {}
        dests = tuple(d for d in destinations(args) if not self._dest_from_user(d))
        classes = tuple(c for c in sorted(self.classes_of(tool)) if not self._class_from_user(c))
        if dests:
            return Decision(False, f"{tool}: destination {dests[0]!r} did not come from the user's request", "destination",
                            dests[0], dests, classes)
        if classes:
            words = ", ".join(sorted(CLASSES[classes[0]][1])[:6])
            return Decision(False, f"{tool} is a '{classes[0]}' action and the request used none of: {words}, ...",
                            f"action:{classes[0]}", classes[0], dests, classes)
        return Decision(True)
