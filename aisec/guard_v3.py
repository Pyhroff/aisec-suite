"""Runtime guard v3: v2 with one fix, to destination detection.

Section 3g of docs/STUDY.md found that 40 of the 79 destination values v2 held in benign AgentDojo tasks were dates such
as ``2024-05-19`` that the phone-number pattern accepted. v3 changes exactly that and nothing else: a phone number must
have 7-15 digits, 10 or more unless it starts with ``+``, and must not look like a date. Name tokenising, effect classes,
class word lists, email/URL/IBAN detection, approvals and the decision logic are v2's, untouched. The protocol is
docs/GUARD_V3_PROTOCOL.md, written before the evaluation.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

from .guard_v2 import _DEST_PARAM, _EMAIL, _IBAN, _PHONE, _URL, CLASSES, Decision, GuardV2, _values, classify

_DATE = re.compile(r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}")


def phones(text: str) -> list[str]:
    out = []
    for m in _PHONE.finditer(text):
        t = m.group(0).strip()
        digits = len(re.sub(r"\D", "", t))
        if _DATE.search(t) or not 7 <= digits <= 15 or (not t.startswith("+") and digits < 10):
            continue
        out.append(t)
    return out


def destinations(args: dict[str, object]) -> list[str]:
    """v2's destinations(), with ``phones`` in place of the raw phone pattern."""
    found: list[str] = []
    for key, val in args.items():
        for s in _values(val):
            if _DEST_PARAM.match(str(key)):
                found.append(s)
            else:
                found += [m.group(0) for rx in (_EMAIL, _URL, _IBAN) for m in rx.finditer(s)] + phones(s)
    return list(dict.fromkeys(found))


class GuardV3(GuardV2):
    def __init__(self, user_request: str, trusted: Iterable[str] = ()) -> None:
        super().__init__(user_request, trusted)

    def check(self, tool: str, args: dict[str, object] | None = None) -> Decision:
        if not self.tainted:
            return Decision(True)
        args = args or {}
        dests = tuple(d for d in destinations(args) if not self._dest_from_user(d))
        classes = tuple(c for c in sorted(classify(tool)) if not self._class_from_user(c))
        if dests:
            return Decision(False, f"{tool}: destination {dests[0]!r} did not come from the user's request", "destination",
                            dests[0], dests, classes)
        if classes:
            words = ", ".join(sorted(CLASSES[classes[0]][1])[:6])
            return Decision(False, f"{tool} is a '{classes[0]}' action and the request used none of: {words}, ...",
                            f"action:{classes[0]}", classes[0], dests, classes)
        return Decision(True)
