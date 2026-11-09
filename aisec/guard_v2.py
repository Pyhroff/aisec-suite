"""Runtime guard v2: provenance for destinations *and* for actions that have no destination.

Design is fixed in docs/GUARD_V2_PROTOCOL.md, written before the evaluation. v1 (``runtime_guard.py``) is unchanged so
its published numbers stay reproducible. What v2 adds, from reading v1's code and its AgentDojo results (section 3f of
docs/STUDY.md), never from the benchmark it is evaluated on:

* **Name tokenising.** ``DeleteEmails``, ``delete_emails`` and ``delete-emails`` are the same tool. v1's verb rules only
  matched snake_case.
* **Effect classes for destination-free actions.** v1 held only deletes, password changes and sends to a destination.
  v2 sorts every tool by the verbs in its name into read-only, or one of: delete, money, access, control, publish, exec,
  credential, modify. After the agent has read untrusted content, a call in a class is held unless the user's request
  used a word of that class. Tools matching no verb are not held (stated in the protocol as a known gap).
* **Destination values by shape, not by parameter name.** Emails, URLs, phone numbers and IBAN-like strings in *any*
  argument must come from the user's request, the trusted set, or something the user approved. v1 needed the parameter
  to be named in the policy.
* **Fewer repeated prompts.** ``approve`` records what the user confirmed (a destination value, or an action class),
  so the next step that needs the same thing does not ask again. Read-only tools carrying no destination are never
  held.

Like v1, it never blocks silently: ``check`` returns a decision with the reason, for the host to ask the user.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

READ_VERBS = frozenset({
    "get", "search", "list", "read", "view", "find", "check", "retrieve", "estimate", "verify", "track", "show", "describe",
    "query", "lookup", "look", "count", "summarize", "fetch", "preview", "inspect", "monitor", "browse", "calculate",
})

# class -> (verb stems in tool names, words in the user's request that authorise the class)
CLASSES: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "delete": (
        frozenset({"delete", "remove", "erase", "clear", "cancel", "drop", "destroy", "purge", "wipe", "unfollow", "unsubscribe",
                   "leave", "revoke", "ban", "kick", "deactivate", "disable", "block", "terminate", "uninstall"}),
        frozenset({"delete", "remove", "erase", "clear", "cancel", "discard", "drop", "destroy", "purge", "wipe", "unfollow",
                   "unsubscribe", "leave", "revoke", "ban", "kick", "deactivate", "disable", "block", "terminate", "uninstall"}),
    ),
    "money": (
        frozenset({"pay", "transfer", "withdraw", "deposit", "purchase", "order", "buy", "trade", "book", "booking", "checkout",
                   "transaction", "invest", "sell", "refund", "donate"}),
        frozenset({"pay", "transfer", "send", "withdraw", "deposit", "buy", "purchase", "order", "trade", "invest", "book",
                   "reserve", "checkout", "money", "transaction", "sell", "refund", "donate", "bill", "payment"}),
    ),
    "access": (
        frozenset({"unlock", "grant", "share", "invite", "authorize", "permit", "allow", "guest", "member", "privacy", "permission",
                   "access", "collaborator"}),
        frozenset({"unlock", "grant", "share", "invite", "add", "allow", "authorize", "permission", "guest", "access", "privacy",
                   "open", "collaborate"}),
    ),
    "control": (
        frozenset({"control", "schedule", "dispatch", "redirect", "lock", "start", "stop", "play", "navigate", "go", "move",
                   "reboot", "restart", "shutdown", "activate"}),
        frozenset({"control", "turn", "set", "schedule", "dispatch", "lock", "unlock", "open", "close", "start", "stop", "play",
                   "navigate", "go", "move", "redirect", "manage", "reboot", "restart", "shutdown", "activate", "switch"}),
    ),
    "publish": (
        frozenset({"post", "tweet", "publish", "send", "message", "sms", "email", "reply", "forward", "broadcast", "comment", "notify"}),
        frozenset({"send", "email", "mail", "message", "text", "post", "tweet", "publish", "share", "tell", "notify", "reply",
                   "forward", "broadcast", "comment", "write", "sms"}),
    ),
    "exec": (
        frozenset({"execute", "exec", "run", "shell", "eval", "command", "script", "deploy", "install", "invoke", "call"}),
        frozenset({"run", "execute", "exec", "command", "terminal", "shell", "script", "deploy", "install", "invoke", "call"}),
    ),
    "credential": (
        frozenset({"password", "credential", "apikey", "secret", "token", "passphrase", "ssh"}),
        frozenset({"password", "credential", "key", "secret", "token", "passphrase", "ssh", "login"}),
    ),
    "modify": (
        frozenset({"update", "set", "change", "modify", "edit", "rename", "upload", "create", "add", "store", "save", "write",
                   "manage", "import", "generate", "manipulate", "put", "patch", "enable", "register", "follow", "join", "request"}),
        frozenset({"update", "change", "edit", "set", "modify", "rename", "upload", "create", "add", "store", "save", "write", "make",
                   "new", "manage", "import", "generate", "put", "patch", "enable", "register", "follow", "join", "request", "fix"}),
    ),
}

_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")
_WORD = re.compile(r"[a-z0-9]+")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>]+|\bwww\.[^\s\"'<>]+", re.I)
_PHONE = re.compile(r"(?<![\w.])\+?\d[\d\-\s().]{7,}\d(?![\w])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_DEST_PARAM = re.compile(
    r"^(?:to|cc|bcc|recipients?|recipient_\w+|emails?|email_address|user_email|address|url|uri|link|endpoint|webhook(?:_url)?|"
    r"callback(?:_url)?|iban|account(?:_number)?|phone(?:_number)?|destination|target_url|host|participants?|user|users)$",
    re.I,
)


def name_tokens(name: str) -> list[str]:
    """``GmailDeleteEmails`` / ``gmail_delete_emails`` / ``gmail-delete.emails`` -> [gmail, delete, emails]."""
    out: list[str] = []
    for part in re.split(r"[^A-Za-z0-9]+", name):
        out += [t.lower() for t in _CAMEL.findall(part)]
    return out


def _stem(word: str) -> str:
    for suffix in ("ing", "ed", "es", "s"):
        if word.endswith(suffix) and len(word) > len(suffix) + 2:
            word = word[: -len(suffix)]
            break
    return word[:-1] if word.endswith("e") and len(word) > 3 else word


def _stem_in(word: str, vocab: frozenset[str]) -> bool:
    """The request word is one of the class words, allowing inflections ("deleting", "cancelled", "sends")."""
    if word in vocab:
        return True
    a = _stem(word)
    return len(a) >= 3 and any(a == b or (len(a) >= 4 and len(b) >= 4 and (a.startswith(b) or b.startswith(a)))
                               for b in (_stem(w) for w in vocab))


def classify(tool: str) -> frozenset[str]:
    """Effect classes of a tool by the verbs in its name. Empty set: read-only, or no verb recognised."""
    toks = name_tokens(tool)
    classes = {c for c, (verbs, _) in CLASSES.items() if any(t in verbs for t in toks)}
    return frozenset(classes)


def is_read_only(tool: str) -> bool:
    toks = name_tokens(tool)
    return any(t in READ_VERBS for t in toks) and not classify(tool)


def _values(v: object) -> list[str]:
    if v is None:
        return []
    if isinstance(v, dict):
        return [x for item in v.values() for x in _values(item)]
    if isinstance(v, (list, tuple, set)):
        return [x for item in v for x in _values(item)]
    s = str(v).strip()
    return [s] if s else []


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower().rstrip("/"))


def destinations(args: dict[str, object]) -> list[str]:
    """Values in the arguments that name a place data can go: by parameter name, or by shape (email, URL, phone, IBAN)."""
    found: list[str] = []
    for key, val in args.items():
        for s in _values(val):
            if _DEST_PARAM.match(str(key)):
                found.append(s)
            else:
                found += [m.group(0) for rx in (_EMAIL, _URL, _IBAN, _PHONE) for m in rx.finditer(s)]
    return list(dict.fromkeys(found))


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str = ""
    kind: str = ""          # "destination" or "action:<class>" of the first thing held
    value: str = ""         # that destination value, or class
    dests: tuple[str, ...] = ()     # every destination of this call that did not come from the user
    classes: tuple[str, ...] = ()   # every action class of this call that the user's request did not use


class GuardV2:
    """Per-conversation guard. ``observe_result`` for every tool result, ``check`` before every tool call, ``approve``
    with a held decision once the user has confirmed it."""

    def __init__(self, user_request: str, trusted: Iterable[str] = ()) -> None:
        self.request = _norm(user_request)
        self.request_words = set(_WORD.findall(self.request))
        self.trusted = {_norm(t) for t in trusted if t}
        self.approved_values: set[str] = set()
        self.approved_classes: set[str] = set()
        self.tainted = False

    def observe_result(self, _tool: str = "", _result: object = None) -> None:
        self.tainted = True

    def approve(self, decision: Decision) -> None:
        """The user confirmed this call: everything it was held for (all destinations and action classes) is approved."""
        self.approved_values.update(_norm(d) for d in decision.dests)
        self.approved_classes.update(decision.classes)

    def _dest_from_user(self, value: str) -> bool:
        v = _norm(value)
        return v in self.trusted or v in self.approved_values or (len(v) >= 3 and v in self.request)

    def _class_from_user(self, cls: str) -> bool:
        if cls in self.approved_classes:
            return True
        vocab = CLASSES[cls][1]
        return any(_stem_in(w, vocab) for w in self.request_words)

    def check(self, tool: str, args: dict[str, object] | None = None) -> Decision:
        if not self.tainted:
            return Decision(True)
        args = args or {}
        dests = tuple(d for d in destinations(args) if not self._dest_from_user(d))
        classes = tuple(c for c in sorted(classify(tool)) if not self._class_from_user(c))
        if dests:
            return Decision(False, f"{tool}: destination {dests[0]!r} did not come from the user's request", "destination", dests[0],
                            dests, classes)
        if classes:
            words = ", ".join(sorted(CLASSES[classes[0]][1])[:6])
            return Decision(False, f"{tool} is a '{classes[0]}' action and the request used none of: {words}, ...",
                            f"action:{classes[0]}", classes[0], dests, classes)
        return Decision(True)
