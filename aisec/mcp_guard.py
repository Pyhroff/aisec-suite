"""Run the runtime guard in front of any MCP server: a stdio proxy that holds unsafe tool calls.

    aisec guard-mcp --request "Summarise my unread email" -- python my_server.py

The proxy starts the server, relays MCP's newline-delimited JSON-RPC in both directions, and applies
``aisec.runtime_guard`` to every ``tools/call``:

* every tool result the server returns marks the session as having read untrusted content;
* after that, a call whose destination argument (recipient, email, URL, IBAN, ...) did not appear in the user's request
  or the trusted list, or a destructive tool (delete, remove, revoke, ...) the request did not ask for, is not forwarded.
  The client gets a normal tool result with ``isError: true`` explaining why, so the agent can ask the user.

``--guard v3`` swaps the engine for ``aisec.guard_v3`` (effect classes read from tool names, destinations recognised by
shape in any argument; docs/STUDY.md sections 3g-3h). It needs no policy: only ``trusted`` from a policy file is used,
and a file with ``sinks`` or ``actions`` is refused rather than silently ignored. v1 stays the default.

With v1, which tools are sinks and which arguments are destinations is inferred from the server's own ``tools/list`` by name
(``infer_policy``); a JSON policy file can add or override entries. The user's request comes from ``--request`` or from
``--request-file``, which is re-read on every call so a host can update it each turn. Every decision can be logged as
JSON lines (``--log``). Nothing is sent anywhere else.
"""
from __future__ import annotations

import json
import re
import subprocess  # nosec B404 - starts the server command the user gave
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from aisec.guard_v3 import GuardV3
from aisec.runtime_guard import GuardPolicy, RuntimeGuard

ENGINES = ("v1", "v3")

DEST_PARAM = re.compile(
    r"^(?:to|cc|bcc|recipients?|recipient_\w+|emails?|email_address|user_email|address|url|uri|link|endpoint|"
    r"webhook(?:_url)?|callback(?:_url)?|iban|account(?:_number)?|phone(?:_number)?|destination|target_url|host)$",
    re.I,
)
ACTION_TOOL = {
    re.compile(r"(?:^|_)(?:delete|remove|drop|destroy|purge|wipe|truncate|erase)(?:_|$)", re.I): ("delete", "remove", "clear", "erase"),
    re.compile(r"(?:^|_)(?:revoke|ban|kick|deactivate|disable)(?:_|$)", re.I): ("revoke", "remove", "ban", "kick", "disable"),
    re.compile(r"password|credential|api_?key|secret", re.I): ("password", "credential", "key", "secret"),
}


def infer_policy(tools: list[dict[str, Any]]) -> GuardPolicy:
    """Sinks and destructive tools from an MCP ``tools/list`` result, by tool and parameter name."""
    sinks: dict[str, tuple[str, ...]] = {}
    actions: dict[str, tuple[str, ...]] = {}
    for t in tools:
        name = str(t.get("name", ""))
        props = (t.get("inputSchema") or t.get("input_schema") or {}).get("properties") or {}
        dests = tuple(p for p in props if DEST_PARAM.match(p))
        if dests:
            sinks[name] = dests
        for rx, words in ACTION_TOOL.items():
            if rx.search(name):
                actions[name] = words
                break
    return GuardPolicy(sinks=sinks, actions=actions)


def merge(base: GuardPolicy, extra: dict[str, Any]) -> GuardPolicy:
    sinks = {**base.sinks, **{k: tuple(v) for k, v in extra.get("sinks", {}).items()}}
    actions = {**base.actions, **{k: tuple(v) for k, v in extra.get("actions", {}).items()}}
    trusted = base.trusted | frozenset(str(x).lower() for x in extra.get("trusted", []))
    return GuardPolicy(sinks=sinks, actions=actions, trusted=trusted)


@dataclass
class GuardSession:
    """Protocol-level state for one proxied connection. Pure logic: the stream plumbing is in ``run``."""
    request: Callable[[], str]
    trusted: list[str] = field(default_factory=list)
    overrides: dict[str, Any] = field(default_factory=dict)
    log: Callable[[dict[str, Any]], None] = lambda _e: None
    policy: GuardPolicy = field(default_factory=GuardPolicy)
    engine: str = "v1"
    tainted: bool = False
    _pending: dict[Any, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.engine not in ENGINES:
            raise ValueError(f"unknown guard engine {self.engine!r}; use one of {ENGINES}")
        if self.engine == "v3" and (self.overrides.get("sinks") or self.overrides.get("actions")):
            raise ValueError("a policy file with 'sinks' or 'actions' only applies to --guard v1; v3 reads only 'trusted'")
        self.policy = merge(self.policy, self.overrides)

    def _guard(self) -> RuntimeGuard | GuardV3:
        if self.engine == "v3":
            return GuardV3(self.request(), [*self.trusted, *self.overrides.get("trusted", [])])
        return RuntimeGuard(self.policy, self.request(), self.trusted)

    def from_client(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """Return a reply to send straight back to the client instead of forwarding, or None to forward."""
        method = msg.get("method")
        with self._lock:
            if method == "tools/list" and "id" in msg:
                self._pending[msg["id"]] = "tools/list"
                return None
            if method != "tools/call" or "id" not in msg:
                return None
            params = msg.get("params") or {}
            name = str(params.get("name", ""))
            args = params.get("arguments") or {}
            guard = self._guard()
            guard.tainted = self.tainted
            decision = guard.check(name, args if isinstance(args, dict) else {})
            self.log({"event": "call", "tool": name, "allowed": decision.allow, "reason": decision.reason})
            if decision.allow:
                self._pending[msg["id"]] = "tools/call"
                return None
        text = (f"Held by aisec guard: {decision.reason}. This call was not sent to the server. "
                "Ask the user to confirm the destination or action before retrying.")
        return {"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": text}], "isError": True}}

    def from_server(self, msg: dict[str, Any]) -> None:
        if "id" not in msg or "method" in msg:
            return
        with self._lock:
            kind = self._pending.pop(msg["id"], None)
            if kind == "tools/call":
                self.tainted = True   # whatever the tool returned is untrusted from now on
            elif kind == "tools/list" and self.engine == "v3":
                self.log({"event": "policy", "engine": "v3"})
            elif kind == "tools/list":
                tools = (msg.get("result") or {}).get("tools") or []
                self.policy = merge(infer_policy(tools), self.overrides)
                self.log({"event": "policy", "sinks": sorted(self.policy.sinks), "actions": sorted(self.policy.actions)})


def _pump(src: IO[bytes], dst: IO[bytes], on_message: Callable[[dict[str, Any]], dict[str, Any] | None],
          reply: Callable[[dict[str, Any]], None]) -> None:
    for line in iter(src.readline, b""):
        try:
            msg = json.loads(line)
        except ValueError:
            msg = None
        answer = on_message(msg) if isinstance(msg, dict) else None
        if answer is not None:
            reply(answer)
            continue
        dst.write(line)
        dst.flush()
    try:
        dst.close()
    except OSError:
        pass


def run(command: list[str], session: GuardSession) -> int:
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)  # noqa: S603  # nosec B603
    if proc.stdin is None or proc.stdout is None:
        raise RuntimeError("could not open pipes to the MCP server")
    client_in, client_out = sys.stdin.buffer, sys.stdout.buffer
    out_lock = threading.Lock()

    def to_client(obj: dict[str, Any]) -> None:
        with out_lock:
            client_out.write((json.dumps(obj) + "\n").encode())
            client_out.flush()

    class _Locked:
        def write(self, b: bytes) -> None:
            with out_lock:
                client_out.write(b)

        def flush(self) -> None:
            with out_lock:
                client_out.flush()

        def close(self) -> None:
            pass

    def server_side(msg: dict[str, Any]) -> None:
        session.from_server(msg)
        return None

    t = threading.Thread(target=_pump, args=(proc.stdout, _Locked(), server_side, to_client), daemon=True)
    t.start()
    _pump(client_in, proc.stdin, session.from_client, to_client)
    code = proc.wait()
    t.join(timeout=5)
    return code


def build_session(request: str | None, request_file: str | None, trusted: list[str], policy_file: str | None,
                  log_file: str | None, engine: str = "v1") -> GuardSession:
    if request_file:
        path = Path(request_file)

        def get_request() -> str:
            try:
                return path.read_text(encoding="utf-8")
            except OSError:
                return ""
    else:
        fixed = request or ""

        def get_request() -> str:
            return fixed
    overrides = json.loads(Path(policy_file).read_text(encoding="utf-8")) if policy_file else {}
    if log_file:
        log_path = Path(log_file)

        def log(event: dict[str, Any]) -> None:
            with log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
    else:
        def log(event: dict[str, Any]) -> None:
            if event.get("event") == "call" and not event.get("allowed"):
                print(f"aisec guard: held {event['tool']}: {event['reason']}", file=sys.stderr)
    return GuardSession(request=get_request, trusted=trusted, overrides=overrides, log=log, engine=engine)
