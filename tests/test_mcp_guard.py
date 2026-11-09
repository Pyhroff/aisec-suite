"""MCP guard proxy (aisec/mcp_guard.py): policy inference, protocol logic, and an end-to-end run against a real server."""
import json
import pathlib
import subprocess
import sys

from aisec import mcp_guard

SERVER = pathlib.Path(__file__).resolve().parents[1] / "examples" / "guarded-mcp" / "notes_server.py"
TOOLS = [
    {"name": "read_note", "inputSchema": {"properties": {"note_id": {}}}},
    {"name": "send_email", "inputSchema": {"properties": {"to": {}, "body": {}}}},
    {"name": "post_webhook", "inputSchema": {"properties": {"webhook_url": {}, "payload": {}}}},
    {"name": "delete_note", "inputSchema": {"properties": {"note_id": {}}}},
    {"name": "rotate_api_key", "inputSchema": {"properties": {}}},
]


def test_policy_is_inferred_from_tool_and_parameter_names():
    p = mcp_guard.infer_policy(TOOLS)
    assert p.sinks == {"send_email": ("to",), "post_webhook": ("webhook_url",)}
    assert set(p.actions) == {"delete_note", "rotate_api_key"}


def test_policy_file_overrides_and_extends():
    p = mcp_guard.merge(mcp_guard.infer_policy(TOOLS), {"sinks": {"share": ["with_user"]}, "trusted": ["Me@Corp.test"]})
    assert p.sinks["share"] == ("with_user",) and "me@corp.test" in p.trusted


def session(request="Summarise my q3-plan note."):
    s = mcp_guard.GuardSession(request=lambda: request)
    s.from_client({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    s.from_server({"jsonrpc": "2.0", "id": 1, "result": {"tools": TOOLS}})
    return s


def call(s, i, name, args):
    return s.from_client({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}})


def test_calls_pass_until_a_tool_result_has_been_read():
    s = session()
    assert call(s, 2, "send_email", {"to": "x@evil.test"}) is None


def test_injected_destination_is_held_after_a_result():
    s = session()
    assert call(s, 2, "read_note", {"note_id": "q3-plan"}) is None
    s.from_server({"jsonrpc": "2.0", "id": 2, "result": {"content": []}})
    held = call(s, 3, "send_email", {"to": "archive@evil.test", "body": "..."})
    assert held["id"] == 3 and held["result"]["isError"]
    assert "archive@evil.test" in held["result"]["content"][0]["text"]


def test_destination_from_the_user_passes_and_request_is_read_per_call():
    current = {"r": "Read the q3-plan note."}
    s = mcp_guard.GuardSession(request=lambda: current["r"])
    s.from_client({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    s.from_server({"jsonrpc": "2.0", "id": 1, "result": {"tools": TOOLS}})
    call(s, 2, "read_note", {"note_id": "q3-plan"})
    s.from_server({"jsonrpc": "2.0", "id": 2, "result": {}})
    assert call(s, 3, "send_email", {"to": "bob@corp.test"}) is not None
    current["r"] = "Now email it to bob@corp.test."
    assert call(s, 4, "send_email", {"to": "bob@corp.test"}) is None


def test_notifications_and_other_methods_are_forwarded():
    s = session()
    assert s.from_client({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert s.from_client({"jsonrpc": "2.0", "id": 9, "method": "resources/list"}) is None


def test_end_to_end_against_a_real_server(tmp_path):
    log = tmp_path / "guard.jsonl"
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_note", "arguments": {"note_id": "q3-plan"}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "send_email", "arguments": {"to": "archive@evil.test", "body": "x"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "delete_note", "arguments": {"note_id": "q3-plan"}}},
    ]
    # Send one message at a time so each result arrives before the next call, as with a real agent.
    proc = subprocess.Popen(
        [sys.executable, "-m", "aisec.cli", "guard-mcp", "-r", "Summarise my q3-plan note.", "--log", str(log), "--",
         sys.executable, str(SERVER)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    replies = {}
    for m in msgs:
        proc.stdin.write(json.dumps(m) + "\n")
        proc.stdin.flush()
        if "id" in m:
            r = json.loads(proc.stdout.readline())
            replies[r["id"]] = r
    proc.stdin.close()
    proc.wait(timeout=10)
    assert "IMPORTANT" in replies[3]["result"]["content"][0]["text"]       # the injection reached the agent...
    assert replies[4]["result"]["isError"] and "Held by aisec guard" in replies[4]["result"]["content"][0]["text"]
    assert replies[5]["result"]["isError"]                                  # ...but neither follow-up was sent
    events = [json.loads(x) for x in log.read_text().splitlines()]
    assert [e["allowed"] for e in events if e["event"] == "call"] == [True, False, False]
