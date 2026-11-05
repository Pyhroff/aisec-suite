"""Cross-language reachability through an IPC bridge (aisec/reach_bridge.py), on a synthetic Godot-style project."""
import textwrap

import pytest

from aisec import reach, reach_bridge
from aisec.extract import extract_tools

SERVER_TS = """
import { z } from "zod";
function sendCommand(name, payload) {
  socket.write(JSON.stringify({ command: name, params: payload }));
}
server.tool("game_get_property", "Read a property of a node in the running game", { path: z.string(), property: z.string() },
  async ({ path, property }) => sendCommand("get_property", { path, property }));
server.tool("game_run", "Run a shell command in the game host", { path: z.string() },
  async ({ path }) => sendCommand("run_shell", { path }));
server.tool("game_load", "Load a level file", { path: z.string() },
  async ({ path }) => sendCommand("load_level", { path }));
server.tool("game_call", "Call a method on a node", { path: z.string() },
  async ({ path }) => sendCommand("call_method", { path }));
server.tool("game_helper", "Uses an unresolved helper", { path: z.string() },
  async ({ path }) => sendCommand("uses_helper", { path }));
server.tool("game_missing", "Command with no engine-side handler", { path: z.string() },
  async ({ path }) => sendCommand("not_a_command", { path }));
server.tool("game_dup", "Command handled by two dispatchers", { path: z.string() },
  async ({ path }) => sendCommand("duplicated", { path }));
server.tool("game_mixed", "JS-side file write next to the bridge call", { path: z.string() },
  async ({ path }) => { fs.writeFileSync(path, "x"); return sendCommand("get_property", { path }); });
"""

ENGINE_GD = """
extends Node

func _handle(command: String, params: Dictionary) -> void:
\tmatch command:
\t\t"get_property":
\t\t\t_cmd_get_property(params)
\t\t"run_shell":
\t\t\tOS.execute("sh", ["-c", params["path"]])
\t\t\t_send_response({"ok": true})
\t\t"load_level":
\t\t\tvar scene = load(params["path"])
\t\t\t_send_response({"ok": scene != null})
\t\t"call_method":
\t\t\tvar n = get_node(params["path"])
\t\t\tn.callv(params["method"], [])
\t\t"uses_helper":
\t\t\tsome_global_helper(params)
\t\t"duplicated":
\t\t\t_send_response({})

func _cmd_get_property(params: Dictionary) -> void:
\tvar node = get_node(params["path"])
\t_send_response({"value": str(node.get(params["property"]))})

func _send_response(data: Dictionary) -> void:
\tvar s = JSON.stringify(data)
\t_client.put_data(s.to_utf8_buffer())

func _a(): _send_response({})
func _b(): _send_response({})
"""

OTHER_GD = """
func _dispatch(op: String, params: Dictionary) -> void:
\tmatch op:
\t\t"duplicated":
\t\t\tFileAccess.open(params["path"], FileAccess.WRITE)
\t\t"a1":
\t\t\tpass
\t\t"a2":
\t\t\tpass
\t\t"a3":
\t\t\tpass
\t\t"a4":
\t\t\tpass
"""


@pytest.fixture
def tools(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "server.ts").write_text(textwrap.dedent(SERVER_TS))
    (tmp_path / "game").mkdir()
    (tmp_path / "game" / "engine.gd").write_text(ENGINE_GD)
    (tmp_path / "game" / "other.gd").write_text(OTHER_GD)
    return {t["name"]: t for t in extract_tools(tmp_path)}


def test_command_without_sink_on_the_engine_side_is_refuted(tools):
    r = reach.assess(tools["game_get_property"])
    assert r.verdict == "no_sink"
    assert "bridge 'get_property'" in r.evidence[0]


def test_engine_side_command_execution_is_found(tools):
    r = reach.assess(tools["game_run"])
    assert (r.verdict, r.kinds) == ("sink_unguarded", ["exec"])
    assert "engine.gd: OS.execute()" in r.evidence[0]


def test_loading_a_parameter_path_is_a_file_sink(tools):
    assert reach.assess(tools["game_load"]).kinds == ["fs"]


@pytest.mark.parametrize(
    ("tool", "why"),
    [
        ("game_call", "callv picks the method at runtime"),
        ("game_helper", "helper not defined in the engine script"),
        ("game_missing", "no dispatcher arm for the literal"),
    ],
)
def test_no_claim_when_the_engine_side_is_not_fully_resolved(tools, tool, why):
    assert reach.assess(tools[tool]).verdict == "unknown", why


def test_ambiguous_literal_across_dispatchers_makes_no_claim(tools):
    # "duplicated" is a no-op in one dispatcher and a file write in another: we cannot tell which one runs.
    assert reach.assess(tools["game_dup"]).verdict == "unknown"


def test_js_side_sink_still_wins_over_the_bridge(tools):
    assert reach.assess(tools["game_mixed"]).verdict == "sink_unguarded"


def test_reply_channel_is_transport_not_capability(tmp_path):
    (tmp_path / "e.gd").write_text(ENGINE_GD)
    gf = reach_bridge.index(tmp_path).files[0]
    assert "_send_response" in gf.transport


def test_small_local_switches_are_not_dispatchers(tmp_path):
    (tmp_path / "e.gd").write_text('func f(x):\n\tmatch x:\n\t\t"a":\n\t\t\tpass\n\t\t"b":\n\t\t\tpass\n')
    assert reach_bridge.index(tmp_path).files == []


def test_empty_arm_is_not_a_refutation(tmp_path):
    arms = "".join(f'\t\t"c{i}":\n\t\t\tpass\n' for i in range(5))
    (tmp_path / "e.gd").write_text('func f(cmd):\n\tmatch cmd:\n\t\t"empty":\n' + arms)
    r = reach_bridge.resolve("empty", tmp_path)
    assert not r.complete and not r.kinds


def test_comments_and_strings_do_not_create_arms_or_sinks(tmp_path):
    arms = "".join(f'\t\t"c{i}":\n\t\t\tprint("OS.execute is mentioned only in a string")  # OS.execute\n' for i in range(5))
    (tmp_path / "e.gd").write_text("func f(cmd):\n\tmatch cmd:\n" + arms)
    r = reach_bridge.resolve("c0", tmp_path)
    assert r.complete and not r.kinds


def test_without_a_repository_root_there_is_no_bridge_claim(tools):
    t = {k: v for k, v in tools["game_get_property"].items() if k != "root"}
    assert reach.assess(t).verdict == "unknown"
