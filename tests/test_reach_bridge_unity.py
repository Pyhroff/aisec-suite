"""Cross-language reachability into Unity editor plugins written in C# (aisec/reach_bridge.py)."""
import textwrap

import pytest

from aisec import reach, reach_bridge
from aisec.extract import extract_tools

SERVER_TS = """
import { z } from "zod";
server.tool("unity_read_scene", "List objects in the open scene", { path: z.string() },
  async ({ path }) => bridge.sendCommand("get_hierarchy", { path }));
server.tool("unity_write_script", "Create a C# script", { path: z.string() },
  async ({ path }) => bridge.sendCommand("manage_script", { path }));
server.tool("unity_menu", "Run an editor menu item", { path: z.string() },
  async ({ path }) => mcpUnity.sendRequest({ method: "execute_menu_item", params: { path } }));
server.tool("unity_reflect", "Invoke a component method", { path: z.string() },
  async ({ path }) => bridge.sendCommand("invoke_method", { path }));
server.tool("unity_download", "Fetch a package", { path: z.string() },
  async ({ path }) => bridge.sendCommand("download", { path }));
server.tool("unity_unknown", "No handler on the C# side", { path: z.string() },
  async ({ path }) => bridge.sendCommand("not_a_command", { path }));
"""

DISPATCHER_CS = """
using Newtonsoft.Json.Linq;
namespace McpBridge {
  public static class CommandRouter {
    // case "fake_from_comment": File.Delete(x);
    public static object Route(string commandType, JObject p) {
      switch (commandType) {
        case "get_hierarchy":
          return SceneTools.GetHierarchy(p);
        case "manage_script":
          return ScriptTools.HandleCommand(p);
        case "invoke_method":
        case "call_method":
          return ReflectionTools.Invoke(p);
        case "ping":
          return Reply("pong");
        case "log":
          Debug.Log("File.Delete is only text here");
          return Reply("ok");
        default:
          return Reply("unknown");
      }
    }
    private static object Reply(string s) { return new JObject { ["result"] = s }; }
  }
}
"""

TOOLS_CS = {
    "SceneTools.cs": """
public static class SceneTools {
  public static object GetHierarchy(JObject p) {
    var roots = SceneManager.GetActiveScene().GetRootGameObjects();
    return Describe(roots);
  }
  private static object Describe(GameObject[] roots) { return roots.Length; }
}
""",
    "ScriptTools.cs": """
public static class ScriptTools {
  public static object HandleCommand(JObject p) {
    string path = p["path"].ToString();
    File.WriteAllText(path, "class X {}");
    AssetDatabase.ImportAsset(path);
    return null;
  }
}
""",
    "ReflectionTools.cs": """
public static class ReflectionTools {
  public static object Invoke(JObject p) {
    var m = typeof(Component).GetMethod(p["method"].ToString());
    return m.Invoke(null, null);
  }
}
""",
}

TABLE_CS = """
public class McpUnityServer {
  private readonly Dictionary<string, Func<JObject, object>> _tools = new Dictionary<string, Func<JObject, object>> {
    { "execute_menu_item", MenuTools.Execute },
    { "download", p => Net.Download(p) },
    { "select", SelectTool },
    { "noop1", SelectTool },
    { "noop2", SelectTool },
  };
  private static object SelectTool(JObject p) { return Selection.activeObject; }
}
public static class MenuTools { public static object Execute(JObject p) { return EditorApplication.ExecuteMenuItem(p["menuPath"].ToString()); } }
public static class Net { public static object Download(JObject p) { return UnityWebRequest.Get(p["url"].ToString()); } }
"""


@pytest.fixture
def tools(tmp_path):
    (tmp_path / "Server~").mkdir()
    (tmp_path / "Server~" / "index.ts").write_text(textwrap.dedent(SERVER_TS))
    editor = tmp_path / "Editor"
    editor.mkdir()
    (editor / "CommandRouter.cs").write_text(DISPATCHER_CS)
    for name, src in TOOLS_CS.items():
        (editor / name).write_text(src)
    (editor / "McpUnityServer.cs").write_text(TABLE_CS)
    return {t["name"]: t for t in extract_tools(tmp_path)}


def test_handler_in_another_class_without_a_sink_is_refuted(tools):
    r = reach.assess(tools["unity_read_scene"])
    assert r.verdict == "no_sink", r
    assert "bridge 'get_hierarchy'" in r.evidence[0]


def test_file_write_in_a_handler_class_is_found(tools):
    r = reach.assess(tools["unity_write_script"])
    assert (r.verdict, r.kinds) == ("sink_unguarded", ["fs"])
    assert any("ScriptTools.cs: File.WriteAllText()" in e for e in r.evidence)


def test_object_literal_sender_and_handler_table_reach_menu_execution(tools):
    r = reach.assess(tools["unity_menu"])
    assert (r.verdict, r.kinds) == ("sink_unguarded", ["exec"])


def test_lambda_entries_in_a_handler_table_are_followed(tools):
    assert reach.assess(tools["unity_download"]).kinds == ["net"]


@pytest.mark.parametrize("tool", ["unity_reflect", "unity_unknown"])
def test_reflection_and_missing_handlers_make_no_claim(tools, tool):
    assert reach.assess(tools[tool]).verdict == "unknown"


def test_fall_through_labels_share_one_arm(tmp_path):
    (tmp_path / "R.cs").write_text(DISPATCHER_CS)
    idx = reach_bridge.index(tmp_path)
    assert idx.arms_for("invoke_method") == idx.arms_for("call_method")


def test_comments_strings_and_default_create_no_arms_or_sinks(tmp_path):
    (tmp_path / "R.cs").write_text(DISPATCHER_CS)
    idx = reach_bridge.index(tmp_path)
    assert not idx.arms_for("fake_from_comment")
    assert not idx.arms_for("unknown")
    r = reach_bridge.resolve("log", tmp_path)
    assert r.complete and not r.kinds


def test_small_switches_are_not_dispatchers(tmp_path):
    (tmp_path / "S.cs").write_text('class S { int F(string x) { switch (x) { case "a": return 1; case "b": return 2; } return 0; } }')
    assert reach_bridge.index(tmp_path).files == []


def test_unresolved_pascal_case_call_is_not_assumed_safe(tmp_path):
    # C# methods are PascalCase, so an unknown bare call may be a sink we cannot see: no refutation.
    arms = "".join(f'        case "c{i}": return Reply();\n' for i in range(4))
    src = ('class R { object Reply() { return null; }\n  object Route(string c) {\n    switch (c) {\n'
           f'        case "go": return WriteEverything(c);\n{arms}    }}\n    return null;\n  }}\n}}\n')
    (tmp_path / "R.cs").write_text(src)
    r = reach_bridge.resolve("go", tmp_path)
    assert not r.complete and not r.kinds
