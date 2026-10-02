import textwrap

from aisec import reach
from aisec.extract import extract_tools


def _tool(tmp_path, body, params="path: str"):
    src = textwrap.dedent(f'''
        import os, subprocess, requests, json
        from pathlib import Path

        @mcp.tool()
        def tool({params}) -> str:
            """Do something."""
{textwrap.indent(textwrap.dedent(body), " " * 12)}
    ''')
    (tmp_path / "server.py").write_text(src)
    return extract_tools(tmp_path)[0]


def test_unguarded_file_read_is_a_sink(tmp_path):
    r = reach.assess(_tool(tmp_path, "return open(path).read()"))
    assert r.verdict == "sink_unguarded" and r.kinds == ["fs"]


def test_taint_flows_through_assignments_and_join(tmp_path):
    r = reach.assess(_tool(tmp_path, "full = os.path.join('/data', path)\nreturn Path(full).read_text()"))
    assert r.verdict == "sink_unguarded"


def test_containment_check_counts_as_guard(tmp_path):
    body = """
        base = os.path.realpath('/data')
        full = os.path.realpath(os.path.join(base, path))
        if not full.startswith(base + os.sep):
            raise ValueError('escape')
        return open(full).read()
    """
    assert reach.assess(_tool(tmp_path, body)).verdict == "sink_guarded"


def test_allowlist_membership_is_a_guard(tmp_path):
    body = "if path not in ALLOWED:\n    raise ValueError()\nreturn open(path).read()"
    assert reach.assess(_tool(tmp_path, body)).verdict == "sink_guarded"


def test_no_sink_when_param_is_just_data(tmp_path):
    """Scene-tree / menu 'path' that never touches the filesystem: the classic scope false positive."""
    r = reach.assess(_tool(tmp_path, "node = scene.get_node(path)\nreturn json.dumps({'node': str(node)})"))
    assert r.verdict in ("no_sink", "unknown")  # get_node is unresolved -> must NOT claim no_sink wrongly
    r2 = reach.assess(_tool(tmp_path, "return json.dumps({'echo': path.upper()})"))
    assert r2.verdict == "no_sink"


def test_unresolved_callee_keeps_verdict_unknown(tmp_path):
    assert reach.assess(_tool(tmp_path, "return helper_from_elsewhere(path)")).verdict == "unknown"


def test_same_module_helper_is_followed(tmp_path):
    src = textwrap.dedent('''
        import subprocess
        def run_it(cmd):
            return subprocess.run(cmd, shell=True)

        @mcp.tool()
        def exec_tool(command: str) -> str:
            """Run."""
            return run_it(command)
    ''')
    (tmp_path / "s.py").write_text(src)
    r = reach.assess(extract_tools(tmp_path)[0])
    assert r.verdict == "sink_unguarded" and r.kinds == ["exec"]


def test_constant_path_is_not_a_sink_for_tainted_content(tmp_path):
    r = reach.assess(_tool(tmp_path, "Path('/tmp/x').write_text(path)\nreturn 'ok'"))
    assert r.verdict == "no_sink"  # tainted value is the *content*, the path is fixed


def test_url_sink(tmp_path):
    assert reach.assess(_tool(tmp_path, "return requests.get(path).text", "path: str")).kinds == ["net"]


def test_sql_string_building(tmp_path):
    r = reach.assess(_tool(tmp_path, "return cur.execute(f\"select * from t where a='{path}'\")"))
    assert r.kinds == ["sql"]


def test_js_positive_evidence_only(tmp_path):
    (tmp_path / "s.ts").write_text('server.tool("read", "Read a file", { path: z.string() }, async ({ path }) => { return fs.readFileSync(path, "utf8"); });')
    t = extract_tools(tmp_path)[0]
    assert reach.assess(t).verdict == "sink_unguarded"
    (tmp_path / "s.ts").write_text('server.tool("echo", "Echo", { text: z.string() }, async ({ text }) => handlers.echo(text));')
    assert reach.assess(extract_tools(tmp_path)[0]).verdict == "unknown"  # handler elsewhere: never claim "no sink"


def test_severity_adjustment():
    R = reach.Reach
    assert reach.adjust_severity("high", R("no_sink")) == "low"
    assert reach.adjust_severity("high", R("sink_guarded")) == "medium"
    assert reach.adjust_severity("high", R("sink_unguarded"), strict=True) == "high"
    assert reach.adjust_severity("high", R("unknown")) == "high"                    # annotate mode never loses recall
    assert reach.adjust_severity("high", R("unknown"), strict=True) == "medium"      # strict: unproven != HIGH
    assert reach.adjust_severity("low", R("unknown"), strict=True) == "low"


def test_hostile_source_does_not_crash(tmp_path):
    t = _tool(tmp_path, "return 1")
    t["module_src"] = "(" * 5000  # deep nesting / syntax error
    assert reach.assess(t).verdict == "unknown"


def test_dispatcher_helper_with_varargs_is_not_a_false_refutation(tmp_path):
    """tool -> _safe_call(fn, *args) -> fn(*args): taint must follow *args or we wrongly claim 'no sink'."""
    src = textwrap.dedent('''
        def _safe_call(fn, *args, **kwargs):
            return fn(*args, **kwargs)

        @mcp.tool()
        def write_bytes(path: str, data: str) -> dict:
            """Write."""
            return _safe_call(toolbox.write_bytes, path, data)
    ''')
    (tmp_path / "s.py").write_text(src)
    assert reach.assess(extract_tools(tmp_path)[0]).verdict == "unknown"
