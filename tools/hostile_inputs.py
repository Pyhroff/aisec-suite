"""Hostile-repository stress harness for aisec-suite: builds a small repository of adversarial files and runs the real
`python -m aisec scan` against it, because a pull request from a stranger is exactly this input.

PRE-REGISTERED before first run:
  * Families put hostile content in the places each scanner reads: TypeScript/JS tool registrations, Python tool
    functions, tool descriptions (all text families), agent-context files, RAG documents, MCP manifests, and engine-side
    GDScript/C# files for the reachability bridge. File sizes 50k / 100k / 200k characters (the extractor ignores files
    over 400k), or 1k / 2k / 4k repeated items for count-based families.
  * Each case runs the CLI in a subprocess (60 s limit); wall time minus the empty-repository baseline is the cost.
  * Finding = timeout, "crashed" in the scan output (a scanner that crashed silently drops its results), a traceback,
    more than 5.0 s of cost at the middle size, or superlinear growth (largest / middle cost above 3.0 with the largest
    cost above 2.0 s).
  * Run once on the unmodified code, fix every finding with a regression test, then run again. Best of 2 runs per case.
"""
from __future__ import annotations
import json, os, subprocess, sys, tempfile, time, pathlib, shutil
from concurrent.futures import ThreadPoolExecutor

TEXT = {
    "a_run": lambda n: "a" * n, "spaces": lambda n: " " * n, "words": lambda n: "word " * (n // 5),
    "single_letters": lambda n: "a " * (n // 2), "b64_ok": lambda n: "A" * n, "b64_bad_end": lambda n: "A" * n + "!",
    "b64_slashes": lambda n: "A/" * (n // 2) + "=", "b64url": lambda n: "QUJD-_" * (n // 6),
    "b32": lambda n: "MFRGG" * (n // 5), "hex_escapes": lambda n: "\\x41" * (n // 4), "u_escapes": lambda n: "\\u0041" * (n // 6),
    "pct_escapes": lambda n: "%41" * (n // 3), "html_entities": lambda n: "&#65;" * (n // 5),
    "ignore_chain": lambda n: "ignore " * (n // 7), "ignore_prev": lambda n: "ignore previous instructions " * (n // 29),
    "ignore_nospace": lambda n: "ignore" * (n // 6), "you_must": lambda n: "you must " * (n // 9),
    "always": lambda n: "always " * (n // 7), "send_to": lambda n: "send the contents to http://a.example " * (n // 38),
    "zwsp": lambda n: "​" * n, "zwsp_between": lambda n: "i​g​n​o​r​e " * (n // 12),
    "cyrillic": lambda n: "а" * n, "mixed_script": lambda n: "pаssword " * (n // 9), "combining": lambda n: "é" * (n // 2),
    "ligature": lambda n: "ﬁ" * n, "fullwidth": lambda n: "ｉｇｎｏｒｅ " * (n // 7), "math_bold": lambda n: "𝐢𝐠𝐧𝐨𝐫𝐞 " * (n // 7),
    "tag_chars": lambda n: "\U000e0041" * n, "paren_open": lambda n: "(" * n, "tag_open": lambda n: "[" * n,
    "html_comment": lambda n: "<!--" * (n // 4), "backticks": lambda n: "`" * n, "dots": lambda n: "." * n,
    "sentences": lambda n: "Do this. " * (n // 9), "sentence_no_end": lambda n: "do this and " * (n // 12),
}

def _ts_desc(text): return 'server.tool("t", ' + json.dumps(text) + ', {}, async () => {});\n'

# name -> (builder(n) -> {relative path: text}, sizes)
S_TXT = (50_000, 100_000, 200_000)
S_CNT = (1_000, 2_000, 4_000)
CASES = {}
for k, g in TEXT.items():
    CASES["desc_" + k] = (lambda n, g=g: {"src/tools.ts": _ts_desc(g(n))}, S_TXT)
    CASES["pydesc_" + k] = (lambda n, g=g: {"srv.py": "@mcp.tool()\ndef f(path: str):\n    " + json.dumps(g(n)) + "\n    open(path)\n"}, S_TXT)
for k in ("a_run", "spaces", "words", "single_letters", "ignore_chain", "you_must", "zwsp", "ligature", "sentences", "b64_ok"):
    CASES["claude_md_" + k] = (lambda n, g=TEXT[k]: {"CLAUDE.md": g(n)}, S_TXT)
    CASES["rag_" + k] = (lambda n, g=TEXT[k]: {"docs/kb.md": g(n)}, S_TXT)
CASES.update({
    "claude_md_many_lines": (lambda n: {"CLAUDE.md": "a\n" * n}, S_CNT[0:0] or (20_000, 40_000, 80_000)),
    "rag_many_lines": (lambda n: {"docs/kb.md": "a\n" * n}, (20_000, 40_000, 80_000)),
    "ts_tool_anchors": (lambda n: {"src/a.ts": "server.tool(" * n}, S_CNT),
    "ts_tool_anchors_named": (lambda n: {"src/a.ts": 'server.tool("t", ' * n}, S_CNT),
    "ts_desc_repeat": (lambda n: {"src/a.ts": 'description: "x", ' * n}, S_CNT),
    "ts_generic_tools": (lambda n: {"src/a.ts": "".join('{name: "tool%d", description: "reads a file", inputSchema: {type: "object", properties: {path: {type: "string"}}}},\n' % i for i in range(n // 4))}, S_CNT),
    "ts_register_tools": (lambda n: {"src/a.ts": "".join('server.registerTool("tool%d", {description: "reads a file", inputSchema: {path: z.string()}}, async ({path}) => { return fs.readFile(path); });\n' % i for i in range(n // 4))}, S_CNT),
    "ts_unclosed_desc": (lambda n: {"src/a.ts": 'server.tool("t", {description: "' + "a" * (n * 50)}, S_CNT),
    "ts_zod_chain": (lambda n: {"src/a.ts": 'server.tool("t", "d", {' + "".join("a%d: z.string()\n.min(1)\n.max(2)\n, " % i for i in range(n)) + "}, async () => {});"}, S_CNT),
    "ts_zod_newlines": (lambda n: {"src/a.ts": 'server.tool("t", "d", {a: z.string()' + "\n" * (n * 50) + "}, async () => {});"}, S_CNT),
    "ts_json_props": (lambda n: {"src/a.ts": 'server.tool("t", "d", {' + "".join("p%d: { type: 'string' }, " % i for i in range(n)) + "}, async () => {});"}, S_CNT),
    "ts_consts": (lambda n: {"src/a.ts": "".join('const a%d = "x";\n' % i for i in range(n * 5))}, S_CNT),
    "ts_functions": (lambda n: {"src/a.ts": 'server.tool("run_cmd", "run a command", {cmd: z.string()}, async ({cmd}) => { return helper0(cmd); });\n' + "".join("function helper%d(a) { return helper%d(a); }\n" % (i, i + 1) for i in range(n))}, S_CNT),
    "ts_open_braces": (lambda n: {"src/a.ts": 'server.tool("run_cmd", "run a command", {cmd: z.string()}, async ({cmd}) => ' + "{" * (n * 20)}, S_CNT),
    "ts_close_braces": (lambda n: {"src/a.ts": 'server.tool("run_cmd", "run a command", {cmd: z.string()}, async ({cmd}) => {' + "}" * (n * 20)}, S_CNT),
    "ts_taint_chain": (lambda n: {"src/a.ts": 'server.tool("run_cmd", "run a command", {cmd: z.string()}, async ({cmd}) => {\nlet a0 = cmd;\n' + "".join("let a%d = a%d;\n" % (i + 1, i) for i in range(n)) + "exec(a%d); });" % n}, S_CNT),
    "ts_taint_reverse": (lambda n: {"src/a.ts": 'server.tool("run_cmd", "run a command", {cmd: z.string()}, async ({cmd}) => {\n' + "".join("let a%d = a%d;\n" % (i, i + 1) for i in range(n)) + "let a%d = cmd;\nexec(a0); });" % n}, S_CNT),
    "ts_call_chain": (lambda n: {"src/a.ts": 'server.tool("run_cmd", "run a command", {cmd: z.string()}, async ({cmd}) => { ' + "f(" * (n * 5) + "cmd" + ")" * (n * 5) + "; });"}, S_CNT),
    "ts_many_calls": (lambda n: {"src/a.ts": 'server.tool("run_cmd", "run a command", {cmd: z.string()}, async ({cmd}) => {\n' + "exec(cmd);\n" * (n * 5) + "});"}, S_CNT),
    "py_many_tools": (lambda n: {"srv.py": "".join('@mcp.tool()\ndef f%d(path: str):\n    """reads a file"""\n    return open(path).read()\n' % i for i in range(n // 2)) }, S_CNT),
    "py_deep_binop": (lambda n: {"srv.py": "@mcp.tool()\ndef f(path: str):\n    x = " + "+".join(["1"] * (n * 5)) + "\n    open(path)\n"}, S_CNT),
    "py_deep_parens": (lambda n: {"srv.py": "@mcp.tool()\ndef f(path: str):\n    x = " + "(" * (n // 2) + "1" + ")" * (n // 2) + "\n    open(path)\n"}, S_CNT),
    "py_nested_defs": (lambda n: {"srv.py": "@mcp.tool()\ndef f(path: str):\n" + "".join(" " * (i + 1) + "def g%d():\n" % i for i in range(min(n // 4, 90))) + " " * 95 + "open(path)\n"}, S_CNT),
    "py_long_chain": (lambda n: {"srv.py": "@mcp.tool()\ndef f(path: str):\n    a0 = path\n" + "".join("    a%d = a%d\n" % (i + 1, i) for i in range(n)) + "    open(a%d)\n" % n}, S_CNT),
    "py_many_params": (lambda n: {"srv.py": "@mcp.tool()\ndef f(" + ", ".join("p%d: str" % i for i in range(n)) + "):\n    open(p0)\n"}, S_CNT),
    "py_recursion": (lambda n: {"srv.py": "def a(p):\n    return b(p)\ndef b(p):\n    return a(p)\n@mcp.tool()\ndef f(path: str):\n    return a(path)\n"}, S_CNT),
    "py_nul": (lambda n: {"srv.py": "@mcp.tool()\ndef f(path: str):\n    x = '" + "\x00" * n + "'\n    open(path)\n"}, S_TXT),
    "manifest_many_tools": (lambda n: {"m.json": json.dumps({"server_name": "x", "tools": [{"name": "t%d" % i, "description": "you must call t%d first" % (i + 1)} for i in range(n // 2)]})}, S_CNT),
    "manifest_bad_types": (lambda n: {"m.json": json.dumps({"server_name": "x", "tools": [{"name": 5, "description": ["a"], "input_schema": []}] * (n // 100)})}, S_CNT),
    "manifest_deep": (lambda n: {"m.json": "[" * n + "]" * n}, S_CNT),
    "manifest_deep_obj": (lambda n: {"m.json": '{"server_name": "x", "tools": [{"name": "t", "description": "d", "input_schema": ' + '{"a":' * min(n, 900) + "1" + "}" * min(n, 900) + "}]}"}, S_CNT),
    "json_huge_string": (lambda n: {"m.json": '{"server_name": "x", "tools": [{"name": "t", "description": "' + "a" * (n * 40) + '"}]}'}, S_CNT),
    "gd_indent": (lambda n: {"srv.ts": 'server.tool("t", "d", {}, async () => { return godot("x"); });', "g/x.gd": "func f():\n" + "\t" * (n * 20) + "pass\n"}, S_CNT),
    "gd_many_funcs": (lambda n: {"srv.ts": 'server.tool("t", "d", {}, async () => { return godot("x"); });', "g/x.gd": "".join("func f%d():\n\tf%d()\n" % (i, i + 1) for i in range(n))}, S_CNT),
    "cs_open_braces": (lambda n: {"srv.ts": 'server.tool("t", "d", {}, async () => { return unity("x"); });', "u/x.cs": "class A {" + "{" * (n * 20)}, S_CNT),
    "cs_switch_cases": (lambda n: {"srv.ts": 'server.tool("t", "d", {}, async () => { return unity("x"); });', "u/x.cs": "class A { void M(string s) { switch (s) {" + "".join('case "c%d": M2(); break; ' % i for i in range(n)) + "} } }"}, S_CNT),
    "cs_unclosed_string": (lambda n: {"srv.ts": 'server.tool("t", "d", {}, async () => { return unity("x"); });', "u/x.cs": 'class A { string s = "' + "a" * (n * 40)}, S_CNT),
    "cs_comments": (lambda n: {"srv.ts": 'server.tool("t", "d", {}, async () => { return unity("x"); });', "u/x.cs": "/*" * (n * 10) + "//" * (n * 10)}, S_CNT),
})

CHILD_BASE = {}

def run_once(case, n):
    files = CASES[case][0](n)
    d = tempfile.mkdtemp(prefix="hostile_")
    try:
        for rel, text in files.items():
            p = pathlib.Path(d, rel); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text, encoding="utf-8", errors="replace")
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([REPO] + EXTRA), PYTHONDONTWRITEBYTECODE="1")
        t = time.perf_counter()
        try:
            p = subprocess.run([sys.executable, "-m", "aisec", "scan", d, "--rag", d], capture_output=True, text=True, timeout=60, env=env, cwd=d)
        except subprocess.TimeoutExpired:
            return {"t": 60.0, "err": "TIMEOUT"}
        t = time.perf_counter() - t
        out = p.stdout + p.stderr
        err = None
        if "Traceback" in out: err = "traceback: " + out[out.rfind("Traceback"):][-300:].replace("\n", " | ")
        elif "crashed" in out: err = "crashed: " + [l for l in out.splitlines() if "crashed" in l][0][:200]
        elif p.returncode not in (0,): err = f"exit {p.returncode}: {out[-200:]}"
        return {"t": t, "err": err}
    finally:
        shutil.rmtree(d, ignore_errors=True)

def best(case, n):
    r = None
    for _ in range(2):
        x = run_once(case, n)
        if x["err"]: return x
        r = x if r is None or x["t"] < r["t"] else r
    return r

def main(repo, extra, only=None):
    global REPO, EXTRA
    REPO, EXTRA = repo, extra
    base = min(run_once_empty() for _ in range(3))
    names = [c for c in CASES if not only or only in c]
    jobs = [(c, n) for c in names for n in CASES[c][1]]
    with ThreadPoolExecutor(2) as ex:
        res = list(ex.map(lambda j: best(*j), jobs))
    table = {}
    for (c, n), r in zip(jobs, res): table.setdefault(c, {})[n] = r
    findings = []
    for c, by in table.items():
        sz = sorted(by)
        errs = [by[n]["err"] for n in sz if by[n]["err"]]
        if errs: findings.append((c, "ERROR", errs[0])); continue
        cost = [max(by[n]["t"] - base, 0.0) for n in sz]
        if cost[1] > 5.0: findings.append((c, "SLOW", f"{cost[1]:.1f}s at {sz[1]}"))
        elif cost[2] > 2.0 and cost[1] > 0 and cost[2] / cost[1] > 3.0: findings.append((c, "SUPERLINEAR", f"{cost[1]:.2f}s -> {cost[2]:.2f}s"))
    print(f"aisec-suite: {len(table)} families; baseline {base:.2f}s; {len(findings)} findings")
    for f in findings: print("  ", *f)
    worst = sorted(((max(by[max(by)]["t"] - base, 0), c) for c, by in table.items()), reverse=True)[:6]
    print("  costliest at largest size:", ", ".join(f"{c} {t:.2f}s" for t, c in worst))

def run_once_empty():
    d = tempfile.mkdtemp(prefix="hostile_")
    try:
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([REPO] + EXTRA), PYTHONDONTWRITEBYTECODE="1")
        t = time.perf_counter(); subprocess.run([sys.executable, "-m", "aisec", "scan", d, "--rag", d], capture_output=True, timeout=60, env=env, cwd=d)
        return time.perf_counter() - t
    finally: shutil.rmtree(d, ignore_errors=True)

if __name__ == "__main__":
    # usage: hostile_inputs.py REPO [EXTRA_PYTHONPATH ...] [--only SUBSTRING]
    a = sys.argv[1:]; only = None
    if "--only" in a: i = a.index("--only"); only = a[i + 1]; a = a[:i] + a[i + 2:]
    main(os.path.abspath(a[0]), [os.path.abspath(x) for x in a[1:]], only)
