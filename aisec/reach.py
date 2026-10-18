"""Sink-aware reachability: does a tool's parameter actually flow into a file, command, network or SQL sink,
and is there a guard on the way?

Why: scope heuristics that match a parameter *name* ("path", "url") or a description *word* ("run", "file") flag
scene paths, IAM role prefixes and menu paths as filesystem access. Looking at the handler body gives evidence
instead of a guess. A 90-repo study found only 37.5% of such HIGH findings accurate.

Design rules (this runs on untrusted repositories):
- Source is only ever parsed (ast / regex), never imported or executed.
- Everything is bounded: module size, AST size, helper-call depth.
- Three-valued on purpose: when the analysis cannot see the whole flow (unresolved call, JS/TS handler defined
  elsewhere) the verdict is "unknown" and the original severity stands. Only a positive "no sink on any path we
  could follow" lowers severity; recall is protected by erring toward "unknown".
"""
from __future__ import annotations

import ast
import functools
import re
from dataclasses import dataclass, field

MAX_DEPTH = 2
MAX_NODES = 20_000
SEVERITIES = ["low", "medium", "high", "critical"]

_FS_FUNC = {"open", "io.open", "os.remove", "os.unlink", "os.rename", "os.replace", "os.listdir", "os.scandir", "os.walk",
            "os.makedirs", "os.mkdir", "os.rmdir", "os.chmod", "os.chown", "os.symlink", "os.link", "os.truncate",
            "os.startfile", "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree", "shutil.move",
            "shutil.rmtree", "glob.glob", "glob.iglob", "tarfile.open", "zipfile.ZipFile"}
_FS_TWO_ARGS = {"os.rename", "os.replace", "os.symlink", "os.link", "shutil.copy", "shutil.copy2", "shutil.copyfile",
                "shutil.copytree", "shutil.move"}
_FS_METH = {"read_text", "write_text", "read_bytes", "write_bytes", "open", "unlink", "rmdir", "mkdir", "rename",
            "replace", "iterdir", "glob", "rglob", "touch", "chmod", "symlink_to", "extractall", "extract"}
_FS_METH_ARGS_ARE_PATH = {"rename", "replace", "extractall", "extract", "symlink_to"}
_EXEC_PREFIX = ("subprocess.", "os.exec", "os.spawn", "asyncio.create_subprocess", "pty.spawn", "commands.")
_EXEC_NAMES = {"os.system", "os.popen", "eval", "exec", "Popen", "check_output", "check_call"}
_NET_PREFIX = ("requests.", "httpx.", "aiohttp.", "urllib3.", "urllib.request.")
_NET_NAMES = {"urlopen", "urllib.urlopen", "webbrowser.open", "socket.create_connection", "fetch"}
_NET_METH = {"get", "post", "put", "delete", "patch", "head", "request", "fetch", "stream", "urlopen", "send"}
_NET_RECV = re.compile(r"session|client|http|requests|httpx|api|aiohttp", re.I)
_SQL_METH = {"execute", "executemany", "executescript", "exec_driver_sql"}

_SAFE_PREFIX = ("json.", "re.", "logging.", "logger.", "log.", "os.path.", "posixpath.", "ntpath.", "datetime.", "time.",
                "uuid.", "hashlib.", "base64.", "urllib.parse.", "pathlib.PurePath", "Path", "textwrap.", "string.")
_SAFE_NAMES = {"len", "str", "int", "float", "bool", "repr", "print", "isinstance", "sorted", "list", "dict", "set", "tuple",
               "min", "max", "sum", "range", "enumerate", "zip", "any", "all", "bytes", "type", "getattr", "hasattr",
               "urlparse", "quote", "unquote", "abs", "round", "reversed", "map", "filter", "next", "iter", "id", "hash"}
_SAFE_METHODS = {"strip", "lstrip", "rstrip", "lower", "upper", "split", "rsplit", "splitlines", "join", "format", "startswith",
                 "endswith", "replace", "encode", "decode", "get", "items", "keys", "values", "append", "extend", "add",
                 "update", "pop", "count", "find", "index", "isdigit", "isalnum", "resolve", "expanduser", "absolute",
                 "exists", "is_file", "is_dir", "stat", "with_suffix", "joinpath", "relative_to", "is_relative_to",
                 "as_posix", "title", "capitalize", "partition", "rpartition", "isoformat", "hexdigest", "copy",
                 "debug", "info", "warning", "error", "exception", "critical", "setdefault", "model_dump", "dict", "json"}

_GUARD_NAMES = {"fs": {"is_relative_to", "relative_to", "commonpath", "secure_filename", "safe_join", "samefile"},
                "exec": {"quote", "shlex"},
                "net": {"hostname", "netloc", "ipaddress", "is_private", "is_loopback", "allowed_hosts", "allowlist",
                        "ALLOWED_HOSTS", "ALLOWED_DOMAINS"},
                "sql": set()}


@dataclass
class Reach:
    verdict: str                      # sink_unguarded | sink_guarded | no_sink | unknown
    kinds: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    forwarded: list[str] = field(default_factory=list)   # callees we could not see into, that received a parameter

    def note(self) -> str:
        if self.verdict == "no_sink":
            return "reach: no data flow from any parameter to a file/command/network/SQL sink found in the handler (declared capability only)"
        if self.verdict in ("sink_unguarded", "sink_guarded"):
            g = "guard detected" if self.verdict == "sink_guarded" else "no guard detected"
            return f"reach: parameter reaches {', '.join(self.kinds)} sink ({g}): " + "; ".join(self.evidence[:3])
        if self.verdict == "unknown":
            if self.forwarded:
                return "reach: unverified - parameter forwarded to " + ", ".join(sorted(set(self.forwarded))[:3]) + "() outside the visible code"
            return "reach: unverified - handler could not be fully resolved"
        return ""


class _ModuleInfo:
    def __init__(self, src: str):
        self.tree = ast.parse(src)
        self.funcs: dict[str, list] = {}
        for n in ast.walk(self.tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs.setdefault(n.name, []).append(n)
        # Shared AST memoization caches per module source to eliminate redundant O(N^2) walks
        self.name_cache: dict[int, set[str]] = {}
        self.dotted_cache: dict[int, str] = {}
        self.store_name_cache: dict[int, set[str]] = {}


@functools.lru_cache(maxsize=128)
def _get_module_info(src: str) -> _ModuleInfo:
    """Parse module AST and build function index once per source string (~200x speedup for multi-tool modules)."""
    return _ModuleInfo(src)


class _Ctx:
    def __init__(self, mod: _ModuleInfo, fname: str):
        self.fname = fname
        self.funcs = mod.funcs
        self.name_cache = mod.name_cache
        self.dotted_cache = mod.dotted_cache
        self.store_name_cache = mod.store_name_cache
        self.kinds: set[str] = set()
        self.evidence: list[str] = []
        self.guards: set[str] = set()
        self.unknown = False
        self.forwarded: list[str] = []
        self.seen: set[tuple[int, frozenset]] = set()


def _dotted(n, ctx: _Ctx) -> str:
    nid = id(n)
    if nid in ctx.dotted_cache:
        return ctx.dotted_cache[nid]
    if isinstance(n, ast.Name):
        res = n.id
    elif isinstance(n, ast.Attribute):
        res = f"{_dotted(n.value, ctx)}.{n.attr}"
    elif isinstance(n, ast.Call):
        res = f"{_dotted(n.func, ctx)}()"
    elif isinstance(n, ast.Subscript):
        res = f"{_dotted(n.value, ctx)}[]"
    else:
        res = "?"
    ctx.dotted_cache[nid] = res
    return res


def _names(n, ctx: _Ctx) -> set[str]:
    nid = id(n)
    if nid in ctx.name_cache:
        return ctx.name_cache[nid]
    res = {x.id for x in ast.walk(n) if isinstance(x, ast.Name)}
    ctx.name_cache[nid] = res
    return res


def _store_names(t, ctx: _Ctx) -> set[str]:
    tid = id(t)
    if tid in ctx.store_name_cache:
        return ctx.store_name_cache[tid]
    if isinstance(t, ast.Name):
        res = {t.id}
    elif isinstance(t, (ast.Tuple, ast.List)):
        res = set().union(*(_store_names(e, ctx) for e in t.elts)) if t.elts else set()
    elif isinstance(t, ast.Starred):
        res = _store_names(t.value, ctx)
    else:
        res = set()  # attribute/subscript targets (self.x = ...) deliberately do not taint their base
    ctx.store_name_cache[tid] = res
    return res


def _propagate(nodes: list[ast.AST], tainted: set[str], ctx: _Ctx) -> set[str]:
    tainted = set(tainted)
    for _ in range(3):
        before = len(tainted)
        for node in nodes:
            pairs: list[tuple[set[str], ast.AST]] = []
            if isinstance(node, ast.Assign):
                pairs = [(set().union(*(_store_names(t, ctx) for t in node.targets)), node.value)]
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
                pairs = [(_store_names(node.target, ctx), node.value)]
            elif isinstance(node, ast.NamedExpr):
                pairs = [(_store_names(node.target, ctx), node.value)]
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                pairs = [(_store_names(node.target, ctx), node.iter)]
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                pairs = [(_store_names(i.optional_vars, ctx), i.context_expr) for i in node.items if i.optional_vars]
            for targets, value in pairs:
                if _names(value, ctx) & tainted:
                    tainted |= targets
        if len(tainted) == before:
            break
    return tainted


def _is_safe_call(name: str) -> bool:
    if name in _SAFE_NAMES or name.startswith(_SAFE_PREFIX):
        return True
    return name.rsplit(".", 1)[-1] in _SAFE_METHODS and "." in name


def _arg_tainted(call: ast.Call, tainted: set[str], ctx: _Ctx, positions=(0,), kws=("path", "file", "filename", "src", "dst", "url", "uri")) -> bool:
    for i in positions:
        if i < len(call.args) and _names(call.args[i], ctx) & tainted:
            return True
    return any(k.arg in kws and _names(k.value, ctx) & tainted for k in call.keywords)


def _guards_in(nodes: list[ast.AST], tainted: set[str], ctx: _Ctx) -> set[str]:
    called, ids = set(), set()
    for n in nodes:
        if isinstance(n, ast.Call):
            called.add(_dotted(n.func, ctx).rsplit(".", 1)[-1])
        if isinstance(n, ast.Attribute):
            ids.add(n.attr)
        if isinstance(n, ast.Name):
            ids.add(n.id)
        if isinstance(n, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn)) for o in n.ops):
            if _names(n.left, ctx) & tainted and any(isinstance(c, (ast.Set, ast.Tuple, ast.List, ast.Dict)) or
                                                (isinstance(c, ast.Name) and c.id.isupper()) for c in n.comparators):
                return {"fs", "exec", "net", "sql"}  # explicit allowlist membership check on the tainted value
    seen = called | ids
    g = set()
    for kind, names in _GUARD_NAMES.items():
        if seen & names:
            g.add(kind)
    if "startswith" in called and seen & {"realpath", "resolve", "abspath", "normpath"}:
        g.add("fs")
    # NOTE: a helper merely *named* validate_/sanitize_/safe_ is not evidence of containment (it often only rejects
    # "..") so it does not count as a guard; only recognisable containment checks and allowlist membership do.
    return g


def _walk_fn(fn, tainted: set[str], ctx: _Ctx, depth: int) -> None:
    key = (id(fn), frozenset(tainted))
    if key in ctx.seen:
        return
    ctx.seen.add(key)

    # Perform a single pass flat walk of fn AST nodes
    fn_nodes = list(ast.walk(fn))
    if len(fn_nodes) > MAX_NODES:
        ctx.unknown = True
        return
    tainted = _propagate(fn_nodes, tainted, ctx)
    ctx.guards |= _guards_in(fn_nodes, tainted, ctx)

    def hit(kind: str, call: ast.Call, label: str) -> None:
        ctx.kinds.add(kind)
        ctx.evidence.append(f"{label}() at {ctx.fname}:{call.lineno}")

    for call in (n for n in fn_nodes if isinstance(n, ast.Call)):
        name = _dotted(call.func, ctx)
        last = name.rsplit(".", 1)[-1]
        recv = call.func.value if isinstance(call.func, ast.Attribute) else None
        tainted_any = any(_names(a, ctx) & tainted for a in call.args) or any(_names(k.value, ctx) & tainted for k in call.keywords)
        if name in _FS_FUNC and _arg_tainted(call, tainted, ctx, (0, 1) if name in _FS_TWO_ARGS else (0,)):
            hit("fs", call, name)
        elif recv is not None and last in _FS_METH and ((_names(recv, ctx) & tainted) or
                                                        (last in _FS_METH_ARGS_ARE_PATH and tainted_any)):
            hit("fs", call, name)
        elif (name.startswith(_EXEC_PREFIX) or name in _EXEC_NAMES) and tainted_any:
            hit("exec", call, name)
        elif (name.startswith(_NET_PREFIX) or name in _NET_NAMES) and _arg_tainted(call, tainted, ctx):
            hit("net", call, name)
        elif recv is not None and last in _NET_METH and _NET_RECV.search(_dotted(recv, ctx)) and _arg_tainted(call, tainted, ctx):
            hit("net", call, name)
        elif last in _SQL_METH and call.args and isinstance(call.args[0], (ast.JoinedStr, ast.BinOp)) and _names(call.args[0], ctx) & tainted:
            hit("sql", call, name)
        elif tainted_any or (recv is not None and _names(recv, ctx) & tainted):
            # not a known sink: follow same-module helpers, otherwise remember we could not see inside
            callee = ctx.funcs.get(last) if (isinstance(call.func, ast.Name) or
                                             (isinstance(call.func, ast.Attribute) and _dotted(call.func.value, ctx) in ("self", "cls"))) else None
            if callee and depth < MAX_DEPTH:
                for target in callee[:3]:
                    a = target.args
                    offset = 1 if a.args and a.args[0].arg in ("self", "cls") else 0
                    pos = [x.arg for x in a.posonlyargs + a.args][offset:]
                    named = set(pos) | {x.arg for x in a.kwonlyargs}
                    bound: set[str] = set()
                    for i, arg in enumerate(call.args):
                        if _names(arg, ctx) & tainted:
                            if i < len(pos):
                                bound.add(pos[i])
                            elif a.vararg:
                                bound.add(a.vararg.arg)      # e.g. _safe_call(fn, *args): the dispatcher pattern
                    for k in call.keywords:
                        if _names(k.value, ctx) & tainted:
                            if k.arg in named:
                                bound.add(k.arg)
                            elif a.kwarg:
                                bound.add(a.kwarg.arg)
                    if bound:
                        _walk_fn(target, bound, ctx, depth + 1)
                    elif tainted_any:                         # could not map the tainted value: be conservative
                        ctx.unknown = True
                        ctx.forwarded.append(name)
            elif not _is_safe_call(name):
                ctx.unknown = True
                ctx.forwarded.append(name)


def assess_python(tool: dict) -> Reach:
    src = tool.get("module_src") or ""
    try:
        mod = _get_module_info(src)
    except Exception:  # SyntaxError, RecursionError, ValueError
        return Reach("unknown")
    params = set(tool.get("input_schema", {}).get("properties", {}))
    if not params:
        return Reach("unknown")
    ctx = _Ctx(mod, tool.get("file", "?"))
    fn = next((n for n in ctx.funcs.get(tool.get("handler"), []) if n.lineno == tool.get("line")), None)
    if fn is None:
        return Reach("unknown")
    _walk_fn(fn, params, ctx, 0)
    if ctx.kinds:
        guarded = ctx.kinds <= ctx.guards
        return Reach("sink_guarded" if guarded else "sink_unguarded", sorted(ctx.kinds), ctx.evidence)
    return Reach("unknown", forwarded=ctx.forwarded) if ctx.unknown else Reach("no_sink")


def assess_js(tool: dict) -> Reach:
    from aisec import reach_js  # local import: reach_js imports Reach from this module
    return reach_js.assess(tool)


def assess(tool: dict) -> Reach:
    try:
        if tool.get("lang") == "python":
            return assess_python(tool)
        if tool.get("lang") == "js":
            return assess_js(tool)
    except Exception:  # analysis must never take down a scan
        pass
    return Reach("unknown")


def adjust_severity(severity: str, r: "Reach", strict: bool = False) -> str:
    """Evidence tiers. Refuted (no sink / guarded) always lowers. Unproven (could not see the flow) lowers only in
    strict mode, so a CI gate on HIGH means 'a sink was actually reached'. Proven keeps the claimed severity."""
    i = SEVERITIES.index(severity)
    if r.verdict == "no_sink":
        return "low"
    if r.verdict == "sink_guarded":
        return SEVERITIES[max(i - 1, 0)]
    if r.verdict == "unknown" and strict:
        return SEVERITIES[min(i, 1)] if i > 1 else severity   # cap at medium
    return severity
