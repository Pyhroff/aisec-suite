"""Cross-language reachability for bridge servers: follow a command name across an IPC boundary.

Many MCP servers for game engines and editors (Godot, Unity, Blender, ...) do no work in the TypeScript handler.
The handler sends a command name plus the tool arguments to a process written in another language, and the real
capability lives in that process's dispatcher:

    this.gameCommand('get_property', args, ...)          # TypeScript side: a string literal names the command
    match command:                                       # GDScript side: the dispatcher arm for that literal
        "get_property": _cmd_get_property(params)

Single-language reachability can only say "unknown" here, which is why it removed no false positives on the bridge
servers in the 135-repo study. This module indexes dispatcher arms in the repository's engine-side scripts, resolves
the arm to its handler functions, and looks for file, command, network and dynamic-code sinks there.

Supported engine languages: GDScript (``match`` arms) and C# for Unity editor plugins (``switch``/``case`` on a string
and handler tables such as ``{ "cmd", Handler }`` or ``["cmd"] = Handler``). Everything is parsed as text, nothing is executed, and every
step is bounded. The verdict is three-valued like the rest of reach:

* sink found in the resolved engine-side handler -> the parameter is treated as reaching it (evidence names the arm);
* arm fully resolved, no sink, no dynamic dispatch, no call we could not follow -> ``no_sink``;
* anything else (literal not found, ambiguous, dynamic call, unresolved helper) -> no claim.
"""
from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass, field

MAX_FILES = 200
MAX_FILE_BYTES = 1_000_000
MAX_DEPTH = 2
# A function called from at least this share of a file's functions is the reply/transport channel (every command
# answers through it), not the capability of any one command.
TRANSPORT_SHARE = 0.3

_GD_SINKS = {
    "exec": re.compile(r"\bOS\.(?:execute|execute_with_pipe|create_process|create_instance|shell_open|kill)\s*\(|"
                       r"\bExpression\.new\s*\(|\bJavaScriptBridge\.eval\s*\(|\bGDScript\.new\s*\("),
    "fs": re.compile(r"\bFileAccess\.open\w*\s*\(|\bDirAccess\.\w+\s*\(|\bResourceSaver\.save\s*\(|"
                     r"\bProjectSettings\.save\w*\s*\(|\.save_(?:png|jpg|webp|exr)\w*\s*\(|"
                     r"(?<![\w.])(?:load|ResourceLoader\.load)\s*\(\s*(?![\"'])"),
    "net": re.compile(r"\b(?:HTTPRequest|HTTPClient|StreamPeerTCP|TCPServer|WebSocketPeer|PacketPeerUDP|UDPServer|"
                      r"ENetMultiplayerPeer|WebSocketMultiplayerPeer)\.new\s*\("),
}
# Calls whose target is chosen at runtime: we cannot say what they reach.
_GD_DYNAMIC = re.compile(r"\.(?:callv|call|call_deferred|set_script)\s*\(|\bCallable\s*\(|\bstr_to_var\s*\(|"
                         r"\bdict_to_inst\s*\(|\bClassDB\.instantiate\s*\(")
_GD_BUILTINS = {
    "str", "int", "float", "bool", "len", "range", "print", "prints", "printerr", "print_rich", "push_error",
    "push_warning", "typeof", "is_instance_valid", "is_instance_of", "var_to_str", "type_string", "error_string",
    "abs", "absf", "absi", "min", "mini", "minf", "max", "maxi", "maxf", "clamp", "clampi", "clampf", "lerp", "lerpf",
    "round", "roundi", "floor", "floori", "ceil", "ceili", "sqrt", "pow", "sin", "cos", "tan", "atan2", "deg_to_rad",
    "rad_to_deg", "randi", "randf", "randi_range", "randf_range", "snapped", "sign", "fmod", "posmod", "hash", "char",
    "ord", "weakref", "assert", "is_equal_approx", "is_zero_approx", "wrapf", "wrapi", "inst_to_dict", "instance_from_id",
    "preload", "super", "await", "Vector2", "Vector2i", "Vector3", "Vector3i", "Vector4", "Color", "Rect2", "Rect2i",
    "Transform2D", "Transform3D", "Basis", "Quaternion", "Plane", "AABB", "NodePath", "StringName", "Array",
    "Dictionary", "PackedStringArray", "PackedByteArray", "PackedInt32Array", "PackedInt64Array", "PackedFloat32Array",
    "PackedFloat64Array", "PackedVector2Array", "PackedVector3Array", "PackedColorArray", "get_node", "get_node_or_null",
    "has_node", "get_tree", "get_viewport", "get_parent", "get_children", "get_child", "get_child_count", "add_child",
    "remove_child", "find_child", "emit_signal", "queue_free", "get_window", "get_class", "is_class", "get", "set",
    "has_method", "has_signal", "is_inside_tree", "get_path",
}
_KEYWORDS = {"if", "elif", "else", "for", "while", "match", "return", "and", "or", "not", "in", "is", "as", "var",
             "const", "func", "pass", "break", "continue", "await", "signal", "class", "extends", "static"}

_FUNC = re.compile(r"^(?:static\s+)?func\s+(\w+)\s*\(", re.M)
_ARM = re.compile(r'^(\s*)((?:"[\w./-]+"\s*,\s*)*"[\w./-]+")\s*:\s*(.*)$')
_CALL = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\s*\(")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _strip_comment(line: str) -> str:
    out, q = [], None
    for ch in line:
        if q:
            q = None if ch == q else q
        elif ch in "\"'":
            q = ch
        elif ch == "#":
            break
        out.append(ch)
    return "".join(out)


@dataclass
class GdFile:
    """One engine-side script: its functions, dispatcher arms and reply channel. Used for GDScript and C# alike."""
    path: str
    funcs: dict[str, str] = field(default_factory=dict)          # name -> body text
    arms: dict[str, list[str]] = field(default_factory=dict)     # literal -> arm bodies (top-level dispatchers only)
    transport: set[str] = field(default_factory=set)
    lang: str = "gd"
    classes: tuple[str, ...] = ()                               # C#: classes declared in the file (for Class.Method calls)


def _parse_gd(path: str, src: str) -> GdFile:
    lines = [_strip_comment(raw).rstrip() for raw in src.splitlines()]
    gf = GdFile(path)
    starts = [(m.group(1), src.count("\n", 0, m.start())) for m in _FUNC.finditer(src)]
    for i, (name, ln) in enumerate(starts):
        end = starts[i + 1][1] if i + 1 < len(starts) else len(lines)
        gf.funcs.setdefault(name, "\n".join(lines[ln:end]))
    # dispatcher arms: `match <x>:` blocks whose arms are string literals
    for ln, line in enumerate(lines):
        m = re.match(r"^(\s*)match\s+(\w+)\s*:\s*$", line)
        if not m:
            continue
        base = _indent(line)
        arm_indent = None
        j = ln + 1
        current: list[str] | None = None
        lits: list[str] = []
        block: dict[str, str] = {}
        while j < len(lines):
            cur = lines[j]
            if cur.strip():
                ind = _indent(cur)
                if ind <= base:
                    break
                am = _ARM.match(cur)
                if am and (arm_indent is None or ind == arm_indent):
                    arm_indent = ind
                    if current is not None:
                        for lit in lits:
                            block[lit] = "\n".join(current)
                    lits = re.findall(r'"([\w./-]+)"', am.group(2))
                    current = [am.group(3)] if am.group(3) else []
                elif current is not None and arm_indent is not None and ind > arm_indent:
                    current.append(cur)
                elif arm_indent is not None and ind <= arm_indent and not am:
                    current = None   # non-literal arm (`_:`, variable pattern): stop collecting
                    lits = []
            j += 1
        if current is not None:
            for lit in lits:
                block[lit] = "\n".join(current)
        if len(block) >= 5:   # a command dispatcher, not a small local switch
            for lit, body in block.items():
                gf.arms.setdefault(lit, []).append(body)
    callers: dict[str, int] = {}
    for body in gf.funcs.values():
        for name in {c for c in _CALL.findall(body) if c in gf.funcs}:
            callers[name] = callers.get(name, 0) + 1
    n = max(len(gf.funcs), 1)
    gf.transport = {name for name, k in callers.items() if k / n >= TRANSPORT_SHARE}
    return gf


# --- C# (Unity editor plugins) -----------------------------------------------------------------------------------------

_CS_SINKS = {
    "exec": re.compile(r"\bProcess\.Start\s*\(|\bnew\s+ProcessStartInfo\s*\(|\bEditorApplication\.ExecuteMenuItem\s*\(|"
                       r"\bCSharpCodeProvider\b|\bCSharpScript\.\w+\s*\(|\bAssembly\.Load\w*\s*\("),
    "fs": re.compile(r"\bFile\.(?:Write\w*|Append\w*|Delete|Copy|Move|Create\w*|Open\w*|Replace|ReadAll\w*)\s*\(|"
                     r"\bDirectory\.(?:Delete|Move|CreateDirectory)\s*\(|\bnew\s+(?:StreamWriter|FileStream)\s*\(|"
                     r"\bAssetDatabase\.(?:DeleteAsset|MoveAsset|CopyAsset|CreateAsset|ImportAsset|LoadAssetAtPath|"
                     r"CreateFolder|ExportPackage|ImportPackage)\w*\s*\(|\bFileUtil\.\w+\s*\(|\bPrefabUtility\.SaveAs\w*\s*\("),
    "net": re.compile(r"\bnew\s+(?:HttpClient|WebClient|TcpClient|UdpClient|TcpListener)\s*\(|\bUnityWebRequest\.\w+\s*\(|"
                      r"\bWebRequest\.Create\s*\("),
}
_CS_DYNAMIC = re.compile(r"\.Invoke\s*\(|\.GetMethod\s*\(|\bType\.GetType\s*\(|\bActivator\.CreateInstance\s*\(|"
                         r"\.SendMessage\s*\(|\.BroadcastMessage\s*\(|\.DynamicInvoke\s*\(|\bdynamic\b")
_CS_KEYWORDS = _KEYWORDS | {"switch", "case", "default", "new", "typeof", "nameof", "sizeof", "catch", "using", "lock",
                            "foreach", "throw", "base", "this", "checked", "unchecked", "fixed", "when"}
_CS_METHOD = re.compile(r"(?:^|[{};])\s*(?:(?:public|private|protected|internal|static|async|override|virtual|sealed|"
                        r"unsafe|extern|new)\s+)*([\w<>\[\],.?]+)\s+(\w+)\s*\([^;{}()]*(?:\([^()]*\)[^;{}()]*)*\)\s*"
                        r"(?:where[^{]*)?\{", re.M)
_CS_CLASS = re.compile(r"\b(?:class|struct)\s+(\w+)")
_CS_CASE = re.compile(r'^\s*case\s+"([\w./-]+)"\s*:')
_CS_TABLE = re.compile(r'\{\s*"([\w./-]+)"\s*,\s*(?:new\s+(\w+)\s*\(|([\w.]+)\s*\}|\(?[^)]*\)?\s*=>\s*([^}]*)\})|'
                       r'\[\s*"([\w./-]+)"\s*\]\s*=\s*(?:new\s+(\w+)\s*\(|([\w.]+)\s*;|\(?[^)]*\)?\s*=>\s*([^;]*);)')
_CS_CALL = re.compile(r"(?<![\w.])(?:([A-Z]\w*)\.)?([A-Za-z_]\w*)\s*\(")


def _cs_clean(src: str) -> str:
    """Blank comments and the contents of strings (keeping offsets and the string-literal shells for case labels)."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in src[i:j]))
            i = j
        elif c == '"' or (c in "@$" and i + 1 < n and src[i + 1] == '"'):
            start = i
            i += 1 if c == '"' else 2
            verbatim = c == "@"
            while i < n and src[i] != '"':
                if src[i] == "\\" and not verbatim:
                    i += 1
                i += 1
            body = src[start:i + 1]
            lit = re.fullmatch(r'"([\w./-]+)"', body)
            out.append(body if lit else '"' + " " * max(len(body) - 2, 0) + '"')
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _brace_block(src: str, open_idx: int) -> int:
    """Index just past the brace block that opens at `open_idx`."""
    depth = 0
    for i in range(open_idx, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(src)


def _cs_switch_arms(block: str) -> dict[str, str]:
    """`case "lit":` arms of one switch body. Consecutive labels share a body (fall-through); default and non-literal
    case labels end the current arm and start none."""
    arms: dict[str, str] = {}
    lits: list[str] = []
    body: list[str] = []
    depth = 0
    for line in [*block.splitlines(), 'default:']:
        label = _CS_CASE.match(line) if depth == 0 else None
        other = depth == 0 and not label and re.match(r'^\s*(?:default|case\b[^"]*?)\s*:', line)
        if (label and any(x.strip() for x in body)) or other:
            if lits and any(x.strip() for x in body):
                arms.update(dict.fromkeys(lits, "\n".join(body)))
            lits, body = [], []
        if label:
            lits.append(label.group(1))
            body.append(line[label.end():])
        elif lits and not other:
            body.append(line)
        depth += line.count("{") - line.count("}")
    return arms


def _parse_cs(path: str, raw: str) -> GdFile:
    src = _cs_clean(raw)
    gf = GdFile(path, lang="cs")
    gf.classes = tuple(_CS_CLASS.findall(src))
    for m in _CS_METHOD.finditer(src):
        rtype, name = m.group(1), m.group(2)
        if name in _CS_KEYWORDS or rtype in _CS_KEYWORDS or rtype in ("return", "await", "else"):
            continue
        gf.funcs.setdefault(name, src[m.end() - 1:_brace_block(src, m.end() - 1)])
    # switch (x) { case "a": ... }
    for m in re.finditer(r"\bswitch\s*\([^)]*\)\s*\{", src):
        block = src[m.end():_brace_block(src, m.end() - 1) - 1]
        arms = _cs_switch_arms(block)
        if len(arms) >= 5:
            for lit, b in arms.items():
                gf.arms.setdefault(lit, []).append(b)
    # handler tables: { "cmd", Handler } / ["cmd"] = Handler / new Handler() / lambda
    table: dict[str, str] = {}
    for m in _CS_TABLE.finditer(src):
        lit = m.group(1) or m.group(5)
        new_cls = m.group(2) or m.group(6)
        ref = m.group(3) or m.group(7)
        lam = m.group(4) or m.group(8)
        table[lit] = f"{new_cls}.HandleCommand()" if new_cls else (f"{ref}()" if ref else lam)
    if len(table) >= 5:
        for lit, b in table.items():
            gf.arms.setdefault(lit, []).append(b)
    callers: dict[str, int] = {}
    for b in gf.funcs.values():
        for name in {c for _cl, c in _CS_CALL.findall(b) if c in gf.funcs}:
            callers[name] = callers.get(name, 0) + 1
    n = max(len(gf.funcs), 1)
    gf.transport = {name for name, k in callers.items() if k / n >= TRANSPORT_SHARE and n >= 4}
    return gf


@dataclass
class BridgeIndex:
    files: list[GdFile] = field(default_factory=list)
    classes: dict[str, GdFile] = field(default_factory=dict)   # C# class name -> file, for Class.Method calls

    def arms_for(self, literal: str) -> list[tuple[GdFile, str]]:
        return [(f, body) for f in self.files for body in f.arms.get(literal, [])]


_CACHE: dict[str, BridgeIndex] = {}


def index(root: str | pathlib.Path) -> BridgeIndex:
    key = str(root)
    if key in _CACHE:
        return _CACHE[key]
    idx = BridgeIndex()
    rootp = pathlib.Path(root)
    count = 0
    for p in sorted([*rootp.rglob("*.gd"), *rootp.rglob("*.cs")]):
        if count >= MAX_FILES or any(part in ("node_modules", ".git", "addons", "Library", "obj", "bin") for part in p.parts):
            continue
        try:
            if p.is_symlink() or p.stat().st_size > MAX_FILE_BYTES:
                continue
            src = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(p.relative_to(rootp))
        gf = _parse_cs(rel, src) if p.suffix == ".cs" else _parse_gd(rel, src)
        for cls in gf.classes:
            idx.classes.setdefault(cls, gf)
        if gf.arms:
            idx.files.append(gf)
        count += 1
    _CACHE[key] = idx
    return idx


@dataclass
class BridgeResult:
    literal: str
    kinds: set[str] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)
    complete: bool = False   # arm found, uniquely, and every call in it was followed or is a known built-in


def _analyse(gf: GdFile, body: str, depth: int, seen: set[str], res: BridgeResult, idx: BridgeIndex) -> bool:
    """Scan one body; recurse into helpers (same file, or `Class.Method` in another C# file). -> True if all resolved."""
    sinks, dynamic = (_CS_SINKS, _CS_DYNAMIC) if gf.lang == "cs" else (_GD_SINKS, _GD_DYNAMIC)
    complete = True
    for kind, rx in sinks.items():
        for m in rx.finditer(body):
            res.kinds.add(kind)
            res.evidence.append(f"bridge '{res.literal}' -> {gf.path}: {m.group(0).rstrip('( ').strip()}()")
    if dynamic.search(body):
        complete = False
    if gf.lang == "cs":
        calls = {(cls or "", name) for cls, name in _CS_CALL.findall(body)}
    else:
        calls = {("", name) for name in _CALL.findall(body)}
    for cls, name in calls:
        if cls:
            target = idx.classes.get(cls)
            if target is None or name not in target.funcs:
                continue   # a framework / library type: sinks among them are matched above
        elif name in gf.funcs:
            target = gf
        elif gf.lang == "cs" and name in idx.classes:
            continue   # constructor-like reference to a project class without a call into it
        else:
            if name in _KEYWORDS or name in _CS_KEYWORDS:
                continue
            if gf.lang == "gd" and (name in _GD_BUILTINS or name[:1].isupper()):
                continue   # engine built-ins, constructors (sinks among them are matched above)
            complete = False
            continue
        if not cls and name in gf.transport:
            continue   # the reply channel
        key = f"{target.path}:{name}"
        if key in seen:
            continue
        if depth >= MAX_DEPTH:
            complete = False
            continue
        seen.add(key)
        complete = _analyse(target, target.funcs[name], depth + 1, seen, res, idx) and complete
    return complete


def resolve(literal: str, root: str | pathlib.Path) -> BridgeResult:
    res = BridgeResult(literal)
    idx = index(root)
    arms = idx.arms_for(literal)
    if len(arms) != 1:   # not found, or ambiguous across dispatchers: no claim
        return res
    gf, body = arms[0]
    if not body.strip():   # placeholder or fall-through arm: we have not seen what it does
        return res
    res.complete = _analyse(gf, body, 0, set(), res, idx)
    return res


# --- JS/TS side: which string literals does the handler send across a bridge? ------------------------------------------

_JS_FORWARD = re.compile(r"(?<![\w$])(?:this\.|self\.)?([\w$]+)\s*\(\s*['\"`]([A-Za-z_][\w./-]{1,60})['\"`]\s*,")
# sendRequest({ method: "cmd", params }) and similar: the command travels as a field of an object literal
_JS_FORWARD_OBJ = re.compile(r"(?<![\w$])(?:this\.|self\.)?([\w$]+)\s*\(\s*\{\s*(?:method|command|type|action|tool)\s*:\s*"
                             r"['\"`]([A-Za-z_][\w./-]{1,60})['\"`]")


def forwards(text: str) -> list[re.Match[str]]:
    """Calls that send a string-literal command name: group(1) is the sender, group(2) the command."""
    return [*_JS_FORWARD.finditer(text), *_JS_FORWARD_OBJ.finditer(text)]


def forwarded_literals(texts: list[str], forwarders: set[str]) -> list[str]:
    """String-literal command names passed to calls we could not see into (the bridge senders)."""
    out: list[str] = []
    for t in texts:
        for m in forwards(t):
            if m.group(1) in forwarders and m.group(2) not in out:
                out.append(m.group(2))
    return out
