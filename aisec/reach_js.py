"""JS/TS handler resolution + lightweight taint, regex/brace-matching based (no JS parser, nothing executed).

Verdicts are positive-evidence only: sink_guarded / sink_unguarded / unknown (never no_sink).
Resolution order for a registered tool name: inline callback after the registration, then a `case "name":` dispatch
branch (and the handler function it calls), then a `name: handler` map entry. If no complete handler text can be
found, the verdict is "unknown": we never claim "no sink" about code we have not seen.
"""
from __future__ import annotations

import re

from aisec.reach import Reach

MAX_SCAN = 30_000
_KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "typeof", "await", "new", "else", "do", "try"}
_CONTAINERS = {"args", "params", "input", "request", "req", "options", "opts", "arguments", "payload", "data", "body", "ctx"}

_SINKS = {
    "fs": re.compile(r"\b(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|"
                     r"readdir|readdirSync|unlink|unlinkSync|rmSync|rm|rename|renameSync|mkdir|mkdirSync|copyFile|copyFileSync|cp|cpSync|"
                     r"opendir|readTextFile|writeTextFile|truncate|chmod|symlink)\s*\("),
    "exec": re.compile(r"\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork|eval|execa|execaSync|runInNewContext|"
                       r"runInThisContext|Bun\.spawn|Deno\.run)\s*\(|\bnew\s+Function\s*\("),
    "net": re.compile(r"\b(?:fetch|axios(?:\.\w+)?|got|ky|superagent|needle|https?\.(?:request|get)|undici\.\w+)\s*\("),
}
_CONTAIN = re.compile(r"isPathInside|assertInside|path\.relative\([^)]*\)[\s\S]{0,120}startsWith\(['\"`]\.\.|"
                      r"(?:resolve|realpath|normalize)\([^)]*\)[\s\S]{0,160}startsWith\(|"
                      r"(?:allowed\w*|ALLOWED\w*|whitelist\w*|allowlist\w*)\.(?:includes|has|some)\(|"
                      r"new URL\([^)]*\)[\s\S]{0,160}\.(?:hostname|host)\b")
_GUARD = _CONTAIN
_SAFE_CALL = re.compile(r"^(?:path\.\w+|JSON\.\w+|String|Number|Boolean|parseInt|parseFloat|Array\.\w+|Object\.\w+|console\.\w+|"
                        r"logger\.\w+|log\.\w+|Math\.\w+|encodeURIComponent|decodeURIComponent|encodeURI|z\.\w+|existsSync|"
                        r"Error|TypeError|RangeError|Promise\.\w+|Date\.\w+|Buffer\.\w+|URL|resolve|join|basename|dirname|extname|"
                        r"normalize|relative|isAbsolute|require|import|expect|typeof|void)$")
_SAFE_METH = {"trim", "toLowerCase", "toUpperCase", "split", "join", "map", "filter", "includes", "startsWith", "endsWith",
              "replace", "replaceAll", "slice", "substring", "push", "get", "set", "has", "toString", "concat", "indexOf",
              "padStart", "padEnd", "some", "every", "find", "forEach", "reduce", "keys", "values", "entries", "length",
              "toFixed", "match", "test", "then", "catch", "finally", "json", "text", "stringify", "parse", "isArray",
              "trimStart", "trimEnd", "charAt", "at", "flat", "flatMap", "sort", "reverse", "delete", "add", "clear"}


def _balanced(src: str, start: int, open_c: str = "{", close_c: str = "}") -> str | None:
    """Text from the opening bracket at `start` to its match, skipping strings/comments. None if unbalanced in MAX_SCAN."""
    depth, i, n = 0, start, min(len(src), start + MAX_SCAN)
    while i < n:
        c = src[i]
        if c in "\"'`":
            q, i = c, i + 1
            while i < n and src[i] != q:
                i += 2 if src[i] == "\\" else 1
        elif src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i == -1 else i
        elif src.startswith("/*", i):
            i = src.find("*/", i)
            i = n if i == -1 else i + 1
        elif c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return src[start: i + 1]
        i += 1
    return None


_FN_DEFS = [
    re.compile(r"(?:async\s+)?function\s*\*?\s*(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)\s*(?::[^{=]+)?\{"),
    re.compile(r"(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:function\b[^(]*)?\(([^)]*)\)\s*(?::[^={]+)?(?:=>)?\s*\{"),
    re.compile(r"^[ \t]*(?:(?:private|public|protected|static|async|readonly)\s+)*(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)\s*(?::[^{;=]+)?\{", re.M),
]


def functions(src: str) -> dict[str, tuple[list[str], str]]:
    out: dict[str, tuple[list[str], str]] = {}
    for rx in _FN_DEFS:
        for m in rx.finditer(src):
            name = m.group(1)
            if name in _KEYWORDS or name in out:
                continue
            body = _balanced(src, m.end() - 1)
            if body:
                params = [re.sub(r"[:=?].*$", "", p).strip().lstrip(".") for p in m.group(2).split(",")]
                out[name] = ([p for p in params if re.fullmatch(r"\w+", p)], body)
    return out


def _idents(text: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_$][\w$]*", text))


def taint(text: str, params: set[str]) -> set[str]:
    tainted = set(params) | _CONTAINERS
    decl = re.compile(r"(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[\w$]+)\s*(?::[^=]+)?=\s*([^;\n]+)")
    assign = re.compile(r"(?<![\w$.])([\w$]+)\s*[+\-*]?=(?!=)\s*([^;\n]+)")
    for _ in range(3):
        before = len(tainted)
        for rx in (decl, assign):
            for m in rx.finditer(text):
                if _idents(m.group(2)) & tainted:
                    lhs = m.group(1)
                    names = re.findall(r"(?:\w+\s*:\s*)?([\w$]+)(?:\s*=[^,}]+)?(?=[,}\]\s]|$)", lhs) if lhs[0] in "{[" else [lhs]
                    tainted |= {n for n in names if n not in _KEYWORDS}
        if len(tainted) == before:
            break
    return tainted


def _call_args(text: str, open_paren: int) -> str:
    return _balanced(text, open_paren, "(", ")") or text[open_paren: open_paren + 400]


def analyse_text(text: str, params: set[str], funcs: dict, depth: int = 0, seen: set | None = None) -> tuple[set, list, list]:
    """-> (sink kinds reached, evidence, names of unresolved callees that received a tainted argument)"""
    seen = seen if seen is not None else set()
    tainted = taint(text, params)
    kinds: set[str] = set()
    ev: list[str] = []
    unresolved: list[str] = []
    sink_spans = []
    for kind, rx in _SINKS.items():
        for m in rx.finditer(text):
            args = _call_args(text, m.end() - 1)
            if _idents(args) & tainted:
                kinds.add(kind)
                ev.append(f"{m.group(0).rstrip('( ').strip()}() at +{text.count(chr(10), 0, m.start())} lines")
            sink_spans.append(m.start())
    for m in re.finditer(r"(?<![\w$])((?:[\w$]+\.)*)([\w$]+)\s*\(", text):
        prefix, fname = m.group(1), m.group(2)
        full = prefix + fname
        if m.start() in sink_spans or fname in _KEYWORDS or _SAFE_CALL.match(full) or fname in _SAFE_METH:
            continue
        if any(rx.match(text, m.start()) for rx in _SINKS.values()):
            continue
        args = _call_args(text, m.end() - 1)
        if not (_idents(args) & tainted):
            continue
        callee = funcs.get(fname) if prefix in ("", "this.", "self.") else None
        if callee and depth < 2 and (fname, depth) not in seen:
            seen.add((fname, depth))
            k2, e2, u2 = analyse_text(callee[1], set(callee[0]), funcs, depth + 1, seen)
            kinds |= k2
            ev += e2
            unresolved += u2
        else:
            unresolved.append(full)
    return kinds, ev, unresolved


def handler_texts(tool: dict) -> tuple[list[str], dict, bool]:
    """Candidate handler bodies for this tool, plus the file's function index, and whether any is known-complete."""
    src = tool.get("module_src") or ""
    name = re.escape(tool.get("name", ""))
    funcs = functions(src) if src else {}
    texts: list[str] = []
    complete = False
    if tool.get("body_kind") == "callback" and tool.get("body"):
        texts.append(tool["body"])
        complete = len(tool["body"]) < 4400   # a window that hit the cap may have truncated the callback
    for m in re.finditer(r"case\s+['\"]" + name + r"['\"]\s*:", src):
        seg = src[m.end(): m.end() + 2500]
        nxt = re.search(r"\n\s*(?:case\s+['\"`]|default\s*:)", seg)
        seg = seg[: nxt.start()] if nxt else seg
        texts.append(seg)
        complete = True
        for c in re.finditer(r"(?:this\.)?([\w$]+)\s*\(", seg):
            if c.group(1) in funcs and c.group(1) not in _KEYWORDS:
                texts.append(funcs[c.group(1)][1])
                break
    for m in re.finditer(r"['\"]?" + name + r"['\"]?\s*:\s*(?:async\s*)?(?:\([^)]*\)\s*=>|function\b|([\w$]+)\s*[,}\n])", src):
        if m.group(1) in funcs:
            texts.append(funcs[m.group(1)][1])
            complete = True
        else:
            body = _balanced(src, src.find("{", m.end() - 1)) if "{" in src[m.end() - 1: m.end() + 200] else None
            if body:
                texts.append(body)
                complete = True
    return texts, funcs, complete


def assess(tool: dict) -> Reach:
    params = {p for p in tool.get("input_schema", {}).get("properties", {}) if re.fullmatch(r"[\w$]+", p)}
    texts, funcs, complete = handler_texts(tool)
    if not texts or not params:
        return Reach("unknown")
    kinds: set[str] = set()
    ev: list[str] = []
    unresolved: list[str] = []
    for t in texts:
        k, e, u = analyse_text(t, params, funcs)
        kinds |= k
        ev += e
        unresolved += u
    if kinds:
        guarded = bool(_GUARD.search("\n".join(texts)))
        return Reach("sink_guarded" if guarded else "sink_unguarded", sorted(kinds), ev)
    # Deliberately never "no_sink" for JS/TS: handler resolution here is regex-level, and a wrong refutation (calling a
    # real hole "declared capability only") is worse than saying "unverified". Absence of evidence is not evidence.
    return Reach("unknown", forwarded=unresolved)
