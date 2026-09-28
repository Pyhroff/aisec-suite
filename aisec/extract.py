"""Statically extract MCP tool definitions (name, description, input schema) from source code.

No code is executed. Supports Python FastMCP-style decorators (via ast) and TypeScript/JavaScript
registerTool()/addTool()/server.tool() calls with zod or JSON schemas, plus generic
{name, description, inputSchema} object literals. Best-effort: a 90-repo study found about 60% of
repos yielded tools, so treat "no tools found" as "unknown", not "safe".
"""
from __future__ import annotations

import ast
import pathlib
import re

_ALWAYS_SKIP = {"node_modules", ".git", "dist", "build", "venv", ".venv", "__pycache__", "docs"}
_TEST_DIRS = {"tests", "test", "__tests__", "examples", "example", "e2e", "bench", "fixtures", "scripts"}
_TEST_FILE = re.compile(r"\.(spec|test)\.[jt]sx?$")
_STR = r'(?:"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'|`((?:[^`\\]|\\.)*)`)'
_ANCHOR = re.compile(r"(?:registerTool|addTool|defineTool|definePageTool|\.tool)\s*\(\s*")


def _lit(m):
    return next(g for g in m.groups() if g is not None)


def _files(root: pathlib.Path, exts, include_tests: bool):
    skip = set(_ALWAYS_SKIP) | (set() if include_tests else _TEST_DIRS)
    for p in root.rglob("*"):
        if p.suffix in exts and p.is_file() and p.stat().st_size < 400_000:
            rel = p.relative_to(root)
            if set(rel.parts[:-1]) & skip:
                continue
            if not include_tests and _TEST_FILE.search(p.name):
                continue
            yield p


def _py_tools(path: pathlib.Path) -> list[dict]:
    try:
        tree = ast.parse(path.read_text(errors="ignore"))
    except Exception:
        return []
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        dec = None
        for d in fn.decorator_list:
            base = d.func if isinstance(d, ast.Call) else d
            if (isinstance(base, ast.Attribute) and base.attr == "tool") or (isinstance(base, ast.Name) and base.id == "tool"):
                dec = d
                break
        if dec is None:
            continue
        name, desc = fn.name, ast.get_docstring(fn) or ""
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                    name = str(kw.value.value)
                if kw.arg == "description" and isinstance(kw.value, ast.Constant):
                    desc = str(kw.value.value)
            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                name = dec.args[0].value
        props = {}
        for a in fn.args.args + fn.args.kwonlyargs:
            if a.arg in ("self", "cls", "ctx", "context"):
                continue
            ann = ast.unparse(a.annotation) if a.annotation else ""
            if "Context" in ann:
                continue
            s: dict = {"type": "string"}
            if ann.startswith("Literal["):
                s["enum"] = ["?"]
            elif re.search(r"\bint\b", ann):
                s = {"type": "integer"}
            elif re.search(r"\bfloat\b", ann):
                s = {"type": "number"}
            elif re.search(r"\bbool\b", ann):
                s = {"type": "boolean"}
            elif re.search(r"\b(list|List)\b", ann):
                s = {"type": "array"}
            elif re.search(r"\b(dict|Dict)\b", ann) or (ann and not re.search(r"\bstr\b", ann)):
                s = {"type": "object"}
            props[a.arg] = s
        out.append(dict(name=name, description=desc, input_schema={"type": "object", "properties": props}, line=fn.lineno))
    return out


def _zod_props(block: str) -> dict:
    props = {}
    for m in re.finditer(r"(\w+)\s*:\s*(?:z|zod)\s*\.\s*(string|number|boolean|enum|array|object|any|union|record)\s*\(([^)]*)\)([^,\n]*(?:\n\s*\.[^,\n]*)*)", block):
        key, kind, _arg, chain = m.groups()
        s = {"type": {"string": "string", "number": "number", "boolean": "boolean", "array": "array", "enum": "string"}.get(kind, "object")}
        if kind == "enum":
            s["enum"] = ["?"]
        if re.search(r"\.regex\(|\.startsWith\(|\.endsWith\(|\.includes\(", chain):
            s["pattern"] = "?"
        if re.search(r"\.max\(|\.length\(", chain) and kind == "string":
            s["maxLength"] = 1
        if re.search(r"\.(url|email|uuid|datetime)\(", chain):
            s["format"] = "?"
        props[key] = s
    return props


def _json_props(block: str) -> dict:
    props = {}
    for pm in re.finditer(r"(\w+)\s*:\s*\{\s*type\s*:\s*['\"](\w+)['\"]([^{}]*)\}", block):
        k, ty, tail = pm.groups()
        sc = {"type": ty}
        for f in ("enum", "pattern", "format", "maxLength"):
            if re.search(r"\b%s\s*:" % f, tail):
                sc[f] = "?"
        props[k] = sc
    return props


def _collect_consts(text: str, consts: dict) -> None:
    for m in re.finditer(r"(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*" + _STR + r"\s*(?:as const)?\s*[;\n]", text):
        consts[m.group(1)] = next(g for g in m.groups()[1:] if g is not None)


def _ts_tools(path: pathlib.Path, consts: dict) -> list[dict]:
    t = path.read_text(errors="ignore")
    out = []
    anchors = list(_ANCHOR.finditer(t))
    for i, m in enumerate(anchors):
        end = anchors[i + 1].start() if i + 1 < len(anchors) else len(t)
        win = t[m.end(): min(end, m.end() + 4500)]
        name = None
        if win.startswith("{"):
            nm = re.search(r"\bname\s*:\s*(?:" + _STR + r"|([A-Za-z_]\w*))", win[:600])
        else:
            nm = re.match(r"(?:" + _STR + r"|([A-Za-z_][\w.]*))\s*,", win)
        if nm:
            name = next((g for g in nm.groups()[:3] if g is not None), None) or consts.get(nm.group(4))
        if not name:
            continue
        desc = None
        dm = None if win.startswith("{") else re.match(r"(?:" + _STR + r")\s*,\s*" + _STR, win)
        if dm:
            desc = next(g for g in dm.groups()[3:] if g is not None)
        else:
            dd = re.search(r"description\s*:\s*" + _STR, win)
            if dd:
                desc = _lit(dd)
        if desc is None:
            continue
        props = _zod_props(win)
        props.update({k: v for k, v in _json_props(win).items() if k not in props})
        out.append(dict(name=name, description=desc, input_schema={"type": "object", "properties": props}, line=t.count("\n", 0, m.start()) + 1))
    return out


def extract_tools(root: str | pathlib.Path, include_tests: bool = False) -> list[dict]:
    """Return de-duplicated tool dicts: name, description, input_schema, file (relative), line."""
    root = pathlib.Path(root)
    tools: list[dict] = []
    for p in _files(root, {".py"}, include_tests):
        for t in _py_tools(p):
            tools.append({**t, "file": str(p.relative_to(root))})
    ts = list(_files(root, {".ts", ".js", ".mjs", ".tsx"}, include_tests))
    consts: dict = {}
    for p in ts:
        try:
            _collect_consts(p.read_text(errors="ignore"), consts)
        except Exception:
            pass
    for p in ts:
        try:
            for t in _ts_tools(p, consts):
                tools.append({**t, "file": str(p.relative_to(root))})
        except Exception:
            pass
    seen, uniq = set(), []
    for t in tools:
        k = (t["name"], t["description"][:60])
        if k not in seen:
            seen.add(k)
            uniq.append(t)
    return uniq
