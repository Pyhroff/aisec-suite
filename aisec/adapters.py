"""Adapters that run each scanner and normalise its findings. Scanners are imported lazily; a missing
scanner is reported and skipped rather than crashing the run."""
from __future__ import annotations

import json
import os
import pathlib

from aisec import reach
from aisec.extract import extract_tools
from aisec.model import Finding

CONTEXT_NAMES = {"CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md"}
_SKIP = {"node_modules", ".git", "venv", ".venv"}
_CHUNK = 50  # large manifests scale super-linearly in mcpaudit's cross-tool check


def _rel(p: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def _walk(root: pathlib.Path):
    """Yield regular files under root, pruning vendored dirs *before* descending and never following symlinks
    (a repo under scan is untrusted input: a symlink must not make us read files outside it)."""
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _SKIP]
        for name in files:
            p = pathlib.Path(dirpath, name)
            if not p.is_symlink():
                yield p


def scan_mcp_source(root: pathlib.Path, include_tests: bool = False, warnings: list[str] | None = None, reach_mode: str = "annotate", structural: bool = True) -> tuple[list[Finding], int]:
    """Statically extract tools from source, run mcpaudit's static checks. Returns (findings, tools_found)."""
    try:
        from mcpaudit.checks.description_scan import scan_descriptions
        from mcpaudit.checks.permission_scope import check_scope
        from mcpaudit.manifest import ServerManifest, ToolManifest
    except ImportError:
        if warnings is not None:
            warnings.append("mcpaudit not installed: skipped MCP tool checks")
        return [], 0
    tools = extract_tools(root, include_tests)
    findings: list[Finding] = []
    for i in range(0, len(tools), _CHUNK):
        part = tools[i:i + _CHUNK]
        manifest = ServerManifest(server_name=root.name, tools=[ToolManifest(t["name"], t["description"], t["input_schema"]) for t in part])
        by_name = {t["name"]: t for t in part}
        for f in scan_descriptions(manifest) + check_scope(manifest):
            src = by_name.get(f.tool, {})
            sev, note = f.severity.value, ""
            if reach_mode != "off" and f.check == "permission_scope":
                r = reach.assess(src)
                sev, note = reach.adjust_severity(sev, r, reach_mode == "strict"), r.note()
            findings.append(Finding("mcpaudit", f"{f.check}: {f.title}", sev, f.detail, src.get("file", "."), src.get("line", 1), note))
    if structural:
        from aisec import poison
        findings += poison.findings_for(tools)
    return findings, len(tools)


def scan_manifest_files(root: pathlib.Path, warnings: list[str] | None = None) -> list[Finding]:
    """Scan *.json files shaped like {"server_name":..., "tools":[...]} (e.g. an mcpaudit baseline)."""
    try:
        from mcpaudit.checks.description_scan import scan_descriptions
        from mcpaudit.checks.permission_scope import check_scope
        from mcpaudit.manifest import ServerManifest
    except ImportError:
        return []
    out: list[Finding] = []
    for p in _walk(root):
        if p.suffix != ".json" or p.stat().st_size > 5_000_000:
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            if not (isinstance(d, dict) and "server_name" in d and isinstance(d.get("tools"), list)):
                continue
            m = ServerManifest.from_dict(d)
        except Exception:
            continue
        for f in scan_descriptions(m) + check_scope(m):
            out.append(Finding("mcpaudit", f"{f.check}: {f.title}", f.severity.value, f.detail, _rel(p, root), 1))
    return out


def scan_context_files(root: pathlib.Path, warnings: list[str] | None = None) -> list[Finding]:
    try:
        from memsentry.memfile import MemoryFile
        from memsentry.scanner import scan_file
    except ImportError:
        if warnings is not None:
            warnings.append("memsentry not installed: skipped agent-context file checks")
        return []
    out: list[Finding] = []
    for p in _walk(root):
        if p.name in CONTEXT_NAMES or (p.parent.name == "rules" and p.parent.parent.name == ".cursor"):
            for f in scan_file(MemoryFile.load(p)):
                out.append(Finding("memsentry", f"{f.check}: {f.title}", f.severity.value, f.detail, _rel(p, root), f.line))
    return out


def scan_rag_dir(rag_dir: pathlib.Path, root: pathlib.Path, warnings: list[str] | None = None) -> list[Finding]:
    try:
        from ragsentry.scanner import scan_path
    except ImportError:
        if warnings is not None:
            warnings.append("ragsentry not installed: skipped RAG document checks")
        return []
    out: list[Finding] = []
    for fname, fs in scan_path(str(rag_dir)).items():
        for f in fs:
            out.append(Finding("ragsentry", f"{f.check}: {f.title}", f.severity.value, f.detail, _rel(pathlib.Path(fname), root), f.line))
    return out
