"b""RAG scanning must not treat VCS objects, dependencies or tool caches as documents."""
import pathlib
import sys
import types
from dataclasses import dataclass
from enum import Enum

from aisec.adapters import scan_rag_dir


class _Sev(Enum):
    HIGH = "high"


@dataclass
class _F:
    check: str = "hidden_payload"
    title: str = "invisible characters"
    severity: _Sev = _Sev.HIGH
    detail: str = ""
    line: int = 1


def test_rag_scan_skips_git_and_caches(tmp_path: pathlib.Path, monkeypatch):
    paths = [tmp_path / "docs" / "guide.md", tmp_path / ".git" / "objects" / "pack" / "p.pack",
             tmp_path / ".ruff_cache" / "x", tmp_path / "node_modules" / "a" / "README.md"]
    mod = types.ModuleType("ragsentry.scanner")
    mod.scan_path = lambda _root: {str(p): [_F()] for p in paths}
    monkeypatch.setitem(sys.modules, "ragsentry", types.ModuleType("ragsentry"))
    monkeypatch.setitem(sys.modules, "ragsentry.scanner", mod)

    findings = scan_rag_dir(tmp_path, tmp_path)

    assert [pathlib.Path(f.file).as_posix() for f in findings] == ["docs/guide.md"]
