from pathlib import Path
from typer.testing import CliRunner

from aisec.cli import app
from aisec.modules import resolve_module

def test_native_registry():
    for name in ("mcp", "memory", "rag", "training", "supply-chain", "behavior", "worm"):
        assert resolve_module(name).native is True

def test_native_commands():
    runner = CliRunner()
    for command, label in (
        ("training", "training"),
        ("behavior", "behavior"),
        ("supply-chain", "supply-chain"),
        ("worm", "worm"),
    ):
        result = runner.invoke(app, [command, "--help"])
        assert result.exit_code == 0, result.output
        assert label in result.output.lower()
