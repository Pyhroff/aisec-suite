from pathlib import Path
from typer.testing import CliRunner

from aisec.cli import app
from aisec.modules import resolve_module

def test_all_native_modules_are_marked_native():
    for name in ("mcp", "memory", "rag", "training", "supply-chain", "behavior", "worm"):
        assert resolve_module(name).native is True

def test_training_command_exists():
    result = CliRunner().invoke(app, ["training", "--help"])
    assert result.exit_code == 0
    assert "training" in result.stdout.lower()

def test_behavior_command_exists():
    result = CliRunner().invoke(app, ["behavior", "--help"])
    assert result.exit_code == 0
    assert "behavior" in result.stdout.lower()

def test_supply_chain_command_exists():
    result = CliRunner().invoke(app, ["supply-chain", "--help"])
    assert result.exit_code == 0
    assert "supply-chain" in result.stdout.lower()

def test_worm_command_exists():
    result = CliRunner().invoke(app, ["worm", "--help"])
    assert result.exit_code == 0
    assert "worm" in result.stdout.lower()
