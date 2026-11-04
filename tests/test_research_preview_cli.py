"""Smoke tests for the research-preview demo CLI.

The demos themselves need the private scanner packages (covered by tests/test_wargame_v2.py, which skips without them);
these tests only check wiring that is verifiable with the public install.
"""
import pytest
from typer.testing import CliRunner

pytest.importorskip("numpy")

from research_preview.cli import _DEMO_NOTICE, app  # noqa: E402

runner = CliRunner()


def test_preview_cli_lists_demos_and_labels_them():
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    for cmd in ("wargame", "guard-proxy", "dashboard", "remediate"):
        assert cmd in r.output
    assert "scripted demo" in _DEMO_NOTICE


def test_main_aisec_cli_no_longer_exposes_demos():
    from aisec.cli import app as main_app

    r = runner.invoke(main_app, ["--help"])
    assert "experimental" not in r.output
