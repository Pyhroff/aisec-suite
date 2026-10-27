"""The demo fixture must stay detectable, and the fixed version must stay clean."""
import pathlib

from aisec import extract, poison

DEMO = pathlib.Path(__file__).resolve().parent.parent / "examples" / "demo-mcp-server"


def _scores(variant: str) -> dict:
    tools = extract._py_tools(DEMO / variant / "server.py")
    return {t["name"]: poison.detect(t)[1] for t in tools}


def test_vulnerable_add_tool_is_flagged():
    assert _scores("vulnerable")["add"] in {"medium", "high"}


def test_fixed_server_is_clean():
    assert all(sev is None for sev in _scores("fixed").values())
