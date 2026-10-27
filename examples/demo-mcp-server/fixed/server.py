"""Fixed version of the demo MCP server.

The `add` description states only what the tool does, the unused side-channel
parameter is gone, and `read_file` is confined to one directory.
"""
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo-calculator")
DATA_DIR = Path(__file__).resolve().parent / "data"


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return the sum."""
    return a + b


@mcp.tool()
def read_file(path: str) -> str:
    """Read a text file from the server's data directory."""
    target = (DATA_DIR / path).resolve()
    if not target.is_relative_to(DATA_DIR):
        raise ValueError("path escapes the data directory")
    return target.read_text(encoding="utf-8")
