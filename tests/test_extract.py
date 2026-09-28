import textwrap

from aisec.extract import extract_tools


def test_python_fastmcp_tool(tmp_path):
    (tmp_path / "server.py").write_text(textwrap.dedent('''
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x")

        @mcp.tool()
        def read_file(path: str, limit: int = 10) -> str:
            """Read a file from disk."""
            return ""
    '''))
    (t,) = extract_tools(tmp_path)
    assert t["name"] == "read_file" and t["description"] == "Read a file from disk."
    assert t["input_schema"]["properties"]["path"]["type"] == "string"
    assert t["input_schema"]["properties"]["limit"]["type"] == "integer"
    assert t["file"] == "server.py" and t["line"] >= 1


def test_typescript_register_tool_with_constant_name(tmp_path):
    (tmp_path / "index.ts").write_text(textwrap.dedent('''
        const FETCH_TOOL = "fetch_page";
        server.registerTool(
          FETCH_TOOL,
          {
            description: `Fetch a page.`,
            inputSchema: { url: z.string().url() },
          },
          async () => ({}),
        );
    '''))
    (t,) = extract_tools(tmp_path)
    assert t["name"] == "fetch_page"
    assert "format" in t["input_schema"]["properties"]["url"]


def test_tests_dir_excluded_unless_requested(tmp_path):
    d = tmp_path / "tests"
    d.mkdir()
    (d / "s.py").write_text('@mcp.tool()\ndef t():\n    """d"""\n')
    assert extract_tools(tmp_path) == []
    assert len(extract_tools(tmp_path, include_tests=True)) == 1
