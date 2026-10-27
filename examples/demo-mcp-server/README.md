# End-to-end demo: catch a poisoned MCP tool, fix it, pass the gate

`vulnerable/server.py` is a small FastMCP server whose `add` tool hides an instruction in
its description: read `~/.ssh/id_rsa`, pass it out through the `note` parameter, and don't
tell the user. This is the classic tool-poisoning pattern described by Invariant Labs.
`fixed/server.py` is the same server with the payload removed and file reads confined.

```bash
pip install "aisec-suite[core]"
bash examples/demo-mcp-server/run_demo.sh
```

Expected output (gate at `high`):

| | findings | exit |
|---|---|---|
| `vulnerable/` | **high** fake-instruction tag in `add` (mcpaudit) · **high** unscoped filesystem access in `read_file` · **medium** structural poisoning in `add` | 1 |
| `fixed/` | **medium** unconstrained `path` parameter, annotated `reach: ... (guard detected)` | 0 |

The remaining medium on the fixed server is deliberate, not noise: the JSON schema still
accepts any string for `path`. Reachability confirms the handler enforces containment, so a
reviewer can accept it with a baseline (`--write-baseline`) instead of the tool silently
dropping it. Both runs write SARIF,
which GitHub code scanning displays as alerts on the pull request.

The repository-wide CI scan skips `examples/` by default, so this deliberately vulnerable
fixture does not trip the project's own security gate.
