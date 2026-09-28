# aisec-suite

One command that runs three AI-security scanners on a repository and writes SARIF for GitHub code scanning.

| Scanner | What it checks | Input found automatically |
|---|---|---|
| [mcpaudit](https://github.com/Pyhroff/mcpaudit) | MCP tool poisoning and over-broad tool scope (static checks) | Tool definitions **extracted statically from source** (Python FastMCP decorators, TS/JS `registerTool`/`addTool`/`server.tool`), plus manifest `*.json` files |
| [memsentry](https://github.com/Pyhroff/memsentry) | Injected instructions and hidden payloads in agent context files | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.cursor/rules/*`, `copilot-instructions.md` |
| [ragsentry](https://github.com/Pyhroff/ragsentry) | Injection and retrieval manipulation in RAG source documents | A directory you pass with `--rag` |

No third-party code is executed: tool definitions are read from source, not by launching the server.

```bash
pip install -e .            # plus the three scanners, installed from their repos
aisec scan . --sarif aisec.sarif --fail-on high
aisec scan . --rag ./docs --json findings.json
```

Exit code is 1 when `--fail-on` is set and a finding at or above that severity exists. Use `--include-tests` to also extract tools from tests/examples/fixtures.

## GitHub Action
`action.yml` scans, then uploads SARIF with `github/codeql-action/upload-sarif`. Until the scanners are published to a package index, pass an `install` command that installs them:

```yaml
- uses: Pyhroff/aisec-suite@main
  with:
    fail-on: high
    install: pip install git+https://github.com/Pyhroff/mcpaudit git+https://github.com/Pyhroff/memsentry git+https://github.com/Pyhroff/ragsentry
```
(Private scanner repos need a token in that URL. This action has not been run on GitHub yet; only the CLI is tested.)

## Honest scope
- Static extraction is best-effort. In a study of 90 public MCP repos it found tools in 53 (about 59%); "no tools found" prints a note and means *unknown*, not *safe*.
- Findings are heuristics for human review. In the same study only 37.5% (95% CI 24-53%) of mcpaudit v0.6's HIGH `permission_scope` findings were accurate, and none of the flagged repos had genuine tool poisoning. Use the patched scanners (mcpaudit 0.7 / memsentry 1.2) for fewer false positives; see `mcp-scan-study/REPORT.md`.
- mcpaudit's dynamic (live LLM) and rug-pull checks are not part of this suite; use mcpaudit directly for those.
- Line numbers for extracted tools point at the registration call, not the description text.

## Development
`pip install -e ".[dev]" && pytest -q` (8 tests; scanner-dependent tests skip if the scanners are absent).
