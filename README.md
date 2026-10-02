# aisec-suite

[![tests](https://github.com/Pyhroff/aisec-suite/actions/workflows/tests.yml/badge.svg)](https://github.com/Pyhroff/aisec-suite/actions/workflows/tests.yml) ![python](https://img.shields.io/badge/python-3.10%E2%80%933.12-blue) ![license](https://img.shields.io/badge/license-MIT-green)

One command that runs three AI-security scanners on a repository and writes SARIF for GitHub code scanning.

| Scanner | What it checks | Input found automatically |
|---|---|---|
| [mcpaudit](https://github.com/Pyhroff/mcpaudit) | MCP tool poisoning and over-broad tool scope (static checks) | Tool definitions **extracted statically from source** (Python FastMCP decorators, TS/JS `registerTool`/`addTool`/`server.tool`), plus manifest `*.json` files |
| [memsentry](https://github.com/Pyhroff/memsentry) | Injected instructions and hidden payloads in agent context files | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.cursor/rules/*`, `copilot-instructions.md` |
| [ragsentry](https://github.com/Pyhroff/ragsentry) | Injection and retrieval manipulation in RAG source documents | A directory you pass with `--rag` |

No third-party code is executed: tool definitions are read from source, not by launching the server.

```bash
pip install "aisec-suite[scanners]"   # also installs pyhroff-mcpaudit, memsentry, pyhroff-ragsentry from PyPI
aisec scan . --sarif aisec.sarif --fail-on high
aisec scan . --rag ./docs --json findings.json
```

Exit codes: `0` clean, `1` a finding at or above `--fail-on`, `2` a scanner crashed (so a clean result can't be trusted; only with `--fail-on`). Use `--include-tests` to also extract tools from tests/examples/fixtures.

### Adopting it on an existing repo without a wall of red
```bash
aisec scan . --write-baseline .aisec-baseline.json     # accept what exists today
aisec scan . --baseline .aisec-baseline.json --fail-on high   # CI now fails only on NEW findings
```
Fingerprints ignore line numbers, so moving code around does not resurface accepted findings. Every run also writes a Markdown table to the GitHub job summary (`--summary`).

## GitHub Action
One line, no install step; the scanners come from PyPI:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: Pyhroff/aisec-suite@v0.2.0
    with:
      fail-on: high
```

Inputs: `path`, `fail-on`, `rag-dir`, `baseline`, `install`, `upload-sarif`. Needs `security-events: write` for the upload step. Inputs reach the shell only through quoted env vars, never interpolated into script text.

(The action itself has not yet been run on GitHub Actions; the CLI and adapters are tested, including with fake scanners in CI.)

## Honest scope
- Static extraction is best-effort. In a study of 90 public MCP repos it found tools in 53 (about 59%); "no tools found" prints a note and means *unknown*, not *safe*.
- Findings are heuristics for human review. In the same study only 37.5% (95% CI 24-53%) of mcpaudit v0.6's HIGH `permission_scope` findings were accurate, and none of the flagged repos had genuine tool poisoning. Use the patched scanners (mcpaudit 0.7 / memsentry 1.2) for fewer false positives; see `mcp-scan-study/REPORT.md`.
- mcpaudit's dynamic (live LLM) and rug-pull checks are not part of this suite; use mcpaudit directly for those.
- Line numbers for extracted tools point at the registration call, not the description text.

## Development
`pip install -e ".[dev]" && pytest -q` (adapter tests use in-memory fake scanners and always run; a few end-to-end tests skip unless the real scanners are installed).
