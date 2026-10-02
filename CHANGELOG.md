# Changelog

## 0.3.0
- **Reachability** (`--reach off|annotate|strict`): Python AST taint and JS/TS handler analysis mark scope findings as sink reached / guarded / absent. Zero wrong refutations on 120 labelled findings.
- **Structural tool-poisoning detector** (`--structural/--no-structural`, on by default): decodes hidden and encoded text, scores model-directed instructions in descriptions and parameter metadata. Held-out recall 48.1% at 0.03% false-positive rate on 3,974 real descriptions; see `docs/STUDY.md` for method and limits.
- Benchmarks (`benchmarks/`) with seen/held-out registers and calibration/test negatives.

## 0.2.0
- **Security:** the GitHub Action no longer interpolates inputs into shell script text (script-injection sink); inputs go through env vars and are quoted.
- **Reliability:** a crashing scanner is reported as a warning (and exit code 2 when `--fail-on` is set) instead of a traceback that looked like "findings exist" (exit 1).
- **Safe walking:** vendored dirs are pruned before descent; symlinks are never followed, so a scanned repo cannot make the tool read files outside it.
- **Adoption:** `--write-baseline` / `--baseline` accept today's findings and fail only on new ones. Fingerprints ignore line numbers, so unrelated edits don't resurface them.
- **Visibility:** Markdown job summary (`--summary`, auto-written to `$GITHUB_STEP_SUMMARY`); SARIF now carries `security-severity`, tags, help links and `partialFingerprints` so GitHub ranks and de-duplicates alerts across runs.
- **Tests/CI:** adapter tests with in-memory fake scanners now run in CI (previously skipped there); Python 3.10-3.12 matrix; ruff; least-privilege workflow permissions.
- Scanners are now on PyPI (`pyhroff-mcpaudit`, `memsentry`, `pyhroff-ragsentry`); `pip install "aisec-suite[scanners]"` and the Action need no install command. Trusted-publishing release workflow added.
- Action gains `baseline` and `upload-sarif` inputs.

## 0.1.0
- Initial release: unified `aisec scan`, static MCP tool extraction, SARIF output.
