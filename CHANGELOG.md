# Changelog

## Unreleased
- **Negative result: learned poisoning layer** (`research_preview/semantic.py`, protocol `docs/SEMANTIC_LAYER_PROTOCOL.md`, results `docs/STUDY.md` section 3d). A hashed n-gram classifier trained on MCP-Poison-Bench and the seen register caught 0.8% of MCPTox at a 2.9% false-positive rate on real tool metadata; by the pre-registered rule it is not part of the package.

## 0.5.0
- **External evaluation** (`benchmarks/poison/external.py`, protocol `docs/EXTERNAL_EVAL_PROTOCOL.md`), pre-registered and run once on two datasets written by other authors. MCPTox: 14.0% recall at medium+ on 485 poisoned tools, 0 false positives on the 362 legitimate tools of the same servers (naive regex 6.8%, mcpaudit 3.5%). MCP-Poison-Bench: 14.0% on 86 metadata payloads, 12/12 on its seen register and 0/74 on its held-out register (no baseline catches any held-out payload either). Results and limits in `docs/STUDY.md` section 3c.
- **Unity bridge reachability** (`aisec/reach_bridge.py`): commands are now followed into C# editor plugins (`switch`/`case` dispatchers, `{ "cmd", Handler }` tables, `Class.Method` across files), and JS senders that pass the command as an object field (`sendRequest({ method: "cmd" })`) are recognised. Unresolved calls and reflection make no claim.
- **Benchmark regression gate** (`benchmarks/check.py`, `benchmarks/baseline.json`, `.github/workflows/benchmarks.yml`): every measured number in `docs/STUDY.md` is re-derived from public data weekly and on detector PRs; any change in either direction fails until the baseline and docs are updated together. `benchmarks/fetch_corpus.py` fetches the labelled repositories at their pinned SHAs and validates each entry before running git.
- **Cross-language reachability through IPC bridges** (`aisec/reach_bridge.py`): string-literal commands sent from a JS/TS handler are followed into GDScript dispatcher arms in the same repository and checked for command/file/network/dynamic-code sinks. On the 135-repo study's labelled findings it removes 4 of 30 unseen false positives (previously 0) with all 31 accurate ones kept; 18 of 120 findings now get a decided verdict (was 7). Method and limits in `docs/STUDY.md` section 2. Also fixes `async (...) =>` being treated as a call and method signatures with function-typed parameters failing to resolve.
- **Structural detector hardened against obfuscation** (`aisec/poison.py`, measured by the new `benchmarks/poison/evasion.py`): look-alike letters (Unicode confusables + a mixed-script hidden layer), hard-wrapped and bulleted text, letter-spacing, doubled whitespace, base64url/base32/`\uXXXX` encodings, sentence fragmentation (adjacent-sentence window) and instructions split between the description and a parameter (combined document). Seen attacks caught under look-alike letters: 4 -> 39 of 54. Recall at medium+: seen 63.0% -> 74.1%, held-out 48.1% -> 53.7% (third held-out evaluation, see `docs/STUDY.md`); test FPR 0.03% -> 0.05% (2/3,974). Medium threshold re-fitted by the calibration procedure, 5.5 -> 6.0. **Fix:** patterns with literal single spaces no longer miss text with doubled spaces.
- **Evasion gate in CI** (`tests/test_poison_evasion.py`): per-transform retention floors plus unit tests for each new view and decoder.
- **Breaking: demos moved out of the package.** `aisec experimental ...` is gone; the scripted demos now live in the top-level `research_preview/` package (not in the wheel) and run as `python -m research_preview wargame|guard-proxy|dashboard|remediate`.
- **Detector quality gate in CI** (`tests/test_poison_quality.py`, `tests/fixtures/benign_tools.json`): recall floors on the 108 committed positives and a no-new-false-positives check on 66 realistic benign tool descriptions. Per-feature unit tests added in `tests/test_poison.py`; unused legacy weight/cap values removed from `aisec/poison.py`.
- **Doc correction:** seen-register recall at medium+ reproduces as 63.0% (34/54), not 61.1%; held-out and high-severity figures unchanged.
- **Tooling:** ruff now also checks bugbear, isort, pyupgrade and bandit rules; mypy runs in CI; coverage reported with a floor; `constraints.txt` pins the scanner versions used by CI; a `tests-gate` job aggregates required checks. Fixed `raise ... from` chaining in the CLI and a latent `None` iteration when a scanner report had `"findings": null`.
- **Docs:** README trimmed; policy, lifecycle, reporting and release details moved to `docs/REFERENCE.md`; added `CONTRIBUTING.md`; removed stray `.jules/` agent notes.

## 0.4.0
- **Version reset to the published line.** Development builds labelled 2.0-2.2 in the repository were never released; PyPI goes 0.3.0 -> 0.4.0.
- **Install matches the docs.** `[core]` and `[all]` now contain only packages that exist on PyPI. Unpublished scanners moved to a `[private]` extra that is documented as source-only.
- **Scripted demos separated from scanners.** `wargame`, `guard-proxy`, `dashboard` and `remediate` moved to `aisec experimental ...` and `aisec/experimental/`. They print a notice that they run on fixed synthetic inputs with pre-determined outcomes.
- **`aisec modules`** reports whether each scanner package is actually installed.
- **End-to-end demo** in `examples/demo-mcp-server`: a poisoned MCP tool fails the gate, the fixed server passes. A regression test keeps both behaviours locked in.
- **CI integration job** installs the published scanners so CLI tests run against real mcpaudit and memsentry instead of skipping.
- **Docs.** README leads with the measured MCP study; research-preview modules are no longer reported with perfect scores from self-generated fixtures (`docs/STUDY.md` section 5); module counts and the portfolio map are consistent.

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
