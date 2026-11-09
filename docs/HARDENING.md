# Hostile-repository hardening

aisec-suite runs in CI on repositories it has never seen, including pull requests from strangers, so the repository is
the attacker's input. This note records what a stress run found.

Harness: `tools/hostile_inputs.py` (`python tools/hostile_inputs.py . <paths of mcpaudit, memsentry, ragsentry>`).
Regression tests: `tests/test_hostile_input.py`.

## Protocol (written before the first run)

- 128 families of hostile files, built into a small repository and scanned with the real `aisec scan <dir> --rag <dir>`:
  every text family (long runs, encodings, Unicode tricks, trigger phrases) placed in a TypeScript description and in a
  Python docstring, plus agent-context files, RAG documents, many-line files, thousands of tool registrations, huge
  zod/JSON schemas, deep nesting, taint chains, malformed manifests, and engine-side GDScript/C# for the reachability
  bridge. Sizes 50k, 100k, 200k characters, or 1k, 2k, 4k repeated items.
- A finding is a timeout (60 s), a scanner that reported itself crashed, a traceback, more than 5 s of cost at the
  middle size, or superlinear growth (largest over middle cost above 3.0 with the largest above 2 s). Best of 2 runs.
- Run once on the unmodified code, fix every finding with a regression test, run again.

## First run: 9 findings, 3 causes

| Cause | Where | Effect |
|---|---|---|
| The rot13 candidate pattern (`[A-Za-z]{3,}(?:\s+[A-Za-z]{2,}){4,}`) is retried from every position of a long unbroken run of letters and backtracked in full each time | `poison.views` | quadratic: a 30,000-character description took 9 s, 200,000 characters took over a minute. Six families timed out at 60 s (`a_run`, base64 and base32 look-alikes, `ignore` repeated without spaces, a ligature that NFKC expands to letters) |
| The e-mail pattern `\b[\w.+-]+@[\w-]+\.[\w.-]+\b` scans the rest of the run from every word boundary when there is no `@` | `poison` category `data_flow` | quadratic: 100,000 characters of `QUJD-_` took 12.6 s |
| The reachability analysis re-parses (Python) or re-indexes (JavaScript) the whole module for every tool in it | `reach.assess_python`, `reach_js.functions` | tools times module size: 1,500 Python tools in one file took 82 s; 2,000 timed out; JS registration was superlinear |

## Fixes

- The rot13 pattern only starts at a word boundary (same matches; checked equal to the old pattern on 20,000 random
  texts). The e-mail pattern bounds each part to the sizes the standard allows (64, 255, 255); checked equal in truth
  value on 50,000 random texts.
- `reach._parsed_module` and `reach_js.functions` are cached per module source, so a module is parsed once for all its tools.
  1,500 Python tools now take 0.4 s.

## Second run

0 findings in 128 families; costliest case 2.6 s. A residual: JavaScript registration is still mildly superlinear
(1,000 tools 1.5 s, 4,000 tools several seconds) because each tool is searched for in the module text.

## One more finding, from reading the results (not a protocol criterion)

A TypeScript or JavaScript tool whose description is longer than about 4,500 characters was **never extracted**, so no
check ever saw it: padding a description hid the tool, and an injection in it, from the scan. (Python was not affected.)
`aisec/extract.py` now looks for the description up to the next registration when the normal window does not hold it;
`test_padded_description_does_not_hide_a_tool` covers both registration shapes. Anything the extractor still cannot
parse remains "unknown", as `extract.py` already says.

## Checks that behaviour did not change

`poison.detect` on the 485 poisoned and 362 clean MCPTox tools (pinned commit of the external evaluation): identical
scores before and after (68 of 485 flagged at medium or above, 0 of 362 clean).
