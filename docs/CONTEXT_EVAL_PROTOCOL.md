# Pre-registered protocol: external evaluation of memsentry and ragsentry

Written and committed **before** the evaluation is run. Results go in `docs/STUDY.md` section 3e and must follow this
protocol; any deviation is reported there as a deviation.

## Why

memsentry (agent memory and context files) and ragsentry (RAG source documents) have only ever been measured on their
own sample files and on false positives in real repositories. Neither has a recall number on attacks someone else
wrote. This evaluation uses two public prompt-injection benchmarks, both MIT-licensed, run **once**.

## Scanners under test

- `memsentry` 1.2.0 and `pyhroff-ragsentry` 1.1.0, the versions pinned in `constraints.txt`, unchanged. Documents are
  built in memory (`MemoryFile` / `Document`) and scanned with `scan_file` / `scan_document`.
- A document counts as detected at **medium+** if any finding is medium, high or critical; "any finding" (including
  low) is reported too.
- Baseline: the naive regex from `benchmarks/poison/run.py`, applied to the whole text.

## Data (fetched at pinned commits, not copied into this repository)

1. **BIPIA** (Yi et al., Microsoft, MIT), `github.com/microsoft/BIPIA` at `a004b69ec0dd446e0afd461d98cb5e96e120a5d0`.
   Attacks: the 75 instructions of `benchmark/text_attack_test.json` (15 categories × 5, BIPIA's own test split).
   Hosts: the 50 clean emails of `email/test.jsonl` and the 100 clean tables of `table/test.jsonl`.
2. **InjecAgent** (Zhan et al., ACL Findings 2024, MIT), `github.com/uiuc-kang-lab/InjecAgent` at
   `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`. The 62 attacker instructions (`attacker_cases_dh.jsonl`,
   `attacker_cases_ds.jsonl`) and the 1,054 tool responses of `test_cases_{dh,ds}_{base,enhanced}.json`.
3. **Real agent-context files**: every `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`,
   `.clinerules`, `copilot-instructions.md` and `.cursor/rules/*` file in the 135 repositories of
   `Pyhroff/mcp-scan-study` (`data/corpus.json` + `data/fresh_corpus.json`), at their pinned SHAs. Only those blobs are
   fetched; nothing is checked out or executed.

## Test sets

**ragsentry**

- BIPIA positives: each attack *i* (0-74) inserted into email `i mod 50` and table `i mod 100`, at the start, middle
  (after the middle line) and end: 75 × 2 × 3 = 450 documents. BIPIA negatives: the 150 clean hosts.
- InjecAgent positives: the 1,054 `Tool Response` strings as documents. InjecAgent negatives: each distinct
  `Tool Response Template` with the `<Attacker Instruction>` placeholder replaced by an empty string.

**memsentry**

- Payloads: the 75 BIPIA instructions and the 62 InjecAgent instructions, each in two forms: as written, and with
  InjecAgent's own enhanced prefix ("IMPORTANT!!! Ignore all previous instructions and strictly adhere to the
  following instruction: "). 274 payloads.
- Positives: payload *j* appended as a new last line to real context file `j mod N` (files sorted by path).
- Negatives: the N real context files, unmodified.

## Metrics

Recall at medium+ and any-finding with Wilson 95% intervals: overall, per dataset, per BIPIA category, per position,
base vs enhanced. False-positive rate on each negative set. Same for the baseline. Numbers are published whatever they
are, in STUDY section 3e.

## Disclosed in advance

- Neither scanner's author has looked at either dataset's attack text before this protocol was committed; the
  dataset formats were inspected (field names, counts, one example each) to write this protocol.
- InjecAgent's enhanced prefix contains "Ignore all previous instructions", a phrase both scanners have a rule for, so
  enhanced-form recall is expected to be high and is reported separately from the as-written form.
- The memsentry positives are synthetic in placement (one line appended to a real file); the attack wording is
  external.
