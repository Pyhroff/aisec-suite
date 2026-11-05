# Pre-registered protocol: external evaluation of the structural poisoning detector

Written and committed **before** the evaluation is run. The results section of `docs/STUDY.md` (3c) must follow
this protocol exactly; any deviation is reported there as a deviation, not silently applied.

## Why

Every positive in `benchmarks/poison/attacks.py` was written by the detector's author, and the held-out register
has been evaluated three times (STUDY section 3). Neither measures how the detector does on attacks someone else
wrote. This evaluation uses two public benchmarks built by other authors, run **once**.

## Detector under test

- `aisec.poison.detect` at aisec-suite commit `ffc5b58` (master after #58), unchanged.
- Thresholds as committed: medium 6.0, high 9.5. No retuning, no feature changes, before or after the run.
- Baselines reported alongside: the naive regex and `mcpaudit` 0.8.0 `description_scan` from
  `benchmarks/poison/run.py`.

## Data (fetched at pinned commits, not copied into this repository)

1. **MCPTox** (Wang et al., AAAI 2026), `github.com/zhiqiangwang4/MCPTox-Benchmark` at
   `f85189f9ad12504c197c7f920ab818a40657b1fa`.
   - Positives: every entry of `pure_tool.json` (485 unique poisoned tool descriptions over 45 real MCP servers),
     scored as `{name: tool_name, description: tool_content}`. No input schema is provided for these tools, so
     only the description is scanned.
   - Negatives: the legitimate tools listed in each server's `clean_system_promot` in `response_all.json`,
     parsed from its `Tool:` / `Description:` / `Arguments:` blocks (argument descriptions become schema
     property descriptions).
   - The repository has no licence file: it is used for evaluation only and nothing from it is redistributed.
2. **MCP-Poison-Bench** (Dewan, MIT), `github.com/chirag-dewan/MCP-Poison-Bench` at
   `944ccbb6d8137c08ae1e0027ea525fd1b6b188a2`.
   - Positives: every payload in the `seen` and `heldout` registers of `fixtures/payloads.py` (all objective
     sets) whose carrier is metadata a static scanner can see: `description`, `schema_field`,
     `shadow_description`. `tool_result` (rug-pull, runtime output) is out of scope for a metadata scanner and is
     reported as excluded, not as a miss. Payloads are obtained by importing that one file (it imports only
     `dataclasses`) in an isolated interpreter.
   - Each payload is scored as appended to its benchmark's benign host description, or as a parameter
     description for `schema_field`.

## Metrics

- Recall at medium+ and at high, overall and per MCPTox paradigm (Template-1/2/3) and risk category, and per
  MCP-Poison-Bench attack class and register, with Wilson 95% intervals.
- False-positive rate on the MCPTox legitimate tools at medium+ and high.
- The run is executed once. Numbers are published whatever they are, in STUDY section 3c, with this file's
  commit as the reference.

## Known contamination, disclosed up front

- The detector's feature families were designed from the attack *taxonomies* in the MCPTox paper, Invariant Labs'
  write-ups and MCP-Poison-Bench's README (STUDY section 3). The detector's author did not use either dataset's
  payloads.
- While checking the data formats for this protocol, one MCPTox example (`FileSystem_1`) was viewed in full. No
  detector output on any external example was looked at before this protocol was committed.

## Reproduce

```
python -m benchmarks.poison.external --data <dir> --fetch     # clone both datasets at the pinned commits
python -m benchmarks.poison.external --data <dir> --json external.json
```
