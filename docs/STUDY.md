# What the measurements say

Everything here was measured, not asserted, and every limit is stated next to the number. Scripts: `benchmarks/`.

## 1. Static MCP scanning on real code (90 + 45 repositories)

Pinned-SHA corpus of 135 public MCP server repos, findings hand-labelled.

| scanner version | pooled precision | recall |
|---|---|---|
| mcpaudit 0.6 | 38.8% | n/a |
| mcpaudit 0.7 | 69.4% | 80.6% |

Precision rose by cutting false positives on scope findings (vendored dirs, test fixtures, schema-only tools).

## 2. Reachability (`--reach`)

`aisec/reach.py` (Python AST taint, depth-2 helper following) and `reach_js.py` (JS/TS, positive evidence only) classify a tool handler as `sink_unguarded`, `sink_guarded`, `no_sink` or `unknown`.

* On 120 labelled findings it produced **zero wrong refutations** (a finding lowered by reach that was actually real).
* It yields evidence on only about **9% of findings** and does **not** reduce false positives on this corpus. The dominant false-positive cluster (Unity/Godot bridge servers) forwards parameters to IPC calls reach cannot resolve, so the verdict is `unknown`.
* Rejected experiment: treating "no capability found in the handler" as refutation. It produced wrong refutations and was removed. Name-based guard detection (`validate_*`, `safe_*`) was removed for the same reason: it downgraded accurate findings. Guards now count only containment checks and allowlist membership.

## 3. Tool-poisoning detection benchmark

Question: can a static detector flag malicious instructions hidden in MCP tool metadata, and at what false-positive cost?

**Design.** 108 synthetic positives across categories from MCPTox (explicit/implicit hijack, parameter tampering) and Invariant Labs (shadowing, exfil via parameter, secrecy, hidden Unicode, schema-field, encoded). Split into a **seen** register (used to develop the detector) and a **held-out** register (written separately, same categories, different phrasing and mechanics) to avoid the circularity MCP-Poison-Bench warns about. 8,075 negatives are real tool descriptions from the study corpus, split by repo hash into **calibration** (4,101, used to set thresholds) and **test** (3,974). Wilson 95% intervals in `benchmarks/poison/run.py`.

**Results (final run; positives 54 seen / 54 held-out; FPR on test negatives)**

| detector | recall seen | recall held-out | FPR |
|---|---|---|---|
| naive regex | 42.6% | 0.0% | 0.0% |
| mcpaudit description scan | 42.6% | 3.7% | 0.88% (medium+), 0.05% (high) |
| **aisec structural (medium+)** | **61.1%** | **48.1%** | **0.03% (1/3974)** |
| aisec structural (high) | 20.4% | 13.0% | 0.0% |

Reading: pattern matching memorises its own examples (42.6% seen vs 0-4% held-out). The structural detector (decoding views: invisible chars, Unicode tag block, bidi, NFKC, base64, hex, percent, HTML entities, rot13; per-sentence co-occurrence of model-directed, cross-tool, sensitive-data, data-flow, concealment and override features; parameter descriptions/defaults/enums scanned too) generalises better but still misses about half of held-out attacks.

**Honesty notes.**
* The held-out register was evaluated **twice**. Run 1 (initial detector): 12/54 (22.2%), FPR 1/3974. Between runs I changed features and weights using only seen-register misses and calibration negatives, and moved the medium target from 1% to 0.5% calibration FPR (threshold 6.5 -> 5.5). Run 2 above is 26/54. Held-out misses were never inspected, but a second evaluation still makes the held-out number optimistic compared with a single pre-registered run.
* Positives are synthetic, single-author and defanged; they test metadata only, not runtime behaviour.
* Negatives are presumed clean, not verified; some "false positives" may be real issues, and some negatives may be undetected attacks.
* The detector is a heuristic aid for human review. A 48% held-out recall means it is not a security boundary.

## 4. Context

* MCPTox (arXiv 2508.14925): tool-poisoning attack taxonomy and measurements on real MCP servers.
* MCP-Poison-Bench (github.com/chirag-dewan/MCP-Poison-Bench): argues for held-out registers.
* Cloud Security Alliance note on MCP tool poisoning.

## Reproduce

```
python -m benchmarks.eval_reach --study <study> --corpus <study>/corpus --json out.json
python -m benchmarks.poison.calibrate --study <study>
python -m benchmarks.poison.run --study <study> --json out.json
```
