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
| **aisec structural (medium+)** | **74.1%** | **53.7%** | **0.05% (2/3974)** |
| aisec structural (high) | 37.0% | 16.7% | 0.0% |
| *before this change, medium+* | *63.0%* | *48.1%* | *0.03% (1/3974)* |
| *before this change, high* | *20.4%* | *13.0%* | *0.0%* |

Reading: pattern matching memorises its own examples (42.6% seen vs 0-4% held-out). The structural detector (decoding views: invisible chars, Unicode tag block, bidi, NFKC, base64, hex, percent, HTML entities, rot13; per-sentence co-occurrence of model-directed, cross-tool, sensitive-data, data-flow, concealment and override features; parameter descriptions/defaults/enums scanned too) generalises better but still misses about half of held-out attacks.

**Correction (reproduced from the committed positives):** an earlier revision of this table reported 61.1% (33/54) for seen recall at medium+. Re-running the committed detector on `benchmarks/poison/attacks.py` gives 34/54 = 63.0%; held-out (26/54) and high-severity (11/54, 7/54) figures reproduce exactly. `tests/test_poison_quality.py` now locks these in.

**Honesty notes.**
* The held-out register has been evaluated **three times**. Run 1 (initial detector): 12/54 (22.2%), FPR 1/3974. Between runs I changed features and weights using only seen-register misses and calibration negatives, and moved the medium target from 1% to 0.5% calibration FPR (threshold 6.5 -> 5.5). Run 2 above is 26/54. Held-out misses were never inspected, but a second evaluation still makes the held-out number optimistic compared with a single pre-registered run.
* Positives are synthetic, single-author and defanged; they test metadata only, not runtime behaviour.
* Negatives are presumed clean, not verified; some "false positives" may be real issues, and some negatives may be undetected attacks.
* The detector is a heuristic aid for human review. A 48% held-out recall means it is not a security boundary.

* Run 3 (current table) followed the evasion work in section 3b. Every change was motivated by the seen-register
  evasion suite and checked only against calibration negatives; held-out misses were still never inspected, but the
  aggregate held-out number was printed while choosing between variants, so treat 53.7% as more optimistic again.
  The variant was chosen on seen-register evasion retention and calibration FPR, not on held-out recall.

## 3b. Evasion robustness

Question: does detection survive cheap, meaning-preserving obfuscation an attacker would try first against an open
detector? `benchmarks/poison/evasion.py` takes the **seen** attacks the detector catches (held-out stays untouched),
applies one transform, and counts how many are still caught. Every transform leaves the instruction readable to an LLM.

**Seen attacks still caught after each transform (of 54)**

| transform | before | current |
|---|---|---|
| none | 34 | **40** |
| control: upper-case (encoded blobs kept) | 34 | 40 |
| control: doubled spaces | 27 | **39** |
| Cyrillic/Greek look-alike letters | 4 | **39** |
| hard-wrap at 40 columns | 19 | **39** |
| markdown bullet list | 27 | **40** |
| sentence fragmentation | 27 | **37** |
| letter-spacing (`r e a d`) | 22 | **39** |
| zero-width space inside words | 44 | 44 |
| tail as base64url blob | 40 | 40 |
| tail as base32 blob | 11 | **40** |
| tail as `\uXXXX` escapes | 11 | **40** |
| second half moved into a parameter description | 33 | **37** |

Retention relative to each version's own base set is in `evasion.py --json`; the current minimum is 87.5% (look-alike
letters, 35/40). The controls exposed a real bug in the previous version: some patterns contained literal single spaces, so doubling
the spaces between words dropped 7 detections.

**What changed in the detector.** One extra *canonical* view per text (Unicode confusables folded to Latin,
spaced-out letters re-joined, hard-wrapped lines and bullet lists reflowed into running text, whitespace collapsed); a
*mixed-script* hidden layer (a word mixing Latin with look-alike letters from another script); base64url, base32 and
`\uXXXX`/`\xXX` decoders; a sentence-pair window (adjacent sentences scored together at a fixed 1.5 discount, and a
pair can only win outright); and the description plus parameter descriptions scored as one document so an instruction
split across fields still co-occurs. The window raises scores on benign text too, so the thresholds were re-fitted by
the unchanged calibration procedure: medium 5.5 -> 6.0, high stays 9.5 (calibration FPR 0.44% / 0.05%).

**Cost.** Test-half false positives went from 1 to 2 of 3,974 (no high-severity ones). The new one is a hard-wrapped
docstring sentence that the old line-splitting cut in half; reflowed, it trips an existing concealment pattern
("without ... conversation"). It was found on the test half, so it was reported, not tuned away.

**Limits.** The transforms and the fixes have the same author, so this measures resistance to *these* obfuscations;
the confusables table is broader than the transform's (Armenian, small capitals, more Cyrillic/Greek) but not the full
Unicode list. Paraphrase is still the dominant failure mode (section 3), and an attacker who reads the source can still
write an instruction that avoids every feature.

## 4. Context

* MCPTox (arXiv 2508.14925): tool-poisoning attack taxonomy and measurements on real MCP servers.
* MCP-Poison-Bench (github.com/chirag-dewan/MCP-Poison-Bench): argues for held-out registers.
* Cloud Security Alliance note on MCP tool poisoning.

## Reproduce

```
python -m benchmarks.eval_reach --study <study> --corpus <study>/corpus --json out.json
python -m benchmarks.poison.calibrate --study <study>
python -m benchmarks.poison.run --study <study> --json out.json
python -m benchmarks.poison.evasion --json evasion.json
```

---

## 5. Research-preview modules (not evaluated to this standard)

The private modules (`weightspecter`, `attestinfer`, `circuitshield`, `tokenspecter`, `specprove-sec`) have so far been tested only on fixtures I generated myself, with the attack and the detector written by the same person. Perfect scores on that kind of corpus measure whether the code recognises its own fixtures, which is the circularity section 3 was designed to avoid. They are therefore **not reported as detection results here**.

Before any of them gets a number in this document it needs what section 3 has: attacks written independently of the detector, a held-out split, real negatives, and stated intervals and limits.
