# Pre-registered protocol: runtime guard v3

Written and committed **before** the evaluation is run, with the guard (`aisec/guard_v3.py`), its unit tests and the
evaluation script (`benchmarks/guard_v3_eval.py`). Results go in `docs/STUDY.md` section 3h. v1 and v2 are unchanged.

## What v3 changes, and why

One thing. Section 3g found that 40 of the 79 destination values v2 held in benign AgentDojo tasks were date strings the
phone-number pattern accepted. v3 requires a phone number to have 7-15 digits, 10 or more unless it starts with `+`, and
to not look like a date. Every other rule (tokenising, effect classes, word lists, email/URL/IBAN detection, approvals,
decisions) is v2's. This was derived from the 3g diagnosis only. No ASB data was used to design it; only the first two
attacker-tool names of ASB's `all_attack_tools.jsonl` and the file layout had been seen when this was written.

I am deliberately **not** touching v2's other known weakness (tools whose names contain no recognised verb are never
held), because fixing it now would mean tuning on the benchmark below.

## Data

1. **InjecAgent** base setting, pinned commit `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`, replay exactly as in
   `GUARD_V2_PROTOCOL.md`. Used as a **parity check**: v3 must equal v2 case for case.
2. **AgentDojo v1.2.2** ground-truth replay as in 3f/3g. **Development data**: the bug was diagnosed on it, so these
   numbers are a mechanical check of the fix, not held out.
3. **ASB** (Agent Security Bench, Zhang et al., ICLR 2025, MIT; `agiresearch/ASB`, commit
   `544540ff0788998072f7df463056fd17e62cc9f4`), **not previously used in this study**, the fresh benchmark. Files
   `data/all_attack_tools.jsonl` (400 attacker tools), `data/agent_task.jsonl` (10 agents x 5 tasks) and
   `data/all_normal_tools.jsonl` (20 normal tools). Nothing from it is executed; no model is called.

## ASB replay (fixed now)

- **Attacks.** For each of the 400 attacker tools and each of the 5 tasks of its `Corresponding Agent` (2,000 pairs, minus
  any whose agent has no task entry, reported): the guard gets the task as the user's request, observes one tool result
  (in ASB the injection arrives through a normal tool's output), then the attacker tool is called with the single
  argument `{"request": <Attacker Instruction>}`. **Stopped** = the call is held. Two naming arms: the tool name as
  given (CamelCase) and snake_case.
- **Benign cost.** For each (agent, task) pair, after one observed result, each of that agent's normal tools
  (`all_normal_tools.jsonl`) is called with no arguments. A pair is **held** if any call is held. This can only measure
  action-class holds (the benchmark gives no arguments for normal tools), so it understates v2/v3's destination cost.
  Stated, not hidden.
- Guards: v1 (`infer_policy` over all 420 tool names, no arguments), v2, v3. Trusted destinations: none.
- Reported: stopped overall and by `Attack Type` and by `Aggressive`, with Wilson 95% intervals; benign pairs held; the
  attacker tool names never held, and the share of attacker names with at least one recognised verb class.

## Predictions, written before the run

1. **InjecAgent parity:** v3 and v2 stop exactly the same cases (982/1,054) in both arms, case for case.
2. **AgentDojo (development):** v3 holds fewer benign tasks than v2 (at most 35 of 97) and still more than v1 (more than
   22). Attacks stopped by v3 are within 10 of v2's 606.
3. **ASB, v2 vs v3:** identical per case (ASB instructions contain no date-shaped destination).
4. **ASB, generalisation:** v3 stops between 15% and 60% of the 2,000 pairs; v1 stops under 10%. The 93% seen on
   InjecAgent does not transfer, because ASB's attacker tools have descriptive invented names (`ResourceAllocationHijack`)
   that often contain no verb v2 knows.
5. **ASB, benign cost:** v3 holds between 5% and 40% of the 50 (agent, task) pairs.

## Fixed before the run

The guard, word lists and replay are not changed after the run. A change motivated by the results is a v4 on a new
benchmark. Ground truth is an idealised agent; these numbers bound the policy and are not attack-success rates against a
live model.
