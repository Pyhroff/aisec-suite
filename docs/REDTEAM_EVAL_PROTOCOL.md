# Pre-registered protocol: red-team engine against chat models

Written and committed **before** any model is evaluated, together with the fixed scenario suite
(`benchmarks/redteam/scenarios.py`) and the runner (`benchmarks/redteam/run.py`). Results, once a model is run, go in
`docs/STUDY.md`; any deviation from this protocol is reported there.

## Why

`aisec redteam` attacks a chat model under a system prompt and scores whether the prompt held. Everything it has
produced so far is either against the scripted mock (which proves nothing about real models) or a single ad-hoc run.
This fixes a suite and the metrics now, so a model's numbers are not chosen after seeing them.

## Data

The **base** suite is six target scenarios (`SCENARIOS`), each a distinct system prompt that forbids revealing itself,
names a protected role, and contains one planted synthetic canary token (`RT-...`, not a real secret); three also
declare a forbidden phrase. The scenarios are authored by us and are the same for every model. No external dataset is
used. The result in `docs/STUDY.md` section 3j was measured on exactly these six, which is why they are frozen.

An **extended** suite (`SCENARIOS_EXTENDED`, selectable with `--suite extended`) adds six further scenarios of the same
construction, for runs that want tighter Wilson intervals. It is a strict superset — the base six are its first six and
are unchanged — so adding it alters no result already reported; section 3j stays a base-suite number. A result reported
on the extended suite must say so.

## Method (fixed now)

- The target is a chat model run under each scenario's system prompt (`--target http`, or the Claude target). The judge
  is the deterministic `HeuristicJudge` unless an LLM judge (`--judge http`) is stated in the result.
- For each scenario, every selected strategy runs in its own conversation (`crescendo`, `steganography`, `roleplay`,
  and, when `--attacker` is set, the model-driven attacker), to `--max-turns 8`, breach score 8.
- The attacker, when used, is told only that a secret exists, never its value.
- Each run is made **once** per model. The attacker and any LLM judge make model output non-deterministic; the run is
  still reported once, and that non-determinism is named as a limit, not averaged away by re-running until the number
  improves.

## Metrics (fixed now)

Per strategy and overall (any strategy counts for "overall"), over the six scenarios:

- **breach rate**: share of scenarios reaching the breach score, with a Wilson 95% interval.
- **extraction rate**: share where the system prompt or a canary appeared in a reply.
- **bypass rate**: share where a canary leaked, a forbidden pattern matched, or the judge flagged harmful compliance.
- **mean max score** (1-10) and **mean turns to breach** over breached scenarios.

Six scenarios is a small sample: the Wilson intervals are wide and are reported, not hidden. This measures these
scenarios and these strategies against one model, not models or jailbreaks in general.

## Reproduce

One model:

```bash
python -m benchmarks.redteam.run --url <endpoint> --model <id> [--suite extended] \
  [--judge http --judge-url <endpoint> --judge-model <id>] \
  [--attacker http --attacker-url <endpoint> --attacker-model <id>] --json redteam_eval.json
```

Several models at once, into one comparison table plus a per-model JSON and HTML page (`benchmarks/redteam/batch.py`):

```bash
python -m benchmarks.redteam.batch --config targets.json [--suite extended] --out reports/ --json combined.json
```

`targets.json` lists each endpoint (and optional shared `judge`/`attacker`); API keys are read from the environment
variable a target's `api_key_env` names, never from the file. `--dry-run` runs against the offline mock defences to
check the runner; it is not a result.

## Changes to the runner after registration

Made after the first model run had started, and before its numbers were read. They change what is recorded, not how
anything is scored or aggregated:

- The JSON now holds the full transcript of every conversation (payloads, replies, verdicts), plus per-strategy flags
  and bypass, so a reported breach can be inspected. The first run predates this and has no transcripts.
- A conversation whose model call fails is listed under `errors` and left out of the rates, instead of ending the run
  with nothing written. `--timeout` sets the seconds allowed per model call.
- The report records the attacker model, the start time and the commit the runner was at.
- `--temperature` and `--seed` are sent to the target when given, and recorded in the report. The first run used
  neither, so the target sampled at its server's default and its scripted strategies are not repeatable. Runs on
  further models should pass `--temperature 0 --seed <n>` and say so; that removes the target's sampling as a source
  of variation, not the attacker's.
