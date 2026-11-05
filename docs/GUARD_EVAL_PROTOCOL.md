# Pre-registered protocol: runtime guard on AgentDojo

Written and committed **before** the evaluation is run, together with the guard (`aisec/runtime_guard.py`) and its
AgentDojo policy (`AGENTDOJO_POLICY`), which were written from AgentDojo's tool signatures alone. Results go in
`docs/STUDY.md` section 3f; deviations are reported there.

## Why

Sections 3c-3e show that reading intent from text fails on attacks written as ordinary requests. This tests a guard
that ignores the text and checks provenance instead: after the agent has read tool output, a call that sends data to
a destination the user never named, or that deletes or changes account data the user never asked to change, is held
for confirmation.

## Data

AgentDojo (Debenedetti et al., NeurIPS 2024 Datasets and Benchmarks, MIT), PyPI `agentdojo==0.1.35`, benchmark version
`v1.2.2`: the workspace, travel, banking and slack suites. No model is called: each user task's `ground_truth` calls
(what completes the task) and each injection task's `ground_truth` calls (what the attacker wants) are replayed.

## Metrics (fixed now)

- **Attacks stopped**: over every (user task, injection task) pair, the share where the guard holds at least one of
  the injection task's calls, replayed after one tool result has been observed (the injection arrives in tool output),
  with the guard initialised with the user task's prompt.
- **Utility cost**: the share of user tasks where the guard holds at least one of the task's own ground-truth calls,
  replayed in order, every tool result observed.
- Both per suite and overall, with Wilson 95% intervals; the held benign tasks are listed with the reason.
- No trusted destinations are configured (the operator allow-list is empty), so utility cost is the worst case.

## Fixed before the run

- The guard and policy are not changed after the run. A change motivated by the results would be a new version,
  evaluated on a different benchmark.
- Ground truth is an idealised agent: a real agent may take other routes, call tools the ground truth does not, or
  ignore the injection entirely. The numbers bound what the policy can stop on these attacks and what it costs on
  these tasks; they are not an attack-success rate against a live model.
- AgentDojo's tasks were read only for tool names and signatures before this protocol was committed; no task prompt
  or ground-truth call was looked at.
