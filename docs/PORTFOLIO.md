# AI Security Portfolio Architecture

This repository is the umbrella for a set of focused AI-security scanners. The goal is not maximum repository count; it is composable coverage of distinct trust boundaries, each backed by measurement.

## Evidence model

Every specialist should expose the same chain:

**Threat model -> attack/fixture -> detection/defense -> benchmark -> results -> limitations**

## Flagship: MCP tool-surface security

`mcpaudit` plus the structural tool-poisoning detector and reachability analysis in this repo. This is the most mature part of the portfolio: a 135-repository real-world corpus, hand-labelled findings, a seen/held-out attack split and calibrated thresholds ([`STUDY.md`](STUDY.md)).

## Supporting surfaces

| Surface | Scanner | Maturity |
|---|---|---|
| Agent memory / context files | [memsentry](https://github.com/Pyhroff/memsentry) | published |
| RAG source documents | [ragsentry](https://github.com/Pyhroff/ragsentry) (`pyhroff-ragsentry` on PyPI) | published |
| Fine-tuning data poisoning | [trainsentry](https://github.com/Pyhroff/trainsentry) | public source, not on PyPI |
| Agent loops / behavior | [loopcheck](https://github.com/Pyhroff/loopcheck) | public source, not on PyPI |
| Agent install supply chain | agent-install-guardrail | private |
| Package worms | wormsentry | private, early |
| Formal checks of tool state machines | [specprove-sec](https://github.com/Pyhroff/specprove-sec) | public source, research prototype |
| Weights, inference attestation, activation traces, stream side channels | weightspecter, attestinfer, circuitshield, tokenspecter | private research preview, synthetic fixtures only |
| Attack-side testing of the detectors | [adversagen](https://github.com/Pyhroff/adversagen) | public source, research |

## Promotion rule

A project is promoted to flagship status only when it has:

- a precise threat model
- reproducible fixtures
- automated tests that run in public CI
- quantitative evaluation on data the detector was not developed against
- documented limitations
- a clear security boundary
- an installable interface or integration path

The objective is **depth over project count**.
