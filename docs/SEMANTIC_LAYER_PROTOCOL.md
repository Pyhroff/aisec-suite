# Pre-registered protocol: a learned (semantic) layer for the tool-poisoning detector

Written and committed **before** any model is trained. Results go in `docs/STUDY.md` section 3d and must follow this
protocol; any deviation is reported there as a deviation.

## Why

Both external evaluations (STUDY 3c) show the same gap: the structural detector keys on instruction structure, so
attacks written as ordinary documentation pass it (MCPTox recall 14.0%; MCP-Poison-Bench held-out register 0/74).
This tests whether a small learned text classifier, used alongside the structural detector, closes part of that gap
without raising false positives on real tool metadata.

## Model (fixed before training)

- Text: the detector's existing canonical view (`aisec.poison._canonical`) of each prose field, lower-cased.
- Features: word 1- and 2-grams, hashed (BLAKE2b) into 2^18 buckets, binary, L2-normalised.
- Classifier: logistic regression (scikit-learn, `C=1.0`, `class_weight="balanced"`), trained offline. The shipped
  model is a JSON file of non-zero weights; inference is pure Python (`aisec/semantic.py`). No pickle, no new runtime
  dependency.
- Tool score: the maximum over the tool description and each parameter description, scored separately.
- Threshold: the 99.5th percentile of out-of-fold scores (5-fold, stratified) on the training negatives, i.e. a target
  false-positive rate of about 0.5%. Fixed from training data alone; never adjusted after the test run.
- Combined detector: a tool is flagged at medium if the structural detector flags it at medium or above **or** the
  semantic score is at or above the threshold.

## Training data

- Positives: every MCP-Poison-Bench payload (109, all objectives and registers, MIT licence, commit `944ccbb`), as the
  injection text alone (not the benchmark's host description, so that "arithmetic" is not learned as a poison cue);
  and the seen register of `benchmarks/poison/attacks.py` (54 tools).
- Negatives: the calibration half of the study's real tool descriptions (`benchmarks/poison/run.py` split, by repo)
  and `tests/fixtures/benign_tools.json`.

## Test data (scored once, after the model and threshold are fixed)

1. MCPTox at `f85189f`: 485 poisoned tools and 362 legitimate tools of the same servers (as in STUDY 3c). Not used
   for training, feature design or threshold selection.
2. The held-out register of `attacks.py` (54). It has been evaluated three times against the structural detector;
   it has never been used to train anything.
3. The test half of the study's real tool descriptions (false-positive rate).

Reported for structural alone, semantic alone, and combined: recall at medium+ with Wilson 95% intervals, per MCPTox
paradigm and risk category, and false-positive rate on both negative sets.

## Disclosed in advance

- MCP-Poison-Bench is training data here, so it is no longer an external test for the combined detector; its STUDY
  3c numbers remain the external result for the structural detector.
- MCPTox's results for the structural detector were seen (STUDY 3c). No MCPTox text is used in training; the risk
  that remains is that the feature design was influenced by knowing which risk categories were missed. The feature
  design above is generic (bag of n-grams) to limit that.
- Whatever the result, the combined detector ships only if its false-positive rate on the study test half stays at or
  below 1%. Otherwise the model is published as an experiment and left off by default.
