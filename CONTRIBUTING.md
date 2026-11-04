# Contributing

## Setup

```bash
pip install -c constraints.txt -e ".[core,dev]"
```

## Checks (CI runs all of these)

```bash
ruff check .                      # lint: pyflakes, bugbear, isort, pyupgrade, bandit
mypy                              # type check the aisec package
pytest -q -rs --cov               # tests + coverage floor (see pyproject.toml)
```

`-rs` lists skipped tests. Tests for the private research modules skip when those packages are not installed.

## Detector quality gate

`tests/test_poison_quality.py` locks in recall on the 108 synthetic positives (`benchmarks/poison/attacks.py`) and the
false-positive behaviour on `tests/fixtures/benign_tools.json`. If you change `aisec/poison.py`:

* raise the recall floors when you improve them; never lower a floor without saying why in the PR;
* add benign near-misses to the fixture for any new pattern, and a positive example to `tests/test_poison.py`;
* do not tune on the held-out register. Fit thresholds only on calibration negatives (`benchmarks/poison/calibrate.py`);
* re-run `python -m benchmarks.poison.run --study <study-dir>` for the real-corpus FPR and update `docs/STUDY.md`.

## Pinned scanner versions

`constraints.txt` records the published scanner versions CI last passed against. To upgrade one, change the pin, make
sure the `integration` job passes, and add a line to `CHANGELOG.md`.

## Branch protection

Mark the `tests-gate` check as required. It fails unless both the unit matrix and the real-scanner `integration` job pass.

## Scope

`research_preview/` holds scripted demos (fixed synthetic inputs, pre-determined outcomes). It is not shipped in the wheel
and must not be described as a detection result.
