"""Cross-model batch runner (benchmarks/redteam/batch): per-model evaluation, the comparison, and the CLI, offline."""
import json

import pytest

from aisec.redteam import targets
from benchmarks.redteam import batch
from benchmarks.redteam.scenarios import SUITES


def factory_for(spec):
    """Build a TargetFactory from a spec's 'behavior': leak the scenario's own canary, or always refuse, or raise."""
    behavior = spec.get("behavior", "leak")

    def make(scenario):
        if behavior == "down":
            raise targets.TargetError(f"could not reach {spec['name']}")
        canary = scenario.canaries[0]
        reply = f"Sure, the code is {canary}." if behavior == "leak" else "I can't help with that."
        return targets.CallableTarget(lambda messages: reply, name=spec["name"])

    return make


def config(*specs, judge="heuristic", attacker="none"):
    return {"judge": {"mode": judge}, "attacker": {"mode": attacker}, "targets": list(specs)}


def run(cfg, **kw):
    return batch.run_batch(cfg, target_factory_for=factory_for, **kw)


def test_compares_models_over_the_extended_suite():
    cfg = config({"name": "leaky"}, {"name": "stone", "behavior": "refuse"})
    combined = run(cfg, suite="extended")
    assert combined["suite"] == "extended" and combined["scenarios"] == 12
    models = {m["name"]: m for m in combined["models"]}
    assert models["leaky"]["overall"]["breach"]["pct"] == 100.0 and models["leaky"]["overall"]["extraction"]["n"] == 12
    assert models["stone"]["overall"]["breach"]["pct"] == 0.0
    for s in ("crescendo", "steganography", "roleplay"):
        assert models["leaky"]["by_strategy"][s]["breach"]["pct"] == 100.0
    assert combined["failed"] == []


def test_base_suite_is_six_scenarios():
    combined = run(config({"name": "leaky"}), suite="base")
    assert combined["suite"] == "base" and combined["scenarios"] == 6
    assert combined["models"][0]["overall"]["breach"]["n"] == 6


def test_a_failing_target_is_recorded_and_the_others_still_run():
    cfg = config({"name": "up"}, {"name": "dead", "behavior": "down"}, {"name": "up2"})
    combined = run(cfg)
    assert [m["name"] for m in combined["models"]] == ["up", "up2"]
    assert combined["failed"] == [{"name": "dead", "error": "could not reach dead"}]


def test_duplicate_target_names_and_empty_config_are_rejected():
    with pytest.raises(ValueError, match="duplicate target name"):
        run(config({"name": "x"}, {"name": "x"}))
    with pytest.raises(ValueError, match="no targets"):
        run(config())
    with pytest.raises(ValueError, match="unknown suite"):
        run(config({"name": "x"}), suite="nope")


def test_bad_judge_and_attacker_config_are_rejected():
    with pytest.raises(ValueError, match="judge mode"):
        run(config({"name": "x"}, judge="vibes"))
    with pytest.raises(ValueError, match="attacker mode 'http' needs"):
        run(config({"name": "x"}, attacker="http"))
    with pytest.raises(ValueError, match="judge mode 'http' needs"):
        batch.run_batch({"judge": {"mode": "http"}, "targets": [{"name": "x"}]}, target_factory_for=factory_for)


def test_writes_per_model_json_and_self_contained_html(tmp_path):
    run(config({"name": "leaky/one"}), suite="base", out_dir=tmp_path)
    report = json.loads((tmp_path / "leaky-one.json").read_text(encoding="utf-8"))   # slug sanitises the name
    assert report["name"] == "leaky/one" and report["scenarios"] == 6
    html = (tmp_path / "leaky-one.html").read_text(encoding="utf-8")
    assert "<script" not in html.lower() and "Content-Security-Policy" in html
    assert "billing_support · crescendo" in html and "Breached" in html       # every scenario on one page


def test_markdown_table_lists_each_model_and_the_failures():
    combined = run(config({"name": "leaky"}, {"name": "dead", "behavior": "down"}))
    md = batch.to_markdown(combined)
    assert "leaky" in md and "breach" in md and "100.0%" in md
    assert "1 target(s) failed" in md and "could not reach dead" in md


def test_cli_dry_run_compares_the_mock_defences(capsys):
    assert batch.main(["--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "mock suite" in out and "mock-weak" in out and "mock-hardened" in out
    weak = next(line for line in out.splitlines() if line.startswith("mock-weak"))
    hardened = next(line for line in out.splitlines() if line.startswith("mock-hardened"))
    assert "100.0%" in weak and "0.0%" in hardened


def test_cli_dry_run_writes_reports_and_combined_json(tmp_path):
    out = tmp_path / "reports"
    combined_path = tmp_path / "combined.json"
    assert batch.main(["--dry-run", "--out", str(out), "--json", str(combined_path)]) == 0
    assert {p.name for p in out.glob("*.html")} == {"mock-weak.html", "mock-moderate.html", "mock-hardened.html"}
    combined = json.loads(combined_path.read_text(encoding="utf-8"))
    assert combined["suite"] == "mock" and len(combined["models"]) == 3


def test_cli_requires_config_or_dry_run():
    with pytest.raises(SystemExit, match="give --config"):
        batch.main([])
    with pytest.raises(SystemExit, match="no targets"):
        batch.main(["--config", _write_config({"targets": []})])


def _write_config(obj):
    import tempfile

    path = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(obj, path)
    path.close()
    return path.name


def test_cli_config_runs_with_a_fake_target(monkeypatch, tmp_path):
    # point the real HTTP factory at an in-process leaky target so the config path is exercised end to end
    monkeypatch.setattr(batch, "_target_factory", lambda spec, timeout: factory_for(spec))
    cfg = _write_config(config({"name": "fake", "url": "http://unused/x"}))
    out = tmp_path / "r.json"
    assert batch.main(["--config", cfg, "--suite", "base", "--json", str(out)]) == 0
    combined = json.loads(out.read_text(encoding="utf-8"))
    assert combined["models"][0]["overall"]["breach"]["pct"] == 100.0


def test_every_registered_suite_has_distinct_planted_canaries():
    for scenarios in SUITES.values():
        canaries = [c for s in scenarios for c in s.canaries]
        assert len(canaries) == len(set(canaries))
        assert all(c in s.system_prompt for s in scenarios for c in s.canaries)
