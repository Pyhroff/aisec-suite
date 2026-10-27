r"""Unit tests for v2.0 upgrades (AttestInfer v2.0, CircuitShield v2.0, TokenSpecter v2.0) and aisec-suite v2.2.0 Wargame & Guard-Proxy."""

from __future__ import annotations

import json
import pathlib
import pytest
from typer.testing import CliRunner

from aisec.cli import app
# wargame imported within test cases as needed

np = pytest.importorskip("numpy")

runner = CliRunner()

pytest.importorskip("weightspecter")
pytest.importorskip("attestinfer")
pytest.importorskip("circuitshield")
pytest.importorskip("tokenspecter")

def test_attestinfer_v2_nonlinear_and_speculative_audit() -> None:
    from attestinfer.advanced_verification import (
        audit_speculative_decoding,
        verify_nonlinear_layers,
    )

    rng = np.random.default_rng(11)
    x = rng.normal(0.0, 1.0, size=(4, 16))
    gamma = np.ones((1, 16))
    rms = np.sqrt(np.mean(x**2, axis=-1, keepdims=True) + 1e-5)
    y_rms = (x / rms) * gamma
    y_silu = x / (1.0 + np.exp(-x))
    scores = rng.normal(0.0, 1.0, size=(4, 8))
    exp_s = np.exp(scores - np.max(scores, axis=-1, keepdims=True))
    probs = exp_s / np.sum(exp_s, axis=-1, keepdims=True)

    clean_nl = verify_nonlinear_layers("NL-CLEAN", x, gamma, y_rms, y_silu, scores, probs)
    assert clean_nl.passed is True
    assert clean_nl.verdict == "NONLINEAR_VERIFIED"

    # Spoofed linear approximation to SiLU must be caught
    spoof_nl = verify_nonlinear_layers("NL-SPOOF", x, gamma, y_rms, x * 0.5, scores, probs)
    assert spoof_nl.passed is False
    assert spoof_nl.verdict == "APPROX_ACTIVATION_SPOOF"

    # Speculative decoding draft spoofing check
    p_target = np.full(40, 0.40)
    q_draft = np.full(40, 0.92)
    honest_flags = np.array([1 if i % 2 == 0 else 0 for i in range(40)])
    spoof_flags = np.ones(40, dtype=int)

    honest_spec = audit_speculative_decoding("SPEC-HONEST", p_target, q_draft, honest_flags)
    assert honest_spec.verdict == "SPECULATIVE_VERIFIER_HONEST"

    spoof_spec = audit_speculative_decoding("SPEC-SPOOF", p_target, q_draft, spoof_flags)
    assert spoof_spec.verdict == "UNVERIFIED_SPECULATIVE_DRAFT_FRAUD"
    assert spoof_spec.wald_z_score > 3.0


def test_circuitshield_v2_sae_and_kalman_crescendo() -> None:
    from circuitshield.advanced_circuit import (
        audit_sae_features,
        forecast_crescendo_trajectory,
    )

    sae_enc = np.eye(6)
    sae_b = np.zeros(6)
    h_attack = np.array([1.9, 1.4, 0.0, 0.0, 0.0, 0.0])
    sae_res = audit_sae_features(
        "SAE-01",
        h_attack,
        sae_enc,
        sae_b,
        {0: "DeceptiveAlignment", 1: "ExploitPlanning"},
    )
    assert sae_res.verdict == "SAE_COVERT_DECEPTION_ACTIVE"
    assert len(sae_res.triggered_latents) == 2

    # Multi-turn Crescendo erosion trajectory -> must trigger preemptive block before reaching -0.15
    cresc = forecast_crescendo_trajectory(
        "CRESC-01", [0.45, 0.30, 0.14, -0.01], collapse_threshold=-0.15, horizon_turns=3
    )
    assert cresc.verdict == "PREEMPTIVE_CRESCENDO_INTERCEPT"
    assert cresc.preemptive_block_triggered is True
    assert cresc.predicted_turns_to_collapse in (1, 2)


def test_tokenspecter_v2_speculative_burst_pacing() -> None:
    from tokenspecter.burst_forensics import (
        audit_speculative_burst_leakage,
        pace_speculative_bursts,
    )
    from tokenspecter.sidechannel_engine import (
        EncryptedPacketFrame,
        EncryptedStreamTrace,
    )

    pkts = [
        EncryptedPacketFrame(i, 10, 1.0 if (i % 5 != 0 and i < 15) else 30.0, False, "tok")
        for i in range(20)
    ]
    tr = EncryptedStreamTrace("BURST-01", "PEM_KEY", "Speculative Burst Stream", False, "tok " * 20, pkts)
    pre = audit_speculative_burst_leakage(tr)
    assert pre.verdict == "BURST_LEAKAGE_CRITICAL"
    assert pre.max_burst_cardinality >= 4

    paced = pace_speculative_bursts(tr, tick_ms=25.0, bucket_bytes=64)
    post = audit_speculative_burst_leakage(paced)
    assert post.verdict == "BURST_PACED_SAFE"
    assert post.max_burst_cardinality == 1
    assert post.burst_cardinality_entropy_bits == 0.0


def test_wargame_and_guard_proxy_cli(tmp_path: pathlib.Path) -> None:
    work_dir = tmp_path / "arena"
    html_out = tmp_path / "wargame.html"
    json_out = tmp_path / "wargame.json"

    r_wg = runner.invoke(
        app,
        [
            "experimental",
            "wargame",
            "--work-dir",
            str(work_dir),
            "--html",
            str(html_out),
            "--json",
            str(json_out),
        ],
    )
    assert r_wg.exit_code == 0, r_wg.output
    assert "stages=5/5 blocked" in r_wg.output
    assert html_out.exists()
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["stages_intercepted"] == 5
    assert payload["blue_team_survival_prob"] == 1.0

    proxy_json = tmp_path / "proxy.json"
    r_px = runner.invoke(app, ["experimental", "guard-proxy", "--json", str(proxy_json)])
    assert r_px.exit_code == 0, r_px.output
    assert "guard-proxy demo ran 3 scripted sample check(s)" in r_px.output
    txs = json.loads(proxy_json.read_text(encoding="utf-8"))
    assert len(txs) == 3
