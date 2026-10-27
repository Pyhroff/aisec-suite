"""Adapters that run each scanner and normalise its findings. Scanners are imported lazily; a missing
scanner is reported and skipped rather than crashing the run."""
from __future__ import annotations

import json
import os
import pathlib

from aisec import reach
from aisec.extract import extract_tools
from aisec.model import Finding

CONTEXT_NAMES = {"CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md"}
_SKIP = {"node_modules", ".git", "venv", ".venv"}
_CHUNK = 50  # large manifests scale super-linearly in mcpaudit's cross-tool check


def _rel(p: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def _walk(root: pathlib.Path):
    """Yield regular files under root, pruning vendored dirs *before* descending and never following symlinks
    (a repo under scan is untrusted input: a symlink must not make us read files outside it)."""
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _SKIP]
        for name in files:
            p = pathlib.Path(dirpath, name)
            if not p.is_symlink():
                yield p


def scan_mcp_source(root: pathlib.Path, include_tests: bool = False, warnings: list[str] | None = None, reach_mode: str = "annotate", structural: bool = True) -> tuple[list[Finding], int]:
    """Statically extract tools from source, run mcpaudit's static checks. Returns (findings, tools_found)."""
    try:
        from mcpaudit.checks.description_scan import scan_descriptions
        from mcpaudit.checks.permission_scope import check_scope
        from mcpaudit.manifest import ServerManifest, ToolManifest
    except ImportError:
        if warnings is not None:
            warnings.append("mcpaudit not installed: skipped MCP tool checks")
        return [], 0
    tools = extract_tools(root, include_tests)
    findings: list[Finding] = []
    for i in range(0, len(tools), _CHUNK):
        part = tools[i:i + _CHUNK]
        manifest = ServerManifest(server_name=root.name, tools=[ToolManifest(t["name"], t["description"], t["input_schema"]) for t in part])
        by_name = {t["name"]: t for t in part}
        for f in scan_descriptions(manifest) + check_scope(manifest):
            src = by_name.get(f.tool, {})
            sev, note = f.severity.value, ""
            if reach_mode != "off" and f.check == "permission_scope":
                r = reach.assess(src)
                sev, note = reach.adjust_severity(sev, r, reach_mode == "strict"), r.note()
                try:
                    from specprove.ecosystem_bridge import verify_reach_verdict_with_z3
                    _, z3_note = verify_reach_verdict_with_z3(f.tool, r.verdict, r.kinds)
                    note = f"{note} | {z3_note}" if note else z3_note
                except ImportError:
                    pass
            findings.append(Finding("mcpaudit", f"{f.check}: {f.title}", sev, f.detail, src.get("file", "."), src.get("line", 1), note))
    if structural:
        from aisec import poison
        findings += poison.findings_for(tools)
    return findings, len(tools)


def scan_manifest_files(root: pathlib.Path, warnings: list[str] | None = None) -> list[Finding]:
    """Scan *.json files shaped like {"server_name":..., "tools":[...]} (e.g. an mcpaudit baseline)."""
    try:
        from mcpaudit.checks.description_scan import scan_descriptions
        from mcpaudit.checks.permission_scope import check_scope
        from mcpaudit.manifest import ServerManifest
    except ImportError:
        return []
    out: list[Finding] = []
    for p in _walk(root):
        if p.suffix != ".json" or p.stat().st_size > 5_000_000:
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            if not (isinstance(d, dict) and "server_name" in d and isinstance(d.get("tools"), list)):
                continue
            m = ServerManifest.from_dict(d)
        except Exception:
            continue
        for f in scan_descriptions(m) + check_scope(m):
            out.append(Finding("mcpaudit", f"{f.check}: {f.title}", f.severity.value, f.detail, _rel(p, root), 1))
    return out


def scan_context_files(root: pathlib.Path, warnings: list[str] | None = None) -> list[Finding]:
    try:
        from memsentry.memfile import MemoryFile
        from memsentry.scanner import scan_file
    except ImportError:
        if warnings is not None:
            warnings.append("memsentry not installed: skipped agent-context file checks")
        return []
    out: list[Finding] = []
    for p in _walk(root):
        if p.name in CONTEXT_NAMES or (p.parent.name == "rules" and p.parent.parent.name == ".cursor"):
            for f in scan_file(MemoryFile.load(p)):
                out.append(Finding("memsentry", f"{f.check}: {f.title}", f.severity.value, f.detail, _rel(p, root), f.line))
    return out


# Directories that never hold retrievable documents. ragsentry walks everything it is given, so
# scanning a repository root would otherwise flag git pack files and tool caches as "documents".
_NON_DOCUMENT_DIRS = {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__",
                      ".ruff_cache", ".pytest_cache", ".mypy_cache", ".tox", "dist", "build"}


def _in_non_document_dir(path: pathlib.Path, base: pathlib.Path) -> bool:
    try:
        parts = path.resolve().relative_to(base.resolve()).parts[:-1]
    except ValueError:
        parts = path.parts[:-1]
    return any(part in _NON_DOCUMENT_DIRS or part.endswith(".egg-info") for part in parts)


def scan_rag_dir(rag_dir: pathlib.Path, root: pathlib.Path, warnings: list[str] | None = None) -> list[Finding]:
    try:
        from ragsentry.scanner import scan_path
    except ImportError:
        if warnings is not None:
            warnings.append("ragsentry not installed: skipped RAG document checks")
        return []
    out: list[Finding] = []
    for fname, fs in scan_path(str(rag_dir)).items():
        if _in_non_document_dir(pathlib.Path(fname), rag_dir):
            continue
        for f in fs:
            out.append(Finding("ragsentry", f"{f.check}: {f.title}", f.severity.value, f.detail, _rel(pathlib.Path(fname), root), f.line))
    return out


def scan_specprove_formal(
    root: pathlib.Path,
    include_tests: bool = False,
    warnings: list[str] | None = None,
    lean_out: pathlib.Path | None = None,
) -> list[Finding]:
    """Run SpecProve-Sec Z3 SMT Bounded Model Checker + CEGIS Patch Prover + Lean 4 Certificate generator."""
    try:
        from specprove.ecosystem_bridge import scan_repo_with_specprove
    except ImportError:
        if warnings is not None:
            warnings.append("specprove not installed: skipped Z3 SMT formal state-machine verification")
        return []
    formal_hits = scan_repo_with_specprove(root, include_tests=include_tests, lean_out_dir=lean_out)
    return [
        Finding(
            scanner="specprove",
            rule=fh.rule,
            severity=fh.severity,
            message=fh.message,
            file=fh.file,
            line=fh.line,
            evidence=fh.evidence,
            confidence=1.0,
            target=getattr(fh, "protocol_id", ""),
            remediation=getattr(fh, "cegis_diff", "") or "",
        )
        for fh in formal_hits
    ]


def scan_weightspecter_checkpoints(
    root: pathlib.Path,
    include_tests: bool = False,
    warnings: list[str] | None = None,
) -> list[Finding]:
    """Run WeightSpecter RMT Spectral & Topological Backdoor Detector over `.safetensors` checkpoints."""
    try:
        from weightspecter.spectral_engine import SpectralBackdoorAnalyzer
    except ImportError:
        if warnings is not None:
            warnings.append("weightspecter not installed: skipped RMT spectral .safetensors backdoor checks")
        return []
    analyzer = SpectralBackdoorAnalyzer()
    out: list[Finding] = []
    for p in _walk(root):
        if p.suffix != ".safetensors":
            continue
        if not include_tests and any(part in ("tests", "sanitized") for part in p.parts):
            continue
        rep = analyzer.scan_checkpoint(p)
        if rep.overall_verdict == "CLEAN":
            continue
        for lp in rep.layer_profiles:
            if lp.verdict == "CLEAN":
                continue
            sev = "critical" if lp.verdict == "BACKDOOR_TROJAN" else "high"
            out.append(
                Finding(
                    scanner="weightspecter",
                    rule=f"rmt_spectral_backdoor: {lp.layer_name}",
                    severity=sev,
                    message=(
                        f"BBP Spike={lp.bbp_spike_ratio}x, Top1 Energy={lp.top1_energy_fraction*100:.1f}%, "
                        f"EffRank={lp.effective_entropy_rank}/{lp.nominal_rank}, "
                        f"MaxIPR={max(lp.u1_ipr_normalized, lp.v1_ipr_normalized):.2f}"
                    ),
                    file=_rel(p, root),
                    line=1,
                    evidence=" | ".join(lp.detected_signatures),
                    confidence=round(min(1.0, rep.overall_risk_score / 100.0), 2),
                    target=lp.layer_name,
                    remediation=f"weightspecter sanitize {_rel(p, root)} -o sanitized_{p.name}",
                )
            )
    return out


def scan_tokenspecter_streams(
    root: pathlib.Path,
    include_tests: bool = False,
    warnings: list[str] | None = None,
) -> list[Finding]:
    """Run TokenSpecter Viterbi Side-Channel Cryptanalyzer over `.stream.json` packet captures."""
    try:
        from tokenspecter.sidechannel_engine import (
            SideChannelVulnerabilityAuditor,
            load_stream_trace,
        )
    except ImportError:
        if warnings is not None:
            warnings.append("tokenspecter not installed: skipped encrypted streaming side-channel checks")
        return []
    auditor = SideChannelVulnerabilityAuditor()
    out: list[Finding] = []
    for p in _walk(root):
        if not p.name.endswith(".stream.json"):
            continue
        if not include_tests and "tests" in p.parts:
            continue
        tr = load_stream_trace(p)
        res = auditor.audit_trace(tr)
        if res.verdict == "SHAPED_SAFE":
            continue
        sev = "critical" if res.verdict == "LEAKAGE_CRITICAL" else "high"
        out.append(
            Finding(
                scanner="tokenspecter",
                rule=f"sse_sidechannel_leakage: {res.domain_category}",
                severity=sev,
                message=(
                    f"Mutual Info={res.mutual_information_bits:.2f} bits/tok, "
                    f"Viterbi Recovery={res.token_recovery_accuracy*100:.0f}% ('{res.viterbi_recovered_phrase}')"
                ),
                file=_rel(p, root),
                line=1,
                evidence=f"H(L)={res.length_entropy_bits:.2f}b, timing_cv={res.timing_cv:.3f}",
                confidence=round(min(1.0, res.leakage_risk_score / 100.0), 2),
                target=res.trace_id,
                remediation=f"tokenspecter shape {_rel(p, root)} -o shaped_{p.name}",
            )
        )
    return out


def scan_circuitshield_traces(
    root: pathlib.Path,
    include_tests: bool = False,
    warnings: list[str] | None = None,
) -> list[Finding]:
    """Run CircuitShield Mechanistic Interpretability Firewall over `.act.json` residual traces."""
    try:
        from circuitshield.circuit_engine import (
            CircuitShieldFirewall,
            load_activation_trace,
        )
    except ImportError:
        if warnings is not None:
            warnings.append("circuitshield not installed: skipped mechanistic refusal-subspace checks")
        return []
    fw = CircuitShieldFirewall()
    out: list[Finding] = []
    for p in _walk(root):
        if not p.name.endswith(".act.json"):
            continue
        if not include_tests and "tests" in p.parts:
            continue
        tr = load_activation_trace(p)
        res = fw.audit_trace(tr)
        if res.verdict == "CIRCUIT_INTACT":
            continue
        out.append(
            Finding(
                scanner="circuitshield",
                rule=f"refusal_subspace_ablation: {res.verdict}",
                severity="critical",
                message=(
                    f"Harm={res.mean_harm_score:.2f}, MinRefusalProj={res.min_refusal_projection:.2f}, "
                    f"MinAttnEntropy={res.min_attention_entropy:.2f}b ({res.ablated_layers_count} layers ablated)"
                ),
                file=_rel(p, root),
                line=1,
                evidence=" | ".join(res.detected_anomalies[:2]),
                confidence=round(min(1.0, res.anomaly_score / 100.0), 2),
                target=res.trace_id,
                remediation=f"circuitshield clamp {_rel(p, root)} -o clamped_{p.name}",
            )
        )
    return out


def scan_attestinfer_proofs(
    root: pathlib.Path,
    include_tests: bool = False,
    warnings: list[str] | None = None,
) -> list[Finding]:
    """Run AttestInfer Verifiable Inference Prover over `.proof.json` receipts."""
    try:
        from attestinfer.attest_engine import (
            VerifiableInferenceAuditor,
            load_proof_bundle,
        )
    except ImportError:
        if warnings is not None:
            warnings.append("attestinfer not installed: skipped cryptographic inference verification checks")
        return []
    auditor = VerifiableInferenceAuditor()
    out: list[Finding] = []
    for p in _walk(root):
        if not p.name.endswith(".proof.json"):
            continue
        if not include_tests and "tests" in p.parts:
            continue
        bundle = load_proof_bundle(p)
        v = auditor.verify_proof_bundle(bundle)
        if v.verdict == "VERIFIED_AUTHENTIC":
            continue
        sev = "critical" if v.verdict == "MODEL_DOWNGRADE_FRAUD" else "high"
        out.append(
            Finding(
                scanner="attestinfer",
                rule=f"verifiable_inference_fraud: {v.verdict}",
                severity=sev,
                message=(
                    f"FreivaldsRes={v.freivalds_max_residual:.4f}, SumcheckDiff={v.sumcheck_discrepancy:.4f}, "
                    f"LogitKL={v.logit_kl_divergence:.4f}, W1={v.logit_wasserstein_l1:.4f}"
                ),
                file=_rel(p, root),
                line=1,
                evidence=f"Claimed={v.claimed_model_id}, MerkleMatch={v.merkle_root_matched}",
                confidence=round(min(1.0, v.fraud_risk_score / 100.0), 2),
                target=v.proof_id,
                remediation=f"attestinfer re-attest {_rel(p, root)} -o attested_{p.name}",
            )
        )
    return out



