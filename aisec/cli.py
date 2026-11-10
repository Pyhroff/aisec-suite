from __future__ import annotations

import collections
import json
import os
import pathlib
import re
from typing import Optional

import typer

from aisec import __version__
from aisec.adapters import (
    scan_attestinfer_proofs,
    scan_circuitshield_traces,
    scan_context_files,
    scan_manifest_files,
    scan_mcp_source,
    scan_rag_dir,
    scan_specprove_formal,
    scan_tokenspecter_streams,
    scan_weightspecter_checkpoints,
)
from aisec.benchmark import load_metrics, run_range
from aisec.guard_v3 import GuardV3
from aisec.lifecycle import classify, load_baseline
from aisec.model import SEVERITY_ORDER, at_least
from aisec.modules import available_modules
from aisec.native_adapters import (
    scan_agent_trace,
    scan_supply_chain,
    scan_training_dataset,
    scan_worm_tree,
)
from aisec.policy import PROFILES, apply_policy, load_policy, profile_policy, validate_policy
from aisec.runtime_guard import AGENTDOJO_POLICY, GuardPolicy, RuntimeGuard
from aisec.sarif import to_sarif
from aisec.summary import to_markdown

app = typer.Typer(name="aisec", help="Unified AI security toolkit.", no_args_is_help=True)
policy_app = typer.Typer(name="policy", help="Inspect and validate policy-as-code configuration.")
app.add_typer(policy_app)


@app.callback()
def _main(version: bool = typer.Option(False, "--version", is_eager=True)) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command("modules")
def modules() -> None:
    """List all suite modules and whether each scanner package is installed."""
    for spec in available_modules():
        state = "installed" if spec.installed() else "missing"
        typer.echo(f"{spec.name:13} {state:10} {spec.package:30} {spec.description}")


@policy_app.command("validate")
def policy_validate(path: pathlib.Path = typer.Argument(..., exists=True, dir_okay=False)) -> None:
    """Validate a policy file and print its normalized contract."""
    try:
        policy = load_policy(path)
    except (OSError, ValueError) as e:
        raise typer.BadParameter(f"cannot read policy: {e}") from e
    typer.echo(json.dumps(validate_policy(policy), indent=2, sort_keys=True))


@policy_app.command("init")
def policy_init(
    path: pathlib.Path = typer.Argument(pathlib.Path("aisec-policy.json"), help="Policy file to create."),
    profile: str = typer.Option("balanced", "--profile", help="Built-in profile: strict, balanced, or dev."),
    force: bool = typer.Option(False, "--force", help="Replace an existing policy file."),
) -> None:
    """Create a reviewable policy file from a deterministic built-in profile."""
    try:
        policy = profile_policy(profile)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e
    if path.exists() and not force:
        raise typer.BadParameter(f"refusing to overwrite existing file: {path}; use --force")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(validate_policy(policy), indent=2) + "\n", encoding="utf-8")
    typer.echo(f"policy created: {path} (profile={profile})")


@policy_app.command("show")
def policy_show(profile: str = typer.Argument(..., help="Built-in profile: strict, balanced, or dev.")) -> None:
    """Show a built-in policy profile."""
    try:
        policy = profile_policy(profile)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e
    typer.echo(json.dumps(validate_policy(policy), indent=2, sort_keys=True))


def _emit(findings: list, *, json_out: Optional[pathlib.Path], sarif: Optional[pathlib.Path]) -> None:
    if sarif:
        sarif.write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")
    if json_out:
        json_out.write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")


@app.command()
def scan(
    path: pathlib.Path = typer.Argument(..., exists=True, file_okay=False, help="Repository root to scan."),
    only: Optional[str] = typer.Option(None, "--only", help="Comma-separated modules: mcp,memory,rag,training,behavior,supply-chain,worm,formal,weights,sidechannel,circuit,attest."),
    all_modules: bool = typer.Option(False, "--all", help="Run every native suite module against the repository where applicable."),
    rag: Optional[pathlib.Path] = typer.Option(None, "--rag", help="Directory of RAG source documents."),
    sarif: Optional[pathlib.Path] = typer.Option(None, "--sarif", help="Write SARIF 2.1.0 here."),
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json", help="Write normalized findings as JSON."),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit 1 at low|medium|high|critical."),
    policy_profile: Optional[str] = typer.Option(None, "--policy-profile", help="Built-in policy profile: strict, balanced, or dev."),
    include_tests: bool = typer.Option(False, "--include-tests", help="Also inspect tests/examples/fixtures."),
    reach: str = typer.Option("annotate", "--reach", help="off | annotate | strict."),
    structural: bool = typer.Option(True, "--structural/--no-structural", help="Enable structural MCP poisoning detector."),
    formal: bool = typer.Option(False, "--formal/--no-formal", help="Run SpecProve-Sec Z3 SMT formal state-machine verification & CEGIS patch prover."),
    lean_out: Optional[pathlib.Path] = typer.Option(None, "--lean-out", help="Directory to export Lean 4 formal proof certificates when --formal is enabled."),
    weights: bool = typer.Option(False, "--weights/--no-weights", help="Run WeightSpecter RMT spectral & topological LoRA/safetensors backdoor detector."),
    sidechannel: bool = typer.Option(False, "--sidechannel/--no-sidechannel", help="Run TokenSpecter encrypted streaming SSE Viterbi side-channel auditor."),
    circuit: bool = typer.Option(False, "--circuit/--no-circuit", help="Run CircuitShield mechanistic interpretability refusal-subspace firewall."),
    attest: bool = typer.Option(False, "--attest/--no-attest", help="Run AttestInfer cryptographic Freivalds verifiable inference prover."),
    baseline: Optional[pathlib.Path] = typer.Option(None, "--baseline", help="Accepted finding fingerprints."),
    write_baseline: Optional[pathlib.Path] = typer.Option(None, "--write-baseline", help="Accept all current findings."),
    summary: Optional[pathlib.Path] = typer.Option(None, "--summary", help="Write Markdown summary."),
    policy: Optional[pathlib.Path] = typer.Option(None, "--policy", exists=True, dir_okay=False, help="JSON policy-as-code file."),
) -> None:
    if reach not in ("off", "annotate", "strict"):
        raise typer.BadParameter("--reach must be off, annotate or strict")
    if fail_on and fail_on not in SEVERITY_ORDER:
        raise typer.BadParameter("must be one of low|medium|high|critical")
    if policy_profile and policy_profile not in PROFILES:
        raise typer.BadParameter("policy profile must be strict, balanced, or dev")
    if policy and policy_profile:
        raise typer.BadParameter("--policy and --policy-profile are mutually exclusive")

    root = path.resolve()
    warnings: list[str] = []
    crashed: list[str] = []

    def guarded(label, fn, default, *args):
        try:
            return fn(*args)
        except Exception as e:
            crashed.append(label)
            warnings.append(f"{label} crashed ({type(e).__name__}: {e}); its results are missing")
            return default

    findings: list = []
    n_tools = 0
    selected = {"mcp", "memory"}
    if rag:
        selected.add("rag")
    if formal or lean_out is not None:
        selected.add("formal")
    if weights:
        selected.add("weights")
    if sidechannel:
        selected.add("sidechannel")
    if circuit:
        selected.add("circuit")
    if attest:
        selected.add("attest")
    if all_modules and only:
        raise typer.BadParameter("--all cannot be combined with --only")
    if all_modules and rag is None:
        rag = root
    all_set = {"mcp", "memory", "rag", "training", "behavior", "supply-chain", "worm", "formal", "weights", "sidechannel", "circuit", "attest"}
    if all_modules:
        selected = set(all_set)
    if only:
        requested = {x.strip() for x in only.split(",") if x.strip()}
        unknown = requested - all_set
        if unknown:
            raise typer.BadParameter("unsupported modules: " + ", ".join(sorted(unknown)))
        selected = requested
    if not selected:
        raise typer.BadParameter("no runnable static modules selected")

    if "mcp" in selected:
        findings, n_tools = guarded(
            "mcpaudit (source)", scan_mcp_source, ([], 0), root, include_tests, warnings, reach, structural
        )
        findings = list(findings)
        findings += guarded("mcpaudit (manifests)", scan_manifest_files, [], root, warnings)
    if "memory" in selected:
        findings += guarded("memsentry", scan_context_files, [], root, warnings)
    if "rag" in selected and rag:
        findings += guarded("ragsentry", scan_rag_dir, [], rag.resolve(), root, warnings)
    if "formal" in selected:
        findings += guarded("specprove (z3-smt)", scan_specprove_formal, [], root, include_tests, warnings, lean_out)
    if "weights" in selected:
        findings += guarded("weightspecter (rmt)", scan_weightspecter_checkpoints, [], root, include_tests, warnings)
    if "sidechannel" in selected:
        findings += guarded("tokenspecter (viterbi)", scan_tokenspecter_streams, [], root, include_tests, warnings)
    if "circuit" in selected:
        findings += guarded("circuitshield (subspace)", scan_circuitshield_traces, [], root, include_tests, warnings)
    if "attest" in selected:
        findings += guarded("attestinfer (freivalds)", scan_attestinfer_proofs, [], root, include_tests, warnings)
    if "training" in selected:
        dataset = root / "training_data.jsonl"
        if dataset.is_file():
            findings += guarded("trainsentry", scan_training_dataset, [], dataset, warnings)
        else:
            warnings.append("training selected but training_data.jsonl was not found; skipped")
    if "behavior" in selected:
        trace = root / "trace.json"
        if trace.is_file():
            findings += guarded("loopcheck", scan_agent_trace, [], trace, warnings)
        else:
            warnings.append("behavior selected but trace.json was not found; skipped")
    if "supply-chain" in selected:
        manifest = root / "pyproject.toml"
        target = str(manifest if manifest.is_file() else root)
        findings += guarded("agent-install-guardrail", scan_supply_chain, [], target, warnings)
    if "worm" in selected:
        findings += guarded("wormsentry", scan_worm_tree, [], root, warnings)

    if policy:
        try:
            policy_obj = load_policy(policy)
            findings, excluded = apply_policy(findings, policy_obj)
            if excluded:
                warnings.append(f"{excluded} finding(s) excluded by policy")
            if policy_obj.fail_on:
                fail_on = policy_obj.fail_on
        except (OSError, ValueError) as e:
            raise typer.BadParameter(f"cannot read policy: {e}") from e
    elif policy_profile:
        profile = profile_policy(policy_profile)
        if profile.fail_on:
            fail_on = profile.fail_on
        warnings.append(f"using built-in policy profile: {policy_profile}")

    _finish(path, findings, n_tools, warnings, crashed, fail_on, baseline, write_baseline, sarif, json_out, summary)


def _finish(path, findings, n_tools, warnings, crashed, fail_on, baseline, write_baseline, sarif, json_out, summary):
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line, f.scanner, f.rule))
    if write_baseline:
        write_baseline.write_text(json.dumps(sorted({f.fingerprint for f in findings}), indent=2), encoding="utf-8")
        typer.echo(f"baseline written: {len(findings)} findings accepted -> {write_baseline}")

    lifecycle = None
    suppressed = 0
    if baseline:
        try:
            accepted = load_baseline(baseline)
        except (OSError, ValueError) as e:
            raise typer.BadParameter(f"cannot read baseline: {e}") from e
        lifecycle = classify(findings, accepted)
        suppressed = lifecycle.existing_count
        findings = list(lifecycle.new)

    _emit(findings, json_out=json_out, sarif=sarif)
    summary_path = summary or (
        pathlib.Path(os.environ["GITHUB_STEP_SUMMARY"]) if os.environ.get("GITHUB_STEP_SUMMARY") else None
    )
    if summary_path:
        with summary_path.open("a", encoding="utf-8") as fh:
            fh.write(to_markdown(findings, n_tools, warnings, suppressed, lifecycle))

    for w in warnings:
        typer.echo(f"warning: {w}", err=True)
    by_sev = collections.Counter(f.severity for f in findings)
    typer.echo(
        f"tools extracted: {n_tools} | findings: {len(findings)} "
        f"(critical {by_sev['critical']}, high {by_sev['high']}, medium {by_sev['medium']}, low {by_sev['low']})"
    )
    if suppressed:
        typer.echo(f"baseline-suppressed: {suppressed}")
    if lifecycle:
        typer.echo(
            f"lifecycle: new={lifecycle.new_count} "
            f"existing={lifecycle.existing_count} "
            f"resolved={lifecycle.resolved_count}"
        )
    for f in findings[:25]:
        typer.echo(f"  [{f.severity:8}] {f.file}:{f.line}  {f.scanner}  {f.rule}")
    if len(findings) > 25:
        typer.echo(f"  ... and {len(findings) - 25} more")
    if fail_on and crashed and not any(at_least(f.severity, fail_on) for f in findings):
        typer.echo(f"error: {len(crashed)} scanner(s) crashed; result is incomplete (exit 2)", err=True)
        raise typer.Exit(2)
    if fail_on and any(at_least(f.severity, fail_on) for f in findings):
        raise typer.Exit(1)


def _single_module(module: str, target: pathlib.Path | str, out: Optional[pathlib.Path], sarif: Optional[pathlib.Path], fail_on: Optional[str]) -> None:
    if fail_on and fail_on not in SEVERITY_ORDER:
        raise typer.BadParameter("must be one of low|medium|high|critical")
    warnings: list[str] = []
    crashed: list[str] = []
    if module == "training":
        findings = scan_training_dataset(pathlib.Path(target), warnings)
    elif module == "behavior":
        findings = scan_agent_trace(pathlib.Path(target), warnings)
    elif module == "worm":
        findings = scan_worm_tree(pathlib.Path(target), warnings)
    else:
        findings = scan_supply_chain(str(target), warnings) if module == "supply-chain" else []
    _finish(pathlib.Path(str(target)), findings, 0, warnings, crashed, fail_on, None, None, sarif, out, None)


@app.command("training")
def training(
    dataset: pathlib.Path = typer.Argument(..., exists=True, dir_okay=False),
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json"),
    sarif: Optional[pathlib.Path] = typer.Option(None, "--sarif"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on"),
) -> None:
    _single_module("training", dataset, json_out, sarif, fail_on)


@app.command("behavior")
def behavior(
    trace: pathlib.Path = typer.Argument(..., exists=True, dir_okay=False),
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json"),
    sarif: Optional[pathlib.Path] = typer.Option(None, "--sarif"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on"),
) -> None:
    _single_module("behavior", trace, json_out, sarif, fail_on)


@app.command("supply-chain")
def supply_chain(
    target: str = typer.Argument(...),
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json"),
    sarif: Optional[pathlib.Path] = typer.Option(None, "--sarif"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on"),
) -> None:
    _single_module("supply-chain", target, json_out, sarif, fail_on)


@app.command("worm")
def worm(
    path: pathlib.Path = typer.Argument(..., exists=True, file_okay=False),
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json"),
    sarif: Optional[pathlib.Path] = typer.Option(None, "--sarif"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on"),
) -> None:
    _single_module("worm", path, json_out, sarif, fail_on)


@app.command("guard-check")
def guard_check(
    request: str = typer.Option(..., "--request", "-r", help="Initial user prompt / request."),
    tool: str = typer.Option(..., "--tool", "-t", help="Tool name to check."),
    args_json: str = typer.Option("{}", "--args", "-a", help="Tool arguments as JSON string."),
    tainted: bool = typer.Option(True, "--tainted/--untainted", help="Whether the agent has already read untrusted tool output."),
    policy_file: Optional[pathlib.Path] = typer.Option(None, "--policy", exists=True, dir_okay=False, help="Custom GuardPolicy JSON file."),
    trusted: list[str] = typer.Option([], "--trusted", help="Additional trusted destinations."),
    json_out: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
    guard_engine: str = typer.Option("v1", "--guard", help="Guard engine: v1 (default, policy inferred from tool names) or v3 (effect classes and shape-based destinations; STUDY 3g-3h)."),
) -> None:
    """Evaluate runtime data provenance for an agent tool call."""
    if guard_engine not in ("v1", "v3"):
        raise typer.BadParameter("--guard must be v1 or v3")
    try:
        parsed_args = json.loads(args_json)
        if not isinstance(parsed_args, dict):
            raise ValueError("Tool arguments must be a JSON object")
    except Exception as e:
        raise typer.BadParameter(f"invalid --args JSON: {e}") from e

    if policy_file:
        try:
            data = json.loads(policy_file.read_text(encoding="utf-8"))
            if guard_engine == "v3" and (data.get("sinks") or data.get("actions")):
                raise ValueError("'sinks' and 'actions' only apply to --guard v1; v3 reads only 'trusted'")
            policy = GuardPolicy(
                sinks={k: tuple(v) for k, v in data.get("sinks", {}).items()},
                actions={k: tuple(v) for k, v in data.get("actions", {}).items()},
                trusted=frozenset(str(x).strip().lower().rstrip("/") for x in data.get("trusted", ())),
            )
        except Exception as e:
            raise typer.BadParameter(f"cannot load guard policy from {policy_file}: {e}") from e
    else:
        policy = AGENTDOJO_POLICY

    guard: RuntimeGuard | GuardV3
    if guard_engine == "v3":
        guard = GuardV3(request, [*trusted, *sorted(policy.trusted)])
    else:
        guard = RuntimeGuard(policy=policy, user_request=request, trusted=trusted)
    if tainted:
        guard.observe_result("pre-existing-untrusted-read")

    decision = guard.check(tool, parsed_args)

    if json_out:
        typer.echo(json.dumps({"allow": decision.allow, "reason": decision.reason, "tool": tool, "args": parsed_args}))
    else:
        status = "ALLOW" if decision.allow else "HOLD"
        msg = f"[{status}] {tool}"
        if decision.reason:
            msg += f" -> {decision.reason}"
        typer.echo(msg)

    if not decision.allow:
        raise typer.Exit(code=1)


@app.command("guard-mcp", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def guard_mcp(
    ctx: typer.Context,
    request: Optional[str] = typer.Option(None, "--request", "-r", help="The user's request for this session."),
    request_file: Optional[pathlib.Path] = typer.Option(None, "--request-file", help="File holding the current user request; re-read on every call."),
    trusted: list[str] = typer.Option([], "--trusted", help="Destinations always allowed (repeatable)."),
    policy_file: Optional[pathlib.Path] = typer.Option(None, "--policy", exists=True, dir_okay=False, help="JSON with extra sinks/actions/trusted."),
    log_file: Optional[pathlib.Path] = typer.Option(None, "--log", help="Append every guard decision here as JSON lines."),
    guard_engine: str = typer.Option("v1", "--guard", help="Guard engine: v1 (default, policy inferred from tool names) or v3 (effect classes and shape-based destinations; STUDY 3g-3h)."),
) -> None:
    """Run an MCP server behind the runtime guard: aisec guard-mcp -r "..." -- <server command>."""
    from aisec import mcp_guard

    command = list(ctx.args)
    if not command:
        raise typer.BadParameter("give the MCP server command after --, e.g. aisec guard-mcp -r '...' -- python server.py")
    if request is None and request_file is None:
        raise typer.BadParameter("give the user's request with --request or --request-file")
    try:
        session = mcp_guard.build_session(request, str(request_file) if request_file else None, trusted,
                                          str(policy_file) if policy_file else None, str(log_file) if log_file else None, guard_engine)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e
    raise typer.Exit(code=mcp_guard.run(command, session))


@app.command("benchmark")
def benchmark(
    range_dir: pathlib.Path = typer.Argument(..., exists=True, file_okay=False, help="agent-test-range checkout."),
    metrics_json: Optional[pathlib.Path] = typer.Option(None, "--json", help="Write/read machine-readable benchmark metrics."),
) -> None:
    """Run the controlled regression benchmark and report detection quality."""
    output = metrics_json or (range_dir / "benchmark" / "metrics.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    code, output_text = run_range(range_dir, output)
    typer.echo(output_text, nl=False)
    if output.is_file():
        payload = load_metrics(output)
        overall = payload["overall"]
        typer.echo(
            f"benchmark: cases={payload['cases']} "
            f"precision={overall['precision']:.4f} "
            f"recall={overall['recall']:.4f} "
            f"f1={overall['f1']:.4f} "
            f"fpr={overall['false_positive_rate']:.4f}"
        )
        for scanner, metrics in payload["by_scanner"].items():
            typer.echo(
                f"  {scanner}: precision={metrics['precision']:.4f} "
                f"recall={metrics['recall']:.4f} f1={metrics['f1']:.4f} "
                f"fpr={metrics['false_positive_rate']:.4f}"
            )
    raise typer.Exit(code)


@app.command("redteam")
def redteam(
    target: str = typer.Option("mock", "--target", help="mock (offline, scripted) or claude (a Claude model run under --system-prompt-file)."),
    defense: str = typer.Option("moderate", "--defense", help="Mock target defence level: weak, moderate or hardened."),
    model: Optional[str] = typer.Option(None, "--model", help="Model ID for --target claude."),
    system_prompt_file: Optional[pathlib.Path] = typer.Option(None, "--system-prompt-file", exists=True, dir_okay=False, help="System prompt to protect (required for --target claude)."),
    canary: list[str] = typer.Option([], "--canary", help="Synthetic secret planted in the system prompt (repeatable)."),
    forbidden: list[str] = typer.Option([], "--forbidden", help="Regex; a reply matching it breaks the system prompt's rules (repeatable)."),
    strategy: list[str] = typer.Option([], "--strategy", "-s", help="crescendo, steganography or roleplay (repeatable; default all)."),
    max_turns: int = typer.Option(8, "--max-turns", min=1, max=50, help="Turn budget per strategy."),
    breach_score: int = typer.Option(8, "--breach-score", min=1, max=10, help="Judge score at or above which an attack counts as a breach."),
    judge: str = typer.Option("heuristic", "--judge", help="heuristic (deterministic), mock-llm (LLM-judge path, offline stand-in) or claude (LLM-as-a-judge)."),
    judge_model: Optional[str] = typer.Option(None, "--judge-model", help="Model ID for --judge claude."),
    json_out: Optional[pathlib.Path] = typer.Option(None, "--json", help="Write the full JSON report here."),
    fail_on_breach: bool = typer.Option(False, "--fail-on-breach", help="Exit 1 when any attack reaches --breach-score."),
) -> None:
    """Run adaptive multi-turn jailbreak attacks against an LLM target you are authorised to test."""
    from aisec.redteam import engine, targets
    from aisec.redteam import judge as judges
    from aisec.redteam.model import Objective
    from aisec.redteam.report import to_report

    the_target: targets.Target
    try:
        if target == "mock":
            if system_prompt_file or canary or forbidden or model:
                raise typer.BadParameter("--system-prompt-file, --canary, --forbidden and --model apply to --target claude; the mock has its own")
            mock = targets.MockTarget(defense)
            the_target, objective = mock, mock.objective
        elif target == "claude":
            if system_prompt_file is None:
                raise typer.BadParameter("--target claude needs --system-prompt-file")
            prompt = system_prompt_file.read_text(encoding="utf-8")
            missing = [c for c in canary if c not in prompt]
            if missing:
                raise typer.BadParameter(f"canary not present in the system prompt, so it could never leak: {', '.join(missing)}")
            objective = Objective(system_prompt=prompt, canaries=tuple(canary), forbidden=tuple(forbidden))
            the_target = targets.AnthropicTarget(prompt, model or targets.DEFAULT_MODEL)
        else:
            raise typer.BadParameter("--target must be mock or claude")

        the_judge: judges.Judge
        if judge == "heuristic":
            the_judge = judges.HeuristicJudge(objective)
        elif judge == "mock-llm":
            the_judge = judges.LLMJudge(judges.MockJudgeModel(objective), objective)
        elif judge == "claude":
            the_judge = judges.LLMJudge(judges.ClaudeJudgeModel(judge_model), objective)
        else:
            raise typer.BadParameter("--judge must be heuristic, mock-llm or claude")
        result = engine.run(the_target, the_judge, objective, strategies=strategy, max_turns=max_turns, breach_score=breach_score)
    except (ValueError, re.error) as e:
        raise typer.BadParameter(str(e)) from e
    except targets.TargetError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(code=2) from e

    report = to_report(result)
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    typer.echo(f"target: {result.target} | judge: {result.judge} | breach score: {breach_score}")
    for a in report["attacks"]:
        path = " -> ".join(f"{step['technique'].split('/', 1)[1]}={step['score']}" for step in a["attack_path"])
        typer.echo(f"  [{a['outcome'].upper():8}] {a['strategy']:14} max {a['max_score']:>2}/10 in {a['turns_used']} turns | {path}")
    summary = report["summary"]
    typer.echo(
        f"result: {summary['verdict']} | attacks breached: {summary['attacks_breached']}/{summary['attacks_run']} | "
        f"system prompt extracted: {'yes' if summary['system_prompt_extracted'] else 'no'} | "
        f"bypassed: {'yes' if summary['system_prompt_bypassed'] else 'no'}"
    )
    if target == "mock":
        typer.echo("note: the mock target is scripted; this run checks the engine, not any real model.")
    if json_out:
        typer.echo(f"report: {json_out}")
    if fail_on_breach and result.breached:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
