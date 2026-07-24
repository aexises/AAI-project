from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from benchmarks.agentdojo_adapter import (
    load_selection,
    validate_selection,
    verify_agentdojo_installation,
)
from benchmarks.schema import default_cases_path, load_cases
from traceguard.agent import ReActRunner, ScriptedAgent
from traceguard.experiments import (
    default_ablations_path,
    load_ablations,
    regenerate_analysis_from_traces,
    run_experiment,
)
from traceguard.policy.engine import DeterministicPolicy, load_default_policy
from traceguard.runtime import TraceGuardRuntime
from traceguard.sandbox.config import default_sandbox_configuration_path
from traceguard.sandbox.runner import ContainerRunner, SandboxUnavailable
from traceguard.supervisor.heuristic import HeuristicSupervisor
from traceguard.tools.registry import default_registry
from traceguard.types import ExecutionPlan, ExecutionTarget, SafeguardConfig, ToolCall


def _smoke(root: Path) -> int:
    artifacts = root / "artifacts"
    registry = default_registry(root, artifacts)
    runtime = TraceGuardRuntime(
        tools=registry,
        config=SafeguardConfig(
            defensive_prompt=True, deterministic_policy=True, llm_supervisor=True
        ),
        policy=DeterministicPolicy(load_default_policy()),
        supervisor=HeuristicSupervisor(),
    )
    call = ToolCall(
        task_id="smoke", step_id=0, tool_name="calculator", arguments={"expression": "12 * 7"}
    )
    result = ReActRunner(runtime, ScriptedAgent([call])).run("Calculate 12 times 7")
    print(
        json.dumps(
            {
                "stopped_reason": result.stopped_reason,
                "observations": [item.model_dump(mode="json") for item in result.observations],
            },
            indent=2,
        )
    )
    return 0


def _experiment(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    cases_path = args.cases.resolve() if args.cases else default_cases_path()
    ablations_path = args.ablations.resolve() if args.ablations else default_ablations_path()
    cases = load_cases(cases_path, split=args.split)
    ablations = load_ablations(ablations_path)
    if args.post_run:
        ablations = {
            name: config.model_copy(update={"post_run_reevaluation": True})
            for name, config in ablations.items()
        }
    ablation_filter = {args.ablation} if args.ablation else None
    case_filter = {args.case} if args.case else None
    artifacts_dir = (args.artifacts or (root / "artifacts")).resolve()
    results, report, run_dir = run_experiment(
        cases=cases,
        ablations=ablations,
        seed=args.seed,
        artifacts_dir=artifacts_dir,
        code_revision=args.code_revision,
        split=args.split,
        cases_path=cases_path,
        ablation_filter=ablation_filter,
        case_filter=case_filter,
        container_execution=args.container,
        sandbox_config_path=args.sandbox_config.resolve(),
    )
    print(
        json.dumps(
            {
                "run_dir": str(run_dir),
                "n_results": len(results),
                "episode_metrics": report.episode,
                "by_threat_model": report.by_threat_model,
            },
            indent=2,
        )
    )
    return 0


def _smoke_matrix(root: Path, artifacts: Path | None, seed: int) -> int:
    cases = load_cases(default_cases_path(), split="dev")
    smoke_ids = {
        "benign_math_dev",
        "policy_unnecessary_shell",
        "direct_destructive_command",
        "indirect_document_instruction",
    }
    selected = [case for case in cases if case.case_id in smoke_ids]
    results, report, run_dir = run_experiment(
        cases=selected,
        ablations=load_ablations(default_ablations_path()),
        seed=seed,
        artifacts_dir=(artifacts or (root / "artifacts")).resolve(),
        split="dev",
        cases_path=default_cases_path(),
    )
    print(
        json.dumps(
            {
                "run_dir": str(run_dir),
                "n_results": len(results),
                "episode_metrics": report.episode,
            },
            indent=2,
        )
    )
    return 0


def _agentdojo_info(_: argparse.Namespace) -> int:
    selection = load_selection()
    payload: dict[str, object] = {"selection": selection}
    try:
        payload["installed"] = verify_agentdojo_installation()
        payload["validated_selection"] = validate_selection()
    except RuntimeError as exc:
        payload["installed"] = None
        payload["install_error"] = str(exc)
        print(json.dumps(payload, indent=2))
        return 1
    print(json.dumps(payload, indent=2))
    return 0


def _analyze(args: argparse.Namespace) -> int:
    results, report = regenerate_analysis_from_traces(args.run_dir.resolve())
    print(
        json.dumps(
            {
                "run_dir": str(args.run_dir.resolve()),
                "n_results": len(results),
                "episode_metrics": report.episode,
            },
            indent=2,
        )
    )
    return 0


def _sandbox_check(args: argparse.Namespace) -> int:
    runner = ContainerRunner(
        args.config.resolve(),
        workspace_root=args.root.resolve(),
        artifact_root=args.artifacts.resolve(),
    )
    try:
        architecture = runner.check_environment()
    except SandboxUnavailable as exc:
        print(json.dumps({"ready": False, "error": str(exc)}, indent=2))
        return 1
    print(
        json.dumps(
            {
                "ready": True,
                "architecture": architecture,
                "image": runner.image,
                "config_version": runner.config.version,
                "enabled_profiles": sorted(
                    name for name, profile in runner.config.profiles.items() if profile.enabled
                ),
            },
            indent=2,
        )
    )
    return 0


def _sandbox_benchmark(args: argparse.Namespace) -> int:
    config_path = args.config.resolve()
    runner = ContainerRunner(
        config_path,
        workspace_root=args.root.resolve(),
        artifact_root=args.artifacts.resolve(),
    )
    architecture = runner.check_environment()
    implementation_hasher = hashlib.sha256()
    for relative in (
        "src/traceguard/cli.py",
        "src/traceguard/runtime.py",
        "src/traceguard/sandbox/config.py",
        "src/traceguard/sandbox/runner.py",
        "src/traceguard/types.py",
    ):
        path = args.root.resolve() / relative
        implementation_hasher.update(relative.encode())
        implementation_hasher.update(path.read_bytes())
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=args.root.resolve(),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    durations: list[float] = []
    peak_memory: list[int] = []
    disk_usage: list[int] = []
    workload_ms = 1500
    for index in range(args.runs):
        call = ToolCall(
            task_id="sandbox-benchmark",
            step_id=index,
            tool_name="restricted_command",
            arguments={
                "command": [
                    "python3",
                    "-c",
                    "import time; print('traceguard-canary', flush=True); time.sleep(1.5)",
                ]
            },
        )
        evidence = runner.execute(
            ExecutionPlan(
                effective_call=call,
                target=ExecutionTarget.CONTAINER,
                sandbox_profile="isolated_compute",
                validated=True,
                validation_reason="fixed sandbox benchmark canary",
            )
        )
        if evidence.exit_code != 0 or evidence.stdout.strip() != "traceguard-canary":
            raise SandboxUnavailable("sandbox benchmark canary failed")
        durations.append(max(0.0, evidence.duration_ms - workload_ms))
        if evidence.peak_memory_bytes is not None:
            peak_memory.append(evidence.peak_memory_bytes)
        if evidence.disk_usage_bytes is not None:
            disk_usage.append(evidence.disk_usage_bytes)
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "code_revision": revision.stdout.strip() if revision.returncode == 0 else "unknown",
        "implementation_sha256": implementation_hasher.hexdigest(),
        "config_version": runner.config.version,
        "config_path": str(config_path),
        "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "image": runner.image,
        "architecture": architecture,
        "host_platform": platform.platform(),
        "runs": args.runs,
        "fixed_workload_ms": workload_ms,
        "cold_start_ms": durations[0],
        "warm_mean_ms": statistics.fmean(durations[1:]) if len(durations) > 1 else None,
        "durations_ms": durations,
        "cleanup_successes": args.runs,
        "peak_memory_bytes": max(peak_memory) if peak_memory else None,
        "max_writable_layer_bytes": max(disk_usage) if disk_usage else None,
    }
    output = args.artifacts.resolve() / "sandbox_benchmark.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({**payload, "output": str(output)}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="traceguard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    smoke = subparsers.add_parser("smoke", help="run an offline supervised episode")
    smoke.add_argument("--root", type=Path, default=Path.cwd())

    smoke_matrix = subparsers.add_parser(
        "smoke-matrix",
        help="run four representative threat cases across all eight ablations",
    )
    smoke_matrix.add_argument("--root", type=Path, default=Path.cwd())
    smoke_matrix.add_argument("--artifacts", type=Path, default=None)
    smoke_matrix.add_argument("--seed", type=int, default=0)

    experiment = subparsers.add_parser(
        "experiment",
        help="run one case, one ablation, or the full safeguard matrix",
    )
    experiment.add_argument("--root", type=Path, default=Path.cwd())
    experiment.add_argument("--cases", type=Path, default=None)
    experiment.add_argument("--ablations", type=Path, default=None)
    experiment.add_argument("--artifacts", type=Path, default=None)
    experiment.add_argument("--split", choices=["dev", "test", "all"], default="dev")
    experiment.add_argument("--ablation", type=str, default=None, help="e.g. A2")
    experiment.add_argument("--case", type=str, default=None, help="single case_id")
    experiment.add_argument("--seed", type=int, default=0)
    experiment.add_argument("--code-revision", type=str, default=None)
    experiment.add_argument(
        "--container",
        action="store_true",
        help="execute approved container routes instead of failing closed",
    )
    experiment.add_argument(
        "--sandbox-config",
        type=Path,
        default=default_sandbox_configuration_path(),
    )
    experiment.add_argument(
        "--post-run",
        action="store_true",
        help="enable exploratory supervisor reevaluation of container evidence",
    )

    analyze = subparsers.add_parser(
        "analyze",
        help="regenerate summary.json and summary.csv from sanitized traces",
    )
    analyze.add_argument("--run-dir", type=Path, required=True)

    subparsers.add_parser(
        "agentdojo-info",
        help="show pinned AgentDojo selection and installation status",
    )

    sandbox_check = subparsers.add_parser(
        "sandbox-check",
        help="verify Docker, architecture, image digest, and trusted profiles",
    )
    sandbox_check.add_argument("--root", type=Path, default=Path.cwd())
    sandbox_check.add_argument(
        "--config",
        type=Path,
        default=default_sandbox_configuration_path(),
    )
    sandbox_check.add_argument(
        "--artifacts",
        type=Path,
        default=Path.cwd() / "artifacts",
    )

    sandbox_benchmark = subparsers.add_parser(
        "sandbox-benchmark",
        help="measure cold/warm containment latency and cleanup reliability",
    )
    sandbox_benchmark.add_argument("--root", type=Path, default=Path.cwd())
    sandbox_benchmark.add_argument(
        "--config",
        type=Path,
        default=default_sandbox_configuration_path(),
    )
    sandbox_benchmark.add_argument(
        "--artifacts",
        type=Path,
        default=Path.cwd() / "artifacts",
    )
    sandbox_benchmark.add_argument("--runs", type=int, choices=range(1, 101), default=5)

    args = parser.parse_args(argv)
    if args.command == "smoke":
        return _smoke(args.root.resolve())
    if args.command == "smoke-matrix":
        return _smoke_matrix(args.root.resolve(), args.artifacts, args.seed)
    if args.command == "experiment":
        return _experiment(args)
    if args.command == "agentdojo-info":
        return _agentdojo_info(args)
    if args.command == "analyze":
        return _analyze(args)
    if args.command == "sandbox-check":
        return _sandbox_check(args)
    if args.command == "sandbox-benchmark":
        try:
            return _sandbox_benchmark(args)
        except SandboxUnavailable as exc:
            print(json.dumps({"completed": False, "error": str(exc)}, indent=2))
            return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
