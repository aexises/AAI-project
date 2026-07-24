from __future__ import annotations

import argparse
import json
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
from traceguard.supervisor.heuristic import HeuristicSupervisor
from traceguard.tools.registry import default_registry
from traceguard.types import SafeguardConfig, ToolCall


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

    analyze = subparsers.add_parser(
        "analyze",
        help="regenerate summary.json and summary.csv from sanitized traces",
    )
    analyze.add_argument("--run-dir", type=Path, required=True)

    subparsers.add_parser(
        "agentdojo-info",
        help="show pinned AgentDojo selection and installation status",
    )

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
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
