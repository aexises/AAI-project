from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmarks.agentdojo_adapter import load_selection, verify_agentdojo_installation
from benchmarks.schema import default_cases_path, load_cases
from traceguard.agent import ReActRunner, ScriptedAgent
from traceguard.experiments import default_ablations_path, load_ablations, run_experiment
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


def _agentdojo_info(_: argparse.Namespace) -> int:
    selection = load_selection()
    payload: dict[str, object] = {"selection": selection}
    try:
        payload["installed"] = verify_agentdojo_installation()
    except RuntimeError as exc:
        payload["installed"] = None
        payload["install_error"] = str(exc)
    print(json.dumps(payload, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="traceguard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    smoke = subparsers.add_parser("smoke", help="run an offline supervised episode")
    smoke.add_argument("--root", type=Path, default=Path.cwd())

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
    experiment.add_argument("--code-revision", type=str, default="local")

    subparsers.add_parser(
        "agentdojo-info",
        help="show pinned AgentDojo selection and installation status",
    )

    args = parser.parse_args(argv)
    if args.command == "smoke":
        return _smoke(args.root.resolve())
    if args.command == "experiment":
        return _experiment(args)
    if args.command == "agentdojo-info":
        return _agentdojo_info(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
