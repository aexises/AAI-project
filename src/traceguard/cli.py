from __future__ import annotations

import argparse
import json
from pathlib import Path

from traceguard.agent import ReActRunner, ScriptedAgent
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
        config=SafeguardConfig(defensive_prompt=True, deterministic_policy=True, llm_supervisor=True),
        policy=DeterministicPolicy(load_default_policy()),
        supervisor=HeuristicSupervisor(),
    )
    call = ToolCall(task_id="smoke", step_id=0, tool_name="calculator", arguments={"expression": "12 * 7"})
    result = ReActRunner(runtime, ScriptedAgent([call])).run("Calculate 12 times 7")
    print(json.dumps({"stopped_reason": result.stopped_reason, "observations": [item.model_dump(mode="json") for item in result.observations]}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="traceguard")
    subparsers = parser.add_subparsers(dest="command", required=True)
    smoke = subparsers.add_parser("smoke", help="run an offline supervised episode")
    smoke.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    if args.command == "smoke":
        return _smoke(args.root.resolve())
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

