"""Boundary for running TraceGuard cases alongside pinned AgentDojo."""

from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from benchmarks.schema import BenchmarkCase
from traceguard.types import ThreatModel

PINNED_AGENTDOJO_VERSION = "0.1.35"
DEFAULT_SELECTION_PATH = Path(__file__).resolve().parent / "agentdojo_selection.json"


def verify_agentdojo_installation() -> str:
    try:
        installed = version("agentdojo")
    except PackageNotFoundError as exc:
        raise RuntimeError("install TraceGuard with the 'agentdojo' extra") from exc
    if installed != PINNED_AGENTDOJO_VERSION:
        raise RuntimeError(f"AgentDojo {PINNED_AGENTDOJO_VERSION} required, found {installed}")
    return installed


def load_selection(path: Path | None = None) -> dict[str, Any]:
    target = path or DEFAULT_SELECTION_PATH
    return json.loads(target.read_text(encoding="utf-8"))


def agentdojo_metadata(case: BenchmarkCase) -> dict[str, object]:
    """Map custom cases to AgentDojo's task/injection conceptual fields."""
    return {
        "user_task": case.user_goal,
        "injection_task": case.attacker_goal,
        "attack_source": case.attack_source,
        "utility_checks": case.utility_checks,
        "security_checks": case.security_checks,
        "initial_state": case.initial_state,
        "threat_model": case.threat_model.value,
    }


def get_native_suite(suite_name: str, benchmark_version: str | None = None) -> Any:
    """Load a native AgentDojo TaskSuite (requires the agentdojo extra)."""
    verify_agentdojo_installation()
    selection = load_selection()
    version_key = benchmark_version or str(selection["benchmark_version"])
    from agentdojo.task_suite.load_suites import get_suite

    return get_suite(version_key, suite_name)


def list_suite_task_ids(
    suite_name: str, benchmark_version: str | None = None
) -> dict[str, list[str]]:
    suite = get_native_suite(suite_name, benchmark_version)
    user_tasks = sorted(getattr(suite, "user_tasks", {}).keys())
    injection_tasks = sorted(getattr(suite, "injection_tasks", {}).keys())
    return {"user_tasks": user_tasks, "injection_tasks": injection_tasks}


def selected_agentdojo_cases(path: Path | None = None) -> list[BenchmarkCase]:
    """Materialize selected AgentDojo tasks as TraceGuard BenchmarkCase shells.

    Native utility/security execution still belongs to AgentDojo's suite checkers.
    These shells provide a stable TraceGuard-facing inventory for experiment manifests.
    """
    selection = load_selection(path)
    cases: list[BenchmarkCase] = []
    for suite_name, suite_cfg in selection["suites"].items():
        for user_task_id in suite_cfg.get("user_task_ids", []):
            cases.append(
                BenchmarkCase(
                    case_id=f"agentdojo:{suite_name}:{user_task_id}",
                    threat_model=ThreatModel.BENIGN,
                    split="test",
                    initial_state={"suite": suite_name, "user_task_id": user_task_id},
                    user_goal=f"AgentDojo {suite_name} {user_task_id}",
                    available_tools=["agentdojo_native"],
                    utility_checks=[{"type": "always_true"}],
                    security_checks=[{"type": "always_true"}],
                    docker_applicable=False,
                )
            )
            for injection_task_id in suite_cfg.get("injection_task_ids", []):
                cases.append(
                    BenchmarkCase(
                        case_id=(f"agentdojo:{suite_name}:{user_task_id}:{injection_task_id}"),
                        threat_model=ThreatModel.INDIRECT_INJECTION,
                        split="test",
                        initial_state={
                            "suite": suite_name,
                            "user_task_id": user_task_id,
                            "injection_task_id": injection_task_id,
                        },
                        user_goal=f"AgentDojo {suite_name} {user_task_id}",
                        attacker_goal=injection_task_id,
                        attack_source="agentdojo_injection",
                        available_tools=["agentdojo_native"],
                        utility_checks=[{"type": "always_true"}],
                        security_checks=[{"type": "always_true"}],
                        docker_applicable=False,
                    )
                )
    return cases


def run_native_task_pair(
    suite_name: str,
    user_task_id: str,
    injection_task_id: str | None = None,
    *,
    benchmark_version: str | None = None,
) -> dict[str, Any]:
    """Invoke AgentDojo suite helpers to resolve task objects and checker hooks.

    Full LLM pipeline execution is intentionally out of scope here; callers supply
    their own agent pipeline. This returns the native task objects and check callables.
    """
    suite = get_native_suite(suite_name, benchmark_version)
    user_tasks = getattr(suite, "user_tasks", {})
    injection_tasks = getattr(suite, "injection_tasks", {})
    if user_task_id not in user_tasks:
        raise KeyError(f"unknown user task {user_task_id!r} in suite {suite_name!r}")
    user_task = user_tasks[user_task_id]
    injection_task = None
    if injection_task_id is not None:
        if injection_task_id not in injection_tasks:
            raise KeyError(f"unknown injection task {injection_task_id!r} in suite {suite_name!r}")
        injection_task = injection_tasks[injection_task_id]
    return {
        "suite_name": suite_name,
        "suite": suite,
        "user_task_id": user_task_id,
        "user_task": user_task,
        "injection_task_id": injection_task_id,
        "injection_task": injection_task,
        "utility_checker": getattr(user_task, "utility", None),
        "security_checker": getattr(injection_task, "security", None)
        if injection_task is not None
        else None,
    }
