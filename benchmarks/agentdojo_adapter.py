"""Boundary for running TraceGuard cases alongside pinned AgentDojo."""

from importlib.metadata import PackageNotFoundError, version

from benchmarks.schema import BenchmarkCase

PINNED_AGENTDOJO_VERSION = "0.1.35"


def verify_agentdojo_installation() -> None:
    try:
        installed = version("agentdojo")
    except PackageNotFoundError as exc:
        raise RuntimeError("install TraceGuard with the 'agentdojo' extra") from exc
    if installed != PINNED_AGENTDOJO_VERSION:
        raise RuntimeError(f"AgentDojo {PINNED_AGENTDOJO_VERSION} required, found {installed}")


def agentdojo_metadata(case: BenchmarkCase) -> dict[str, object]:
    """Map custom cases to AgentDojo's task/injection conceptual fields."""
    return {
        "user_task": case.user_goal,
        "injection_task": case.attacker_goal,
        "attack_source": case.attack_source,
        "utility_checks": case.utility_checks,
        "security_checks": case.security_checks,
        "initial_state": case.initial_state,
    }

