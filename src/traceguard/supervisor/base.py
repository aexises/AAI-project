"""Supervisor interface and deterministic combination semantics."""

from __future__ import annotations

from typing import Protocol

from traceguard.types import Observation, SandboxEvidence, SupervisorOutput, ToolCall


class Supervisor(Protocol):
    def evaluate(
        self, user_task: str, call: ToolCall, observations: list[Observation]
    ) -> SupervisorOutput: ...

    def reevaluate(self, user_task: str, call: ToolCall, evidence: SandboxEvidence): ...


_PRECEDENCE = {"ALLOW": 0, "REWRITE": 1, "ESCALATE": 2, "BLOCK": 3}
_RISK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def merge_outputs(outputs: list[SupervisorOutput]) -> SupervisorOutput | None:
    if not outputs:
        return None
    winner = max(outputs, key=lambda output: _PRECEDENCE[output.decision.value])
    container_outputs = [
        output for output in outputs if output.execution_target and output.container_profile
    ]
    if container_outputs and winner.decision.value not in {"BLOCK", "ESCALATE"}:
        strictest = max(container_outputs, key=lambda output: _RISK[output.risk.value])
        return winner.model_copy(
            update={
                "execution_target": strictest.execution_target,
                "container_profile": strictest.container_profile,
            }
        )
    return winner
