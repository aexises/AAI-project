"""Minimal ReAct loop with a pluggable call-proposal agent."""

from __future__ import annotations

from typing import Protocol

from traceguard.runtime import RuntimeResult, TraceGuardRuntime, build_system_prompt
from traceguard.types import Observation, ToolCall


class TaskAgent(Protocol):
    def propose(
        self, system_prompt: str, user_task: str, observations: list[Observation], step_id: int
    ) -> ToolCall | None: ...


class EpisodeResult:
    def __init__(
        self, observations: list[Observation], steps: list[RuntimeResult], stopped_reason: str
    ) -> None:
        self.observations = observations
        self.steps = steps
        self.stopped_reason = stopped_reason


class ReActRunner:
    def __init__(self, runtime: TraceGuardRuntime, agent: TaskAgent, max_steps: int = 10) -> None:
        self.runtime = runtime
        self.agent = agent
        self.max_steps = max_steps

    def run(
        self, user_task: str, initial_observations: list[Observation] | None = None
    ) -> EpisodeResult:
        system_prompt = build_system_prompt(self.runtime.config.defensive_prompt)
        observations: list[Observation] = list(initial_observations or [])
        steps: list[RuntimeResult] = []
        for step_id in range(self.max_steps):
            call = self.agent.propose(system_prompt, user_task, observations, step_id)
            if call is None:
                return EpisodeResult(observations, steps, "agent_finished")
            result = self.runtime.execute_call(user_task, call, observations)
            steps.append(result)
            if result.observation:
                observations.append(result.observation)
            if result.trace.episode_outcome in {"BLOCK", "ESCALATE"}:
                return EpisodeResult(observations, steps, result.trace.episode_outcome.lower())
        return EpisodeResult(observations, steps, "max_steps")


class ScriptedAgent:
    """Reproducible agent for benchmark plumbing and integration tests."""

    def __init__(self, calls: list[ToolCall]) -> None:
        self.calls = calls

    def propose(
        self, system_prompt: str, user_task: str, observations: list[Observation], step_id: int
    ) -> ToolCall | None:
        del system_prompt, user_task
        if step_id >= len(self.calls):
            return None
        call = self.calls[step_id]
        if "$last_observation" not in call.consumed_observation_ids:
            return call
        if not observations:
            raise ValueError("$last_observation requires a prior observation")
        return call.model_copy(
            update={
                "consumed_observation_ids": [
                    observations[-1].observation_id if item == "$last_observation" else item
                    for item in call.consumed_observation_ids
                ]
            }
        )
