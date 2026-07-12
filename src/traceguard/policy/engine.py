"""Inspectable deterministic policy checks."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from traceguard.types import (
    Decision,
    ExecutionTarget,
    GoalNecessity,
    GoalRelevance,
    Observation,
    RiskLevel,
    SupervisorOutput,
    ToolCall,
    TrustLabel,
)


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    allowed_read_roots: list[str]
    allowed_write_roots: list[str]
    blocked_command_tokens: list[str]
    blocked_shell_operators: list[str]
    sandbox_command_tokens: list[str]
    max_command_length: int = Field(gt=0)

    @classmethod
    def from_file(cls, path: Path) -> PolicyConfig:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))


class DeterministicPolicy:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def evaluate(
        self,
        user_task: str,
        call: ToolCall,
        observations: list[Observation],
    ) -> SupervisorOutput:
        del user_task
        if call.tool_name in {"read_file", "write_report"}:
            return self._evaluate_path(call)
        if call.tool_name == "restricted_command":
            return self._evaluate_command(call, observations)
        return self._allow("POLICY_TOOL_LOW_RISK")

    def _evaluate_path(self, call: ToolCall) -> SupervisorOutput:
        raw_path = str(call.arguments.get("path", ""))
        path = PurePosixPath(raw_path)
        roots = self.config.allowed_read_roots if call.tool_name == "read_file" else self.config.allowed_write_roots
        if call.tool_name == "write_report" and not path.is_absolute() and ".." not in path.parts and len(path.parts) == 1:
            rewritten = call.model_copy(update={"arguments": {**call.arguments, "path": f"artifacts/{raw_path}"}})
            return SupervisorOutput(
                decision=Decision.REWRITE,
                risk=RiskLevel.LOW,
                confidence=1.0,
                policy_violation=False,
                goal_relevance=GoalRelevance.STRONG,
                goal_necessity=GoalNecessity.HELPFUL,
                reason="Normalize report output into the allowed artifacts root.",
                matched_rules=["POLICY_WRITE_ROOT_REWRITE"],
                rewritten_call=rewritten,
            )
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] not in roots:
            return self._block("POLICY_PATH_OUTSIDE_ROOT", RiskLevel.HIGH)
        return self._allow("POLICY_PATH_ALLOWED")

    def _evaluate_command(self, call: ToolCall, observations: list[Observation]) -> SupervisorOutput:
        command = call.arguments.get("command", [])
        if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
            return self._block("POLICY_COMMAND_SCHEMA", RiskLevel.HIGH)
        rendered = " ".join(command)
        lowered = {part.casefold() for part in command}
        if len(rendered) > self.config.max_command_length:
            return self._block("POLICY_COMMAND_TOO_LONG", RiskLevel.HIGH)
        if lowered.intersection(token.casefold() for token in self.config.blocked_command_tokens):
            return self._block("POLICY_COMMAND_BLOCKED_TOKEN", RiskLevel.CRITICAL)
        if any(operator in rendered for operator in self.config.blocked_shell_operators):
            return self._block("POLICY_SHELL_OPERATOR", RiskLevel.HIGH)
        has_untrusted_input = any(
            obs.observation_id in call.consumed_observation_ids
            and obs.trust in {TrustLabel.UNTRUSTED_DOCUMENT, TrustLabel.UNTRUSTED_TOOL}
            for obs in observations
        )
        if command and (command[0].casefold() in self.config.sandbox_command_tokens or has_untrusted_input):
            return SupervisorOutput(
                decision=Decision.ALLOW,
                risk=RiskLevel.MEDIUM,
                confidence=0.85,
                policy_violation=False,
                goal_relevance=GoalRelevance.STRONG,
                goal_necessity=GoalNecessity.HELPFUL,
                reason="Medium-risk command must use a predefined container profile.",
                matched_rules=["POLICY_COMMAND_CONTAINER"],
                execution_target=ExecutionTarget.CONTAINER,
                container_profile="isolated_compute",
            )
        return self._allow("POLICY_COMMAND_LOW_RISK")

    @staticmethod
    def _allow(rule: str) -> SupervisorOutput:
        return SupervisorOutput(
            decision=Decision.ALLOW,
            risk=RiskLevel.LOW,
            confidence=1.0,
            policy_violation=False,
            goal_relevance=GoalRelevance.STRONG,
            goal_necessity=GoalNecessity.HELPFUL,
            reason="Deterministic policy allows the call.",
            matched_rules=[rule],
        )

    @staticmethod
    def _block(rule: str, risk: RiskLevel) -> SupervisorOutput:
        return SupervisorOutput(
            decision=Decision.BLOCK,
            risk=risk,
            confidence=1.0,
            policy_violation=True,
            goal_relevance=GoalRelevance.IRRELEVANT,
            goal_necessity=GoalNecessity.UNNECESSARY,
            reason="Deterministic policy denies the call.",
            matched_rules=[rule],
        )


def load_default_policy() -> PolicyConfig:
    path = Path(__file__).parents[1] / "data" / "policy" / "default.json"
    return PolicyConfig.from_file(path)
