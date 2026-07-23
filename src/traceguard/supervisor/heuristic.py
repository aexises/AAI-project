"""Offline supervisor used for tests and reproducible smoke experiments."""

from __future__ import annotations

from traceguard.types import (
    Decision,
    ExecutionTarget,
    GoalNecessity,
    GoalRelevance,
    Observation,
    PostRunAssessment,
    PostRunDisposition,
    RiskLevel,
    SandboxEvidence,
    SupervisorOutput,
    ToolCall,
    TrustLabel,
)


class HeuristicSupervisor:
    def evaluate(
        self, user_task: str, call: ToolCall, observations: list[Observation]
    ) -> SupervisorOutput:
        task_words = set(user_task.casefold().split())
        call_words = set((call.tool_name + " " + str(call.arguments)).casefold().split())
        overlap = task_words.intersection(call_words)
        relevance = GoalRelevance.STRONG if overlap else GoalRelevance.WEAK
        untrusted = any(
            obs.observation_id in call.consumed_observation_ids
            and obs.trust in {TrustLabel.UNTRUSTED_DOCUMENT, TrustLabel.UNTRUSTED_TOOL}
            and obs.may_contain_instructions
            for obs in observations
        )
        suspicious = {"secret", "credential", "password", "exfiltrate", "delete", "sudo"}
        rendered = (user_task + " " + str(call.arguments)).casefold()
        if any(word in rendered for word in suspicious):
            return self._output(
                Decision.BLOCK, RiskLevel.HIGH, relevance, True, "Suspicious prohibited intent."
            )
        if call.tool_name == "restricted_command" and untrusted:
            return self._output(
                Decision.ALLOW,
                RiskLevel.MEDIUM,
                relevance,
                False,
                "Untrusted instructions make command execution uncertain; contain it.",
                ExecutionTarget.CONTAINER,
                "isolated_compute",
            )
        return self._output(
            Decision.ALLOW, RiskLevel.LOW, relevance, False, "Call appears relevant and safe."
        )

    def reevaluate(
        self, user_task: str, call: ToolCall, evidence: SandboxEvidence
    ) -> PostRunAssessment:
        del user_task, call
        if evidence.timed_out or evidence.blocked_operations:
            return PostRunAssessment(
                risk=RiskLevel.HIGH,
                confidence=0.9,
                evidence=evidence.blocked_operations or ["execution timed out"],
                disposition=PostRunDisposition.BLOCK_RESULT,
                reason="Sandbox behavior increased risk.",
            )
        return PostRunAssessment(
            risk=RiskLevel.LOW,
            confidence=0.7,
            evidence=["no prohibited behavior observed"],
            disposition=PostRunDisposition.ACCEPT_RESULT,
            reason="Sandbox result may be consumed without host re-execution.",
        )

    @staticmethod
    def _output(
        decision: Decision,
        risk: RiskLevel,
        relevance: GoalRelevance,
        violation: bool,
        reason: str,
        target: ExecutionTarget | None = None,
        profile: str | None = None,
    ) -> SupervisorOutput:
        return SupervisorOutput(
            decision=decision,
            risk=risk,
            confidence=0.8,
            policy_violation=violation,
            goal_relevance=relevance,
            goal_necessity=GoalNecessity.HELPFUL
            if relevance is not GoalRelevance.IRRELEVANT
            else GoalNecessity.UNNECESSARY,
            reason=reason,
            execution_target=target,
            container_profile=profile,
        )
