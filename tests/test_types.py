import pytest
from pydantic import ValidationError

from traceguard.types import (
    Decision,
    ExecutionTarget,
    GoalNecessity,
    GoalRelevance,
    RiskLevel,
    SupervisorOutput,
)


def test_rewrite_requires_rewritten_call():
    with pytest.raises(ValidationError):
        SupervisorOutput(
            decision=Decision.REWRITE,
            risk=RiskLevel.LOW,
            confidence=1,
            policy_violation=False,
            goal_relevance=GoalRelevance.STRONG,
            goal_necessity=GoalNecessity.HELPFUL,
            reason="rewrite",
        )


def test_container_target_requires_profile():
    with pytest.raises(ValidationError):
        SupervisorOutput(
            decision=Decision.ALLOW,
            risk=RiskLevel.MEDIUM,
            confidence=1,
            policy_violation=False,
            goal_relevance=GoalRelevance.STRONG,
            goal_necessity=GoalNecessity.HELPFUL,
            reason="contain",
            execution_target=ExecutionTarget.CONTAINER,
        )
