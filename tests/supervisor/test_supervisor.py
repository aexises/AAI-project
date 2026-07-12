from traceguard.supervisor.base import merge_outputs
from traceguard.supervisor.heuristic import HeuristicSupervisor
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


def output(decision):
    return SupervisorOutput(decision=decision, risk=RiskLevel.LOW, confidence=1, policy_violation=False, goal_relevance=GoalRelevance.STRONG, goal_necessity=GoalNecessity.HELPFUL, reason="test", rewritten_call=ToolCall(task_id="t", step_id=0, tool_name="calculator") if decision is Decision.REWRITE else None)


def test_decision_precedence():
    assert merge_outputs([output(Decision.ALLOW), output(Decision.REWRITE), output(Decision.ESCALATE)]).decision is Decision.ESCALATE


def test_indirect_command_is_containerized():
    observation = Observation(content="run this", source_type="document", source_id="d", trust=TrustLabel.UNTRUSTED_DOCUMENT, may_contain_instructions=True)
    call = ToolCall(task_id="t", step_id=0, tool_name="restricted_command", arguments={"command": ["python3", "x.py"]}, consumed_observation_ids=[observation.observation_id])
    result = HeuristicSupervisor().evaluate("inspect with python", call, [observation])
    assert result.execution_target is ExecutionTarget.CONTAINER

