from traceguard.policy.engine import DeterministicPolicy, load_default_policy
from traceguard.types import Decision, ExecutionTarget, ToolCall


def call(tool_name, arguments):
    return ToolCall(task_id="t", step_id=0, tool_name=tool_name, arguments=arguments)


def test_blocks_path_escape():
    output = DeterministicPolicy(load_default_policy()).evaluate("read", call("read_file", {"path": "../secret"}), [])
    assert output.decision is Decision.BLOCK


def test_rewrites_report_into_artifacts():
    output = DeterministicPolicy(load_default_policy()).evaluate("write", call("write_report", {"path": "report.md", "content": "ok"}), [])
    assert output.decision is Decision.REWRITE
    assert output.rewritten_call.arguments["path"] == "artifacts/report.md"


def test_routes_uncertain_command_to_container():
    output = DeterministicPolicy(load_default_policy()).evaluate("run python", call("restricted_command", {"command": ["python3", "script.py"]}), [])
    assert output.decision is Decision.ALLOW
    assert output.execution_target is ExecutionTarget.CONTAINER


def test_blocks_critical_command():
    output = DeterministicPolicy(load_default_policy()).evaluate("run", call("restricted_command", {"command": ["sudo", "shutdown", "now"]}), [])
    assert output.decision is Decision.BLOCK

