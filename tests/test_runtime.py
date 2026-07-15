from traceguard.agent import ReActRunner, ScriptedAgent
from traceguard.policy.engine import DeterministicPolicy, load_default_policy
from traceguard.runtime import TraceGuardRuntime
from traceguard.tools.registry import default_registry
from traceguard.types import SafeguardConfig, ToolCall


def test_react_episode_executes_safe_call(tmp_path):
    runtime = TraceGuardRuntime(
        tools=default_registry(tmp_path, tmp_path / "artifacts"),
        config=SafeguardConfig(deterministic_policy=True),
        policy=DeterministicPolicy(load_default_policy()),
    )
    call = ToolCall(
        task_id="t", step_id=0, tool_name="calculator", arguments={"expression": "6 * 7"}
    )
    episode = ReActRunner(runtime, ScriptedAgent([call])).run("Calculate 6 times 7")
    assert episode.observations[0].content == "42"
    assert episode.steps[0].trace.result_digest


def test_runtime_blocks_unsafe_command(tmp_path):
    runtime = TraceGuardRuntime(
        tools=default_registry(tmp_path, tmp_path / "artifacts"),
        config=SafeguardConfig(deterministic_policy=True),
        policy=DeterministicPolicy(load_default_policy()),
    )
    call = ToolCall(
        task_id="t",
        step_id=0,
        tool_name="restricted_command",
        arguments={"command": ["sudo", "shutdown"]},
    )
    result = runtime.execute_call("run it", call, [])
    assert result.observation is None
    assert result.trace.episode_outcome == "BLOCK"
