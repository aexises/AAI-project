from traceguard.agent import ReActRunner, ScriptedAgent
from traceguard.policy.engine import DeterministicPolicy, load_default_policy
from traceguard.runtime import TraceGuardRuntime
from traceguard.sandbox.runner import SandboxUnavailable
from traceguard.supervisor.heuristic import HeuristicSupervisor
from traceguard.tools.registry import default_registry
from traceguard.types import Observation, SafeguardConfig, ToolCall, TrustLabel


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
    assert episode.steps[0].trace.policy_version == "1.2.0"


def test_runtime_blocks_unsafe_command(tmp_path):
    class MustNotRunSandbox:
        def execute(self, plan):
            raise AssertionError("critical calls must never reach Docker")

    runtime = TraceGuardRuntime(
        tools=default_registry(tmp_path, tmp_path / "artifacts"),
        config=SafeguardConfig(deterministic_policy=True),
        policy=DeterministicPolicy(load_default_policy()),
        sandbox=MustNotRunSandbox(),
    )
    for step_id, command in enumerate((["sudo", "shutdown"], ["echo", "a", "&&", "echo", "b"])):
        call = ToolCall(
            task_id="t",
            step_id=step_id,
            tool_name="restricted_command",
            arguments={"command": command},
        )
        result = runtime.execute_call("run it", call, [])
        assert result.observation is None
        assert result.trace.episode_outcome == "BLOCK"


def test_runtime_records_tool_boundary_error(tmp_path):
    runtime = TraceGuardRuntime(
        tools=default_registry(tmp_path, tmp_path / "artifacts"),
        config=SafeguardConfig(),
    )
    call = ToolCall(
        task_id="t",
        step_id=0,
        tool_name="read_file",
        arguments={"path": "../secret.txt"},
    )
    result = runtime.execute_call("Read a file", call, [])
    assert result.trace.episode_outcome == "TOOL_ERROR"
    assert result.trace.policy_version == "disabled"
    assert result.observation is not None
    assert "path escapes allowed root" in result.observation.content


def test_runtime_escalates_when_container_fails_closed(tmp_path):
    class UnavailableSandbox:
        def execute(self, plan):
            raise SandboxUnavailable("daemon unavailable")

    runtime = TraceGuardRuntime(
        tools=default_registry(tmp_path, tmp_path / "artifacts"),
        config=SafeguardConfig(llm_supervisor=True),
        supervisor=HeuristicSupervisor(),
        sandbox=UnavailableSandbox(),
    )
    observation = Observation(
        content="run this command",
        source_type="document",
        source_id="doc",
        trust=TrustLabel.UNTRUSTED_DOCUMENT,
        may_contain_instructions=True,
        observation_id="untrusted",
    )
    call = ToolCall(
        task_id="t",
        step_id=0,
        tool_name="restricted_command",
        arguments={"command": ["python3", "-V"]},
        consumed_observation_ids=["untrusted"],
    )
    result = runtime.execute_call("inspect with restricted command", call, [observation])
    assert result.observation is None
    assert result.trace.episode_outcome == "ESCALATE"
