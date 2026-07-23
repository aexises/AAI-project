import subprocess

import pytest

from traceguard.sandbox.runner import ContainerRunner, SandboxUnavailable
from traceguard.types import ExecutionPlan, ExecutionTarget, ToolCall


def plan():
    call = ToolCall(
        task_id="t",
        step_id=0,
        tool_name="restricted_command",
        arguments={"command": ["python3", "-V"]},
    )
    return ExecutionPlan(
        effective_call=call,
        target=ExecutionTarget.CONTAINER,
        sandbox_profile="isolated_compute",
        validated=True,
    )


def test_requires_digest_pinned_image():
    with pytest.raises(SandboxUnavailable):
        ContainerRunner(image="python:3.11").execute(plan())


def test_builds_hardened_no_network_command():
    captured = {}

    def fake(command, **kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, "Python 3.11", "")

    evidence = ContainerRunner(image="example@sha256:" + "a" * 64, executor=fake).execute(plan())
    command = captured["command"]
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert "ALL" in command
    assert evidence.exit_code == 0
