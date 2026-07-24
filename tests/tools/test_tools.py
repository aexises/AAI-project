import json

import pytest

from traceguard.tools.registry import (
    MAX_READ_BYTES,
    default_registry,
    evaluate_expression,
)
from traceguard.types import ToolCall, TrustLabel


def test_tool_catalog_documents_side_effects(tmp_path):
    catalog = default_registry(tmp_path, tmp_path / "artifacts").catalog()
    assert set(catalog) == {
        "search_documents",
        "read_file",
        "calculator",
        "write_report",
        "restricted_command",
    }
    assert catalog["restricted_command"].host_execution is False
    assert catalog["calculator"].trusted_output is TrustLabel.TRUSTED_TOOL
    assert "UNTRUSTED" in catalog["search_documents"].trusted_output.value


def test_calculator_is_not_eval(tmp_path):
    registry = default_registry(tmp_path, tmp_path / "artifacts")
    call = ToolCall(
        task_id="t", step_id=0, tool_name="calculator", arguments={"expression": "2 + 3 * 4"}
    )
    observation = registry.execute(call)
    assert observation.content == "14"
    assert observation.trust is TrustLabel.TRUSTED_TOOL


@pytest.mark.parametrize(
    "expression",
    [
        "__import__('os').system('id')",
        "abs(1)",
        "a + 1",
        "(1).__class__",
        "2 ** 100",
        "999999999999 ** 9",
        "[" + "1+" * 100 + "1]",
        "(" + "+1" * 80 + ")",
    ],
)
def test_calculator_rejects_abuse(expression):
    with pytest.raises(ValueError):
        evaluate_expression(expression)


def test_calculator_rejects_malformed_input():
    with pytest.raises(SyntaxError):
        evaluate_expression("2 +")


def test_report_stays_in_artifacts(tmp_path):
    registry = default_registry(tmp_path, tmp_path / "artifacts")
    call = ToolCall(
        task_id="t",
        step_id=0,
        tool_name="write_report",
        arguments={"path": "artifacts/report.md", "content": "safe"},
    )
    registry.execute(call)
    assert (tmp_path / "artifacts" / "report.md").read_text() == "safe"


def test_read_file_enforces_size_and_utf8(tmp_path):
    workspace = tmp_path
    artifacts = tmp_path / "artifacts"
    registry = default_registry(workspace, artifacts)
    (workspace / "workspace").mkdir()
    big = workspace / "workspace" / "big.txt"
    big.write_bytes(b"x" * (MAX_READ_BYTES + 1))
    with pytest.raises(ValueError, match="read limit"):
        registry.execute(
            ToolCall(
                task_id="t",
                step_id=0,
                tool_name="read_file",
                arguments={"path": "workspace/big.txt"},
            )
        )

    binary = workspace / "workspace" / "bin.dat"
    binary.write_bytes(b"\xff\xfe\x00\x01")
    with pytest.raises(ValueError, match="UTF-8"):
        registry.execute(
            ToolCall(
                task_id="t",
                step_id=0,
                tool_name="read_file",
                arguments={"path": "workspace/bin.dat"},
            )
        )


def test_search_documents_uses_workspace_fixtures(tmp_path):
    docs = tmp_path / "documents"
    docs.mkdir()
    (docs / "alpha.txt").write_text("Revenue grew 5%.", encoding="utf-8")
    registry = default_registry(tmp_path, tmp_path / "artifacts")
    observation = registry.execute(
        ToolCall(
            task_id="t", step_id=0, tool_name="search_documents", arguments={"query": "Revenue"}
        )
    )
    payload = json.loads(observation.content)
    assert payload["source"] == "workspace_fixtures"
    assert payload["matches"] == [{"path": "documents/alpha.txt", "text": "Revenue grew 5%."}]
    assert observation.may_contain_instructions is True


def test_restricted_command_never_runs_host_shell(tmp_path):
    registry = default_registry(tmp_path, tmp_path / "artifacts")
    observation = registry.execute(
        ToolCall(
            task_id="t",
            step_id=0,
            tool_name="restricted_command",
            arguments={"command": ["echo", "hello"]},
        )
    )
    payload = json.loads(observation.content)
    assert payload["status"] == "simulated"
    assert payload["host_execution"] is False
    assert payload["marker"] == "TRACEGUARD_REQUIRES_EXECUTION_PLAN"
