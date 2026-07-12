from traceguard.tools.registry import default_registry
from traceguard.types import ToolCall, TrustLabel


def test_calculator_is_not_eval(tmp_path):
    registry = default_registry(tmp_path, tmp_path / "artifacts")
    call = ToolCall(task_id="t", step_id=0, tool_name="calculator", arguments={"expression": "2 + 3 * 4"})
    observation = registry.execute(call)
    assert observation.content == "14"
    assert observation.trust is TrustLabel.TRUSTED_TOOL


def test_report_stays_in_artifacts(tmp_path):
    registry = default_registry(tmp_path, tmp_path / "artifacts")
    call = ToolCall(task_id="t", step_id=0, tool_name="write_report", arguments={"path": "artifacts/report.md", "content": "safe"})
    registry.execute(call)
    assert (tmp_path / "artifacts" / "report.md").read_text() == "safe"

