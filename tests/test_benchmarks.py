import json
from pathlib import Path

from benchmarks.agentdojo_adapter import (
    PINNED_AGENTDOJO_VERSION,
    agentdojo_metadata,
    load_selection,
    selected_agentdojo_cases,
)
from benchmarks.checkers import CheckContext, evaluate_check
from benchmarks.schema import load_cases
from traceguard.agent import EpisodeResult
from traceguard.experiments import (
    load_ablations,
    regenerate_analysis_from_traces,
    run_experiment,
)
from traceguard.types import SafeguardConfig, ThreatModel, ToolCall


def test_custom_cases_cover_threat_models_and_splits():
    cases = load_cases(Path("benchmarks/cases/custom_cases.json"))
    assert {case.threat_model for case in cases} >= {
        ThreatModel.BENIGN,
        ThreatModel.POLICY_VIOLATION,
        ThreatModel.DIRECT_ATTACK,
        ThreatModel.INDIRECT_INJECTION,
    }
    assert {case.split for case in cases} == {"dev", "test"}
    assert all(case.utility_checks and case.security_checks for case in cases)
    assert all(case.proposed_calls for case in cases)
    assert all(
        proposed.expected_relevance is not None
        and proposed.expected_necessity is not None
        and proposed.unsafe_proposal is not None
        for case in cases
        for proposed in case.proposed_calls
    )
    assert all(
        check["type"] != "always_true"
        for case in cases
        for check in [*case.utility_checks, *case.security_checks]
    )
    indirect_sources = {
        case.attack_source for case in cases if case.threat_model is ThreatModel.INDIRECT_INJECTION
    }
    assert "cybersecurity_artifact" in indirect_sources


def test_primary_matrix_contains_all_eight_ablations():
    ablations = load_ablations(Path("configs/ablations.json"))
    assert set(ablations) == {f"A{index}" for index in range(8)}
    combinations = {
        (config.defensive_prompt, config.deterministic_policy, config.llm_supervisor)
        for config in ablations.values()
    }
    assert len(combinations) == 8


def test_checkers_safe_refusal_and_content_absent():
    call = ToolCall(task_id="t", step_id=0, tool_name="read_file", arguments={"path": "x"})
    episode = EpisodeResult(
        observations=[],
        steps=[],
        stopped_reason="block",
    )
    # Minimal blocked episode with a synthetic trace-less stop still counts as refusal.
    context = CheckContext(case_id="c", user_goal="g", episode=episode, proposed_calls=[call])
    assert evaluate_check({"type": "safe_refusal"}, context) is True
    assert evaluate_check({"type": "content_absent", "value": "SECRET"}, context) is True


def test_agentdojo_selection_is_pinned():
    selection = load_selection()
    assert selection["pinned_agentdojo"] == PINNED_AGENTDOJO_VERSION
    assert "workspace" in selection["suites"]
    cases = selected_agentdojo_cases()
    assert any(case.threat_model is ThreatModel.INDIRECT_INJECTION for case in cases)
    meta = agentdojo_metadata(cases[0])
    assert "user_task" in meta


def test_run_smoke_matrix(tmp_path):
    all_dev = load_cases(Path("benchmarks/cases/custom_cases.json"), split="dev")
    by_id = {case.case_id: case for case in all_dev}
    cases = [
        by_id["benign_math_dev"],
        by_id["policy_unnecessary_shell"],
        by_id["direct_destructive_command"],
    ]
    ablations = {
        "A0": SafeguardConfig(),
        "A2": SafeguardConfig(deterministic_policy=True),
        "A7": SafeguardConfig(
            defensive_prompt=True, deterministic_policy=True, llm_supervisor=True
        ),
    }
    results, report, run_dir = run_experiment(
        cases=cases,
        ablations=ablations,
        seed=1,
        artifacts_dir=tmp_path / "artifacts",
    )
    assert len(results) == 9
    assert (run_dir / "results.jsonl").exists()
    assert (run_dir / "summary.json").exists()
    assert (run_dir / "summary.csv").exists()
    assert (run_dir / "representative_traces.json").exists()
    assert report.by_threat_model
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert set(summary["paired_comparisons_vs_A0"]) == {"A2", "A7"}
    manifest = json.loads((run_dir / "manifest_A0.json").read_text(encoding="utf-8"))
    assert manifest["cases_digest"]
    assert manifest["initial_state_digest"]
    assert manifest["code_revision"] != "local"
    summary_before = (run_dir / "summary.json").read_bytes()
    csv_before = (run_dir / "summary.csv").read_bytes()
    regenerated, regenerated_report = regenerate_analysis_from_traces(run_dir)
    assert len(regenerated) == len(results)
    assert regenerated_report == report
    assert (run_dir / "summary.json").read_bytes() == summary_before
    assert (run_dir / "summary.csv").read_bytes() == csv_before
    # Policy-enabled ablation should block the unnecessary shell case.
    shell = next(
        result
        for result in results
        if result.case_id == "policy_unnecessary_shell" and result.ablation == "A2"
    )
    assert shell.security_passed is True
    assert shell.stopped_reason == "block"


def test_no_safeguard_path_escape_is_measured_not_crashed(tmp_path):
    cases = load_cases(Path("benchmarks/cases/custom_cases.json"), split="dev")
    unsafe = next(case for case in cases if case.case_id == "policy_unsafe_path_escape")
    results, _, _ = run_experiment(
        cases=[unsafe],
        ablations={"A0": SafeguardConfig()},
        seed=0,
        artifacts_dir=tmp_path,
        split="dev",
    )
    assert results[0].stopped_reason == "agent_finished"
    assert results[0].traces[0]["episode_outcome"] == "TOOL_ERROR"
    assert results[0].security_passed is True


def test_persisted_traces_are_redacted(tmp_path):
    cases = load_cases(Path("benchmarks/cases/custom_cases.json"), split="dev")
    direct = next(case for case in cases if case.case_id == "direct_credentials")
    _, _, run_dir = run_experiment(
        cases=[direct],
        ablations={"A0": SafeguardConfig()},
        seed=0,
        artifacts_dir=tmp_path,
        split="dev",
    )
    persisted = (run_dir / "traces.jsonl").read_text(encoding="utf-8")
    assert "TRACEGUARD_CANARY" not in persisted
    assert "[REDACTED_CANARY]" in persisted


def test_verify_agentdojo_is_strict_when_called():
    from benchmarks.agentdojo_adapter import verify_agentdojo_installation

    try:
        installed = verify_agentdojo_installation()
        assert installed == PINNED_AGENTDOJO_VERSION
    except RuntimeError as exc:
        assert "agentdojo" in str(exc).casefold()
