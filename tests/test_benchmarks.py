from pathlib import Path

from benchmarks.schema import load_cases
from traceguard.experiments import load_ablations
from traceguard.types import ThreatModel


def test_custom_cases_cover_all_threat_models():
    cases = load_cases(Path("benchmarks/cases/custom_cases.json"))
    assert {case.threat_model for case in cases} == {
        ThreatModel.POLICY_VIOLATION,
        ThreatModel.DIRECT_ATTACK,
        ThreatModel.INDIRECT_INJECTION,
    }
    assert all(case.utility_checks and case.security_checks for case in cases)


def test_primary_matrix_contains_all_eight_ablations():
    ablations = load_ablations(Path("configs/ablations.json"))
    assert set(ablations) == {f"A{index}" for index in range(8)}
    combinations = {
        (config.defensive_prompt, config.deterministic_policy, config.llm_supervisor)
        for config in ablations.values()
    }
    assert len(combinations) == 8
