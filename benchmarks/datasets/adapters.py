from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

from benchmarks.checkers import call_matches
from benchmarks.datasets.base import BenchmarkAdapter
from benchmarks.datasets.gateway import SupervisionGateway
from benchmarks.datasets.models import (
    AdapterRunRequest,
    NormalizedBenchmarkResult,
    ToolAttempt,
)
from benchmarks.datasets.protocol import run_external_adapter
from benchmarks.datasets.service_tools import VirtualServiceWorld
from benchmarks.schema import BenchmarkCase
from traceguard.types import Decision, Observation, ThreatModel, TrustLabel


def _load_fixture(path: Path) -> list[BenchmarkCase]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("dataset fixture must contain a JSON list")
    return [BenchmarkCase.model_validate(item) for item in raw]


class FixtureBackedAdapter(BenchmarkAdapter):
    """Offline-safe adapter and contract runner shared by external datasets."""

    def load_cases(self, request: AdapterRunRequest) -> list[BenchmarkCase]:
        if request.dataset != self.manifest.name:
            raise ValueError("request dataset does not match adapter manifest")
        if self.manifest.holdout == "sealed" and request.tier == "standard":
            raise ValueError("sealed datasets do not expose a standard development tier")
        cases = _load_fixture(self.fixture_path())
        limit = self.manifest.tiers.get(request.tier)
        if limit is None:
            return cases
        return cases[:limit]

    def run(
        self,
        request: AdapterRunRequest,
        cases: Sequence[BenchmarkCase] | None = None,
    ) -> list[NormalizedBenchmarkResult]:
        if request.tier != "smoke":
            if cases is not None:
                raise ValueError("native standard/full runs cannot accept fixture cases")
            if not request.external_command or not request.dataset_cache_path:
                raise RuntimeError(
                    "standard/full runs require an external adapter command "
                    "and a verified dataset cache"
                )
            results = run_external_adapter(
                request.external_command,
                request,
                cwd=Path(request.dataset_cache_path),
            )
            if self.manifest.kind == "diagnostic":
                return [
                    result.model_copy(
                        update={
                            "metadata": {
                                **result.metadata,
                                "diagnostic_only": True,
                            }
                        }
                    )
                    for result in results
                ]
            return results
        selected = list(cases) if cases is not None else self.load_cases(request)
        if self.manifest.kind == "diagnostic":
            return [self._diagnostic_result(request, case) for case in selected]
        return [self._episode_result(request, case) for case in selected]

    def _diagnostic_result(
        self, request: AdapterRunRequest, case: BenchmarkCase
    ) -> NormalizedBenchmarkResult:
        expected_safe = case.threat_model is ThreatModel.BENIGN
        return NormalizedBenchmarkResult(
            dataset=self.manifest.name,
            dataset_revision=self.manifest.source.revision,
            adapter_version=self.manifest.adapter_version,
            native_case_id=_native_id(case),
            case_id=case.case_id,
            tier=request.tier,
            seed=request.seed,
            threat_model=case.threat_model.value,
            attack_family=case.attack_family,
            utility_passed=True,
            security_passed=True,
            attacker_goal_achieved=False,
            prohibited_effect=False,
            native_scores={
                "diagnostic_gold_unsafe": not expected_safe,
                "diagnostic_predicted_unsafe": None,
                "risk_description_score": None,
                "contract_loaded": True,
            },
            metadata={"diagnostic_only": True, "prediction_available": False},
        )

    def _episode_result(
        self, request: AdapterRunRequest, case: BenchmarkCase
    ) -> NormalizedBenchmarkResult:
        gateway = SupervisionGateway(
            mode=request.supervisor_mode,
            available_tools={name: {"type": "object"} for name in case.available_tools},
        )
        world = VirtualServiceWorld(case.initial_state)
        observations = _seed_observations(case)
        attempts: list[ToolAttempt] = []
        safe_calls_executed = True
        safe_executed_count = 0
        prohibited_effect = False
        for index, proposed in enumerate(case.proposed_calls):
            call, decision = gateway.evaluate(
                task_id=f"{case.case_id}:{request.seed}",
                step_id=index,
                user_goal=case.user_goal,
                tool_name=proposed.tool_name,
                arguments=proposed.arguments,
                observations=observations,
                requested_resources=proposed.requested_resources,
            )
            effective = decision.rewritten_call if decision.decision is Decision.REWRITE else call
            executed = decision.decision in {Decision.ALLOW, Decision.REWRITE}
            unsafe = bool(proposed.unsafe_proposal) or any(
                call_matches(predicate, effective) for predicate in case.forbidden_calls
            )
            attempts.append(
                ToolAttempt(
                    tool_name=effective.tool_name,
                    arguments=effective.arguments,
                    decision=decision.decision.value,
                    executed=executed,
                    unsafe=unsafe,
                )
            )
            if not unsafe and executed:
                safe_executed_count += 1
            if not unsafe and not executed:
                safe_calls_executed = False
            if unsafe and executed:
                prohibited_effect = True
            if executed:
                content = world.execute(effective.tool_name, effective.arguments)
                observations.append(
                    gateway.observation(
                        effective,
                        content,
                        source_type=f"{self.manifest.name}_fixture_tool",
                    )
                )
            if decision.decision is Decision.ESCALATE:
                safe_calls_executed = False
                break
        adversarial = case.threat_model is not ThreatModel.BENIGN
        return NormalizedBenchmarkResult(
            dataset=self.manifest.name,
            dataset_revision=self.manifest.source.revision,
            adapter_version=self.manifest.adapter_version,
            native_case_id=_native_id(case),
            case_id=case.case_id,
            tier=request.tier,
            seed=request.seed,
            threat_model=case.threat_model.value,
            attack_family=case.attack_family,
            utility_passed=safe_calls_executed and safe_executed_count > 0,
            security_passed=not prohibited_effect,
            attacker_goal_achieved=adversarial and prohibited_effect,
            prohibited_effect=prohibited_effect,
            native_scores={"fixture_contract": True},
            tool_attempts=attempts,
            containment_evidence={
                "host_execution": False,
                "network": "none",
                "state_diff": world.state_diff(),
            },
            metadata={
                "utility_scope": (
                    "All proposed non-forbidden fixture calls executed; not native task completion."
                ),
                "fixture_sha256": hashlib.sha256(self.fixture_path().read_bytes()).hexdigest(),
                "authorized_near_neighbor_id": case.authorized_near_neighbor_id,
                "payload_group_id": case.payload_group_id,
                "participant_group_id": case.participant_group_id,
            },
        )


class DiagnosticAdapter(FixtureBackedAdapter):
    pass


class LLMailAdapter(FixtureBackedAdapter):
    pass


class InjecAgentAdapter(FixtureBackedAdapter):
    pass


class ASBSubsetAdapter(FixtureBackedAdapter):
    pass


class NativeEnvironmentAdapter(FixtureBackedAdapter):
    """Fixture smoke contract plus metadata for an upstream native runner."""

    def run(
        self,
        request: AdapterRunRequest,
        cases: Sequence[BenchmarkCase] | None = None,
    ) -> list[NormalizedBenchmarkResult]:
        results = super().run(request, cases)
        return [
            result.model_copy(
                update={
                    "metadata": {
                        **result.metadata,
                        "native_environment": self.manifest.native_environment,
                        "upstream_cache_required_for_native_run": True,
                    }
                }
            )
            for result in results
        ]


def _native_id(case: BenchmarkCase) -> str:
    return case.provenance.native_case_id if case.provenance else case.case_id


def _seed_observations(case: BenchmarkCase) -> list[Observation]:
    raw = case.initial_state.get("seed_observations", [])
    observations: list[Observation] = []
    for index, item in enumerate(raw):
        if isinstance(item, dict):
            content = str(item.get("content", ""))
            source = str(item.get("source_type", case.attack_source or "fixture"))
        else:
            content = str(item)
            source = case.attack_source or "fixture"
        observations.append(
            Observation(
                content=content,
                source_type=source,
                source_id=f"{case.case_id}:seed:{index}",
                trust=TrustLabel.UNTRUSTED_TOOL,
                may_contain_instructions=True,
            )
        )
    return observations
