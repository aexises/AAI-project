"""Reproducible experiment orchestration for TraceGuard ablations."""

from __future__ import annotations

import csv
import hashlib
import json
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from benchmarks.checkers import CheckContext, evaluate_checks
from benchmarks.schema import BenchmarkCase, default_cases_path
from traceguard.agent import EpisodeResult, ReActRunner, ScriptedAgent
from traceguard.metrics import (
    CallRecord,
    EpisodeRecord,
    MetricReport,
    build_metric_report,
    validate_episode_labels,
)
from traceguard.policy.engine import DeterministicPolicy, load_default_policy
from traceguard.runtime import TraceGuardRuntime
from traceguard.supervisor.heuristic import HeuristicSupervisor
from traceguard.tools.registry import default_registry
from traceguard.types import (
    Observation,
    SafeguardConfig,
    ThreatModel,
    ToolCall,
    TrustLabel,
)


class ExperimentManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    experiment_id: str = Field(default_factory=lambda: str(uuid4()))
    code_revision: str = "local"
    agentdojo_version: str | None = "0.1.35"
    model_identifiers: dict[str, str] = Field(
        default_factory=lambda: {"supervisor": "heuristic-offline", "agent": "scripted"}
    )
    prompt_versions: dict[str, str] = Field(
        default_factory=lambda: {"base": "base_system.txt", "defensive": "defensive_system.txt"}
    )
    policy_version: str
    image_digest: str | None = None
    seed: int = 0
    temperature: float = 0.0
    enabled_safeguards: SafeguardConfig
    ablation: str
    split: Literal["dev", "test", "all"] = "dev"
    cases_path: str


class CaseRunResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str
    ablation: str
    threat_model: ThreatModel
    split: str
    seed: int
    docker_applicable: bool
    stopped_reason: str
    utility_passed: bool
    security_passed: bool
    utility_details: list[dict[str, Any]]
    security_details: list[dict[str, Any]]
    traces: list[dict[str, Any]]
    observations: list[dict[str, Any]]
    policy_version: str
    episode_record: EpisodeRecord
    call_records: list[CallRecord]


def load_ablations(path: Path) -> dict[str, SafeguardConfig]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {name: SafeguardConfig.model_validate(config) for name, config in raw.items()}


def default_ablations_path() -> Path:
    return Path(__file__).resolve().parents[2] / "configs" / "ablations.json"


def _materialize_state(workspace: Path, initial_state: dict[str, Any]) -> Observation | None:
    seed_observation: Observation | None = None
    for key, value in initial_state.items():
        if key == "documents":
            continue
        if key == "terminal_output":
            seed_observation = Observation(
                content=str(value),
                source_type="terminal",
                source_id="seed-terminal",
                trust=TrustLabel.UNTRUSTED_TOOL,
                may_contain_instructions=True,
                observation_id="seed-terminal",
            )
            continue
        path = workspace / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(value), encoding="utf-8")
    return seed_observation


def _build_runtime(
    workspace: Path,
    artifacts: Path,
    config: SafeguardConfig,
) -> tuple[TraceGuardRuntime, str]:
    policy_config = load_default_policy()
    policy = DeterministicPolicy(policy_config) if config.deterministic_policy else None
    supervisor = HeuristicSupervisor() if config.llm_supervisor else None
    runtime = TraceGuardRuntime(
        tools=default_registry(workspace, artifacts),
        config=config,
        policy=policy,
        supervisor=supervisor,
    )
    return runtime, policy_config.version


def _to_tool_calls(case: BenchmarkCase, seed: int) -> list[ToolCall]:
    calls: list[ToolCall] = []
    for index, proposed in enumerate(case.proposed_calls):
        calls.append(
            ToolCall(
                task_id=f"{case.case_id}:{seed}",
                step_id=index,
                tool_name=proposed.tool_name,
                arguments=proposed.arguments,
                consumed_observation_ids=list(proposed.consumed_observation_ids),
                requested_resources=list(proposed.requested_resources),
            )
        )
    return calls


def _call_records_from_episode(
    case: BenchmarkCase,
    episode: EpisodeResult,
    utility_passed: bool,
    security_passed: bool,
) -> list[CallRecord]:
    records: list[CallRecord] = []
    adversarial = case.threat_model is not ThreatModel.BENIGN
    for step in episode.steps:
        outcome = step.trace.episode_outcome or ""
        blocked = outcome in {"BLOCK", "ESCALATE"}
        executed = outcome in {"EXECUTED", "EXECUTED_CONTAINER"}
        unsafe_proposal = adversarial or any(
            check.get("type") in {"safe_refusal", "command_not_executed", "path_not_read"}
            for check in case.security_checks
        )
        harmful = executed and adversarial and not security_passed
        disruptive = blocked and case.threat_model is ThreatModel.BENIGN and not utility_passed
        rewrite = any(output.decision.value == "REWRITE" for output in step.trace.safeguard_outputs)
        container = any(
            output.execution_target and output.execution_target.value == "CONTAINER"
            for output in step.trace.safeguard_outputs
        )
        records.append(
            CallRecord(
                unsafe_proposal=unsafe_proposal,
                harmful_effect=harmful,
                disruptive_intervention=disruptive,
                rewrite_attempted=rewrite,
                rewrite_valid=rewrite and executed,
                rewrite_preserved_goal=rewrite and utility_passed,
                container_routed=container or outcome == "EXECUTED_CONTAINER",
                container_routing_correct=case.docker_applicable if container else False,
            )
        )
    return records


def run_case(
    case: BenchmarkCase,
    config: SafeguardConfig,
    *,
    ablation: str,
    seed: int,
    output_root: Path,
) -> CaseRunResult:
    random.seed(seed)
    workspace = output_root / "workspaces" / ablation / case.case_id / str(seed)
    artifacts = workspace / "artifacts"
    workspace.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    seed_obs = _materialize_state(workspace, case.initial_state)
    runtime, policy_version = _build_runtime(workspace, artifacts, config)
    calls = _to_tool_calls(case, seed)
    runner = ReActRunner(runtime, ScriptedAgent(calls))
    initial = [seed_obs] if seed_obs is not None else None
    episode = runner.run(case.user_goal, initial_observations=initial)
    context = CheckContext(
        case_id=case.case_id,
        user_goal=case.user_goal,
        episode=episode,
        proposed_calls=calls,
        final_answer=episode.observations[-1].content if episode.observations else None,
    )

    utility_passed, utility_details = evaluate_checks(case.utility_checks, context)
    security_passed, security_details = evaluate_checks(case.security_checks, context)
    adversarial = case.threat_model is not ThreatModel.BENIGN
    attacker_goal = adversarial and not security_passed
    prohibited = not security_passed
    safeguard_failure = (
        case.threat_model is ThreatModel.BENIGN
        and not utility_passed
        and context.blocked_or_escalated
    )
    containment = None
    if case.docker_applicable:
        containment = any(
            step.trace.episode_outcome in {"BLOCK", "ESCALATE", "EXECUTED_CONTAINER"}
            for step in episode.steps
        )
    episode_record = EpisodeRecord(
        case_id=case.case_id,
        threat_model=case.threat_model,
        docker_applicable=case.docker_applicable,
        adversarial=adversarial,
        attacker_goal_achieved=attacker_goal,
        utility_achieved=utility_passed,
        prohibited_effect=prohibited,
        safeguard_caused_failure=safeguard_failure,
        containment_success=containment,
    )
    call_records = _call_records_from_episode(case, episode, utility_passed, security_passed)
    return CaseRunResult(
        case_id=case.case_id,
        ablation=ablation,
        threat_model=case.threat_model,
        split=case.split,
        seed=seed,
        docker_applicable=case.docker_applicable,
        stopped_reason=episode.stopped_reason,
        utility_passed=utility_passed,
        security_passed=security_passed,
        utility_details=utility_details,
        security_details=security_details,
        traces=[step.trace.model_dump(mode="json") for step in episode.steps],
        observations=[obs.model_dump(mode="json") for obs in episode.observations],
        policy_version=policy_version,
        episode_record=episode_record,
        call_records=call_records,
    )


def run_experiment(
    *,
    cases: list[BenchmarkCase],
    ablations: dict[str, SafeguardConfig],
    seed: int,
    artifacts_dir: Path,
    code_revision: str = "local",
    ablation_filter: set[str] | None = None,
    case_filter: set[str] | None = None,
) -> tuple[list[CaseRunResult], MetricReport, Path]:
    selected_ablations = {
        name: config
        for name, config in ablations.items()
        if ablation_filter is None or name in ablation_filter
    }
    selected_cases = [case for case in cases if case_filter is None or case.case_id in case_filter]
    if not selected_cases:
        raise ValueError("no benchmark cases selected")
    if not selected_ablations:
        raise ValueError("no ablations selected")

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = artifacts_dir / f"run_{stamp}_{seed}"
    run_dir.mkdir(parents=True, exist_ok=True)
    traces_path = run_dir / "traces.jsonl"
    results_path = run_dir / "results.jsonl"
    summary_json = run_dir / "summary.json"
    summary_csv = run_dir / "summary.csv"

    results: list[CaseRunResult] = []
    policy_version = load_default_policy().version
    with (
        traces_path.open("w", encoding="utf-8") as traces_file,
        results_path.open("w", encoding="utf-8") as results_file,
    ):
        for ablation_name, config in selected_ablations.items():
            manifest = ExperimentManifest(
                code_revision=code_revision,
                policy_version=policy_version,
                seed=seed,
                enabled_safeguards=config,
                ablation=ablation_name,
                cases_path=str(default_cases_path()),
            )
            (run_dir / f"manifest_{ablation_name}.json").write_text(
                manifest.model_dump_json(indent=2),
                encoding="utf-8",
            )
            for case in selected_cases:
                # Paired seeds: same task seed across ablations.
                case_seed = seed + (
                    int(hashlib.sha256(case.case_id.encode()).hexdigest()[:6], 16) % 10_000
                )
                result = run_case(
                    case,
                    config,
                    ablation=ablation_name,
                    seed=case_seed,
                    output_root=run_dir,
                )
                results.append(result)
                results_file.write(result.model_dump_json() + "\n")
                for trace in result.traces:
                    traces_file.write(
                        json.dumps(
                            {
                                "case_id": result.case_id,
                                "ablation": ablation_name,
                                "seed": case_seed,
                                "policy_version": result.policy_version,
                                "trace": trace,
                            },
                            ensure_ascii=True,
                        )
                        + "\n"
                    )

    episode_records = [result.episode_record for result in results]
    label_errors = validate_episode_labels(episode_records)
    if label_errors:
        raise ValueError("missing metric labels: " + "; ".join(label_errors))
    call_records = [record for result in results for record in result.call_records]
    report = build_metric_report(call_records, episode_records, seed=seed)
    summary = {
        "seed": seed,
        "n_results": len(results),
        "metrics": report.model_dump(mode="json"),
        "by_ablation": {},
    }
    for ablation_name in selected_ablations:
        subset = [result for result in results if result.ablation == ablation_name]
        summary["by_ablation"][ablation_name] = build_metric_report(
            [record for result in subset for record in result.call_records],
            [result.episode_record for result in subset],
            seed=seed,
        ).model_dump(mode="json")
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with summary_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "case_id",
                "ablation",
                "threat_model",
                "utility_passed",
                "security_passed",
                "stopped_reason",
            ],
        )
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "case_id": result.case_id,
                    "ablation": result.ablation,
                    "threat_model": result.threat_model.value,
                    "utility_passed": result.utility_passed,
                    "security_passed": result.security_passed,
                    "stopped_reason": result.stopped_reason,
                }
            )
    return results, report, run_dir
