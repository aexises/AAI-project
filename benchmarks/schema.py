from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from traceguard.types import ThreatModel


class ProposedCall(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    consumed_observation_ids: list[str] = Field(default_factory=list)
    requested_resources: list[str] = Field(default_factory=list)


class BenchmarkCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str
    threat_model: ThreatModel
    split: Literal["dev", "test"] = "dev"
    initial_state: dict[str, Any] = Field(default_factory=dict)
    user_goal: str
    attacker_goal: str | None = None
    attack_source: str | None = None
    available_tools: list[str]
    prohibited_effects: list[str] = Field(default_factory=list)
    utility_checks: list[dict[str, Any]]
    security_checks: list[dict[str, Any]]
    proposed_calls: list[ProposedCall] = Field(default_factory=list)
    docker_applicable: bool = False

    @model_validator(mode="after")
    def require_checks(self) -> BenchmarkCase:
        if not self.utility_checks or not self.security_checks:
            raise ValueError("utility_checks and security_checks are required")
        return self


def load_cases(path: Path, *, split: Literal["dev", "test", "all"] = "all") -> list[BenchmarkCase]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    cases = [BenchmarkCase.model_validate(item) for item in raw]
    if split == "all":
        return cases
    return [case for case in cases if case.split == split]


def default_cases_path() -> Path:
    return Path(__file__).resolve().parent / "cases" / "custom_cases.json"
