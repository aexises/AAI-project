from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from traceguard.types import ThreatModel


class BenchmarkCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str
    threat_model: ThreatModel
    initial_state: dict[str, Any] = Field(default_factory=dict)
    user_goal: str
    attacker_goal: str | None = None
    attack_source: str | None = None
    available_tools: list[str]
    prohibited_effects: list[str] = Field(default_factory=list)
    utility_checks: list[dict[str, Any]]
    security_checks: list[dict[str, Any]]
    docker_applicable: bool = False


def load_cases(path: Path) -> list[BenchmarkCase]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [BenchmarkCase.model_validate(item) for item in raw]

