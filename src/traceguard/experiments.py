"""Load reproducible ablation definitions."""

from __future__ import annotations

import json
from pathlib import Path

from traceguard.types import SafeguardConfig


def load_ablations(path: Path) -> dict[str, SafeguardConfig]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {name: SafeguardConfig.model_validate(config) for name, config in raw.items()}

