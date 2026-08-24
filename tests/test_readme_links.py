"""Regression checks for repository-local README links."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOCUMENTATION_PATHS = (REPOSITORY_ROOT / "README.md", REPOSITORY_ROOT / "setup.md")
LOCAL_LINK_PATTERN = re.compile(r"\[[^]]+\]\(([^)#]+)(?:#[^)]*)?\)")


def test_public_documentation_local_links_target_tracked_files() -> None:
    """Keep public documentation independent of ignored developer-local documents."""
    targets = [
        target
        for path in DOCUMENTATION_PATHS
        for target in LOCAL_LINK_PATTERN.findall(path.read_text(encoding="utf-8"))
    ]

    missing = [target for target in targets if not (REPOSITORY_ROOT / target).is_file()]
    assert not missing, f"Public documentation links target missing files: {', '.join(missing)}"

    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", *targets],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "Public documentation links must target tracked files, not local-only documents: "
        f"{', '.join(targets)}"
    )
