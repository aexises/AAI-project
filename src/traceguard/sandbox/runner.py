"""Hardened Docker execution for argv-only command calls."""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable

from traceguard.types import ExecutionPlan, ExecutionTarget, SandboxEvidence


class SandboxUnavailable(RuntimeError):
    pass


class ContainerRunner:
    SUPPORTED_PROFILES = {"isolated_compute", "readonly_input", "artifact_build"}

    def __init__(
        self,
        image: str | None = None,
        executor: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.image = image or os.environ.get("TRACEGUARD_SANDBOX_IMAGE", "")
        self.executor = executor

    def execute(self, plan: ExecutionPlan) -> SandboxEvidence:
        if plan.target is not ExecutionTarget.CONTAINER:
            raise ValueError("ContainerRunner requires a CONTAINER execution plan")
        if plan.sandbox_profile not in self.SUPPORTED_PROFILES:
            raise SandboxUnavailable(
                f"unsupported or unsafe sandbox profile: {plan.sandbox_profile}"
            )
        if "@sha256:" not in self.image:
            raise SandboxUnavailable("TRACEGUARD_SANDBOX_IMAGE must be pinned by sha256 digest")
        command = plan.effective_call.arguments.get("command")
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(part, str) for part in command)
        ):
            raise ValueError("restricted_command requires a non-empty argv list")

        limits = plan.limits
        docker_command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--user",
            "65532:65532",
            "--pids-limit",
            str(limits.pids),
            "--memory",
            f"{limits.memory_mb}m",
            "--cpus",
            str(limits.cpu_count),
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            self.image,
            *command,
        ]
        started = time.monotonic()
        try:
            result = self.executor(
                docker_command,
                capture_output=True,
                text=True,
                timeout=limits.timeout_seconds,
                check=False,
            )
            return SandboxEvidence(
                exit_code=result.returncode,
                stdout=result.stdout[: limits.output_bytes],
                stderr=result.stderr[: limits.output_bytes],
                duration_ms=(time.monotonic() - started) * 1000,
                profile=plan.sandbox_profile,
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxEvidence(
                exit_code=None,
                stdout=(exc.stdout or "")[: limits.output_bytes],
                stderr=(exc.stderr or "")[: limits.output_bytes],
                duration_ms=(time.monotonic() - started) * 1000,
                timed_out=True,
                blocked_operations=["timeout"],
                profile=plan.sandbox_profile,
            )
        except FileNotFoundError as exc:
            raise SandboxUnavailable("Docker CLI is unavailable") from exc
