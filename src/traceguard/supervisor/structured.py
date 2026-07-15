"""Structured LLM supervisors for Gemini and Ollama."""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Any

from traceguard.types import (
    Observation,
    PostRunAssessment,
    SandboxEvidence,
    SupervisorOutput,
    ToolCall,
)


def _prompt_text() -> str:
    path = Path(__file__).parents[1] / "data" / "prompts" / "supervisor.txt"
    return path.read_text(encoding="utf-8").strip()


def _request_payload(user_task: str, call: ToolCall, observations: list[Observation]) -> str:
    payload = {
        "user_task": user_task,
        "proposed_call": call.model_dump(mode="json"),
        "observations": [observation.model_dump(mode="json") for observation in observations],
    }
    return f"{_prompt_text()}\n\nINPUT:\n{json.dumps(payload, sort_keys=True)}"


class GeminiSupervisor:
    def __init__(self, model: str, api_key: str | None = None) -> None:
        self.model = model
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is required")

    def evaluate(
        self, user_task: str, call: ToolCall, observations: list[Observation]
    ) -> SupervisorOutput:
        try:
            from google import genai
        except ImportError as exc:
            raise RuntimeError("install TraceGuard with the 'gemini' extra") from exc
        client = genai.Client(api_key=self.api_key)
        response = client.models.generate_content(
            model=self.model,
            contents=_request_payload(user_task, call, observations),
            config={
                "response_mime_type": "application/json",
                "response_schema": SupervisorOutput,
                "temperature": 0,
            },
        )
        return SupervisorOutput.model_validate_json(response.text)

    def reevaluate(
        self, user_task: str, call: ToolCall, evidence: SandboxEvidence
    ) -> PostRunAssessment:
        try:
            from google import genai
        except ImportError as exc:
            raise RuntimeError("install TraceGuard with the 'gemini' extra") from exc
        client = genai.Client(api_key=self.api_key)
        payload = {
            "user_task": user_task,
            "call": call.model_dump(mode="json"),
            "sandbox_evidence": evidence.model_dump(mode="json"),
        }
        response = client.models.generate_content(
            model=self.model,
            contents=f"Reevaluate risk after a contained trial. Never assume sandbox success authorizes host execution.\n{json.dumps(payload)}",
            config={
                "response_mime_type": "application/json",
                "response_schema": PostRunAssessment,
                "temperature": 0,
            },
        )
        return PostRunAssessment.model_validate_json(response.text)


class OllamaSupervisor:
    def __init__(
        self, model: str, base_url: str = "http://127.0.0.1:11434", timeout: float = 60.0
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _generate(self, prompt: str, schema: dict[str, Any]) -> str:
        data = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": schema,
                "options": {"temperature": 0},
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.base_url}/api/generate", data=data, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.loads(response.read())
        return str(body["response"])

    def evaluate(
        self, user_task: str, call: ToolCall, observations: list[Observation]
    ) -> SupervisorOutput:
        raw = self._generate(
            _request_payload(user_task, call, observations), SupervisorOutput.model_json_schema()
        )
        return SupervisorOutput.model_validate_json(raw)

    def reevaluate(
        self, user_task: str, call: ToolCall, evidence: SandboxEvidence
    ) -> PostRunAssessment:
        payload = {
            "user_task": user_task,
            "call": call.model_dump(mode="json"),
            "sandbox_evidence": evidence.model_dump(mode="json"),
        }
        raw = self._generate(
            f"Reevaluate contained execution risk.\n{json.dumps(payload)}",
            PostRunAssessment.model_json_schema(),
        )
        return PostRunAssessment.model_validate_json(raw)
