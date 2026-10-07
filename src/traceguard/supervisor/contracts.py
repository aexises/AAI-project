"""Structured contracts for LLM supervisor providers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal, Protocol

from jsonschema import Draft202012Validator, SchemaError
from jsonschema import ValidationError as JsonSchemaError
from pydantic import Field, model_validator
from referencing.exceptions import Unresolvable

from traceguard.policy.authorization import check_authority, tool_effect
from traceguard.types import (
    Decision,
    Observation,
    PostRunDisposition,
    RiskLevel,
    SandboxEvidence,
    StrictModel,
    TaskAuthority,
    ToolCall,
)

SupervisorGoalRelevance = Literal["RELEVANT", "UNRELATED", "UNCERTAIN"]
SupervisorNecessity = Literal["NECESSARY", "UNNECESSARY", "UNCERTAIN"]
SupervisorRiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class RewrittenToolCall(StrictModel):
    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)


class SupervisorProviderMetadata(StrictModel):
    provider: str
    model: str
    model_tag: str | None = None
    model_digest: str | None = None
    quantization: str | None = None
    memory_use: str | None = None
    latency_ms: float | None = Field(default=None, ge=0)
    prompt_eval_count: int | None = Field(default=None, ge=0)
    eval_count: int | None = Field(default=None, ge=0)
    retries: int = Field(default=0, ge=0)


class SupervisorEvaluationLog(StrictModel):
    user_goal: str
    proposed_call: dict[str, Any]
    deterministic_enabled: bool
    deterministic_decision: str | None = None
    provider_called: bool = False
    provider_response: dict[str, Any] | None = None
    final_decision: dict[str, Any]
    error: str | None = None


class SupervisorRequest(StrictModel):
    user_goal: str
    proposed_call: ToolCall
    available_tools: dict[str, dict[str, Any]] = Field(default_factory=dict)
    trusted_policy: dict[str, Any] = Field(default_factory=dict)
    task_authority: TaskAuthority = Field(default_factory=TaskAuthority)
    previous_calls: list[ToolCall] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    argument_provenance: dict[str, list[str]] = Field(default_factory=dict)
    step_already_rewritten: bool = False
    enable_rewrite: bool = True
    confidence_threshold: float = Field(default=0.55, ge=0.0, le=1.0)


class SupervisorResponse(StrictModel):
    decision: Decision
    goal_relevance: SupervisorGoalRelevance
    necessity: SupervisorNecessity
    risk_level: SupervisorRiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1, max_length=800)
    rewritten_call: RewrittenToolCall | None = None
    metadata: SupervisorProviderMetadata | None = None

    @model_validator(mode="after")
    def validate_rewrite_payload(self) -> SupervisorResponse:
        if self.decision is Decision.REWRITE and self.rewritten_call is None:
            raise ValueError("REWRITE requires rewritten_call")
        if self.decision is not Decision.REWRITE and self.rewritten_call is not None:
            raise ValueError("rewritten_call must be absent unless decision is REWRITE")
        return self


class PostRunSupervisorRequest(StrictModel):
    user_goal: str
    executed_call: ToolCall
    sandbox_evidence: SandboxEvidence


class PostRunSupervisorResponse(StrictModel):
    disposition: PostRunDisposition
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    reason: str = Field(min_length=1, max_length=800)
    metadata: SupervisorProviderMetadata | None = None


class SupervisorProvider(Protocol):
    def evaluate(self, request: SupervisorRequest) -> SupervisorResponse: ...

    def evaluate_post_run(self, request: PostRunSupervisorRequest) -> PostRunSupervisorResponse: ...


class SupervisorProviderError(RuntimeError):
    """Base class for provider failures."""


class SupervisorSchemaError(SupervisorProviderError):
    """Provider returned syntactically valid data that failed the schema."""


class SupervisorTransportError(SupervisorProviderError):
    """Provider transport failed."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


def validate_rewrite_against_request(
    response: SupervisorResponse,
    request: SupervisorRequest,
) -> None:
    """Validate generic rewrite constraints against current runtime tool schemas."""

    if response.decision is not Decision.REWRITE:
        return
    if response.rewritten_call is None:
        raise SupervisorSchemaError("REWRITE response missing rewritten_call")
    if not request.enable_rewrite:
        raise SupervisorSchemaError("REWRITE returned while rewriting is disabled")
    if request.step_already_rewritten:
        raise SupervisorSchemaError("second rewrite for same logical step")

    tool_name = response.rewritten_call.tool_name
    if tool_name not in request.available_tools:
        raise SupervisorSchemaError(f"rewritten tool does not exist: {tool_name}")

    original_effect = tool_effect(request.proposed_call)
    replacement = request.proposed_call.model_copy(
        update={
            "tool_name": tool_name,
            "arguments": response.rewritten_call.arguments,
        }
    )
    if original_effect == "read" and tool_effect(replacement) != "read":
        raise SupervisorSchemaError("rewrite expands tool effects")
    if tool_name != request.proposed_call.tool_name and tool_effect(replacement) != "read":
        raise SupervisorSchemaError("mutating rewrite cannot change tool family")
    for field in ("recipients", "to", "recipient", "participants", "requested_resources"):
        old = request.proposed_call.arguments.get(field)
        new = replacement.arguments.get(field)
        if old is not None and new is not None:
            old_set = set(old if isinstance(old, list) else [old])
            new_set = set(new if isinstance(new, list) else [new])
            if not new_set.issubset(old_set):
                raise SupervisorSchemaError(f"rewrite expands {field}")
    denied = check_authority(
        request.user_goal, replacement, request.observations, request.task_authority
    )
    if denied is not None:
        raise SupervisorSchemaError(f"rewrite violates authority: {denied.reason}")
    if not set(replacement.requested_resources).issubset(request.proposed_call.requested_resources):
        raise SupervisorSchemaError("rewrite expands requested resources")
    schema = request.available_tools[tool_name]
    _validate_arguments_against_json_schema(response.rewritten_call.arguments, schema)


def _validate_arguments_against_json_schema(
    arguments: Mapping[str, Any], schema: Mapping[str, Any]
) -> None:
    """Validate nested types, enums, bounds and references before approving effects."""

    def reject_remote_refs(value):
        if isinstance(value, Mapping):
            for keyword in ("$ref", "$dynamicRef", "$recursiveRef"):
                if keyword in value and not str(value[keyword]).startswith("#"):
                    raise SupervisorSchemaError("external schema references are not supported")
            for child in value.values():
                reject_remote_refs(child)
        elif isinstance(value, list):
            for child in value:
                reject_remote_refs(child)

    reject_remote_refs(schema)
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(dict(arguments))
    except (SchemaError, JsonSchemaError, Unresolvable) as exc:
        raise SupervisorSchemaError("tool arguments failed JSON schema validation") from exc
    properties = schema.get("properties")
    if properties and set(arguments) - set(properties):
        raise SupervisorSchemaError("tool arguments contain unknown keys")


def validate_replacement(
    original: ToolCall,
    replacement: ToolCall,
    *,
    goal: str,
    observations: list[Observation],
    authority: TaskAuthority,
    schemas: dict[str, dict[str, Any]],
) -> None:
    """Validate proposals from any supervisor, including injected test providers."""
    if (
        replacement.call_id != original.call_id
        or replacement.consumed_observation_ids != original.consumed_observation_ids
    ):
        raise SupervisorSchemaError("rewrite changes call identity or observation context")
    if replacement.task_id != original.task_id or replacement.step_id != original.step_id:
        raise SupervisorSchemaError("rewrite changes task or logical step")
    if not set(replacement.requested_resources).issubset(original.requested_resources):
        raise SupervisorSchemaError("rewrite expands requested resources")
    validate_rewrite_against_request(
        SupervisorResponse(
            decision=Decision.REWRITE,
            goal_relevance="UNCERTAIN",
            necessity="UNCERTAIN",
            risk_level="MEDIUM",
            confidence=1,
            reason="validate replacement",
            rewritten_call=RewrittenToolCall(
                tool_name=replacement.tool_name, arguments=replacement.arguments
            ),
        ),
        SupervisorRequest(
            user_goal=goal,
            proposed_call=original,
            available_tools=schemas,
            observations=observations,
            task_authority=authority,
        ),
    )
