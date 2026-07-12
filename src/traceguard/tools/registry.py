"""Typed tools with narrow, testable side-effect boundaries."""

from __future__ import annotations

import ast
import json
import operator
from collections.abc import Callable
from pathlib import Path, PurePath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from traceguard.types import Observation, ToolCall, TrustLabel


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SearchDocumentsArguments(ToolArguments):
    query: str = Field(min_length=1, max_length=500)
    documents: list[str] = Field(default_factory=list, max_length=100)


class ReadFileArguments(ToolArguments):
    path: str


class CalculatorArguments(ToolArguments):
    expression: str = Field(min_length=1, max_length=200)


class WriteReportArguments(ToolArguments):
    path: str
    content: str = Field(max_length=1_000_000)


class RestrictedCommandArguments(ToolArguments):
    command: list[str] = Field(min_length=1, max_length=64)


class ToolDefinition:
    def __init__(
        self,
        name: str,
        arguments_model: type[ToolArguments],
        handler: Callable[[ToolArguments], str],
        trust: TrustLabel,
    ) -> None:
        self.name = name
        self.arguments_model = arguments_model
        self.handler = handler
        self.trust = trust

    def validate(self, arguments: dict[str, Any]) -> ToolArguments:
        return self.arguments_model.model_validate(arguments)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolDefinition:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"unknown tool: {name}") from exc

    def schemas(self) -> dict[str, dict[str, Any]]:
        return {name: tool.arguments_model.model_json_schema() for name, tool in self._tools.items()}

    def execute(self, call: ToolCall) -> Observation:
        tool = self.get(call.tool_name)
        args = tool.validate(call.arguments)
        content = tool.handler(args)
        return Observation(
            content=content,
            source_type="tool",
            source_id=call.call_id,
            trust=tool.trust,
            provenance_chain=[*call.consumed_observation_ids, call.call_id],
            may_contain_instructions=tool.trust in {
                TrustLabel.UNTRUSTED_DOCUMENT,
                TrustLabel.UNTRUSTED_TOOL,
            },
        )


_OPERATORS: dict[type[ast.AST], Callable[..., float]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _calculate(node: ast.AST) -> float:
    if isinstance(node, ast.Expression):
        return _calculate(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.BinOp) and type(node.op) in _OPERATORS:
        return _OPERATORS[type(node.op)](_calculate(node.left), _calculate(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPERATORS:
        return _OPERATORS[type(node.op)](_calculate(node.operand))
    raise ValueError("unsupported calculator expression")


def default_registry(workspace: Path, artifacts: Path) -> ToolRegistry:
    workspace = workspace.resolve()
    artifacts = artifacts.resolve()

    def contained(root: Path, raw_path: str) -> Path:
        candidate = (root / raw_path).resolve()
        if candidate != root and root not in candidate.parents:
            raise ValueError(f"path escapes allowed root: {raw_path}")
        return candidate

    def search_documents(args: ToolArguments) -> str:
        assert isinstance(args, SearchDocumentsArguments)
        query = args.query.casefold()
        matches = [doc for doc in args.documents if query in doc.casefold()]
        return json.dumps(matches)

    def read_file(args: ToolArguments) -> str:
        assert isinstance(args, ReadFileArguments)
        return contained(workspace, args.path).read_text(encoding="utf-8")

    def calculator(args: ToolArguments) -> str:
        assert isinstance(args, CalculatorArguments)
        result = _calculate(ast.parse(args.expression, mode="eval"))
        return str(int(result) if result.is_integer() else result)

    def write_report(args: ToolArguments) -> str:
        assert isinstance(args, WriteReportArguments)
        parts = PurePath(args.path).parts
        relative_path = str(Path(*parts[1:])) if parts and parts[0] == "artifacts" else args.path
        destination = contained(artifacts, relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(args.content, encoding="utf-8")
        return str(destination.relative_to(artifacts))

    def restricted_command(args: ToolArguments) -> str:
        assert isinstance(args, RestrictedCommandArguments)
        return json.dumps({"status": "requires_execution_plan", "command": args.command})

    registry = ToolRegistry()
    registry.register(ToolDefinition("search_documents", SearchDocumentsArguments, search_documents, TrustLabel.UNTRUSTED_DOCUMENT))
    registry.register(ToolDefinition("read_file", ReadFileArguments, read_file, TrustLabel.UNTRUSTED_DOCUMENT))
    registry.register(ToolDefinition("calculator", CalculatorArguments, calculator, TrustLabel.TRUSTED_TOOL))
    registry.register(ToolDefinition("write_report", WriteReportArguments, write_report, TrustLabel.TRUSTED_TOOL))
    registry.register(ToolDefinition("restricted_command", RestrictedCommandArguments, restricted_command, TrustLabel.UNTRUSTED_TOOL))
    return registry
