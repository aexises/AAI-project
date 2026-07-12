# Repository Guidelines

## Project Structure & Module Organization

This repository is a research skeleton; `proposal.md` defines TraceGuard's goals. Add Python code under `src/traceguard/`, grouped by ownership: `supervisor/` for LLM supervision, `sandbox/` for Docker execution, and `tools/` plus `policy/` for tool definitions and deterministic checks. Put AgentDojo adapters and custom attacks in `benchmarks/`, tests in `tests/`, experiment configurations in `configs/`, and generated results in ignored `artifacts/`. Keep shared schemas in `src/traceguard/types.py` to prevent circular ownership.

## Build, Test, and Development Commands

No executable scaffold exists yet. When adding `pyproject.toml`, standardize on these commands:

- `python3 -m venv .venv && source .venv/bin/activate`: create the local environment.
- `python -m pip install -e '.[dev]'`: install TraceGuard and development dependencies.
- `python -m pytest`: run all tests.
- `python -m pytest tests/supervisor -q`: run one workstream's tests.
- `ruff check .` and `ruff format --check .`: lint and verify formatting.

Document any new benchmark or evaluation command in the README and expose it through a Python module or script, not an undocumented shell sequence.

## Coding Style & Naming Conventions

Use Python 3.11+, four-space indentation, type hints on public interfaces, and Ruff formatting. Use `snake_case` for modules and functions, `PascalCase` for classes, and uppercase names for enums and constants. Prefer typed dataclasses or Pydantic models for tool calls, observations, policies, and supervisor outputs. Keep prompts and policy rules versioned as data files rather than embedding long strings throughout the code.

## Testing Guidelines

Use `pytest`; name files `test_<component>.py` and tests `test_<behavior>`. Every safety decision (`ALLOW`, `BLOCK`, `ESCALATE`, `REWRITE`) needs golden cases. Test provenance propagation, goal relevance and necessity, policy precedence, container limits, and metric calculations. Use harmless canaries, simulated services, and disposable containers; never test with real credentials or destructive host commands.

## Commit & Pull Request Guidelines

History is minimal, so adopt concise imperative commits such as `Add supervisor decision schema`. Keep commits scoped to one concern. Pull requests must identify the owning workstream, summarize behavior and interface changes, list tests run, and note benchmark or security impact. Link the relevant issue or experiment. Include screenshots only for visual reports; include representative trace output for runtime changes.

## Security & Configuration

Load Gemini credentials from environment variables and commit only `.env.example`. Never log secrets or hidden chain-of-thought. Pin AgentDojo dependencies, model identifiers, prompts, seeds, and Docker image digests so experiments remain reproducible.
