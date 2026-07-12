# TraceGuard

TraceGuard is a research runtime for evaluating system-prompt defenses, deterministic policy, and LLM supervision for tool-using agents. Docker is used only as a conditional containment mechanism for uncertain, medium-risk command calls.

## Setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
ruff check .
ruff format --check .
```

Install `.[gemini]`, `.[agentdojo]`, or both for external evaluations. Gemini credentials and model choices belong in environment variables; Ollama uses its local HTTP API. Copy `.env.example` into your untracked environment configuration and pin exact model identifiers in each experiment manifest.

## Offline smoke run

```bash
python -m traceguard smoke
```

The smoke run uses the deterministic policy and offline heuristic supervisor. It does not require credentials, Ollama, AgentDojo, or Docker.

## Repository layout

- `src/traceguard/supervisor/`: Gemini, Ollama, and offline supervisors.
- `src/traceguard/sandbox/`: hardened Docker execution.
- `src/traceguard/tools/` and `src/traceguard/policy/`: typed tools and deterministic checks.
- `benchmarks/`: AgentDojo boundary and custom threat-model cases.
- `configs/`: eight primary ablations and sandbox profiles.
- `artifacts/`: ignored experiment output.

## Security boundary

`restricted_command` never invokes a host shell. Without an approved container plan it returns a simulated runtime marker. Container execution requires `TRACEGUARD_SANDBOX_IMAGE` to contain a pinned `@sha256:` digest and uses argv directly, without shell interpretation. The current prototype supports no-network container profiles; `restricted_network` remains declarative until an enforceable egress proxy is added.

Post-run reevaluation consumes bounded, untrusted sandbox evidence. It never automatically reruns a command on the host.

## Benchmarking

AgentDojo is pinned to `0.1.35`. Custom cases in `benchmarks/cases/custom_cases.json` keep policy violations, direct attacks, and indirect injections distinct. Experiment runners must use paired task/model seeds across the eight configurations in `configs/ablations.json` and record outputs under `artifacts/`.

