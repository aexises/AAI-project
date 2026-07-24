# TraceGuard

TraceGuard is a research runtime for evaluating system-prompt defenses, deterministic policy, and LLM supervision for tool-using agents. Docker is used only as a conditional containment mechanism for uncertain, medium-risk command calls.

The owner-specific implementation and research checklist is in [`TODO.md`](TODO.md).

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

## Experiments

```bash
# four representative threat cases across all eight ablations
python -m traceguard smoke-matrix --seed 0

# one case + one ablation
python -m traceguard experiment --split dev --case benign_math_dev --ablation A2

# full eight-ablation matrix on the development split
python -m traceguard experiment --split dev --seed 0

# held-out custom cases
python -m traceguard experiment --split test --seed 0

# frozen custom evaluation across both splits
python -m traceguard experiment --split all --seed 0

# regenerate summary.json and summary.csv from a completed run's sanitized traces
python -m traceguard analyze --run-dir artifacts/run_<timestamp>_0

# validate the AgentDojo install, version, suites, and selected task IDs
python -m traceguard agentdojo-info
```

Traces, manifests, CSV/JSON summaries, paired comparisons, and representative traces are
written under `artifacts/run_*`. Pairing keeps the same per-case seed across ablations.
Manifests record content digests for the cases and initial state. Persisted results redact
TraceGuard canaries, common secret assignments, and literal patterns configured through
`TRACEGUARD_REDACT_PATTERNS`.

`agentdojo-info` exits nonzero when AgentDojo is missing, its version differs from `0.1.35`,
or a configured suite/task ID is unavailable.

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
