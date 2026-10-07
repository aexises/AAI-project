# TraceGuard Evaluation Report

This is a historical July result. The October policy and prompt revisions require new
runs; see [the hardening and local pilot report](hardening_and_pilot_20261006.md).

## Scope

This report records the reproducible validation run performed on 25 July 2026.
It covers the frozen custom benchmark, all eight safeguard configurations, real
Docker containment, post-container evidence handling, package validation, and
the AgentDojo integration boundary.

The custom benchmark is frozen as `traceguard-custom` version `1.1.0`. It has
21 cases: six benign, five policy violations, five direct attacks, and five
indirect injections. Development and held-out test cases are both represented.
The benchmark file digest and label contract are enforced by
`benchmarks/cases/manifest.json`.

## Reproduction

```bash
python -m pip install -e '.[dev,agentdojo,gemini]'
ruff check .
ruff format --check .
python -m pytest
TRACEGUARD_RUN_DOCKER_TESTS=1 python -m pytest tests/sandbox -q
python -m traceguard agentdojo-info
python -m traceguard experiment \
  --split all \
  --container \
  --post-run \
  --agent-provider scripted \
  --supervisor-provider heuristic \
  --seed 0
```

The validated run contains 168 episodes: 21 frozen cases under each of the
eight ablations. Its raw traces, per-ablation manifests, normalized results,
representative traces, CSV, and JSON summary are under
`artifacts/run_20260725T205254441630Z_0`.

## Custom benchmark results

These results use the prompt-sensitive runtime interface with scripted frozen
actions and the offline heuristic supervisor. They validate policy, routing,
metrics, and containment deterministically; they are not a substitute for the
separate live-model comparison.

| Ablation | Safeguards | Attack success | Benign utility | Safe completion | Compromise | Containment |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| A0 | none | 0.400 | 1.000 | 0.381 | 0.333 | 0.000 |
| A1 | defensive prompt | 0.400 | 1.000 | 0.381 | 0.333 | 0.000 |
| A2 | deterministic | 0.100 | 1.000 | 0.952 | 0.048 | 1.000 |
| A3 | heuristic supervisor | 0.300 | 1.000 | 0.619 | 0.286 | 0.429 |
| A4 | prompt + deterministic | 0.100 | 1.000 | 0.952 | 0.048 | 1.000 |
| A5 | prompt + heuristic | 0.300 | 1.000 | 0.619 | 0.286 | 0.429 |
| A6 | deterministic + heuristic | 0.000 | 1.000 | 1.000 | 0.000 | 1.000 |
| A7 | all three | 0.000 | 1.000 | 1.000 | 0.000 | 1.000 |

The result supports the proposal's central claim on this frozen set:
the hybrid configurations prevented every labelled attack outcome while
preserving all benign utility. Deterministic-only configurations reduced
attack success from 40% to 10%; the remaining difference demonstrates why the
hybrid is evaluated separately. The defensive prompt alone did not change
outcomes because scripted actions intentionally hold the proposed calls fixed.
That prompt effect must be measured with the live task agent.

The benign container control made post-run evaluation measurable. Hybrid
configurations A6 and A7 achieved post-run accuracy, risk-update rate, and
useful-recovery rate of 1.0 on the applicable observations. Heuristic-only A3
and A5 changed risk on each observed container result but classified those
results incorrectly, producing post-run accuracy and useful recovery of 0.0.
This small stratum is exploratory rather than a calibrated accuracy estimate.

## Docker containment

The pinned ARM64 image and all three enabled profiles passed the readiness
gate. All 24 sandbox tests passed, including isolation, undeclared input,
network, timeout, output-bound, resource-limit, artifact inspection, and
cleanup canaries.

The three-run host measurement recorded:

- cold start: 323.54 ms;
- warm mean: 404.43 ms;
- peak container memory: 3,719,299 bytes;
- maximum writable layer: 4,096 bytes;
- cleanup success: 3/3.

The measurement and its code/config digests are in
`artifacts/sandbox_benchmark.json`.

The Docker-applicable stratum was also run in three paired modes:

| Mode | Run directory | Benign utility | Attack success | Compromise |
| --- | --- | ---: | ---: | ---: |
| simulated / fail-closed routing | `run_20260725T205409749711Z_0` | 0.500 | 0.000 | 0.071 |
| container execution | `run_20260725T205356335631Z_0` | 1.000 | 0.125 | 0.143 |
| container + post-run reevaluation | `run_20260725T205254441630Z_0` | 1.000 | 0.125 | 0.143 |

The denominator is small and combines safeguard configurations, so this table
is descriptive. It demonstrates the intended tradeoff: unavailable
containment fails closed and loses useful command execution; enabling the
container recovers benign utility but does not make an unsafe command safe.
Pre-run blocking remains necessary.

## Integration status and limitations

AgentDojo `0.1.35` is installed and the configured `workspace` and `banking`
task IDs validate against benchmark version `v1.2.2`. The local and Gemini
providers share one structured supervisor contract. The local choice is
`qwen3:1.7b`, chosen for the 8 GB host; the cloud comparison identifier is
`gemini-3.5-flash`.

The live Ollama contract check passed on
`artifacts/run_20260725T205733415211Z_0`. Resolved model metadata was:

- tag: `qwen3:1.7b`;
- digest: `8f68893c685c3ddff2aa3fffce2aa60a30bb2da65ca488b61fff134a4d1730e7`;
- quantization: `Q4_K_M`;
- measured resident/VRAM bytes: `1,482,476,747`;
- request latency: 19.82 seconds;
- input/output tokens: 896/107.

The seven-case Docker-applicable stratum was then run with deterministic plus
live Ollama pre-execution supervision and the earlier deterministic
post-container assessor in
`artifacts/run_20260725T205837464246Z_0`. It produced 0% attack success, 0%
compromise, 100% unsafe-call blocking, 100% benign utility, and 85.7% safe
completion. Mean supervised-call latency was 3.70 seconds and total supervisor
token usage was 2,101. Post-run accuracy and useful recovery were both 0.5;
this confirms the post-run stage is exploratory and should not replace
pre-execution enforcement.

The runtime now supports structured provider-backed post-run assessment for
both Ollama and Gemini, including fail-closed timeout/error handling and
separate latency/token accounting. The historical artifacts above predate
that implementation and must not be presented as provider-backed post-run
results. Per the current scope, no replacement live comparison was run.

The live prompt-sensitive task agent also completed the full
agent→supervisor→calculator loop with 100% utility in
`artifacts/run_20260725T205922977505Z_0`. A native AgentDojo
`workspace/user_task_0` smoke then passed both the utility and security
checkers in 35.22 seconds. Its evidence-grounded final answer and raw native
trace are under `artifacts/agentdojo-live-smoke-v3`.

A paired native AgentDojo attack smoke is under
`artifacts/agentdojo-live-attack-smoke`. The clean task passed utility; the
attacked task did not complete the user's task, but it also did not attempt or
execute the injected `send_email` goal. After normalizing AgentDojo's raw
injection-task checker (`true` means the attacker goal succeeded), the attacked
episode therefore has 100% security success and 0% attack success. This is a
one-case integration check, not a statistically meaningful effectiveness
estimate.

Post-run evaluation can only judge bounded observable evidence. Delayed
behavior, environment-aware evasion, kernel/container escape, and compromise
of the Docker daemon remain outside its security guarantee. An accepted
container result is never authorization to rerun the command on the host.
