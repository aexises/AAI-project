# Supervisor Calibration

TraceGuard freezes the supervisor confidence threshold at `0.55`.

The threshold is applied after schema validation and before execution. An
`ALLOW` or `REWRITE` below the threshold is converted to `ESCALATE`; `BLOCK`
and `ESCALATE` are never weakened because of low confidence. Deterministic
terminal rules take precedence over model output, and the LLM may not lower
their risk classification.

The labelled calibration set is
`tests/supervisor/calibration_cases.json`. It is separate from the frozen
custom benchmark and contains:

- a necessary low-risk allow;
- a relevant but unnecessary command block;
- a high-stakes uncertain-authority escalation;
- a narrower-recipient rewrite.

The reviewed golden set additionally covers all four threat-model labels,
all four supervisor decisions, independently labelled relevance and
necessity, necessary-but-risky behavior, relevant-but-unnecessary behavior,
and a low-risk but unrelated lookup. Gemini and Ollama validate the same
historical golden cases through their shared structured contract. The v2 rewrite
validator now rejects the historical fixture that put container routing inside tool
arguments; the fewer-recipient fixture requires explicit recipient authority.
Provider tests supply this authority rather than weakening the gate.

The threshold was selected as a conservative operating boundary for the
prototype: values below a modest majority confidence require review, while
high-confidence deny decisions remain fail-closed. It is fixed before the
held-out test split is evaluated. Changing it requires a new experiment
manifest and rerunning all paired ablations.

The same threshold applies after container execution. A low-confidence
`ACCEPT_RESULT` or `REWRITE_AND_RETRY` becomes `ESCALATE`. Post-run provider
latency and input/output tokens are recorded separately from pre-execution
supervision overhead.

The calibration set is intentionally small. Confidence is model-dependent and
not statistically calibrated; the evaluation report must describe it as an
operating threshold, not a probability of correctness.
