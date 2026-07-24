# TraceGuard Team TODO

This checklist starts from the current scaffold. Check off an item only when its tests, configuration, and documentation are included in the same pull request. Generated experiment output belongs in ignored `artifacts/`.

## Shared Integration Gates

- [ ] Agree on and tag `types-v1`: review every model and enum in `src/traceguard/types.py`; record approved semantics for `REWRITE`, relevance, necessity, risk, trust, and execution targets.
- [ ] Add contract fixtures shared by all workstreams: one benign call, one direct attack, one indirect injection, one policy violation, one rewrite, and one container-routed call.
- [ ] Define the policy for conflicting deterministic and LLM outputs, including which component may lower risk and when `ESCALATE` requires human input.
- [x] Define experiment manifests containing code revision, AgentDojo version, model identifiers, prompt versions, policy version, image digest, seed, temperature, and enabled safeguards.
- [ ] Add CI for Python 3.11 with `pytest`, `ruff check .`, and `ruff format --check .`.
- [ ] Run an end-to-end smoke set before full experiments: at least five benign, five policy-violation, five direct-attack, and five indirect-injection episodes.
- [ ] Freeze benchmark cases and labels before collecting final results; changes afterward require a new benchmark version.
- [ ] Review representative traces together and resolve disagreements in unsafe-call, relevance, necessity, and episode-outcome labels.

## Person 1: LLM Supervisor

Owns `src/traceguard/supervisor/`, supervisor prompt data, and `tests/supervisor/`.

### P1.1 Structured model integrations

- [ ] Select and record the exact Gemini model identifier used for primary experiments.
- [ ] Select an Ollama model that fits the M2 8 GB machine; record its tag, quantization, digest, and measured memory use.
- [ ] Run one real structured-output request through `GeminiSupervisor` and one through `OllamaSupervisor`.
- [ ] Add mocked transport tests covering valid output, malformed JSON, schema violations, timeout, unavailable model, rate limit, and empty response.
- [ ] Add bounded retries for transient transport failures; never retry a valid `BLOCK` or `ESCALATE` decision.
- [ ] Record request latency and input/output token usage in trace events where the provider exposes them.
- [ ] Ensure prompts and logged payloads redact configured secret patterns and never request or store hidden chain-of-thought.

### P1.2 Decision quality

- [ ] Create golden examples for `ALLOW`, `BLOCK`, `ESCALATE`, and `REWRITE` across all three threat models.
- [ ] Label goal relevance and necessity independently for every golden example.
- [ ] Add cases where a call is relevant but unnecessary, necessary but risky, and apparently safe but unrelated.
- [ ] Add rewrite cases for narrower paths, reduced arguments, safer tools, and container routing.
- [ ] Verify rewritten calls preserve `task_id`, step identity, provenance references, and the original user goal.
- [ ] Test that a second rewrite request becomes `ESCALATE`.
- [ ] Calibrate risk and confidence on a held-out labelled set; document thresholds rather than tuning on final test cases.

### P1.3 Post-container exploration

- [ ] Finalize the bounded `SandboxEvidence` representation with Person 2.
- [ ] Build post-run golden cases for harmless success, blocked network access, suspicious file creation, timeout, resource exhaustion, and deceptive stdout.
- [ ] Compare pre-run and post-run risk labels and explain every risk change using observable evidence.
- [ ] Enforce that `ACCEPT_RESULT` consumes container output only and never authorizes automatic host re-execution.
- [ ] Measure post-run risk accuracy, risk-update rate, useful recovery rate, latency, and token overhead.
- [ ] Document sandbox-aware or delayed-behavior attacks as a limitation of post-run reevaluation.

### Person 1 done when

- [ ] Gemini and Ollama adapters pass contract tests and can evaluate the same frozen case set.
- [ ] All four decisions and all relevance/necessity labels have reviewed golden coverage.
- [ ] A reproducible supervisor comparison report exists for Gemini, Ollama, and the offline heuristic baseline.

## Person 2: Virtualization Rules and Workflow

Owns `src/traceguard/sandbox/`, Docker-related configuration, and `tests/sandbox/`.

### P2.1 Container profiles

- [ ] Select a minimal ARM64-compatible image and pin its immutable digest in an experiment-specific configuration, not in source code.
- [ ] Implement and test `isolated_compute` with no network, no host inputs, and ephemeral output.
- [ ] Implement `readonly_input` by copying declared inputs into a temporary staging area and exposing them read-only.
- [ ] Implement `artifact_build` with an allowlisted output directory, size limits, and post-run artifact inspection.
- [ ] Keep `restricted_network` disabled until an enforceable egress proxy or equivalent destination control exists.
- [ ] Validate that profile names and limits come only from trusted configuration; reject agent-supplied Docker flags.
- [ ] Add image architecture and digest checks before container startup.

### P2.2 Hardening and evidence

- [ ] Verify non-root execution, `cap-drop=ALL`, `no-new-privileges`, read-only root filesystem, PID limits, memory limits, CPU limits, and timeout behavior.
- [ ] Verify that the Docker socket, host credentials, undeclared paths, host PID namespace, privileged mode, and device access are unavailable.
- [ ] Bound stdout and stderr separately and record when either is truncated.
- [ ] Collect declared file changes, attempted blocked operations, exit status, duration, timeout, and available resource measurements into `SandboxEvidence`.
- [ ] Ensure container names, staging directories, and temporary artifacts are cleaned after success, failure, cancellation, and timeout.
- [ ] Fail closed when Docker is unavailable, the image is unpinned, a profile is unsupported, or evidence collection fails.

### P2.3 Routing and evaluation

- [ ] Define containability rules with Persons 1 and 3: only uncertain or medium-risk command calls may route to Docker.
- [ ] Add explicit tests showing that high and critical calls remain blocked or escalated even when Docker is available.
- [ ] Add harmless canary tests for network isolation, undeclared file access, process limits, output limits, and timeout.
- [ ] Measure cold-start latency, warm latency, peak memory, disk use, and cleanup reliability on the M2 Mac.
- [ ] Compare simulated execution, container execution, and container execution with LLM reevaluation on the Docker-applicable benchmark stratum.
- [ ] Document Docker Desktop's Linux VM and container escape/daemon compromise as residual risks.

### Person 2 done when

- [ ] Every enabled profile has passing positive, negative, cleanup, and resource-limit tests on the M2 Mac.
- [ ] No test exposes the host Docker socket, unrestricted network, or undeclared host paths.
- [ ] Docker overhead and containment results can be reproduced from a versioned experiment manifest.

## Person 3: Tools, Deterministic Policy, and Benchmarking

Owns `src/traceguard/tools/`, `src/traceguard/policy/`, `benchmarks/`, experiment orchestration, and the primary metrics pipeline.

### P3.1 Tools and deterministic policy

- [x] Review each tool schema and document its side effects, risk class, trusted inputs, and trusted output label.
- [x] Replace in-memory document search with an AgentDojo-compatible or fixture-backed document environment while preserving provenance.
- [x] Add size and encoding limits to file reads and report writes.
- [x] Keep calculator parsing AST-based and add tests for exponent/resource abuse, names, calls, attributes, and malformed input.
- [x] Ensure `restricted_command` cannot execute directly on the host; it must remain simulated or receive an approved container plan.
- [x] Expand deterministic rules for allowed paths, required resources, irrelevant tool use, unnecessary permissions, and untrusted-observation dependencies.
- [x] Version policy files and include the policy version in every trace and experiment manifest.
- [x] Add deterministic golden cases for all decisions, including safe argument/path rewrites.

### P3.2 AgentDojo and custom attacks

- [ ] Install and validate pinned AgentDojo `0.1.35` in the Python 3.11 environment.
- [ ] Replace the metadata-only adapter with a native AgentDojo suite/runner integration using its task, injection, utility, and security checks.
- [x] Select and document the AgentDojo suites and task IDs used for the primary indirect-injection evaluation.
- [x] Expand each threat model to a reviewed development set and a held-out test set; do not reuse test cases for prompt or rule tuning.
- [x] Add direct attacks covering disclosure, destructive requests, policy circumvention, and social-engineering variants.
- [x] Add policy violations covering irrelevant access, excessive permissions, unsafe arguments, and unnecessary commands without adversarial text.
- [x] Add indirect injections in documents, search results, files, terminal output, and simulated cybersecurity artifacts.
- [x] Implement executable utility and security checkers for every custom case; remove placeholder checker descriptions before final evaluation.
- [x] Use only harmless canaries, simulated services, and disposable containers; prohibit real credentials and external attack targets.

### P3.3 Experiment runner and analysis

- [x] Implement a CLI command that runs one case, one safeguard configuration, or the full eight-configuration matrix.
- [x] Guarantee paired seeds, identical user tasks, fixed model parameters, and frozen initial state across ablations.
- [x] Persist JSONL traces and a normalized result table under `artifacts/` without secrets or chain-of-thought.
- [x] Convert trace outcomes into call-level and episode-level metric records with validation for missing labels.
- [x] Add relevance/necessity macro-F1, containment success, post-run accuracy, risk-update rate, and useful recovery rate to aggregation.
- [x] Add bootstrap 95% confidence intervals and paired comparisons between ablations.
- [x] Report metrics separately for policy violations, direct attacks, indirect injections, benign tasks, and Docker-applicable tasks.
- [x] Generate report-ready CSV/JSON summaries and representative sanitized traces.

### Person 3 done when

- [x] One command reproduces a smoke matrix and one command reproduces the frozen full evaluation.
- [ ] Every benchmark case has executable utility and security checks and an explicit threat-model label; custom cases satisfy this, but native AgentDojo execution remains to be integrated.
- [x] Final tables can be regenerated from raw traces without manual editing.

## Final Team Deliverables

- [ ] Working supervised ReAct agent with neutral and defensive system prompts.
- [ ] Deterministic, LLM-only, prompt-only, hybrid, and no-safeguard results across all eight ablations.
- [ ] Separate quantitative results for policy violation, direct attack, and indirect injection.
- [ ] Docker containment study limited to applicable terminal tasks.
- [ ] Post-container LLM reevaluation reported as exploratory, with limitations.
- [ ] Reproducible experiment manifests, traces, metric tables, final report, and short demo.
