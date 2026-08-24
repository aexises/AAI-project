# TraceGuard

TraceGuard is a research platform for evaluating and enforcing safeguards around
tool-using AI agents. It has two complementary components:

- a reproducible research runtime for testing system-prompt defenses, deterministic
  policy, LLM supervision, and Docker containment; and
- a safety control plane for evaluating agent and model actions against versioned policy
  before a mediated side effect is allowed.

It is made for researchers and engineers who need to study prompt injection and unsafe
tool use, compare defense configurations, or build a policy-enforced boundary around
agent actions. TraceGuard is not a general-purpose agent framework and does not make an
unmediated agent safe by itself.

## Prerequisites

The local runtime requires Python 3.11 or newer, `git`, and `pip`. Docker is optional
and is required only for containment checks and container execution. Gemini, AgentDojo,
and external dataset integrations are optional extras. The control-plane Kubernetes
deployment additionally requires Kubernetes 1.27+ and a container registry.

See [setup.md](setup.md) for installation, optional integrations, verification,
experiments, Docker execution, benchmarks, API development, and deployment guidance.

## How it works

For each proposed tool call, TraceGuard combines structured tool definitions,
deterministic policy checks, and an optional supervisor. The policy can allow, block,
escalate for review, or safely rewrite a call. Untrusted evidence and sandbox output
remain bounded inputs to the decision process; they never become host-shell commands.

When an uncertain command is eligible for containment, TraceGuard executes it only in a
configured Docker profile. Profiles use immutable images and fixed resource and isolation
limits. Failure to verify the environment, image, output, or cleanup fails closed.

The control plane applies the same decision model at a versioned HTTP boundary. It
evaluates an action before the caller performs it, records an auditable decision, and can
issue signed, tenant-scoped policy bundles for limited offline authorization. Only explicit,
matching `ALLOW` rules may authorize execution; unknown, stale, unavailable, or
unreviewed actions are blocked or escalated.

## Documentation

- [Setup and operations](setup.md)
- [Policy contracts](docs/contracts.md)
- [Supervisor calibration](docs/supervisor_calibration.md)
- [Control-plane design](docs/control_plane.md)
- [Evaluation report](docs/evaluation_report.md)
- [Demo walkthrough](docs/demo.md)
- [External benchmark guidance](docs/external_benchmarks.md)
