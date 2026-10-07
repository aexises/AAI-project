# TraceGuard hardening and independent-project pilot

6 October 2026. This follows the [policy audit](policy_review_20261006.md). The audit
describes the previous implementation; its historical findings and July benchmark
results have not been rewritten as measurements of the revised policy.

**The enforcement implementation is substantially hardened, but the supervisor's
incremental value is not established.** In the completed local pilot, D and D+LLM
had the same attacked security outcome and achieved the same requested task effects.
Neither agent finished an episode cleanly. This is a development result, not evidence
that the independent-contribution milestone has been met.

The research question is whether a semantic supervisor improves **secure task
completion** beyond the same deterministic gate. Prevented proposals, human escalation,
model failures and executed task outcomes are separate measurements. A negative result
is useful; stopping everything is not a successful defense.

## Implemented decisions

The user selected escalation and termination for missing authority/provider failure,
bounded generic replanning after a confirmed block, local Ollama models for the pilot,
secure task completion as the primary outcome, and blocking identical repeated
mutations unless trusted configuration permits them.

Active versions are `types-v3`, custom filesystem policy `2.0.0`, effect registry
`effects-v1`, pre-execution prompt `supervisor_v2.txt`, and separate post-execution
prompt `post_run_v1.txt`. No model block is converted into an allow. Semantic goal
labels, confidence and monotonic risk survive enforcement; `UNCERTAIN` is represented
explicitly rather than converted into helpfulness. Provider failures escalate in
hybrid and LLM-only modes. Escalation latches the task in the custom runtime and
dataset gateway; native AgentDojo suppresses the entire pending batch and further
agent calls.

The shared effect registry includes the tools inspected in AgentDojo 0.1.35 workspace,
banking, Slack and travel suites. Memory and editor effects depend on their operation.
Unknown effects escalate. The custom runtime retains its additional filesystem,
argv and containment checks; a generic service tool does not inherit those capabilities.

`TaskAuthority` originates in trusted application code. It supports tool scope, exact
arguments, field/source delegation, approval conditions, protected content, a cumulative
payment budget and explicit repeat exceptions. Sources can supply a delegated field
without supplying new permissions. Missing/conflicting delegated data escalates.
Known attacker addresses and memorized calendar participants have been removed.
Native batches reserve pending payment amounts and mutations before approving later
calls. Exact protected-content checks inspect nested argument strings before escaping.
Payment amounts require an exact trusted constraint, delegated value or bounded budget;
a destination alone does not authorize an arbitrary amount. Negative/nonfinite payment
amounts and booleans are rejected.

Replacements from every supervisor are checked for effect/resource expansion, identity
and context preservation, trusted authority, tool existence and nested JSON schema
validity. They are evaluated again before execution; automatic repeated rewrites stop.
Native original arguments are also validated before approval. External schema references
are refused, including dynamic references; unresolved local references are validation
failures. A rewrite cannot express executor routing by smuggling an `execution_target`
tool argument.

Both providers receive the same policy/envelope, actual executed history, stable tool
observation IDs, independently constructed value-occurrence provenance and rewrite
state. Request redaction preserves distinctions between recognized secret values using
opaque request-local labels. Log redaction continues to remove them.

Custom file reads without a named path or trusted delegation escalate. Declared container
inputs also require task scope. Sensitive filenames are checked consistently at direct
access, resource declaration, corpus search and staging; corpus symlinks are rejected.
Math/file mixed goals and participant addition no longer trigger the old pure-math rule.
An argv literal containing punctuation is not treated as a shell operator.

## Gap disposition

| Audit findings | Disposition and remaining boundary |
| --- | --- |
| D1 mixed goals | Fixed the reproduced math/file and participant cases; arbitrary English intent still needs semantic reasoning. |
| D2 broad file permission | Unnamed reads/input staging escalate; exact trusted values and source delegation support scoped dynamic data. |
| D3 protected inputs/corpus | Consistent sensitivity and symlink checks added. Filename matching is not arbitrary secret detection. |
| D4 report disclosure | Exact prohibited content can be configured and checked; arbitrary relevance/factual consistency remains a supervisor test surface. |
| D5 command lexical checks | Literal/operator confusion corrected. Script semantics remain outside the lexical gate; containment is conditional, not authorization. |
| D6 dependency self-report | All available untrusted observations participate in command checks; value occurrences are independent of claimed IDs. Precise causal taint tracking remains unimplemented. |
| D7 label overstatement | Unknown assessments can be `UNCERTAIN`; low risk no longer certifies necessity, and a policy denial need not imply irrelevance. |
| G1/G3/G4 effect/scope/address rules | Shared versioned descriptors, trusted constraints and delegation replace unknown-effect allows and known-address rules. |
| G2/G5 bounded language/calendar | Negation, approvals and selected title/start/duration mismatches checked. Full language/timezone interpretation is not guaranteed. |
| G6 security vocabulary | No blanket sensitive-word scan over the user goal/report body; protected objects/content are checked in their relevant fields. |
| L1–L3 discarded verdicts/failures | Removed overrides, retained labels/risk, made provider failures escalate consistently. |
| L4–L5 policy/state/provenance | Policy, trusted scope, history, stable IDs and occurrence provenance populated. IDs do not prove source authenticity or truth. |
| L6–L9 native contract/envelopes | Nested validation, narrowing, reevaluation, episode stops, canonical envelopes and strict parsing added. |
| L10–L11 post-run/redaction | Separate evidence prompt and relationship-preserving request labels added; neither establishes unobserved effects or arbitrary confidentiality. |
| Prompt/runner confounds | Native research mode disables task-specific action/date/answer corrections, normalization and fallback answers; resolved prompts are saved. Vulnerable mode is identical in clean and attacked runs. |
| Fixture scoring | Diagnostic smoke gold labels are no longer copied into predictions; unavailable prediction metrics are null. Fixture call execution is labelled separately from native completion. |

The complete contract and trusted-scope example are in [contracts.md](contracts.md).

## Pilot protocol

The new frozen development set has 30 attacked cases and 30 authorized neighbors in six
families: unauthorized side effects, destination substitution, forged approval, irrelevant
lookups, summary tampering and memory poisoning. Each family has five payload variants
(role spoofing, dependency pretext, approval claim, prior-assistant claim and forged
supervisor metadata). These are related synthetic variants, **not 30 independent tasks**.
The old 21-case custom corpus and external frozen fixtures were preserved.

Payload mechanisms are adaptations of the research discussed in the audit, not a claim
to reproduce AutoDojo, AgentVigil, InjecAgent or MINJA. They use fictitious `example.test`
destinations and disposable service state. They cannot send real mail, write durable
host memory, perform payments or run a host shell.

The snapshot phase evaluates exactly the same proposed call under D and D+LLM. Neither
arm receives gold labels, forbidden effects or expected answers. Case identifiers supplied
to the models are opaque. Both arms receive identical trusted scope; no deterministic
rule is relaxed to increase the supervisor's opportunity.

The live phase selects variant zero from each family before reading hybrid results:
12 cases, each run under both modes, for 24 bounded episodes. Maximum four proposed
steps, two generic block replans, no automatic rewrite, seed zero, temperature zero.
Both agent and supervisor use the only installed local model, `qwen3:1.7b`, digest
`8f68893c685c3ddff2aa3fffce2aa60a30bb2da65ca488b61fff134a4d1730e7`, Q4_K_M.
The supervisor context is 8192 tokens and generation limit 384; the original task-agent
transport used its default context and generation limit 512. Provider timeout is 60
seconds and supervisor transport retries are disabled. This is a shared-model, one-seed
development pilot, not a held-out or statistically powered efficacy experiment.

## Snapshot result

| Calls | D | D+LLM |
| --- | ---: | ---: |
| Attacked: ALLOW | 10/30 | 7/30 |
| Attacked: BLOCK | 15/30 | 16/30 |
| Attacked: ESCALATE | 5/30 | 7/30 |
| Authorized: ALLOW | 30/30 | 30/30 |

There is **one additional semantic block**, an irrelevant lookup. Two additional
withheld summary-tampering calls are **schema failures**, not successful semantic
judgments. Thus semantic blocking covers only 1/10 deterministic-allowed unsafe
snapshots here. There are no additional benign withholds in the snapshot phase.
These results do not establish an improvement in secure task completion.

## Live result and scoring

All 24 episodes completed their bounded runs. Raw traces retain model metadata,
decisions, errors, actual disposable state and public final answers. Utility checks
the requested effect/answer. Attack-family predicates inspect executed effects and
consequential fields, so changing an incidental subject does not hide the declared
prohibited effect. These predicates assess the declared attacked-case threats;
benign cases have no separate prohibited-effect predicate. Their reported outcome is
task-effect utility, not a general security certification.

| Live outcome | D | D+LLM |
| --- | ---: | ---: |
| Attacked: prohibited effect executed | 1/6 | 1/6 |
| Attacked: requested effect/answer achieved without declared attack effect | 2/6 | 2/6 |
| Benign: requested effect/answer achieved | 4/6 | 4/6 |
| Clean agent termination with achieved utility | 0/12 | 0/12 |
| Episodes stopped by ESCALATE | 1/12 | 8/12 |
| Agent contract errors | 2/12 | 1/12 |
| Supervisor schema failures | No provider calls | 7/24 calls |
| Excess identical executed mutations | 18 | 3 |

The retained `secure_utility` proxy is 6/12 in each arm, with no paired disagreements.
It means the requested effect/answer occurred without a **declared** attack effect;
it does not require clean termination or establish final-answer confidentiality.
All public final answers are absent. Thus neither arm demonstrates reliable automatic
secure task completion, the selected primary outcome.

Both arms emailed incident count **103** although the attacked report's verified data
said **3**. D sent it four times; D+LLM sent it once before a later schema failure
escalated the episode. That later failure did not undo the disclosure or constitute
successful semantic prevention. The fewer repeats in the hybrid mostly reflect early
termination, not a demonstrated supervisor advantage; repeat blocking now belongs to
the common deterministic execution boundary.

The two benign utility failures in each arm were the approval-conditioned summary
without the requested count and a search query that did not match the specified query.
Successful email utility can coexist with later escalation, a step limit or an agent
contract error. The memory attack ended with an unavailable-tool proposal in both arms;
such errors are not credited as LLM prevention.

Supervisor overhead was 40 calls in the snapshot phase and **24 verified calls** in
the live phase. Two raw live `provider_called` flags inherited the previous evaluation
on deterministic memory-argument denials. Independent accounting excludes those flags
using decision metadata/failure rules; raw rows are unchanged. The stale-log issue is
fixed and regression-tested for future calls.

| Supervisor cost on this laptop | Snapshot | Live |
| --- | ---: | ---: |
| Call latency p50 | 12.56 s | 32.11 s |
| Call latency p95, nearest rank | 16.11 s | 47.89 s |
| Summed supervision wall time | 515.52 s | 794.21 s |
| Responses with token metadata | 38/40 | 17/24 |
| Recorded input/output tokens | 61,308 / 5,515 | 35,799 / 2,474 |

Failure token counts and task-agent costs are unavailable. These are supervision-call
timings on the working laptop, not total episode latency or a controlled hardware
benchmark. Snapshot and live failures were respectively 2/40 and 7/24 supervisor calls.

Evidence is in `artifacts/semantic_pilot_20261006_v2/`: `manifest.json`,
`environment.txt`, raw `snapshot.jsonl`/`live.jsonl`, `live_rescored.jsonl`,
`summary_rescored.json`, `scoring_manifest.json` and `independent_analysis.json`.
Independent checks confirm unique complete pairs, unchanged raw security labels and
agreement between recorded email execution and the actual disposable outbox. The
earlier aborted directory is explicitly marked `ABORTED.md` and excluded.

During verification, the original utility matcher was found to require an unspecified
email subject and exact incidental body formatting. The corrected checker evaluates the
authorized recipient and incident count; mathematically equivalent calculator expressions
are also accepted. This correction is applied uniformly to both arms. Original rows are
preserved, rescored rows have a separate file and scoring manifest, and no model call is
rerun or retuned to change the result. Repeated mutations are reported separately.

The pilot was launched before the subsequently requested deterministic repeat guard and
final contract/prompt/checker refinements. It is diagnostic evidence that motivated those
changes, not a measurement of every final-code refinement. The run manifest records the
launch-time source hashes and environment. Future runs also archive source copies; the
first completed pilot records hashes without a complete source archive. Reproduction of
the final code is a new experiment, not a silent relabelling of the retained run.
Future runs record task-agent token counts and total episode latency as well; these
were not captured in the retained pilot and are not reconstructed from guesswork.
Future task-agent context is pinned to 8192 tokens; the retained run used the server's
default. Source copies, frozen cases and dependency configuration are archived in new
run directories.

## Verification and next acceptance criterion

Verification: **239 passed, 7 skipped**, Ruff lint/format and `git diff --check`,
custom smoke execution, a 160-episode offline smoke matrix, native AgentDojo pipeline
regression execution, wheel build/content inspection and a native conclusion-protocol
dry run. The smoke matrix includes unprotected ablations and is a plumbing check,
not evidence of incremental semantic value. Native regressions cover escalation,
rewrites, successful execution history, duplicate mutations and pending payment budgets.
Docker tests remain opt-in; mock staging/evidence tests do not establish a new live
container result. Native pipeline regressions use synthetic functions and no LLM; the
Ollama episodes above use the separate disposable pilot world, not a native suite.

The next acceptance criterion remains a positive paired change in secure completion
under a frozen, broader corpus with repetitions and uncertainty intervals clustered by
task family. Report both the entire corpus and the deterministic-allowed unsafe stratum,
plus benign withholds, human escalation, provider failures, tokens and latency. Snapshot
disagreement is a diagnostic, not the primary efficacy outcome.

Use a more capable independent agent/supervisor pairing when available, and record its
exact configuration rather than extrapolating from this small shared model. Native
benchmark reproduction, fixed-budget adaptive attacks, disjoint held-out families and
full final-answer confidentiality checks remain future research stages. The implemented
gate protects explicit supported constraints; it is not a formal policy interpreter,
causal provenance system, truth oracle or universal prompt-injection defense.

```bash
python -m benchmarks.semantic_pilot --model qwen3:1.7b --live \
  --output artifacts/semantic_pilot_new_run
python -m benchmarks.semantic_pilot --rescore-run artifacts/semantic_pilot_20261006_v2
python -m traceguard.conclusion_ablation --dry-run \
  --agent-model qwen3:1.7b --supervisor-model qwen3:1.7b \
  --output-dir artifacts/conclusion_new_protocol
```
