# Architecture

This is the authoritative design for OctoberBlue. It describes the finished system. What v0.1 implements today is marked in [REQUIREMENTS.md](REQUIREMENTS.md); the build order is in [ROADMAP.md](ROADMAP.md).

Nothing in v0.1 is a reason to drop a requirement here. A milestone that leaves something out moves it to a later milestone; it does not delete it.

## Research question

Can independently evolving offensive and defensive AI systems, learning from verified experience and offline Dreaming, find stronger attacks and build better defenses without hurting legitimate task completion or exceeding practical cost?

**Success** is a reproducible, statistically meaningful reduction in verified attack success on unseen tests, with acceptable legitimate completion, false-positive rate and cost.

**Failure** includes any of: defenses that don't hold, unacceptable task degradation, information leakage, unbounded spending, or unreliable verification.

Exact thresholds are preregistered and frozen before any evaluation result is read.

## Roles

| ID | Kind | Job |
| --- | --- | --- |
| `red_researcher` | Agent | Gathers threat intelligence and records its sources. |
| `red_attacker` | Agent | Builds typed, versioned attack artifacts. |
| `blue_researcher` | Agent | Gathers defense research and records its sources. |
| `blue_guard` | Agent / middleware | Inspects inputs and tool calls at runtime. Deterministic first; model-assisted inspection optional. |
| `target_agent` | Agent | The system under test. Version-pinned for controlled comparisons. |
| `execution_harness` | Trusted code | Runs experiments, injects attacks into declared surfaces, records events. |
| `independent_verifier` | Trusted code | Scores outcomes from recorded tool calls and state changes. Deterministic, never an LLM judge. |

The trusted gateway, budget ledger and holdout store are trusted code too. No agent output can edit the verifier, gateway policy, budgets, holdouts or the active defense.

## Trust boundaries

- **Operator.** Sets budgets, seals holdouts, approves memory promotion, can stop everything.
- **Trusted core.** Harness, sandbox, gateway, verifier, ledger, holdout store.
- **Red side** and **blue side.** Untrusted agents, each with private memory the other side can't read.
- **Sandbox.** The target and its tools run in containerized isolation. Effects outside the permitted experimental environment are blocked.

Attack inputs enter only declared lower-trust surfaces, and every input keeps its provenance and trust label for the whole run. Consequential tool calls go through the gateway, which enforces tool schemas, permissions and quotas. Turning the guard off never turns the gateway off.

## Outcomes

The verifier assigns each run, from evidence alone:

| Outcome | Meaning |
| --- | --- |
| Attempted, prevented | The target tried an unauthorized action and the guard or gateway stopped it. |
| Detected after attempt | The action was flagged after it was attempted. |
| Completed | The attack produced a prohibited effect inside the sandbox. |
| Task success / failure | Whether the legitimate task was done correctly. |
| Indeterminate | The evidence is insufficient to decide. |

A successful attack must be possible inside the controlled benchmark; otherwise comparisons mean nothing. The gateway still blocks effects outside the experimental environment.

Attacker behavior and guard behavior are modeled independently. Each guard is tested for missed attacks and for false positives on legitimate inputs.

## Partitions and holdouts

Runs belong to the **development** partition or the **holdout** partition. Holdouts are sealed before evaluation and never feed learning on either side. Feedback that reaches agents during development is redacted so it can't leak answers. Nothing is promoted into a frozen evaluation snapshot.

## Dreaming

Dreaming is offline memory consolidation, run separately for each side, only between epochs.

1. **Gather** verified development runs. Holdout and indeterminate runs are refused.
2. **Dream.** Batch-synthesize candidate lessons with an efficient model.
3. **Propose** a new memory version linked to its parent version and its evidence runs.
4. **Gate.** Regression tests, then operator approval. A proposal whose parent is no longer the latest version is refused.
5. **Promote.** The version becomes that side's latest. Promotion can be rolled back.

Memory versions are immutable. The active defense is frozen during execution; a new defense takes effect only at the next epoch.

## Models

| Role | Strategy |
| --- | --- |
| `red_researcher` | Efficient research and extraction model; escalate hard analysis. |
| `red_attacker` | Mid- to high-capability adversarial reasoning; top tier when justified. |
| `blue_researcher` | Mid- to high-capability defensive research. |
| `blue_guard` | Deterministic middleware first; optional model-assisted inspection. |
| `target_agent` | Fixed, version-pinned model. |
| Dreaming (both sides) | Batched synthesis with an efficient model. |
| `independent_verifier` | Deterministic code. No model. |

Model IDs are configuration, not code, and every run manifest records them. Swapping models never changes trust boundaries or scoring rules. Provider adapters are pluggable; no single provider is a required dependency.

## Spending

Every paid call requires operator opt-in, verified model pricing, a reservation before the call, settlement after it, and a hard stop on overrun. An overrun is recorded as an unknown charge at its reserved bound, never silently settled. The default model budget is $0.00.

## Evidence and records

- Run records are hashed; a changed record fails to load.
- Experiment manifests record model IDs, prices, seeds, configuration hashes and source revisions.
- Audit packs export a run's events, verdict and evidence.
- No secrets in code, logs or artifacts.

## Stack

- Python backend: FastAPI and Pydantic, managed with uv, tested with pytest.
- Contracts: JSON Schema for every agent and service message.
- Storage: SQLite and the filesystem first; PostgreSQL and object storage as optional scaling.
- Isolation: containerized execution for the target and its tools.
- Frontend: React, TypeScript, Vite, TanStack Query, Tailwind; Playwright tests.
- CI: GitHub Actions running contract validation, unit, integration and security tests, deterministic replay and frontend tests.

A modular monolith, not microservices.

## Reuse from related projects

| Project | Reuse |
| --- | --- |
| Harpy | Selective monitoring, cost ledgers, sampling, provenance and trace analysis. |
| Tattletale | Evidence validation and origin tracing. |
| Reconcile | Schema-driven proposals, deterministic validation, bounded correction. |
| Release Assurance | Independent verification, fixtures, auditable states, regression tests. |

Reuse is modular and justified by reading the actual implementations, not by copying packages. None of these replaces the independent verifier.

## v0.2 in-memory benchmark boundary

The `benchmark.py` fixture runner now demonstrates both successful synthetic task-policy violations and defenses that block them. Synthetic exports write only to an in-memory list; they do not access external files or networks. A capability-checked `SyntheticGateway` validates argument shapes and quotas, and `verifier.py` compares the event ledger to a terminal state snapshot. Guard-on/off trials preserve the case, seed, defense and gateway configuration. The verifier is in a separate module, **not a separate process**; untrusted runtime isolation and sealed evaluation are still pending. The original v0.1 `engine.py` remains available for compatibility.

## v0.1 code map

| Module | What it is |
| --- | --- |
| `contracts.py` | Frozen `Task`, `Attack`, `Defense`, `Outcome` records. Not yet the JSON Schema catalog. |
| `engine.py` | Synthetic non-model worker, marker-based guard, in-process gateway and deterministic verdict. |
| `store.py` | SQLite run store with SHA-256 integrity hashes. Not a security boundary. |
| `memory.py` | Separate red/blue versioned memory: evidence-linked proposals, holdout refusal, stale-parent check, manual approval. Not Dreaming. |
| `budget.py` | Single-connection reservation and settlement with a fail-closed unknown state. Not safe for concurrent paid calls. |
| `cli.py` | The zero-dollar demo. |

## v0.2 wire contracts and process verifier (development)

The `schemas/attack.v1.json` and `schemas/defense.v1.json` JSON Schema 2020-12 files define narrow, versioned synthetic attack/defense messages. `wire.py` validates the same fields without runtime dependencies, rejects unknown keys, and converts parsed messages to the existing benchmark and frozen guard. Every attack names one of two lower-trust surfaces and a source identifier. In the benchmark, the source identifier travels in the trusted input event; payload text is hashed and never logged verbatim. These contracts are not yet enforced at every input adapter and are not comprehensive agent protocol contracts.

`verifier_process.py` optionally invokes `python -m octoberblue.verifier_worker` over a bounded JSON stdin/stdout protocol. The separate process deterministically scores supplied ledger and state snapshots and returns `indeterminate` on invalid/missing output, timeout, or worker failure. This is **process separation, not secure sandboxing**: the default benchmark still calls the verifier directly, the parent still supplies both evidence sources, and there is no evidence attestation, privilege separation or container isolation yet.

## Cross-framework interchange

The development-only Promptfoo JSON test-case adapter is documented at [COMPATIBILITY.md](COMPATIBILITY.md). Tagged attack fixtures can be imported/exported without model execution. The adapter never assigns trusted verifier outcomes or tool permissions. AgentDojo and broader security testing framework adapters are planned, not yet implemented.

## v0.2 request/effect correlation

The harness now tags each synthetic tool execution or denial with the originating request event ID. The verifier requires a matching one-to-one event chain, consistent tool identity, trusted event origin, valid effect schema and final state equality. Missing, duplicated or orphaned effects are **indeterminate**, never pass. This is input-evidence consistency, not cryptographic proof: the harness still supplies the trace and snapshot and has not been separated from the target process.


## v0.2 opt-in target container

In opt-in Docker mode, the toy worker reads a bounded JSON request containing
only the trusted synthetic task amount and any lower-trust text visible after
guard filtering. It has no tool permission, verifier, database, holdout or
gateway credentials. It may only propose tools as bounded JSON output.

The host validates each proposed tool and enforces the capability gateway.
Real synthetic state changes and the corresponding request/effect event IDs
remain host-controlled. A separate subprocess verifies the host-owned event
record and terminal snapshot. Container or transport failures produce
indeterminate outcomes without an inline retry.

Runtime flags include no networking, no bind mounts, non-root UID, read-only
root filesystem, capability drops, no-new-privileges, seccomp and resource
limits. The fixed toy worker and its protocol are suitable for a bounded
demonstration. They are NOT security-certified isolation for arbitrary
adversarial code. Authenticated evidence, pinned image digests, host/kernel
hardening and stronger sandboxing remain future security work.


## Support-ticket task family (v0.2 synthetic development)

`ticket_benchmark.py` is a distinct synthetic workload with 40 authored cases spanning three lower-trust surfaces. `TicketTaskSpecV1` fixes allowed ticket/account read and ticket resolution tool contracts; a separate evaluation-only `TicketOracle` specifies expected priority/reply and binds the task/case hashes. `TicketGateway` accepts strict argument shapes and permits *sandbox-only* simulated prohibited effects when explicitly enabled by its policy. It records one result per tool request, hashed source provenance, and a terminal ticket-state snapshot. `ticket_verifier_worker` is a separate subprocess that replays those state effects and checks the independent task oracle. Missing or inconsistent evidence fails closed. This is an additional task family, not a replacement for the invoice compatibility demo. The default ticket target is in-process; opt-in Docker now isolates the fixed post-read proposal worker using the same restricted transport as the invoice toy. The gateway and state now live in a trusted witness subprocess. The parent supplies the oracle separately; the verifier authenticates the witness envelope against a private run key and frozen manifest digest before replay. This is ephemeral acquisition authentication, not durable audit-pack identity or protection from a compromised trusted host. See [trusted ticket evidence](TRUSTED_TICKET_EVIDENCE.md). Full details: [TICKET_BENCHMARK.md](TICKET_BENCHMARK.md).


## Optional durable ticket audit evidence

The ticket witness can sign the acquired body with an operator-configured
Ed25519 key, kept off the target interface. A signed pack persists alongside the
HMAC acquisition envelope in SQLite. Export accepts an existing witness
signature; replay authenticates against an independently supplied public key
and manifest digest, then applies the pinned deterministic verifier and authored
oracle in a separate process. Signing is an optional dependency, never enabled by
default. Signer/host honesty is still trusted, and a signature is not an outcome
oracle. See [the wire format and key custody](TICKET_AUDIT_PACKS.md).


## Initial versioned service boundary enforcement

The active ticket path now uses frozen RunRequest/RunRecord, Trace and
GuardDecision v1 contracts. Both ends of witness RPCs validate operation shape
and monotonic sequence; ticket verification and audit replay correlate versioned
service envelopes to the request. New SQLite ticket records validate outcome,
trace and manifest bindings; legacy rows remain explicitly unversioned.
DreamProposal v1 guards the current manual evidence-linked memory proposal API
without implementing Dreaming, regression gates or promotion authority.
[The contract catalog](SERVICE_CONTRACTS.md) records schemas, version compatibility
and remaining batch/live-agent requirements. Authentication and deterministic
state verification remain independent of schema validation.


## Bounded one-shot process boundaries

The fixed Docker proposal transport now reads stdout/stderr under hard byte
budgets before parsing any proposals. Image-ID inspection, invoice/ticket
verification and offline audit replay use the same bounded process primitive.
Verifier workers start through an explicit module whitelist with `python -I -B`,
a private temporary cwd and a minimal environment. Source identity includes this
boundary implementation. No partial overflow response becomes evidence or a
verdict. These controls improve startup/resource isolation, while the verifier
still shares the trusted host user and OS privileges. See
[budgets, cleanup and remaining containment work](PROCESS_BOUNDARIES.md).
