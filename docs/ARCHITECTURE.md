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
