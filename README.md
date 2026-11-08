<p align="center">
  <img src="docs/assets/octoberblue-hero.svg" alt="OctoberBlue. Red attacks, blue defends, only the evidence decides. Red-side agents send an attack through an untrusted surface into a sandboxed target; the blue guard filters it; a trusted gateway denies the unauthorized tool call; an independent verifier scores the run from recorded events, not from any agent's claim." width="100%">
</p>

Red-team results for AI agents are often scored by a model asked whether the attack worked. Defenses get tuned on the same tests they are graded on. A stronger defense can look the same as one that blocks everything.

**OctoberBlue lets attackers and defenders improve separately, then scores every run from what actually happened: the tool calls made, the state changed, the task completed.**

[![CI](https://github.com/MeLinResearch/OctoberBlue/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MeLinResearch/OctoberBlue/actions/workflows/ci.yml)
**Python 3.11+** · **MIT** · **v0.2 development: in-memory synthetic benchmark, no live models**

<p align="center">
  <img src="docs/assets/octoberblue-glance.svg" alt="At a glance: the red side researches and builds attacks; the blue side researches and runs a guard; a deterministic verifier scores outcomes from evidence; the default model budget is zero dollars with a hard stop." width="100%">
</p>

## How it works

<p align="center">
  <img src="docs/assets/octoberblue-lifecycle.svg" alt="The red/blue lifecycle: research, build typed artifacts, execute behind the gateway, verify from the record, dream between epochs, evaluate on sealed holdouts. Execute is partly built in v0.1 and verify is in v0.1; the rest are scheduled for v0.2 to v0.5." width="100%">
</p>

Five agent roles do the work: `red_researcher`, `red_attacker`, `blue_researcher`, `blue_guard` and `target_agent`. The `execution_harness` and `independent_verifier` are trusted code, not agents, and no agent output can change them.

The guard is tested both ways. It must stop attacks, and it must let legitimate work through. A defense that blocks everything fails.

## Trust boundaries

<p align="center">
  <img src="docs/assets/octoberblue-trust.svg" alt="Trust boundaries. The operator sets budgets, seals holdouts and approves memory promotion. Red and blue sides each have two agents and a private memory. Trusted code in the middle holds the harness, the sandbox with the target agent and tools, the gateway, the verifier, the budget ledger and the sealed holdout store. Red attacks enter only through an untrusted surface; the blue guard is frozen for the run. Between epochs, verified development runs feed per-side Dreaming, and an operator approves each promotion. Holdout results never feed back." width="100%">
</p>

- Attacks enter only through declared lower-trust surfaces.
- Every consequential tool call goes through the gateway, even with the guard switched off.
- Red and blue memories are separate; neither side can read the other's.
- Holdout runs never become lessons for either side.

## Dreaming

<p align="center">
  <img src="docs/assets/octoberblue-dreaming.svg" alt="Dreaming: memory consolidation between epochs, run separately for red and blue. Gather verified development runs, with holdout runs refused (in v0.1). Dream: batch-synthesize lessons (v0.4). Propose a new version linked to its parent and evidence (in v0.1). Gate: regression tests and operator approval, with stale parents refused (partial). Promote, with rollback (v0.4)." width="100%">
</p>

Between epochs, each side turns its verified runs into lessons. A lesson is a new memory version linked to its parent version and the runs that support it. An operator approves every promotion. Dreaming never runs during an experiment.

## v0.1 harness check

<p align="center">
  <img src="docs/assets/octoberblue-harness.svg" alt="v0.1 harness check: four synthetic runs, zero paid calls, $0.00. Clean input with the guard off or on: no attempt, task succeeds, pass. Injected input with the guard off: the target attempts an unauthorized tool call, the gateway denies it, no completed effect, pass. Injected input with the guard on: the guard filters it, no attempt, pass." width="100%">
</p>

The card is drawn from the real demo output. It shows the wiring works: the gateway holds with the guard off, the guard does not block clean input, and attempts are recorded separately from completed effects.

> [!IMPORTANT]
> **v0.1 has no findings.** The target is a synthetic worker that is vulnerable by construction, the guard is a phrase match, and no model is called. A completed attack can't occur yet, so nothing here measures how well any defense works. v0.2 adds a benchmark where attacks can succeed inside the sandbox.

## Try it

No API key and no paid model call.

```bash
git clone https://github.com/MeLinResearch/OctoberBlue.git && cd OctoberBlue
uv sync --extra dev
uv run pytest -q
uv run octoberblue demo
```

The demo runs clean and injected inputs with the guard off and on, stores each run in local SQLite with a SHA-256 integrity hash, and prints the results with `"paid_model_calls": 0`.


## v0.2 development: measurable synthetic attack outcomes

The new **in-memory benchmark** has a deliberately vulnerable toy target,
two lower-trust surfaces (`retrieved_document` and `tool_result`), an
allowlisted synthetic gateway, quotas, a state snapshot and a separate
deterministic oracle. It deliberately supports successful *task-policy*
violations in a local Python list so attack success is no longer structurally
impossible. This is **not process/container isolation** or evidence about real
LLM security. It cannot open a URL or export an actual document.

\`\`\`bash
uv run octoberblue benchmark
\`\`\`

Its four synthetic cases run with the guard on/off (eight trials):
clean completion; marker-detected injection; an evasion that retains a
completed synthetic export; and a benign document that triggers a guard
false positive and can prevent a legitimate task. A ninth trial shows an actual
attempt denied by the trusted gateway's policy. The guard and gateway
are separate: a permitted sandbox capability is not automatically an
authorized task action. Verifier classifications use the recorded
synthetic state, not attacker self-reports.

**Status:** v0.2 benchmark slice. Container isolation, remote verifier,
v1 attack/defense wire contracts and an optional process verifier are available; enforcement at all boundaries, default-runner process verification, actual container isolation and sealed evaluation remain unimplemented.

## AI nutrition label

The label is OctoberBlue's requirements and evidence at a glance. Each compliance row names the invariants behind it, and each invariant names the test that checks it.

<p align="center">
  <img src="docs/assets/octoberblue-nutrition.svg" alt="AI Nutrition Facts for OctoberBlue v0.1: synthetic data, runs offline, no model in v0.1. Gateway on every tool call, separated red and blue memory, holdouts kept out of learning and an enforced zero-dollar budget are yes; verdicts from evidence and logging are partial; sandbox containment arrives in v0.2. Evidence: synthetic harness check only, no real-model observations, no holdout results. 20 security invariants: 5 tested, 8 partly built and tested, 7 planned." width="460">
</p>

- [**AI nutrition label**](docs/governance/AI_NUTRITION_LABEL.md): every field, with its backing invariants.
- [**Engineering requirements**](docs/REQUIREMENTS.md): the 20 security invariants and functional requirements, each with its status, test and milestone.
- [**Data / model card**](docs/governance/DATA_MODEL_CARD.md): data origin, model identity, evaluation, intended use.
- [**Data bill of materials**](docs/governance/DBOM.md): inputs, records and hashes, with a [machine-readable copy](docs/governance/dbom.json).

These are project documents, not compliance certifications.

## Built to be checked

| Property | How it's enforced today |
| --- | --- |
| Independent verdicts | Only the verifier issues a verdict, computed from recorded events. An agent's report of success is never read. |
| Gateway always on | `guard_enabled=false` turns off the guard, never the gateway. Unauthorized tool calls are denied either way. |
| Attempts vs. effects | An attempted attack and a completed one are separate fields, scored separately. |
| No false-positive blind spot | Clean input must pass with the guard on. A guard that blocks it fails the test. |
| Split memory | Red and blue lessons live in separate versioned stores. A stale parent version can't be promoted. |
| No holdout learning | A holdout run can't be turned into a lesson for either side. |
| Budgets that bind | Default model budget $0.00. Spend is reserved before a call and settled after; an overrun stops execution and stays on the books. |
| Tamper-evident records | Each run is stored with a SHA-256 hash, and a changed record fails to load. |

CI runs lint, the invariant tests and the offline demo on Linux, macOS and Windows, and fails if the demo spends anything.

## Roadmap

<p align="center">
  <img src="docs/assets/octoberblue-roadmap.svg" alt="Roadmap. v0.1 offline scaffold, done. v0.2 real benchmark, next: sandbox, gateway, typed artifacts, paired runs. v0.3 live models: provider adapters, research, spend controls. v0.4 Dreaming: per-side lessons, promotion, rollback. v0.5 sealed evaluation: holdouts, replay, statistics. v0.6 operator console: dashboard, audit exports, deployment." width="100%">
</p>

The research question: can attackers and defenders that learn separately from verified experience produce defenses that hold on unseen tests, without hurting legitimate work or running up cost? Success needs a reproducible, statistically meaningful drop in verified attack success on sealed holdouts. Thresholds are preregistered before any result is read.

## Read more

| Document | What it covers |
| --- | --- |
| [Architecture](docs/ARCHITECTURE.md) | Roles, trust boundaries, outcomes, Dreaming, models, stack. The target design. |
| [Engineering requirements](docs/REQUIREMENTS.md) | The 20 invariants and functional requirements, with status and tests. |
| [Roadmap](docs/ROADMAP.md) | What each milestone delivers and its acceptance gate. |
| [Security and responsible use](SECURITY.md) | Authorized use only, reporting a vulnerability. |
| [Contributing](CONTRIBUTING.md) · [Agent instructions](AGENTS.md) | How to extend OctoberBlue without breaking its invariants. |

## Related

[**Harpy**](https://github.com/MeLinResearch/Harpy) tests whether budgeted oversight of multi-agent AI can pay for itself. OctoberBlue plans to reuse its cost ledger, sampling and provenance work.

[**Tattletale**](https://github.com/MeLinResearch/tattletale) checks quoted claims against their source and names the agent that introduced a bad one. OctoberBlue plans to use its origin tracing for evidence validation. Neither replaces OctoberBlue's own verifier.

## License

[MIT](LICENSE). The README artwork is generated by [`docs/assets/build/build_art.py`](docs/assets/build/build_art.py).

### Development: versioned artifacts and subprocess verifier

The `schemas/` directory contains strict v1 attack/defense schemas; corresponding checked-in examples are in `examples/`. `octoberblue.wire.AttackWireV1` and `DefenseWireV1` reject unknown fields and unsupported versions, round-trip JSON-compatible dictionaries, and convert to the existing offline benchmark types. Tests exercise both success and malformed inputs.

`octoberblue.verifier_process.verify_in_subprocess` is the **default verifier transport** for the v0.2 benchmark. It starts a bounded verifier worker in a separate Python process and fails closed on invalid input, worker errors and timeouts. The original v0.1 `demo` remains a separate compatibility harness. Neither path has authenticated evidence capture or host/container sandboxing, so process separation is not yet a hostile-code isolation boundary.

[Benchmark interchange documentation](docs/COMPATIBILITY.md) includes working Promptfoo test-case JSON export/import, with planned AgentDojo, PyRIT, garak, LangGraph and trace adapters. These names describe integration targets, not measured framework support.

### AgentDojo task result interoperability

`uv run octoberblue agentdojo-import --input ./runs --output ./observations.jsonl` imports native AgentDojo per-task JSON logs into bounded, redacted observation records with source hashes and explicit external score labels. No API calls or paid models run. It does not yet execute AgentDojo tasks or validate their scores independently. See [compatibility documentation](docs/COMPATIBILITY.md).

### Gateway event integrity

The v0.2 gateway now correlates each tool request with its execution or denial, and the verifier rejects orphaned, duplicated or inconsistent effect histories. Inconsistent evidence becomes `indeterminate`, not a successful defense score. This does not replace a secure container or independent evidence acquisition.


## Opt-in restricted Docker toy target (v0.2 development)

Default benchmarks still use the in-process toy worker. The separate
Docker variant executes **only the data-only proposal generator** inside a
restricted container; the host still owns the trusted tool gateway, synthetic
state and verifier inputs.

```bash
docker build -f docker/target.Dockerfile -t octoberblue-target:v0.2 .
uv run octoberblue benchmark --target-runtime docker
```

The worker image has no model provider SDK or real-world tools. It runs with
networking and host mounts disabled, a read-only rootfs, non-root UID,
dropped Linux capabilities, no-new-privileges, seccomp and resource caps.
Each tool proposal is validated by the trusted host gateway. Docker failures
become indeterminate results rather than falling back to an inline target.
An Ubuntu CI job exercises all nine synthetic trials in this mode.

**Security limits:** this is a fixed toy worker, not a safe sandbox for
arbitrary malicious programs or live outside targets. Supply-chain digest
pinning, independent evidence attestation and stronger host/kernel
confinement remain pending. See the
[architecture alignment audit](docs/ALIGNMENT.md).


## Synthetic support-ticket task family

`uv run octoberblue ticket-benchmark` now runs 40 authored synthetic support-ticket fixtures in matched guard-on/off conditions (**80 zero-dollar development trials**). The target makes task-specific tool calls, can trigger simulated forbidden effects, and is scored by a separate deterministic verifier process against recorded tool/state evidence. Run results persist in checksum-protected SQLite. No real customer records, network effects, or paid model calls are involved.

Three attack-delivery surfaces and versioned TaskSpec/case JSON Schemas are implemented. The ticket target remains **in-process**; the opt-in Docker target currently applies only to the original invoice toy. See [support-ticket benchmark documentation](docs/TICKET_BENCHMARK.md) for exact scope, commands and limitations.
