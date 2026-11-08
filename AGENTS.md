# OctoberBlue — AI coding-agent instructions

**Implemented now (v0.1):** offline synthetic harness, in-process gateway, deterministic verdict from events, SQLite run records with integrity hashes, guard-on/off comparison, spend reservations with a $0.00 default, separate red/blue memory with evidence-linked proposals and manual promotion.

**v0.2 in progress:** `benchmark.py` / `verifier.py` demonstrate both successful synthetic task-policy violations and blocked ones in a purely in-memory sandbox; the benchmark now uses the separate-process verifier by default and fails closed; container isolation and trusted evidence attestation remain unimplemented.

**Not implemented:** live models, Dreaming, container sandbox, research tools, operator console. The target design is [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); build order is [docs/ROADMAP.md](docs/ROADMAP.md). Don't drop an architecture requirement because v0.1 lacks it.

## Names

Canonical role IDs: `red_researcher`, `red_attacker`, `blue_researcher`, `blue_guard`, `target_agent`. Trusted non-agents: `execution_harness`, `independent_verifier`. Use only these, in code and docs.

## Invariants you must not break

- Agent outputs never edit the verifier, gateway policy, budgets, holdouts or the active defense.
- Attack inputs enter only lower-trust surfaces. `guard_enabled=false` never disables the gateway.
- Red and blue private memory stay separate. No holdout data in learning.
- Memory promotion is operator-approved, between runs only. Don't describe the proposal API as Dreaming.
- Every paid call needs operator opt-in, verified pricing, reservation before invocation, settlement after, and a hard stop. **Default model budget: $0.00.**

The full list, with tests and status, is [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

## Before and after a change

```bash
uv sync --extra dev
uv run ruff check .
uv run pytest -q
```

- New behavior gets a test named after its invariant (`test_inv<NN>_...`), and its status in REQUIREMENTS.md is updated.
- If a file in the DBOM changed: `uv run python scripts/build_dbom.py`.
- If a status or count changed: regenerate the artwork with `docs/assets/build/build_art.py`.

## Documentation rules

- Don't claim live-model defense quality from fixture tests.
- No invented benchmarks, performance numbers or decorative metrics.
- Don't name or credit outside companies in project docs; refer to "provider adapters" and record exact model IDs in run manifests instead.

## External framework boundary

`agentdojo_adapter.py` imports external run reports as data-only observations. Never promote externally reported utility/security scores to trusted `Outcome` verdicts. Keep framework integration details in `docs/COMPATIBILITY.md`. Upstream runner and oracle integration remain separate work.
