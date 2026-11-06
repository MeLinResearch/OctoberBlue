# Contributing

## Setup

```bash
uv sync --extra dev
uv run ruff check .
uv run pytest -q
uv run octoberblue demo
```

All four must pass before a pull request. CI runs the same on Linux, macOS and Windows.

## Rules that don't bend

Read [AGENTS.md](AGENTS.md) and [ARCHITECTURE.md](docs/ARCHITECTURE.md) first. In short:

- Agent outputs never edit the verifier, gateway policy, budgets, holdouts or the active defense.
- `guard_enabled=false` never disables the gateway.
- Red and blue memory stay separate. Holdout runs never become lessons.
- Any paid call needs operator opt-in, verified pricing, a reservation before the call and settlement after. The default budget stays $0.00.
- No credentials, personal data or external targets in code, tests or fixtures.

## Adding or changing behavior

1. Find the invariant or functional requirement in [REQUIREMENTS.md](docs/REQUIREMENTS.md). If there isn't one, add it.
2. Write the test first. Name it `test_inv<NN>_...` for an invariant.
3. Update its status in REQUIREMENTS.md. A requirement is **Tested** only when a test checks it.
4. If a source file listed in [the DBOM](docs/governance/DBOM.md) changed, run `uv run python scripts/build_dbom.py`.
5. If counts or statuses changed, regenerate the artwork (see `docs/assets/build/build_art.py`) so the nutrition label stays true.

## Claims

Don't claim a result the evidence doesn't support. Synthetic runs are labeled synthetic. No benchmark numbers, performance claims or decorative metrics without a recorded run behind them.
