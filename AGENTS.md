# OctoberBlue — AI coding-agent instructions

**Implemented now:** offline synthetic harness, independent deterministic verdict, SQLite record/archive, guard-on/off comparison, budget reservations and separate red/blue memory proposal interfaces. **Not implemented:** live models, autonomous Dreaming, secure sandbox, external research tools, full-stack UI.

Canonical IDs: `red_researcher`, `red_attacker`, `blue_researcher`, `blue_guard`, `target_agent`. Trusted non-agents: `execution_harness`, `independent_verifier`. No mythological names.

Do not let agent outputs edit verifier, gateway policy, budgets, holdouts or active defense. Attack inputs enter lower-trust synthetic surfaces only. `guard_enabled=false` never disables the trusted gateway.

Separate red and blue private memory. No withheld data in learning. Memory promotion is operator-approved between runs only; do not imply this simple proposal API is autonomous Dreaming.

All paid calls must require operator opt-in, verified model pricing, reservation before invocation, usage settlement, and a hard stop. **Default model budget: $0.00.**

Read `docs/ROADMAP.md`. Run `PYTHONPATH=src python -m unittest discover -s tests -v` before extending. No claims about live model defense quality from fixture tests.
