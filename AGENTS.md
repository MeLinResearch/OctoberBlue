# OctoberBlue — contributor instructions

- Read [the roadmap](docs/ROADMAP.md) for implementation status and dependency order.
- Read [the requirements](docs/REQUIREMENTS.md) for invariant status and acceptance tests.
- Respect [the fixed-worker containment scope](docs/PHASE1_ACCEPTANCE.md); do not infer arbitrary hostile-code containment from a container profile.

## Preserve the trust boundaries

- Use only these agent role IDs: `red_researcher`, `red_attacker`, `blue_researcher`, `blue_guard`, `target_agent`. Use `execution_harness` and `independent_verifier` for trusted non-agents.
- Never let agent outputs edit the verifier, gateway policy, budgets, holdouts or active defense.
- Admit attacks only through declared lower-trust surfaces. Keep the gateway enabled when `guard_enabled=false`.
- Keep red and blue private memory separate; exclude holdout data from learning. Require operator approval for memory promotion, between runs only. Do not describe manual proposal APIs as autonomous Dreaming.
- Require explicit operator opt-in, verified pricing, reservation before invocation, settlement after invocation and a hard stop for every paid call. Preserve the **$0.00 default model budget**. Do not make paid API calls without explicit approval.
- Derive verdicts from independently acquired tool effects and state, never model claims or imported framework scores. Treat external reports as observations; keep framework design in [COMPATIBILITY.md](docs/COMPATIBILITY.md).
- Keep `TicketTaskSpecV1` and `TicketCaseV1` strict and versioned. Never expose oracle fields to tool proposals. Preserve separate-process deterministic verification; use `octoberblue ticket-benchmark` for development fixture checks.
- Consult [ARCHITECTURE.md](docs/ARCHITECTURE.md) and [ALIGNMENT.md](docs/ALIGNMENT.md) before changing boundaries or declaring milestone acceptance.

## Keep each PR independently reviewable

- Address one dependency per PR. Aim for at most 400 hand-written changed lines, excluding generated files. Split larger steps into stacked PRs that each pass CI.
- Commit generated files separately from hand-written code. Identify generated files in the PR description; retain the generated-file attributes in `.gitattributes`.
- Add no function longer than 60 lines. Do not grow an existing function already over 60 lines; split it in the same PR if it must change. Apply the strictest standard to verifier, witness, evidence, gateway, budget and provider invocation code: small named functions, one check each.
- Include a **Reviewer** section in every PR description: what changed in 2–3 sentences; affected invariant IDs; whether a trust boundary is touched and which one; files to read first in order; exact verification commands; generated files in the diff. Follow [.github/pull_request_template.md](.github/pull_request_template.md).
- Merge only after all required checks pass against the PR head.

## Keep documentation ownership clear

- Keep implementation status only in [ROADMAP.md](docs/ROADMAP.md), and per-invariant status only in [REQUIREMENTS.md](docs/REQUIREMENTS.md).
- Use other docs for design and link to those two status owners. Never restate implementation status elsewhere, append progress to this file, or turn it into a progress log.
- Edit only the docs that own the topic changed by the PR.
- Never claim live-model security from synthetic fixtures. Do not invent benchmarks, performance figures or decorative metrics.
- Name external frameworks, tools and providers only where the project uses or integrates them. Never imply outside contribution, review or endorsement. Record exact model IDs in run manifests.

## Verify changes

```sh
uv sync --locked --extra dev --extra audit
uv run ruff check .
uv run pytest -q
```

- Give new behavior an invariant-named test (`test_inv<NN>_...`); update its owning entry in REQUIREMENTS.md.
- Regenerate affected DBOM entries with `uv run python scripts/build_dbom.py`.
- Regenerate wire schemas with `uv run python scripts/build_service_schemas.py` when their definitions change.
- Regenerate artwork with `docs/assets/build/build_art.py` if its displayed status or counts change; keep generated output in a separate commit.
