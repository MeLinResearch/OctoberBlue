# Roadmap

Each milestone ends with an acceptance gate: every invariant it owns in [REQUIREMENTS.md](REQUIREMENTS.md) is **Tested**, and CI is green on Linux, macOS and Windows. Presentation and documentation are updated in every milestone, not saved for the end.

## v0.1 — Offline scaffold (done)

- Synthetic task with lower-trust attack injection and a marker-based guard.
- Always-on in-process gateway; attempted actions and completed effects recorded separately.
- Deterministic verdict from recorded events.
- SQLite run history with SHA-256 integrity hashes.
- Spend reservation and settlement with a fail-closed unknown state; default $0.00.
- Separate red and blue memory with evidence-linked proposals and manual promotion.
- CLI demo, invariant tests, CI, README artwork and governance documents.

The synthetic worker is vulnerable by construction and calls no model. v0.1 results say nothing about real robustness.

## v0.2 — Real benchmark (next)

- Container isolation for the target and its tools; capability-checked gateway with tool schemas, permissions and quotas.
- A synthetic benchmark where attacks **can** succeed inside the sandbox, so completed effects are observable.
- Typed, versioned attack and defense artifacts validated by JSON Schema; multiple delivery surfaces.
- Verifier moved out of the target's process.
- Defense frozen by configuration hash for each run.
- Paired red/blue executions on the same task and seed.
- Gate: INV-01, INV-02, INV-03, INV-05, INV-09 to INV-12, INV-15; INV-04 re-tested against the new gateway.

## v0.3 — Live models

- Provider adapters with configurable, version-pinned model IDs recorded in each run manifest.
- Live research ingestion and attack generation.
- Spend controls safe for concurrent paid calls; verified pricing required.
- Secret redaction in logs and artifacts.
- Gate: INV-17, INV-18 under concurrency.

## v0.4 — Dreaming

- Per-side offline Dreaming between epochs only.
- Evidence-backed lessons, regression gates, operator approval, rollback.
- Redacted development feedback.
- Gate: INV-06, INV-13, INV-14.

## v0.5 — Sealed evaluation

- Holdouts sealed before evaluation; frozen evaluation snapshots.
- Deterministic replay and reproducible records.
- Preregistered thresholds and statistical reports.
- Audit pack export.
- Gate: INV-19, INV-20.

## v0.6 — Operator console

- Dashboard: red/blue lifecycle, trace timelines, comparisons, budgets, Dreaming promotion history.
- Operator controls and audit exports.
- Frontend tests; deployment readiness.
