# Roadmap

Current research-informed positioning and proof gates: [RESEARCH_DIRECTION_2026-11.md](RESEARCH_DIRECTION_2026-11.md). This is an audit of missing capabilities, **not a claim of newly implemented features**.

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

## v0.2 — Real benchmark (in progress)

- **Built:** host-owned synthetic tool gateway with strict capabilities, schemas and quotas. **Partial:** opt-in Docker toy target proposes calls into the trusted gateway with no network or host mounts. **Remaining:** independently authenticated evidence, trusted image pinning and stronger containment for arbitrary hostile programs.
- **Built:** invoice toy and separate support-ticket task family with 20 normal, 10 injected and 10 regression fixtures, three input surfaces, task-specific gateway state and separately verified synthetic effects. **Remaining:** real target adapters and authenticated evidence. An opt-in restricted ticket proposal worker now uses the Docker transport.
- **Built (wire format):** strict v1 attack/defense JSON Schemas, typed parser/serializer, declared surfaces and source IDs, with executable fixtures. **Remaining:** broader contract catalog and full boundary enforcement.
- **Partial:** benchmark verification now defaults to a bounded verifier subprocess, failing closed on worker failure. **Remaining:** authenticated trusted evidence acquisition and real target container isolation.
- **Built:** defense and gateway policy hashes recorded in run metadata.
- **Built:** paired guard-on/off cases with shared case/seed/policy.
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

- **Development interoperability slice:** Promptfoo test-case JSON export/import of explicitly tagged v1 attack artifacts (data-only, no evaluator trust). AgentDojo target/task/trace adapter remains planned.

- **External observations, not verifier evidence:** validated AgentDojo native task-result JSON importer with bounded redacted JSONL, fixture tests and no provider execution. AgentDojo benchmark runner integration remains planned.

- **Gateway evidence check:** each recorded `tool_executed`/`tool_denied` now references exactly one tool request, and the independent subprocess verifier checks completeness before producing a conclusive score. Evidence attestation and target isolation remain pending.

- **Built (ticket task slice):** strict versioned TaskSpec and ticket-case schemas, fixture provenance, paired guard arms, separate verifier-worker process, state replay and a persisted CLI benchmark. No sealed holdout or real-model assessment is claimed.


## Research-alignment priorities (November 8, 2026)

Research update: prioritize **trusted tool-effect witness + authenticated run evidence**, then **Inspect AI / AgentDojo native execution bridge**, followed by matched real-agent baseline comparisons and multi-turn/adaptive + memory-poisoning experiments. These are engineering priorities, **not shipped capabilities**. A generic LangGraph integration is secondary to trusted evidence and reproducible Inspect evaluation. See [the source-backed positioning audit](RESEARCH_DIRECTION_2026-11.md) for acceptance criteria and publication safeguards.
