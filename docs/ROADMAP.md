# Roadmap

**Current Phase 1 acceptance (2026-11-09):** see [the implemented contained profile, reproducible gate and explicit limits](PHASE1_ACCEPTANCE.md). Historical milestone tables below remain historical; live agents and autonomous Dreaming are not implemented.

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

### Implemented ticket witness dependency (November 8, 2026)

Ticket gateway/state now run in a separate trusted witness subprocess. Its
ordered action receipts and terminal snapshot are authenticated to the verifier
with an ephemeral run key, independently retained manifest digest and strict
v1 manifest. Docker ticket execution pins the resolved local image ID. Tampering,
missing receipts, witness failure and run substitution fail closed; the normal
benchmark path never falls back to parent-generated state. This advances E1,
without closing v0.2. Next: durable audit authentication and export/replay, the
remaining Run/Trace/Guard/Dream contracts, and stronger verifier/target isolation.
See [key custody and limits](TRUSTED_TICKET_EVIDENCE.md).

### Implemented durable ticket audit slice (November 8, 2026)

Optional acquisition-time Ed25519 signatures, existing-signature-only export and
standalone offline replay now preserve the synthetic ticket witness evidence
beyond ephemeral HMAC key disposal. External public-key and manifest anchors are
required; source/fixture drift fails closed. Six signed Docker conditions replay
after private-key and database deletion in CI. See
[signed audit packs](TICKET_AUDIT_PACKS.md). Next dependency: the remaining
versioned Run/Trace/Guard/Dream service contracts and boundary enforcement,
followed by bounded hostile output and stronger verifier/target isolation.
Key rotation/revocation and sealed research audit packs remain future work.

### Implemented initial service-contract catalog (November 8, 2026)

RunRequest/RunRecord, Trace, GuardDecision and DreamProposal v1 now guard the
active ticket and manual-memory paths. Witness RPCs are versioned and sequenced;
verifier/replay envelopes are versioned and correlated. Schema reproducibility
and real-message validation run in CI. This is the initial catalog for existing
services, not an implementation of Dreaming or future live-agent messages.
See [compatibility and boundaries](SERVICE_CONTRACTS.md). Next engineering
dependency: bounded hostile target output and stronger verifier/target execution
isolation, before enabling provider-backed roles and framework execution.

### Implemented process resource/startup slice (November 8, 2026)

Target proposal output and one-shot verifier/replay pipes now have streaming byte
caps and deadlines, including stalled input. Docker failures trigger named
container cleanup. Trusted verifiers use isolated Python startup, private cwd
and a minimal environment; contradictory legacy verdicts fail closed. This
advances trusted execution without claiming OS sandbox acceptance. Next:
persistent witness write deadlines, verifier privilege/network isolation and
reviewed containment, including Windows job/process-tree guarantees. See
[process boundaries](PROCESS_BOUNDARIES.md). Provider execution remains disabled.

### Phase 2 concurrent spend prerequisite (November 9, 2026)

Reservations now acquire a SQLite writer lock before checking committed spend.
One persisted ceiling applies to every connection to the same ledger; conflicting
ceilings fail closed. Unknown charges block new reservations across restarts.
Connections must be idle; lock timeouts and duplicate IDs propagate without
admitting a call. Legacy ledgers pin their ceiling on first upgraded open and
reject commitments above that ceiling. Ceiling changes and unknown-charge
reconciliation require future explicit operator tooling. Separate database files
are separate budgets; this is not a distributed or tamper-resistant ledger.

This focused dependency enables no provider execution and retains the $0 default.
Next: version-pinned provider contracts, verified pricing, explicit opt-in,
redacted request/response artifacts and invocation/settlement lifecycle tests,
before native Inspect AI/AgentDojo execution with independently witnessed effects.
Synthetic acceptance establishes no real-model security result.

### Phase 2 provider-contract prerequisite (November 9, 2026)

Strict model pins, operator-reviewed expiring price quotes and provider-call
requests now have immutable runtime contracts and generated wire schemas.
Offline admission checks externally retained approval digests, explicit opt-in,
quote freshness, identity bindings and exact token-based USD bounds with a $0
default. This does not invoke providers or reserve spend. See
[provider contracts and operator trust](PROVIDER_CONTRACTS.md).

Next: a host-owned invocation lifecycle that counts the actual payload, reserves
before dispatch, settles or freezes unknown charges, redacts artifacts and pins
identities in live manifests, followed by a concrete version-pinned adapter and
native Inspect AI/AgentDojo execution with independently witnessed effects.
Paid calls still require explicit approval; no real-model security result exists.

### Durable provider dispatch prerequisite

The INV-18 ledger now commits `inflight` before dispatch, counts its reservation
and freezes new reservations/dispatches until settlement. Lost callers leave a
restart-safe freeze; failures/overruns retain `unknown` charges. Dispatch is
conservative and serial per ledger. See [ledger design](BUDGET.md).
Next dependency: the host-owned invocation coordinator and fake-adapter tests.

### Host-owned provider invocation coordinator

The coordinator now prepares/counts the complete payload through an approved
host adapter, checks source/model pins, reserves and marks dispatch before one
invocation, rechecks pricing freshness, validates identity/usage, and settles or
freezes the ledger. Fake-adapter tests cover this path, including zero output,
secret-bearing failures and the $0 default; no network adapter is enabled.
Next dependency: durable content-free call manifests and response fingerprints.
