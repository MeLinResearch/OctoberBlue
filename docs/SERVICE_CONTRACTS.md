# Versioned service contracts (development v1)

**Current Phase 1 acceptance (2026-11-09):** see [the implemented contained profile, reproducible gate and explicit limits](PHASE1_ACCEPTANCE.md). Historical milestone tables below remain historical; live agents and autonomous Dreaming are not implemented.

OctoberBlue now enforces a strict initial Task/Run/Trace/Guard/Dream **proposal**
catalog across the active synthetic ticket services. This is boundary validation,
not authentication, a live-agent protocol implementation, or completed Dreaming.
Runtime validation uses the standard library. JSON Schema validation is a locked
development dependency, exercised in CI alongside deterministic replay.

## Catalog and active enforcement

| Contract | Wire schema | Enforced boundary |
| --- | --- | --- |
| Ticket task/case | Existing `ticket-task.v1.json`, `ticket-case.v1.json` | Authored fixture/task admission |
| `RunRequestV1` | `run-request.v1.json` | Witness initialization, manifest and synthetic source IDs |
| `RunRecordV1` | `run-record.v1.json` | New ticket SQLite writes and versioned reads; outcome/trace/manifest identity checks |
| `TraceV1` | `trace.v1.json` | Evidence verification and stored run admission; event types, actors, fields, bounds and ordered IDs |
| `GuardDecisionV1` | `guard-decision.v1.json` | Every new live input records a typed guard decision with source, surface, payload/defense hashes and enabled state |
| `DreamProposalV1` | `dream-proposal.v1.json` | Existing manual memory proposal admission, including `Memory.propose_wire` |
| `ServiceMessageV1` | `service-message.v1.json` | Ticket verifier and audit replay request/response envelopes |
| Private witness RPC | `witness-request.v1.json`, `witness-response.v1.json` | Both ends of the witness pipe; versions, operation shapes and monotonic sequence correlation |

All new schemas use `schema_version="1.0"`, reject unknown root fields and bound
identifiers/collections. Guard and Dream records are frozen typed records;
nested Run/Trace/service objects store canonical immutable JSON bytes and return
fresh copies. Mutation of a returned manifest or event dictionary cannot change
the admitted contract. The schemas validate structural shape; Python validators
also enforce relationships such as ordered event IDs, verdict consistency,
request/response correlation, guard provenance, and run/manifest identity.

Generate and check the schema catalog with:

```bash
uv sync --locked --extra dev
uv run python scripts/build_service_schemas.py
uv run python scripts/build_dbom.py
uv run ruff check .
uv run pytest -q
```

The generator and all schemas are hashed in the DBOM. CI regenerates the catalog
and rejects a diff. Tests compile the schemas with the draft 2020-12 validator
using an in-memory registry, without fetching remote references, and validate
actual produced run/trace/guard/proposal messages against them. Optional signed
runs and audit replay continue to require the `audit` extra.

## Trace and guard boundaries

The existing four-field event layout (`event_id`, `origin`, `kind`, `detail`)
is retained. Trace admission rejects unknown events, extra detail fields,
malformed flags, unsupported surfaces and forged origin roles. Only
`independent_verifier` may produce a verdict event. Only `execution_harness`
may record executed effects; the witness metadata endpoint cannot manufacture
them. The target may propose tools, which still require the witness gateway.
A schema-valid tool request is not authorization to execute it.

New input events include a versioned `guard_decision`. It records allow/filter
behavior without copying raw payloads or changing tool policy. Disabled guards
cannot claim a block; decisions bind source/surface/payload hash to their input.
Authenticated verification also binds guard state and defense hash to the frozen
manifest and checks that filter events agree with the decision. The gateway
remains active in every arm. No guard decision can grant tools, edit budgets,
change policy or issue a task/security verdict.

Trace validation does not establish what actually happened. Authentication,
receipt lineage, before/after state replay, task oracle checks and audit signing
remain separate trusted operations. A consistent fabricated trace still cannot
replace authenticated acquisition without the trusted key.

## Private service envelopes

Witness requests carry a version, sequence, operation and operation-specific
parameters. Initialization separates the public RunRequest from private
credentials; public Run/Trace contracts contain no credentials. The worker
requires the next exact sequence, and the client requires a matching response
sequence. A duplicate, reordered, substituted or unknown-version RPC fails
closed before another tool effect can execute.

Verifier and replay envelopes carry a version, request ID, trusted service ID,
operation, request/response type and payload. Both ends validate them; clients
reject another request's response, a mismatched operation or an agent claiming
the verifier service. These labels are not cryptographic proof of identity:
private pipes, trusted code and authenticated evidence still supply that boundary.
The logical-only verifier library API remains explicitly distinct from acquired
evidence verification and is never an acquisition failure fallback.

## Memory proposals are not Dreaming

`DreamProposalV1` is the initial proposal-only envelope over the existing manual
memory API: side, immutable parent reference, one evidence run, bounded lesson,
development partition and mandatory operator approval. `Memory.propose` uses the
same admission path as `Memory.propose_wire`. The store is consulted for actual
evidence partition and conclusive verdict; a self-declared development label
cannot admit a holdout or indeterminate run. Side and current parent are checked
before insertion. Proposal admission never approves or promotes memory.

There is no epoch runner, autonomous consolidation, regression gate, rollback,
sealed holdout, independently reauthenticated learning oracle or model-generated
learning claim here. The existing trusted local/manual evidence boundary is
unchanged. A full batch Dream request/result, counterexamples and promotion
receipts require future explicitly versioned extensions when those services
exist; they are not silently inferred from this proposal envelope.

## Compatibility and remaining work

- Published attack/defense, task/case, manifest and audit-pack formats remain at
  their existing `1.0` versions. No implicit `1.0.0` migration is introduced.
- New ticket records have an explicit RunRecord version while retaining the
  existing outcome fields. Unversioned SQLite rows and invoice fixtures remain
  on an explicit legacy compatibility path; reading them does not authenticate
  them, upgrade them to a new contract, or make them eligible for signed export.
- Historical input events may omit the new guard subdocument. `TraceV1` permits
  that legacy shape, while the new live witness RPC requires it. Audit replay
  still requires the pinned implementation for each pack; no old pack is silently
  regraded with a changed source fingerprint.
- Previously unversioned private witness/verifier/replay wire protocols are
  intentionally replaced by v1 envelopes. These private subprocesses ship and
  execute together under a pinned implementation. Raw old worker packets are
  rejected; public Python call signatures and legacy fixture workflows remain.

One-shot target/verifier output is now streaming-bounded, and verifier startup
is sanitized; see [process boundaries](PROCESS_BOUNDARIES.md). Overall invariant
statuses remain partial: stronger OS privilege/target isolation, persistent
witness write deadlines, key lifecycle, live role orchestration and sealed
scientific evaluation are still pending. There is no new runtime dependency in
the default core, no paid-model invocation and no real-model security finding.
