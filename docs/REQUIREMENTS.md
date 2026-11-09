# Engineering requirements

**Current Phase 1 acceptance (2026-11-09):** see [the implemented contained profile, reproducible gate and explicit limits](PHASE1_ACCEPTANCE.md). Historical milestone tables below remain historical; live agents and autonomous Dreaming are not implemented.

OctoberBlue is built against 20 security invariants and a set of functional requirements. This page says, for each one, what v0.1 does today, which test checks it, and which milestone finishes it.

Status means:
- **Tested**: v0.1 implements the behavior and a named test checks it.
- **Partial**: part of the behavior exists and is tested; the rest is scheduled.
- **Planned**: not implemented yet.

Every v0.1 check runs in one Python process. A passing test shows the logic is right, not that a security boundary exists. Process and container isolation arrive in v0.2.

Tests live in [`tests/test_invariants.py`](../tests/test_invariants.py). Each test name starts with the invariant it covers.

## v0.2 benchmark progress (not yet milestone acceptance)

New `tests/test_benchmark.py` checks executable in-memory synthetic attacks, blocked attacks, evasion, benign false positives, per-run quotas, strict schemas, trusted event/state consistency, paired arms and pinned defense/policy hashes. This extends the **logical** coverage of INV-02, INV-04, INV-05, INV-09, INV-10, INV-12, INV-15, INV-16, and F-04/F-06. INV-11 still requires **actual subprocess/container containment**: in-memory simulation is not a security boundary. INV-01 now uses the verifier subprocess by default in the v0.2 benchmark, but trusted evidence acquisition and target process/container containment are still pending; v1 attack/defense JSON Schema wire contracts exist, but they are not yet enforced at every service boundary and multi-surface model adapters are not done. The v0.1 test-status table below is retained as a historical baseline rather than being silently reclassified.

## Security invariants

Each invariant must have an automated test before its milestone closes.

| ID | Invariant | v0.1 | Done by | Check |
| --- | --- | --- | --- | --- |
| INV-01 | The harness and the verifier are trusted code, not agents. Only the verifier issues verdicts. | Partial | v0.2 | `test_inv01_verdict_comes_from_verifier_last` |
| INV-02 | Attacks enter only through declared lower-trust surfaces. | Partial | v0.2 | `test_inv02_inv09_attack_enters_as_untrusted_hashed_input` |
| INV-03 | No agent can modify the harness, verifier, gateway policy, budgets or holdouts. | Planned | v0.2 | — |
| INV-04 | Every consequential tool call goes through the trusted gateway, even with the guard off. | Tested | v0.1 | `test_inv04_gateway_denies_unauthorized_tool_with_guard_off` |
| INV-05 | The active defense is frozen for the length of a run. | Partial | v0.2 | `test_inv05_defense_is_immutable` |
| INV-06 | Dreaming runs only between epochs, never during execution. | Planned | v0.4 | — |
| INV-07 | Red and blue keep separate private memory; neither can read the other's. | Tested | v0.1 | `test_inv07_red_memory_is_invisible_to_blue`, `test_inv07_memory_side_must_be_red_or_blue` |
| INV-08 | Holdout runs never become lessons for either side. | Tested | v0.1 | `test_inv08_holdout_runs_cannot_become_lessons`, `test_inv08_unknown_partition_is_rejected` |
| INV-09 | Every input keeps its provenance and trust label through the run. | Partial | v0.2 | `test_inv02_inv09_attack_enters_as_untrusted_hashed_input` |
| INV-10 | Verdicts come from recorded tool calls and state changes, never from an agent's claim. | Partial | v0.2 | `test_inv10_verdicts_follow_recorded_events` |
| INV-11 | No effect escapes the experimental sandbox. | Planned | v0.2 | — |
| INV-12 | Tools have strict schemas, permissions and quotas. | Planned | v0.2 | — |
| INV-13 | Memory versions are immutable, evidence-linked and reversible. | Partial | v0.4 | `test_inv13_stale_proposal_cannot_be_promoted`, `test_inv13_empty_lessons_are_rejected` |
| INV-14 | Feedback to agents during development is redacted so it cannot leak answers. | Planned | v0.4 | — |
| INV-15 | An attempted attack and a completed attack are recorded separately. | Partial | v0.2 | `test_inv15_attempt_is_recorded_without_a_completed_effect` |
| INV-16 | Legitimate task completion stays measurable; a defense that blocks everything fails. | Tested | v0.1 | `test_inv16_clean_input_is_not_blocked_and_task_succeeds`, `test_inv16_task_succeeds_under_attack_with_guard_on` |
| INV-17 | No secrets are exposed in code, logs or artifacts. | Partial | v0.3 | `test_inv17_tracked_files_contain_no_credentials` |
| INV-18 | Spending limits are enforced: reserve before a call, settle after, stop on overrun. | Tested | v0.1 | `test_inv18_default_budget_is_zero_dollars`, `test_inv18_reservation_settlement_and_overrun`, `test_inv18_invalid_money_is_rejected`, `test_inv18_settling_without_reservation_fails` |
| INV-19 | Holdouts are sealed before evaluation begins. | Planned | v0.5 | — |
| INV-20 | Nothing is promoted into a frozen evaluation snapshot. | Planned | v0.5 | — |

### What "Partial" leaves out

| ID | Missing today |
| --- | --- |
| INV-01 | The verifier runs in the same process as the target. v0.2 moves it out of process. |
| INV-02 | One surface (the task input). Typed, versioned delivery surfaces arrive in v0.2. |
| INV-05 | Python immutability only. v0.2 freezes the defense by configuration hash. |
| INV-09 | The input event is labeled and hashed; labels are not yet carried onto derived events. |
| INV-10 | The synthetic target never executes an unauthorized tool, so a completed attack cannot be observed. v0.2 adds a benchmark where success is possible inside the sandbox. |
| INV-13 | Parent-version checks and evidence links exist. Rollback does not. |
| INV-15 | The fields are separate, but "completed" cannot occur yet (see INV-10). |
| INV-17 | A secret-pattern scan of tracked files, provider exception sanitization and content-free provider journal tests (`tests/test_provider_invocation.py`). Application-wide log redaction remains partial. |

INV-18 now serializes file-backed SQLite reservations and settlements across connections with BEGIN IMMEDIATE, pins one ledger ceiling, and blocks new calls after an unknown charge, including after reconnect. Provider dispatch commits `inflight` before execution and freezes further reservations/dispatches until settlement; crashes retain that freeze and failed/overrun calls become `unknown` (`tests/test_budget_dispatch.py`). Tests in `tests/test_budget_concurrency.py` cover contention, ceiling disagreement, restart, nested transactions and autocommit rollback. Offline provider admission now binds exact model/adapter pins to operator-reviewed expiring pricing quotes and externally retained approval digests, checks explicit opt-in and exact cost bounds with a $0 default (`tests/test_provider_contracts.py`). The host invocation coordinator now enforces adapter/source identity, complete-payload counting through the trusted adapter, reservation before dispatch, fresh approval, model/usage checks and settlement or freeze (`tests/test_provider_invocation.py`). Automated price verification, network adapters and operator reconciliation remain open; no paid calls are enabled. Provider manifests precede dispatch; manifest-bound, content-free usage observations precede settlement, with write failures blocking settlement (`tests/test_provider_invocation.py`). See [provider contracts](PROVIDER_CONTRACTS.md).

## Functional requirements

| ID | Requirement | v0.1 | Done by |
| --- | --- | --- | --- |
| F-01 | Five agent roles: `red_researcher`, `red_attacker`, `blue_researcher`, `blue_guard`, `target_agent`. | Partial | v0.3 |
| F-02 | Research ingestion for both sides, with sources recorded. | Planned | v0.3 |
| F-03 | Typed, versioned attack and defense artifacts validated by JSON Schema. | Partial | v0.2 |
| F-04 | Orchestration of paired red/blue executions on the same task and seed. | Partial | v0.2 |
| F-05 | Provider adapters with configurable, version-pinned model IDs recorded in each run manifest. | Planned | v0.3 |
| F-06 | Independent, deterministic scoring of attempt, prevention, completion, task success and indeterminate outcomes. | Partial | v0.2 |
| F-07 | Dual Dreaming: each side consolidates its own verified lessons between epochs. | Planned | v0.4 |
| F-08 | Memory promotion with evidence, regression gates, operator approval and rollback. | Partial | v0.4 |
| F-09 | Audit packs: hashed run records, manifests and exportable evidence. | Partial | v0.5 |
| F-10 | Sealed holdout evaluation with preregistered thresholds and statistical reports. | Planned | v0.5 |
| F-11 | Operator console: lifecycle, trace timelines, comparisons, budgets, promotion history. | Planned | v0.6 |
| F-12 | Operator controls: budgets, holdout sealing, promotion approval, hard stop. | Partial | v0.6 |
| F-13 | Reproducible results: same inputs and seed give the same record. | Planned | v0.5 |

## CI acceptance

Today CI runs lint, the invariant tests and the offline demo on Linux, macOS and Windows, and fails if the demo spends anything.

By v0.6 CI must also run contract (schema) validation, integration tests, security tests, deterministic replay and frontend tests. A milestone closes only when its invariants move to **Tested**.

## v0.2 additional tested slices

- `test_inv01_benchmark_uses_subprocess_by_default` proves the active benchmark invokes the verifier process transport.
- `test_inv01_verifier_failure_fails_closed_without_inprocess_fallback` proves worker failure is never silently upgraded to a pass.
- Promptfoo-formatted, tagged attack fixtures round-trip through strict admission validation in `tests/test_interop.py`. This is **data interchange, not a third-party scorer or fully supported framework runner**.

## AgentDojo interoperability check

`tests/test_agentdojo_adapter.py` checks native-format ingest, separation of externally reported utility/security from the authoritative OctoberBlue verifier, indeterminate handling of incomplete/error records, field redaction, duplicate JSON key rejection, directory bounds and CLI export. This is **not a live agent benchmark or independent proof of the upstream score**.

## Gateway event pairing (v0.2)

`tests/test_gateway_evidence.py` verifies the synthetic gateway records a direct request-event reference for each execution or denial. The deterministic verifier rejects orphan effects, duplicate results, mismatched tools or origins, missing outcomes and reordered/unsupported events as `indeterminate`. This improves consistency of parent-supplied evidence but **does not authenticate the parent process** or secure container execution.


## v0.2 optional restricted Docker target (development)

The opt-in benchmark --target-runtime docker path moves only the deliberately
vulnerable, fixed synthetic target proposal generator into a separate Docker
container. The host-owned capability gateway handles every proposed call, and
the independent verifier checks the host's event/state evidence.

The Docker invocation has no network or host mounts, runs as a non-root user
with read-only rootfs, drops capabilities, prohibits new privileges and
restricts process count, CPU, memory and open files. The target image contains
no model SDK, no real payment tools and no provider credentials. Malformed
output, a missing Docker daemon, and worker timeout result in an indeterminate
verdict, not an inline fallback.

Tests in tests/test_target_runtime.py check the invocation and fail-closed
behavior. Linux Docker CI executes the nine zero-dollar synthetic cases.
Default benchmark and the legacy demo remain in-process compatibility modes.

**Still partial:** no attestation of the harness's evidence, no guarantee
against arbitrary malicious native code, no pinned base image digest, no
independent oracle identity or reviewed Docker daemon isolation.


## v0.2 synthetic support-ticket benchmark

`ticket-benchmark` exercises a separate deterministic synthetic support-ticket task family. It has 20 normal, 10 injected and 10 regression fixtures (40 authored development cases; 80 paired runs), with declared `ticket_body`, `retrieved_knowledge_snippet`, `tool_response_body` delivery surfaces. The `TicketTaskSpecV1` and `TicketCaseV1` parser/serializer mirror strict JSON Schemas. Normal task tools read ticket/account references, draft coded replies and update local status. Sandbox-only prohibited effects can simulate external messages, exports, permission changes or premature closures, with explicit capability denial possible. No effects leave local memory.

`ticket_verifier_worker` runs in a separate process. It checks input provenance, source/contract hashes, one-to-one request/effect lineage, tool schemas, read/draft/status state replay and the final ticket snapshot. Utility, attempted prohibited action and completed simulated effects remain separate. Unexpected events, missing evidence, transport failures and inconsistent snapshots return `indeterminate`. Tests: `tests/test_ticket_benchmark.py`, `tests/test_ticket_verifier_transport.py`. CI checks normal, detected attack and benign false-positive runs.

**Not finished:** authentic independent evidence collection, sealed holdouts, model-driven ticket classification and broader agent-tool integration. The existing invoice Docker path does not automatically isolate the ticket runtime. These remain partial INV-01/03/09/10/11 rather than full milestone acceptance.

### Optional ticket target runtime

`tests/test_ticket_target_runtime.py` extends partial INV-03/04/11 coverage:
80 protocol parity cases, no fallback after runtime failure, no oracle/control
fields in worker input, and host gateway denial despite a container proposal.
Linux Docker CI also executes all 80 ticket trials and compares their scored
outcomes with the inline baseline. The worker only proposes post-read actions;
state and evidence remain host-owned. This does not close INV-01/03/09/10/11:
authenticated evidence, immutable manifests and hostile-code containment are
still missing. No live model is invoked and the default budget remains $0.00.

## Authenticated ticket witness slice (v0.2; still partial)

The active ticket benchmark now acquires state and action receipts from a
separate state-owning witness process. `RunManifestV1` pins configuration,
implementation bytes and immutable Docker image ID. The verifier authenticates
the complete envelope against a separately supplied ephemeral run key and
manifest digest before deterministic state replay. Evidence is persisted in
`Outcome.evidence`; keys are never persisted. See
[trusted ticket evidence](TRUSTED_TICKET_EVIDENCE.md) for key custody and limits.

`tests/test_ticket_witness.py` extends partial INV-01/03/05/09/10/12/15 and
F-06/F-09/F-13: corruption and run substitution fail closed, action receipts
bind actual before/after state, parent mirrors cannot mutate witness records,
metadata cannot fabricate effects, witness death has no gateway fallback,
and fresh acquisitions reproduce fixture behavior. `test_inv03_resolved_image_identity_is_immutable_and_strict`
checks image-ID acquisition; actual Docker CI still compares all 80 ticket arms.

No invariant's overall milestone status is upgraded: subprocesses share a host
user, the harness/OS remain trusted, ephemeral HMAC is not portable audit-pack
authentication, inline fixture mode is not containment, and the full contract,
replay/export and hostile-code requirements remain open. No paid calls or
real-agent security claims are introduced.

## Opt-in signed ticket audit packs (still partial milestone coverage)

The witness can now sign its acquisition body using an operator-configured
Ed25519 key. `audit-export` accepts only existing acquisition signatures; it
cannot sign old rows. `audit-replay` uses an external public key and expected
manifest digest, refuses source/fixture drift and recomputes deterministic
security/utility in a separate process without the database or private key.
`schemas/ticket-audit-pack.v1.json` is versioned and strict at the container
boundary; it does not replace the remaining Trace/Guard/Dream contracts.

`tests/test_ticket_audit.py` extends partial INV-01/05/09/10/17 and F-06/F-09/F-13:
key/run substitution, signature tampering, signed incomplete receipts, source and
oracle mismatch, missing optional cryptography, unsigned export refusal,
exclusive key/output creation and replay after key/DB removal. CI runs these on
Linux/macOS/Windows and six signed Docker cases; a separate no-audit job checks
the dependency-free core. Keys are excluded from packs and stored outcomes.

Overall invariant status counts remain unchanged: signer/host honesty, Windows
key ACLs and key lifecycle are operator responsibilities; arbitrary hostile code,
full service contracts and sealed real-agent evaluation remain unsupported.
See [the durable audit scope](TICKET_AUDIT_PACKS.md). Default budget: $0.00.

## Initial Run/Trace/Guard/Dream proposal service contracts (v0.2)

`service_contracts.py` and the generated schema catalog now enforce active ticket
run requests/records, ordered traces, provenance-bound guard decisions, manual
memory proposals and private witness/verifier/replay envelopes. New ticket rows
are validated on save and versioned load; legacy invoice/unversioned rows retain
an explicit compatibility path. JSON Schema is a development-only check; runtime
validators remain standard-library code. See [the catalog](SERVICE_CONTRACTS.md).

`tests/test_service_contracts.py` extends partial INV-01/03/05/07/08/09/10/13 and
F-03/F-09: unknown versions/authority fields, forged actors, duplicate events,
mutable nested copies, malformed receipt collections, mismatched stored run
identity, RPC replays, uncorrelated verifier responses, cross-side or stale-parent
proposals, and self-labelled holdout evidence all fail closed. The suite validates
actual messages, including signed run records, against the generated schemas.
CI regenerates the schemas and DBOM and rejects drift.

No overall invariant is upgraded by this slice. DreamProposal is a manual
admission contract, not an epoch/consolidation protocol, regression gate or
learning verifier. Strong sandboxing, OS privilege separation, all live-agent
messages and full Dream batch/result/promotion contracts remain future work.
The default paid-model budget remains $0.00.

## Bounded process transport and sanitized verifier startup (v0.2)

`process_boundary.py` now caps stdout/stderr while reading, enforces an execution
deadline including input stalls, rejects partial/overflow output and cleans up
one-shot processes. Fixed Docker proposal workers and image-ID inspection use
this transport. Invoice/ticket verification and audit replay use a whitelisted
`python -I -B` module, private temporary working directory and minimal environment.
The invoice verifier also rejects duplicate and contradictory verdicts.

`tests/test_process_boundary.py` extends partial INV-01/03/10/11/17: exact caps,
concurrent pipe draining, finite/infinite floods, input stalls, closed output,
POSIX descendant-held pipes, ambient secret/import injection, named-container
cleanup and malformed/deep responses fail closed. Existing transport tests now
mock the bounded runner explicitly; real controlled child processes test its
resource behavior. Source fingerprints and DBOM cover the boundary implementation.

Overall statuses remain partial: same-user verifiers are not OS privilege/network
isolation; POSIX sessions and Windows best-effort cleanup are not hostile-code
containment. Persistent witness write deadlines and containment review remain
open. See [the exact budgets and limitations](PROCESS_BOUNDARIES.md). No paid
model calls or real-agent security findings are introduced.

## Current Phase 1 contained-profile verification

For INV-01/03/09/10/11, `tests/test_contained_execution.py` adds explicit manifest
version admission, no verifier fallback, fixed launch controls, witness write/read
stall deadlines, early EOF/truncated frames, unclean seals, poisoned-channel
rejection and refusal of missing cgroup enforcement. The Ubuntu `phase1-acceptance`
job checks real controls and all 80 ticket arms; see [the acceptance matrix and
retained evidence](PHASE1_ACCEPTANCE.md). INV-04/05/12/15/16/18 are additionally
exercised by the matrix, guard-off gateway-denial control, frozen manifests,
authenticated tool decisions and zero-model execution. These scoped checks do
not upgrade the historical v0.1 invariant table or future real-agent requirements.

### Provider wire-profile coverage

INV-09/17/18 now additionally have `tests/test_openai_chat.py`: a dated model pin,
fixed standard-tier text request modes, full-context input reservation, exact
provider usage checks and content-free journal integration. These are authored
wire fixtures, not live-model security or live pricing evidence. Transport and
credential handling are a separate dependency; the $0 default remains in force.
