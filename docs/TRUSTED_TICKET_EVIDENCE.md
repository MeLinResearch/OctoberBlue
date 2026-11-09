# Trusted ticket evidence acquisition (development v1)

**Current Phase 1 acceptance (2026-11-09):** see [the implemented contained profile, reproducible gate and explicit limits](PHASE1_ACCEPTANCE.md). Historical milestone tables below remain historical; live agents and autonomous Dreaming are not implemented.

This implements the next E1 boundary for **synthetic support-ticket tools**.
It does not establish real-model defense quality, hostile native-code safety,
or hardware attestation. The invoice compatibility workload is unchanged.

## Execution and authority

```mermaid
sequenceDiagram
    participant H as execution_harness
    participant T as target_agent (fixed proposal worker)
    participant W as Trusted ticket witness subprocess
    participant V as independent_verifier subprocess
    H->>H: Freeze manifest; generate nonce and ephemeral run key
    H->>W: Initialize over private stdin (manifest, key, synthetic IDs)
    H->>W: Read tools and provenance metadata
    H->>T: Visible synthetic task input only
    T->>H: Untrusted tool proposals
    H->>W: Proposed tool and arguments
    W->>W: Validate policy; execute; record request/result and before/after state
    H->>W: Finalize
    W->>H: Sealed manifest, event chain, receipts, terminal snapshot
    H->>V: Evidence plus independently retained key and manifest digest
    V->>V: Authenticate; validate chains; replay effects; score task oracle
    V->>H: Deterministic pass/fail/indeterminate
```

The witness owns `TicketGateway`, its quota counter, event recorder and all
synthetic ticket/account state. The harness no longer sends a parent-generated
terminal snapshot to the active verifier path. Its local event mirror cannot
rewrite the witness ledger. Only the witness's tool endpoint emits action or
execution events; its metadata endpoint refuses fabricated tool effects.
Finalization emits the terminal snapshot, seals the response and exits. There
is no mutation endpoint after sealing and no in-process state fallback.

The default target remains a fixed in-process fixture for compatibility. Only
opt-in Docker places the proposal worker behind the target containment boundary.
In Docker mode the harness resolves the selected local image to its immutable
`sha256` image ID and executes that ID with `--pull=never`, preventing a local
tag change between inspection and execution from substituting another image.
An unavailable image identity produces `indeterminate`, never an inline retry.
The image still uses a mutable base tag at build time; runtime identity pinning
does not authenticate the image supplier or certify the build.

## Manifest and receipts

`RunManifestV1` is frozen and strictly parsed; the wire format is
`schemas/run-manifest.v1.json`. It binds run ID, fresh nonce, task/case/oracle,
defense and gateway hashes, source implementation digest, tool/verifier/proposal
protocol references, host Python version, runtime/image identity, guard arm,
seed and the development-only zero-dollar configuration. The implementation
digest covers the actual witness, gateway, target, contract, transport and
verification source files. It identifies bytes, not a signed release identity.
The witness checks its installed implementation against this digest at startup.

Every event extends a SHA-256 chain rooted in the manifest digest. Every tool
call adds an ordered receipt containing the request/result event references,
argument digest, execution/denial decision, actual pre-state and post-state.
Arguments are hashed rather than copied verbatim; this deliberately avoids
retaining arbitrary proposal strings. Therefore a receipt authenticates an
argument digest, not a recoverable full argument transcript. Executed effect
fields and synthetic state remain available for independent replay.

The final envelope authenticates the complete manifest, event chain, receipts
and terminal state with domain-separated HMAC-SHA-256. Missing, duplicated,
reordered, substituted or invented contents fail authentication. Independently
of authentication, the verifier validates chain completeness, receipt lineage,
before/after state transitions, gateway capability/quota constraints, terminal
state equality and the legitimate-task oracle. Security attempt, completed
prohibited effect and task utility remain distinct.

## Key custody and precise claim

The trusted harness generates a fresh 256-bit key per acquisition. It sends it
to the witness and verifier over their private standard-input pipes. It never
passes the key via command arguments, environment, target input, host mounts,
or persisted `Outcome.evidence`. The verifier's expected manifest digest comes
from the harness's frozen manifest, not the candidate evidence envelope.

The target is untrusted. The harness, witness, verifier, OS, Docker daemon and
operator configuration are trusted. A target cannot forge authenticated
receipts without crossing that boundary. A compromised trusted harness can
forge an HMAC, and a compromised witness can misreport state: neither is solved
by cryptography. The subprocesses run under the same host user; they are not
independent host principals or a protection against arbitrary same-user code.
The default inline fixture mode is not hostile-code containment.

Keys are discarded when acquisition closes. The persisted envelope supports
content-integrity inspection and deterministic replay, but **does not provide
portable public-key verification or durable independent source authentication**
after the ephemeral key is gone. Do not treat an exported key supplied alongside
an envelope as proof of origin. Opt-in acquisition-time Ed25519 signatures now support durable audit packs
against an externally supplied operator public key; see
[signed packs and offline replay](TICKET_AUDIT_PACKS.md). HMAC-only historical
records do not gain that guarantee. SQLite insert-only run IDs prevent
normal API overwrites; a database administrator remains trusted.

## Failure behavior and verification

Witness startup/death, invalid or oversized packets, private-pipe timeout,
invalid target output, image-resolution failure, malformed manifests, missing
receipts and authentication failure produce `indeterminate`. No alternate
witness, inline gateway or logical-only verifier is silently retried. The older
`verify_ticket_in_subprocess(events, snapshot, ...)` compatibility API remains
available for logical consistency tests; it makes no source-authentication
claim and is not used as a fallback by `ticket-benchmark`.

`tests/test_ticket_witness.py` exercises acquisition, tampering, key/manifest/run
substitution, incomplete authenticated chains, receipt state replay, witness
crashes, frozen manifests, denial of fabricated effects and deterministic
behavior across fresh acquisitions. Fixed run inputs yield the same event
semantics and state; fresh nonces and HMAC keys intentionally make envelopes
different. This is replay of fixture behavior, not a finished audit-pack replay
command. Existing Linux Docker CI exercises all 80 case/guard arms through the
witness and authenticated verifier, against the inline baseline.

Optional signed audit packs and offline replay now exist for this synthetic
ticket family. Remaining E1 work includes key lifecycle management, the full
future live-agent/Dream batch contracts, persistent witness write deadlines,
verifier OS privilege isolation and containment review. One-shot target and
verifier pipes are now bounded; see [process boundaries](PROCESS_BOUNDARIES.md). Real-agent
execution remains gated behind those boundaries and spending controls.
