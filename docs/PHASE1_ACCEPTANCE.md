# Phase 1: trusted execution acceptance

The implemented `docker-json-v1` profile is a local-first execution and evidence
boundary for **fixed, authored JSON-only support-ticket workers**. It is not a
real-model security result. The default offline mode remains dependency-light
and spends $0.00; Docker and audit signing are explicit opt-ins.

## Reproduce the acceptance gate

On a Linux Docker host with cgroup v2 resource enforcement:

```sh
uv sync --locked --extra dev --extra audit
docker build -f docker/target.Dockerfile -t octoberblue-target:v0.2 .
docker build -f docker/trusted.Dockerfile -t octoberblue-trusted:v0.2 .
uv run --extra audit python -m octoberblue.phase1 --output phase1-audit
```

The output directory must be new. Exit 0 means every reported check passed;
exit 2 means rejection, including unavailable infrastructure or indeterminate
evidence. CI runs this gate on Ubuntu and retains the public audit directory.
The report binds both immutable image IDs and the verifier implementation hash.
The public key and signed acquisition packs accompany the result rows and
manifest anchors. The disposable test private key is never exported.

For an individual run:

```sh
uv run octoberblue ticket-benchmark --target-runtime docker --verifier-runtime docker
```

The one-shot Docker workers have no network, mounts or Docker socket, run as
UID/GID 65534, have a read-only root filesystem, drop all capabilities, enable
seccomp and no-new-privileges, and have bounded memory, CPU, process count,
file descriptors, private noexec temporary storage, streams and deadlines.
The target contains no gateway, verifier, oracle, evidence key or signing key.
The verifier receives only bounded JSON over stdin, including its private
per-run authentication material; it receives no host filesystem access.

## Acceptance matrix

| Dependency | Implementation and evidence |
| --- | --- |
| Containerized ticket target | Minimal fixed worker image, immutable local image ID, strict proposal parser; Docker parity CI retains the invoice and ticket checks. |
| Trusted tool-action witness | Separate state-owning process; sequenced private RPC; chained action receipts and snapshots; ephemeral HMAC authentication; acquisition-time Ed25519 signatures with explicit operator identity. |
| Independent fail-closed verifier | Dedicated Docker image, immutable identity in manifest v2, installed-source fingerprint check; authenticated state replay; no transport fallback; unknown on malformed, incomplete, mismatched or unavailable evidence. |
| Versioned contracts | Strict TaskSpec/case/tools, manifest v1/v2, RunRequest/RunRecord/Trace/GuardDecision/DreamProposal, correlated verifier and sequenced witness service envelopes. Schemas are regenerated and checked in CI. |
| Replay and immutable identity | SQLite INSERT rejects duplicate run IDs; manifests freeze task/case/oracle/defense/gateway/source/seed/images; signatures and externally retained anchors authenticate portable packs. |
| Containment review | Fixed diagnostics use the same launch builders as production workers. Both images must demonstrate non-root, read-only root, no-new-privileges, zero effective capabilities, noexec tmp, blocked outbound access, hidden host sentinel/socket, absent ambient canary, and actual cgroup memory/process/CPU limits. Missing cgroups reject the gate. |
| Functional acceptance | All 40 development cases in both guard arms are determinate and match the offline reference; gateway denial still works with guard off; repeated fixed-seed runs preserve events, decisions and state. Fresh nonces intentionally change cryptographic chains. |
| Evidence regression | Tampered events, receipts, snapshots and manifests become indeterminate; signed offline replay succeeds after deleting the test key file and source SQLite database. Unit tests additionally exercise deleted/duplicated/reordered/substituted receipts, run substitution and malformed transports. |
| Zero default spend | No model invocation exists in this profile; all acceptance runs explicitly report zero calls and a $0.00 ceiling. |

DreamProposal is the implemented manual, side-separated proposal contract.
Autonomous Dream batches and live-agent message contracts belong to Phases 2/3;
this gate does not claim they execute today. Imported benchmark scores remain
observations outside the trusted verdict boundary.

## Containment review and trust assumptions

**Trusted:** operator-controlled source, image build, host/kernel/Docker daemon,
execution harness, witness, independent verifier, signing identity and externally
retained public key/manifest anchors. The witness retains its credentials on
private pipes and owns the only authoritative simulated tool state. The harness
cannot manufacture tool-effect receipts through the witness record API.

**Untrusted:** fixture content on declared lower-trust surfaces, proposal JSON,
and exported packs until authenticated. Proposals cannot select Python modules,
execute shell commands, mount files, supply tool implementations, change gateway
policy, modify verifier code, or update an active defense. Guard-off operation
still uses the gateway. No customer data or paid model credentials enter targets.

This review authorizes the fixed JSON-only task profile. It does **not** authorize
arbitrary attacker-supplied Python/native code, real external tool effects, an
untrusted host/Docker daemon, kernel exploitation, or agent-written executable
plugins. Containers share the host kernel. The local witness subprocess is
trusted code under the host user, not a separate OS security principal. Windows
and macOS retain offline functional CI; the strict contained acceptance profile
is tested on Linux cgroup v2. Long-lived key rotation/revocation, encrypted
custody and external timestamp/notary services remain future operational work;
a signature cannot prove an honest host or establish signing time independently.

A local rootless daemon without cgroups is intentionally rejected. Passing unit
checks on that host must never be presented as passing contained acceptance.

## Next dependency

Phase 2 starts with version-pinned real-agent/provider execution and concurrent
spend reservations, then native Inspect AI/AgentDojo execution that supplies
independently acquired tool effects. Existing fixture metrics provide engineering
controls only. No sealed holdout, adaptive real attacker, autonomous Dual Dreaming,
empirical security finding, backend or dashboard is claimed here.
