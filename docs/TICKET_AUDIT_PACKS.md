# Signed ticket audit packs and offline replay (development v1)

OctoberBlue can now preserve **opt-in acquisition-time Ed25519 signatures**
for the synthetic support-ticket witness. Another engineer can authenticate and
replay the resulting JSON pack with a trusted public key, expected manifest
digest, and the pinned OctoberBlue source/fixture version. Neither the original
private key, ephemeral HMAC key, database, Docker daemon nor a model is needed
for replay. This does not establish real-agent security or an honest host.

## Create and retain an operator identity

Signing is an optional dependency; the default offline core still has no runtime
dependencies or paid-model calls. CI locks and tests the audit dependency on
Linux, macOS and Windows, plus checks the core without it.

```bash
uv sync --locked --extra dev --extra audit
mkdir -p .octoberblue/keys
uv run --extra audit octoberblue audit-keygen \
  --private-key .octoberblue/keys/operator.pem \
  --public-key .octoberblue/keys/operator.pub.pem
```

The command creates both files exclusively and reports the SHA-256 public-key
identifier. It never overwrites an existing key. Private keys are unencrypted
Ed25519 PKCS8 PEM files created with POSIX mode `0600`; broader POSIX permissions
are refused on load. Windows access control is managed by the operator through
ACLs; POSIX mode bits do not establish equivalent protection there. Keep parent
directories operator-controlled. Key files and pack inputs must be regular files;
symlinks, oversized inputs and duplicate JSON properties are refused. A failed
filesystem write can leave a partial output, which is never silently replaced.

`.octoberblue/` is ignored by Git. Keep private keys out of commits, logs,
artifacts and target inputs. Distribute the public key and its fingerprint
through a channel the reviewer trusts independently of the candidate pack.
This slice provides explicit per-command trust anchors, not a key certification,
rotation, revocation, hardware custody or trusted timestamp service.

## Sign during execution, then export

```bash
uv run --extra audit octoberblue ticket-benchmark \
  --target-runtime docker --case support-001 --case support-021 --case support-031 \
  --audit-signing-key .octoberblue/keys/operator.pem \
  --db .octoberblue/signed.sqlite3
```

The key path is operator configuration. The key bytes travel only over the
private initialization pipe to the trusted witness, never to the target, its
image, command arguments or environment. The witness signs its final manifest,
chained events, ordered action receipts and terminal state **before exiting**.
The harness checks this signature against the public key derived from the
configured private key and still uses HMAC-authenticated acquisition and the
separate deterministic verifier. An unavailable or invalid requested signature
fails closed. The private key is never saved in `Outcome` or SQLite.

The command reports `audit_runs`: run IDs, manifest digests and signing key IDs.
Preserve the expected manifest digest independently of the candidate pack; it
binds the particular run, including its nonce, task, guard arm and policy.

```bash
uv run --extra audit octoberblue audit-export \
  --db .octoberblue/signed.sqlite3 --run-id RUN_ID \
  --trusted-public-key .octoberblue/keys/operator.pub.pem \
  --output .octoberblue/run.audit.json
```

Export takes **no private key**. It accepts only a pack already signed by the
witness at acquisition, checks the operator-supplied public key and row identity,
and creates a new output exclusively. Historical HMAC-only records and imported
benchmark observations cannot be retroactively signed through this command.
Database verdict strings are not copied into the pack as authoritative scores.

## Replay independently

Use the same pinned source implementation and fixture catalog as the run. The
implementation digest covers the witness, gateway, verification, audit and
replay source. Replay refuses an implementation mismatch rather than silently
regrading historical evidence with changed logic. It never downloads or executes
source, scripts, containers or tools named by the pack.

```bash
uv run --extra audit octoberblue audit-replay \
  --input .octoberblue/run.audit.json \
  --trusted-public-key .octoberblue/keys/operator.pub.pem \
  --expected-manifest-sha256 EXPECTED_MANIFEST_SHA256
```

The CLI runs replay in a bounded separate process. It verifies the Ed25519
signature, algorithm/version, external key and expected manifest; resolves the
case and oracle from the pinned authored development catalog; validates receipt
and event chains; replays actual effects; and independently scores attempted
prohibited actions, completed effects and legitimate task success. The pack
supplies neither an authoritative oracle nor a trusted verdict. Unknown fixtures,
source drift, missing receipts, corrupt signatures and worker failure yield
`indeterminate`. The JSON report separates `signature_verified` from the verdict:
a valid signature alone is insufficient to establish a safe run.

Exit codes support release gates: `0` = verified pass, `1` = verified task/security
failure, `2` = indeterminate or acquisition/replay input failure. A verified attack
success is valid negative evidence, not an invalid signature. Repeating replay
with the same pack, code, fixtures and trust anchors produces the same report.
Replay does not rerun the target or reconstruct unhashed raw tool arguments.

## Wire format and threat boundary

`schemas/ticket-audit-pack.v1.json` describes the versioned, data-only JSON
container: `schema_version`, `algorithm`, `key_id`, `evidence_body`, `signature`.
There is no embedded public key to trust. The signature covers the entire payload
except the signature field itself, including algorithm and key ID, prefixed by
`octoberblue.ticket.audit-pack.v1` and a zero byte. Canonical bytes use sorted
JSON keys, compact separators, ASCII escaping and rejection of nonfinite numbers.
This is OctoberBlue's defined encoding, not a claim of a general JSON standard.
The live ephemeral HMAC tag and all key material are excluded from the pack.

An attacker without the configured private key cannot replace a safe/unsafe
history, substitute a key or change the run manifest while retaining a valid
signature against the reviewer's external anchors. A compromised trusted signer
**can** fabricate evidence. Signatures identify the configured signer; they do
not prove when signing happened, an honest witness/host, a certified image
supplier, hostile-code containment, or real-model robustness. Inline mode remains
a fixed-fixture compatibility mode. No key is generated or enabled automatically.

Tests cover key substitution, cross-run replay, signed-but-incomplete evidence,
source/oracle drift, key-file handling, unsigned-row export refusal, independent
replay after key/database deletion, and no optional dependency in default mode.
Linux Docker CI repeats normal, injected and benign false-positive guard arms,
then deletes the private key and database before replaying all six packs.
The initial service catalog is now enforced (see [contracts](SERVICE_CONTRACTS.md));
future live-agent/Dream batch contracts, stronger verifier/target isolation, key lifecycle
management, sealed evaluation and real-agent measurements remain incomplete.
