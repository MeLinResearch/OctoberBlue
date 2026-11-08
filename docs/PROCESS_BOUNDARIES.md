# Bounded target I/O and verifier startup (development)

OctoberBlue now bounds subprocess output **while reading**, rather than checking
size only after `capture_output` has accumulated it in memory. This closes a
resource-handling gap in the fixed Docker target and one-shot verifier/replay
transports. It is not an OS sandbox, reviewed hostile-code containment or a
completed Phase 1 acceptance gate.

## Active budgets

| Process | stdout | stderr | Default execution deadline |
| --- | ---: | ---: | ---: |
| Fixed invoice/ticket Docker proposal worker | 16,384 bytes | 4,096 bytes | 12 seconds |
| Local Docker image-ID inspection | 128 bytes | 4,096 bytes | 5 seconds |
| Invoice/ticket verifier | 2,048 bytes | 4,096 bytes | 5 seconds |
| Offline audit replay | 2,048 bytes | 4,096 bytes | 5 seconds |

`process_boundary.run_bounded` drains stdout and stderr concurrently into
independent capped buffers. Each reader consumes at most its budget plus **one
overflow byte**. Overflow immediately causes failure and cleanup; partial output
is never returned as a successful result. A valid JSON prefix followed by a
flood therefore cannot reach the tool gateway or become a passing verdict.
Finite output that crosses the cap just as the child exits is also rejected.

A dedicated writer keeps blocked stdin off the caller's thread, so a child
that stops reading input still reaches the execution deadline. Closing output pipes is not
completion: the process must exit and all I/O producers must finish. Reader,
writer, timeout and malformed-response failures fail closed. Cleanup has a
separate bounded grace period; these are process-operation budgets, not a hard
real-time scheduling guarantee under an unresponsive operating system.

Docker failures, including stdout/stderr overflow and input/output stalls, trigger
removal of the unique named container. Cleanup uses discarded output, so daemon
error text cannot cause another unbounded capture. Image inspection is bounded
before an immutable image ID is accepted. The Docker restriction flags, host-owned
witness gateway, authentication, schemas and state oracle are unchanged.

## Trusted verifier startup

The invoice verifier, ticket verifier and audit replay process now start with:

- an explicitly whitelisted module and the current virtual environment's Python;
- isolated Python mode (`-I`), disabling ambient `PYTHONPATH`, `PYTHONHOME`, user
  site startup and working-directory import injection;
- `-B`, preventing bytecode writes into the trusted source tree;
- a fresh private temporary working directory, also used for temporary files;
- a minimal environment containing only Windows runtime directory variables where
  present, plus the private temporary-directory settings;
- bounded input/output handling and closed unrelated file descriptors.

Ambient provider keys, cloud credentials, proxy settings and other harness
environment values are not forwarded. Explicit HMAC keys/public audit anchors
still travel over their trusted input pipe where required; isolation flags do
not replace authentication. Installed virtual-environment packages and startup
files remain trusted. Replay still refuses a source-fingerprint mismatch, and
the fingerprint now includes the process boundary and additional shared core
modules that execute in the trusted path.

Verifier transport failure remains `indeterminate`, with no inline retry. The
legacy invoice transport also rejects contradictory or duplicate-key verdicts;
its underlying evidence remains logical-only synthetic evidence, not ticket-style
authenticated acquisition. Error reason codes exclude captured output and input.

## Cleanup and explicit limitations

On POSIX, each one-shot subprocess starts in a new session and cleanup kills its
process group, including in-session descendants retaining pipes after their
leader exits. This does not stop malicious code from escaping a session. On
Windows, direct-child and best-effort tree termination use the system process
utility; this is **not** Windows Job Object containment, particularly after a
leader has already exited. Controlled tests do not authorize arbitrary hostile
native code on the host.

The verifier still runs as the harness's host user. A private working directory
and sanitized environment do not deny filesystem access, network syscalls or
privileges. They do not make a compromised host, installed environment, Docker
daemon or witness honest. Persistent witness RPC write deadlines and stronger
OS privilege/network isolation remain separate work. Existing witness RPC read
bounds and schema/sequence checks are retained rather than silently described
as the same one-shot process control.

`tests/test_process_boundary.py` uses controlled Python child fixtures to check
exact byte caps, simultaneous pipe draining, infinite and finite floods, stalled
input, premature output closure, POSIX descendant-held pipes, environment/import
injection, named-container cleanup, recursion limits and legacy verdict rejection.
The Docker integration gate continues to compare all 80 ticket arms and replay
six signed conditions without their original private key or database. These
checks establish transport behavior, not real-model defense quality. The default
model budget stays $0.00 and this slice makes no provider calls.
