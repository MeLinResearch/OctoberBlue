# Security and responsible use

## Authorized use only

OctoberBlue is for research on systems you own or are explicitly authorized to test.

- Run attacks only against the built-in synthetic target or your own sandboxed agents.
- Never point it at external services, other people's accounts, or real credentials.
- Never put real customer or personal data into tasks, attacks or memory.
- Keep model budgets at $0.00 unless you have opted in, verified prices and set a hard cap.

v0.1's checks run in one Python process. They are not a sandbox. Until container isolation lands in v0.2, don't connect the target to real tools or networks.

## What the project guarantees, and what it doesn't

The [security invariants](docs/REQUIREMENTS.md) list what OctoberBlue enforces, which test checks each one, and which are not built yet. Hashes detect changed records; they are not signatures. Nothing here is a compliance certification.

## Reporting a vulnerability

Report it privately through **Security → Report a vulnerability** on this repository. Please include the commit, the steps to reproduce, and what an attacker could do with it. Don't open a public issue for a vulnerability.

A finding that breaks a security invariant (an agent reaching the verifier, memory crossing sides, holdout data reaching a lesson, spend past a cap) is treated as a release blocker.
