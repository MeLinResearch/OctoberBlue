# Spend ledger design

For implementation status see [ROADMAP.md](ROADMAP.md); for INV-18 coverage
see [REQUIREMENTS.md](REQUIREMENTS.md).

Use one SQLite ledger for callers sharing a cap. Reserve a conservative upper
bound before execution. Acquire the writer lock before reading commitments or
changing state. A stored ceiling applies to every connection; separate files
represent separate budgets.

The provider dispatch sequence is `reserved → inflight → settled`. Commit
`inflight` before invoking the adapter. Include it in committed spend and refuse
new reservations or dispatches while any charge is `inflight` or `unknown`.
This deliberately serializes dispatch per ledger while allowing concurrent
reservations before dispatch. A lost process leaves durable `inflight` state;
never automatically retry it or release its bound on restart.

On ambiguous failure, use `inflight → unknown`. On settlement above the reserved
bound, retain the reservation as `unknown` and stop. Only settle a matching
expected state once; never clear an unknown charge through ordinary settlement.
Require operator reconciliation with trusted billing evidence to recover a frozen
ledger. Keep the default ceiling at $0.00; a positive cap alone is not paid-call
approval. See [provider approval design](PROVIDER_CONTRACTS.md).
