# Implementation roadmap

## Delivered: offline scaffold

- Synthetic task, lower-trust attack injection, defensive marker filtering.
- Always-on trusted gateway; unauthorized action attempt vs completed effect measured separately.
- Independent deterministic verifier, SQLite run history with integrity hashes.
- Cost reservation/settlement with fail-closed unknown-charge state; default $0.00.
- Separate red and blue memory stores with development-only proposed lessons and manual promotion.
- CLI and unit tests; no cloud costs or API calls.

## Next: real research-grade harness (not yet implemented)

1. Enforced subprocess/container isolation and a capability-checked tool gateway.
2. Actual model-backed target, attacker and research adapters with strict token and dollar bounds.
3. Provenance-rich attack/defense artifacts and exact version freezes.
4. Strong holdout segregation and independent task/outcome oracles.
5. Per-side asynchronous Dreaming with evidence validation and regression-gated promotion.
6. Comparison statistics, research dashboards and deployment only when needed.

**Caution:** the current synthetic worker is intentionally vulnerable by construction and therefore gives no evidence about real LLM robustness. SQLite cost checks are single-connection scaffolding, not a multi-process payment control.
