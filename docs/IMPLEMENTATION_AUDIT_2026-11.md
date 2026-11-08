# Implementation audit — November 8, 2026

Baseline: main `aa3ab13`, assessed against RESEARCH_DIRECTION_2026-11.md.
This is an implementation audit, not an empirical security finding.

| Research dependency | Baseline evidence | Missing acceptance boundary |
| --- | --- | --- |
| E1 trusted execution | Ticket gateway and separate verifier replay; invoice Docker proposal worker | Ticket container, authenticated witness, immutable manifest, independently acquired evidence |
| Versioned contracts | Attack/defense and ticket TaskSpec/case v1 | Run/Trace/Guard/Dream catalog and boundary enforcement |
| E2 useful real-agent security | Authored ticket guard pairs; external result importer | Real agents, native evaluation execution, pinned providers and concurrent spending controls |
| E3 persistent learning | Separate memory proposals with manual approval | Independent consolidation, regression gates, rollback, poisoning and cross-epoch experiments |
| Scientific release | Local hashed SQLite records, deterministic fixture tests | Sealed holdouts, preregistration, confidence intervals and reproducible real-agent audit packs |
| Operator application | CLI | Backend and dashboard |

The first implementation slice adds opt-in Docker execution of the fixed ticket
post-read proposal worker, retaining host gateway authority and separate verifier
scoring. Initial reads are harness-orchestrated; this is not an interactive agent
loop. The worker receives synthetic task attributes, never the evaluation oracle
or case labels. Linux CI compares every case/guard arm against the inline baseline.
Neither parity nor container flags prove real-model security or hostile-code safety.

Next: move action receipts and post-state acquisition into a trusted witness
boundary inaccessible to the target. Bind run identity, image identity, task,
policy and schema versions in an immutable manifest; independently authenticate
acquisition before scoring. Hashing parent-supplied bytes alone is insufficient.
Transport currently checks output size after capture, so malicious output flooding
is also outside the fixed-worker containment claim and requires bounded streaming
before arbitrary target programs are supported.

No research milestone is closed by this slice. The five role IDs, development-only
fixtures, SQLite storage and $0.00 paid-model default remain unchanged.
