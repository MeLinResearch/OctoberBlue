# Engineering requirements

OctoberBlue is built against 20 security invariants and a set of functional requirements. This page says, for each one, what v0.1 does today, which test checks it, and which milestone finishes it.

Status means:
- **Tested**: v0.1 implements the behavior and a named test checks it.
- **Partial**: part of the behavior exists and is tested; the rest is scheduled.
- **Planned**: not implemented yet.

Every v0.1 check runs in one Python process. A passing test shows the logic is right, not that a security boundary exists. Process and container isolation arrive in v0.2.

Tests live in [`tests/test_invariants.py`](../tests/test_invariants.py). Each test name starts with the invariant it covers.

## v0.2 benchmark progress (not yet milestone acceptance)

New `tests/test_benchmark.py` checks executable in-memory synthetic attacks, blocked attacks, evasion, benign false positives, per-run quotas, strict schemas, trusted event/state consistency, paired arms and pinned defense/policy hashes. This extends the **logical** coverage of INV-02, INV-04, INV-05, INV-09, INV-10, INV-12, INV-15, INV-16, and F-04/F-06. INV-11 still requires **actual subprocess/container containment**: in-memory simulation is not a security boundary. INV-01 still requires verifier process isolation; formal JSON Schema wire contracts and multi-surface model adapters are not done. The v0.1 test-status table below is retained as a historical baseline rather than being silently reclassified.

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
| INV-17 | A secret-pattern scan of tracked files. Log and artifact redaction arrives with live providers in v0.3. |

INV-18 is single-connection SQLite accounting. It is not safe for concurrent paid calls; v0.3 hardens it before any provider is enabled.

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
