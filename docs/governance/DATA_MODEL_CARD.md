# Data / model card

Owner: Melinda Emerson · Covers: v0.1 · Reviewed: November 6, 2026

## Summary

OctoberBlue v0.1 is an offline scaffold. It trains no model, calls no model, and uses no real data. Everything below describes the synthetic harness that exists today.

## Data

| Item | Origin | Contents |
| --- | --- | --- |
| Task | Authored in `contracts.py` | One invoice task, `invoice-001`, with an expected total of `125.00`. |
| Clean input | Authored in `cli.py` | A single benign instruction. |
| Injected input | Authored in `cli.py` | A single prompt-injection string asking the target to send customer data outside. No real customer data exists. |
| Defense | Authored in `contracts.py` | Three lower-cased marker phrases. |
| Run records | Produced at runtime | Events, flags and a verdict, stored in local SQLite with a SHA-256 hash of each record. |
| Memory | Produced by the operator | Lessons proposed against development runs and approved by hand. |

No personal data, credentials or external content are used or stored. Raw attack payloads are never copied into the event log; only their SHA-256 hash is recorded.

## Model

| Item | v0.1 |
| --- | --- |
| Target | A deterministic Python worker. It follows the injected instruction whenever the guard doesn't filter it, by design. |
| Guard | Case-insensitive phrase matching. |
| Verifier | Deterministic Python that reads the event log. |
| Language models | None. |

From v0.3, each role's model ID is configuration, version-pinned, and recorded in every run manifest. See [Architecture](../ARCHITECTURE.md#models).

## Evaluation

The [harness check](../../README.md#v01-harness-check) runs four synthetic runs. It confirms the gateway holds with the guard off, the guard doesn't block clean input, and attempts are recorded separately from completed effects. It is not an evaluation of any defense.

## Intended use

Authorized research only: building and testing the harness, the verifier and the trust boundaries before live models are added.

## Not for

- Attacking systems or accounts you don't own.
- Production security decisions.
- Any claim about how a real model or defense performs.

## Known limits

The target is vulnerable by construction, so a completed attack can't occur and attack success is never observed. All checks run in one process. Budget accounting is single-connection. See the [nutrition label](AI_NUTRITION_LABEL.md) and [requirements](../REQUIREMENTS.md).
