# Data bill of materials

Owner: Melinda Emerson · Version: `0.1.0` · Reviewed: November 6, 2026

Every data asset OctoberBlue v0.1 uses or produces. [dbom.json](dbom.json) is the machine-readable copy with a SHA-256 hash for each source file; regenerate it with `uv run python scripts/build_dbom.py`. This is a project DBOM, not a certified software bill of materials.

| ID | Asset and origin | Use | Rights, integrity, limits |
| --- | --- | --- | --- |
| D01 | Synthetic invoice task, authored in `contracts.py` | Task input; task success means the expected total is reported once | MIT, authored. One task only. |
| D02 | Clean and injected inputs, authored in `cli.py` | Demo workload | MIT, authored. The injected input mentions customer data; none exists. Payloads are hashed in the event log, never copied into it. |
| D03 | Guard marker phrases, authored in `contracts.py` | Marker-based guard | Frozen dataclass for the run. A placeholder, not a real defense. |
| D04 | Run records, produced at runtime | Events, attempted and completed flags, task success, verdict | Local SQLite; SHA-256 per record, checked on every read. Hashes detect changes; they are not signatures. |
| D05 | Memory versions, proposed against runs and approved by an operator | Separate red and blue lessons | Each version links its parent and its evidence run. Holdout and indeterminate runs are refused. |
| D06 | Spend ledger, produced at runtime | Reservations, settlements, unknown charges | $0.00 default. Single-connection accounting; not for concurrent paid calls. |
| D07 | Source tree and `uv.lock` | Experiment identity | Hashed in `dbom.json`. Dependency versions are locked; their licenses are not certified here. |

## Data flow

D01 to D03 feed the harness. The harness and verifier produce D04. An operator turns development runs from D04 into D05. D06 gates any future paid call. D07 identifies the code that produced everything else.

No personal data, credentials, external datasets, model weights or model outputs are used. Live model calls, research ingestion and sealed holdouts arrive in later milestones and will each add assets here with their origin, rights and hashes.

[AI label](AI_NUTRITION_LABEL.md) · [Data / model card](DATA_MODEL_CARD.md) · [Requirements](../REQUIREMENTS.md)

## Ticket witness evidence (v0.2 development)

D09 records the authored witness implementation and strict manifest schema.
Runtime evidence contains hashes, synthetic before/after state and an ephemeral
HMAC tag. Keys and raw proposal arguments are excluded from persisted evidence.
No new external dataset, real customer data or model output is introduced.
The envelope is not a portable source-authentication proof after key disposal.
