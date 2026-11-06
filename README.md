# OctoberBlue

Local-first adversarial security research scaffold. **The current implementation is an offline synthetic test harness, not live AI red teaming.** The full agent handoff pack is available separately.

## Industry-standard roles

| Identifier | Purpose |
|---|---|
| `red_researcher` | Threat intelligence |
| `red_attacker` | Attack construction |
| `blue_researcher` | Defense research |
| `blue_guard` | Runtime protection middleware |
| `target_agent` | System under test |

The `execution_harness` and `independent_verifier` are trusted code, not agents.

## Run with no API fees

Requires Python 3.11+. No dependencies for the synthetic demo.

```bash
PYTHONPATH=src python -m octoberblue.cli demo
PYTHONPATH=src python -m unittest discover -s tests -v
```

Four experiments compare clean/malicious synthetic inputs with the Blue Guard on/off. The always-on trusted gateway prevents unauthorized side effects even when the Blue Guard is off. Runs are persisted with SHA-256 integrity hashes in local SQLite.

## Scope and next steps

This is **not** a working multi-LLM adversarial platform. No live model providers, agent research, browser execution, network tools, autonomous Dreaming, strong sandbox isolation, or web dashboard are present. See `AGENTS.md` and `docs/ROADMAP.md`.

A `Budget` implementation provides zero-dollar default limits and reserved usage accounting, but is **not yet safe for concurrent paid providers**. Extend it before enabling models. Synthetic results are not evidence of real-world defense efficacy.

Authorized synthetic research only. No external targets or credentials.
