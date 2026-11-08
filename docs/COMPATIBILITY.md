# Benchmark interoperability (development)

OctoberBlue is a provider-neutral, evidence-driven **agent** evaluation harness.
A generic chat jailbreak scanner is not a replacement for task-state verification.

## Available: Promptfoo test-case JSON (data-only)

The `octoberblue promptfoo-export` command emits a Promptfoo-compatible JSON
test-case array using the documented `vars` and `metadata` fields. A
`{{input}}` prompt template can consume the input. The inverse
`promptfoo-import` command validates *only* OctoberBlue-tagged tests and
recovers versioned attack artifacts. There is no automatic provider
configuration, live request, or imported success claim.

```bash
uv run octoberblue promptfoo-export --attack examples/attack.v1.json --output /tmp/octoberblue-tests.json
uv run octoberblue promptfoo-import --input /tmp/octoberblue-tests.json --output /tmp/octoberblue-attacks.json
```

A test case's `surface` tag is metadata. Promptfoo does not necessarily
inject it into a trusted tool-result boundary: users must provide their own
authorized application adapter that routes `input` to the right lower-trust
surface. No assertions or external verdicts are imported or synthesized.
Running the test externally may invoke paid models or disclose payloads;
OctoberBlue's zero-dollar guarantee covers only its own local conversion.

## Planned integrations (not implemented)

| Integration | Why it matters | Boundary |
| --- | --- | --- |
| AgentDojo | Task-based prompt-injection benchmark with environment/tool effects | Adapt suite/task/attack plus oracle evidence; pin upstream API |
| PyRIT | Attack execution, scoring and multi-turn experiments | Ingest trace and scorer outputs as observations, not trusted verdicts |
| garak | General LLM probe and finding ecosystem | Import probe evidence, retain detection/attack provenance |
| LangGraph | Runtime for building agents rather than a security scoring standard | Optional target execution adapter; no implicit authority |
| OpenTelemetry | Vendor-neutral traces | Emit correlated spans and tool transitions; redact sensitive data |

OctoberBlue's authoritative verdict must always come from its own
trusted evidence and task-state oracle. No imported model score can
silently become a verified completed effect.

The full synthetic support-ticket benchmark, isolated worker, encrypted
evidence capture, and multi-tool integration are still pending.
