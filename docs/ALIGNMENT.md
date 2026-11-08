# OctoberBlue architecture alignment — November 2026

Basis: the November 2 implementation specification, later Dreaming decisions,
and the actual code and test coverage. This is a traceability record, not a
compliance certificate or a claim of real-model defense quality.

## Approved changes — not accidental drift

- Keep exactly five generic role IDs: red_researcher, red_attacker,
  blue_researcher, blue_guard and target_agent. Their early creative names were
  intentionally removed for a professional public engineering project.
- execution_harness and independent_verifier remain non-agent trusted code.
- Separate red/blue memory, offline dual Dreaming, evidence-linked lessons,
  human approval and rollback are essential future behavior.
- Start with local SQLite and filesystem, adding storage services only when
  needed. The default paid-model budget stays at $0.00.
- Security framework adapters (Promptfoo, AgentDojo and later others) do not
  gain authority over the OctoberBlue verifier.

## Implemented versus planned

| Area | State | Evidence / remaining requirement |
| --- | --- | --- |
| Synthetic benchmark | Built (toy) | Nine offline cases, paired guard arms, synthetic successes, denials, false positives |
| Host gateway | Built (toy) | Strict tool argument checks, quotas, request-effect correlation |
| Deterministic verifier | Partial | Separate subprocess; ticket witness acquisition is authenticated with an ephemeral key; optional durable ticket signatures/replay now exist; bounded pipes and sanitized isolated-Python startup are implemented; OS privilege separation and key lifecycle remain open |
| Target runtime | Partial | Optional restrictive Docker toy worker. Default still in-process; no arbitrary-code assurance |
| Cross-boundary contracts | Partial | Attack/defense, ticket task/case, manifest/audit pack and initial Run/Trace/Guard/Dream proposal v1 are enforced; live-agent and full Dream batch/promotion contracts remain pending |
| Framework compatibility | Partial | Promptfoo test-case import/export and AgentDojo native result importer, not complete runner integrations |
| Legitimate task | Built (toy) | 40 authored synthetic ticket fixtures, four normal tools, simulated forbidden effects and independent state-based scoring; no live model |
| Live agents | Planned | Five role definitions exist; no provider-backed research/construction/orchestration |
| Dual Dreaming | Planned | Memory proposal primitives exist, but no offline batch curator, promotion rollback or evidence gates |
| Sealed holdouts | Planned | No sealed oracle or statistical, preregistered evaluation |
| API and console | Planned | No authenticated FastAPI operator control plane or React dashboard |

## Explicit gaps to resolve without relabeling

1. Invoice and support-ticket benchmarks are both synthetic exercises. The ticket
   workload and optional fixed Docker ticket proposal worker now exist, but
   model-driven classification and full research audit packs remain unimplemented.
   Optional signed ticket packs now support offline verification against external
   operator keys; they do not authenticate a compromised trusted host.
   Ticket evidence now comes from a separate state-owning witness with ephemeral
   authentication; see [the precise trust scope](TRUSTED_TICKET_EVIDENCE.md).
2. Development contract schema_version is "1.0"; the older full-stack draft
   proposed "1.0.0". Make an explicit version-migration decision rather than
   silently breaking existing files.
3. Container isolation of a fixed proposal worker does not verify arbitrary
   target code. The host-supplied state and trace are not cryptographically
   attested by an independent evidence service.
4. v0.1 diagrams and nutrition labels are historical. Never treat their
   older status counts as current measured security effectiveness.
5. AgentDojo result import is not suite execution. Promptfoo interchange does
   not automatically expose tool-result injection in a real target runtime.

## Acceptance order

1. Linux CI must build and run the toy Docker target, reproducing all nine
   zero-dollar outcomes; cross-platform unit CI must remain green.
2. Completed toy task-family slice: support-ticket TaskSpec/cases, three declared
   lower-trust surfaces, gateway tool effects and deterministic verifier replay.
3. Add trusted artifact manifests/evidence acquisition, strong sandbox
   boundaries and immutable run snapshots.
4. Only then enable opt-in live model agents, agent-framework runners and
   red/blue Dreaming under enforced cost and holdout restrictions.


## Research review (November 8, 2026)

The project remains aligned to the original red/blue security-research architecture, but the current toy benchmarks are not competitive security-efficacy evidence. Existing research already covers security-versus-utility tradeoffs, long-horizon injections and executable state scoring; our potential contribution must be the **reproducible, independent evidence chain** and the release gate that refuses unsupported success claims, including poisoned memory promotions. Prioritize Inspect AI / AgentDojo runtime compatibility over merely importing reports. See [current research positioning and acceptance gates](RESEARCH_DIRECTION_2026-11.md). Do not treat this design change as completed implementation.
