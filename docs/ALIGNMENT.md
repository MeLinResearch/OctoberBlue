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
| Deterministic verifier | Partial | Separate subprocess, fail-closed event/state checks; no authenticated evidence source |
| Target runtime | Partial | Optional restrictive Docker toy worker. Default still in-process; no arbitrary-code assurance |
| Cross-boundary contracts | Partial | Attack/defense v1 only, not full Task/Run/Trace/Guard/Dream schemas |
| Framework compatibility | Partial | Promptfoo test-case import/export and AgentDojo native result importer, not complete runner integrations |
| Legitimate task | Planned | Current invoice toy; original synthetic support-ticket task is still required |
| Live agents | Planned | Five role definitions exist; no provider-backed research/construction/orchestration |
| Dual Dreaming | Planned | Memory proposal primitives exist, but no offline batch curator, promotion rollback or evidence gates |
| Sealed holdouts | Planned | No sealed oracle or statistical, preregistered evaluation |
| API and console | Planned | No authenticated FastAPI operator control plane or React dashboard |

## Explicit gaps to resolve without relabeling

1. The invoice benchmark is a synthetic exercise, not the final ticket-handling
   benchmark. Preserve measurable attack success and legitimate task quality.
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
2. Implement the complete synthetic support-ticket workload with TaskSpec,
   input surface adapters, tool effects and independently verifiable state.
3. Add trusted artifact manifests/evidence acquisition, strong sandbox
   boundaries and immutable run snapshots.
4. Only then enable opt-in live model agents, agent-framework runners and
   red/blue Dreaming under enforced cost and holdout restrictions.
