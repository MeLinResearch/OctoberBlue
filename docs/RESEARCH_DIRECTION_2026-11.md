# Research positioning and evidence-backed release gates
*Research review: 2026-11-08 · Working engineering direction, not a measured research result.*

## Thesis and audience

**OctoberBlue: evidence-backed release assurance for tool-using AI agents.**

The distinctive engineering question is **not** whether an LLM says it refused a malicious prompt. It is whether a constrained, legitimately useful agent actually performed an unauthorized effect; whether the intended work still finished; and whether the claimed outcome can survive independent evidence and replay checks. The target audience is AI security engineers, evaluation researchers, platform security teams, and owners of regulated agent workflows.

This is a proposed integration/research *wedge*, **not a claim of original invention**. State-based benchmark scoring, task/attack utility, high-fidelity trajectories, and agent tool policies already exist in other work. A credible contribution requires reproducible measurements or a genuinely useful cross-framework verification capability, not merely naming these ingredients.

## Relevant research as of November 8, 2026

| Work / ecosystem | Verified direction | What it implies for OctoberBlue |
| --- | --- | --- |
| [Ignored, Not Refused (2026-10-16)](https://arxiv.org/abs/2610.23254) | Failed attack is not equivalent to recognized/refused attack or successful legitimate work; 21.7% of assessed AgentDojo episodes were safe but task-failing | Keep task utility distinct from unsafe effects; **this is existing research, not our novel claim** |
| [AgentCanary (2026-06)](https://arxiv.org/abs/2606.10484) | Real executable tools, persistent state, outcome safety, security awareness, utility | Our synthetic ticket traces are insufficient as an external security claim; add high-fidelity state and real-agent adapters |
| [AgentDyn (2026-02)](https://arxiv.org/abs/2602.03117) | Dynamic, open-ended tasks expose over-defensive guards | Add useful third-party content and tasks requiring legitimate use of lower-trust information |
| [AgentLAB (ICML 2026)](https://proceedings.mlr.press/v306/jiang26as.html) | Long-horizon adaptive injection, tool chaining, objective drift, memory poisoning | Add multi-turn adaptive attackers with fixed effort budgets and task-state oracles |
| [Self-Propagating Misalignment (2026-10)](https://arxiv.org/abs/2610.04083) and [MemSecBench (2026-07)](https://arxiv.org/abs/2607.27080) | Harm can persist through agent-written memory and future task epochs; safe forgetting/repair must be measured | Treat **dual Dreaming as an attack surface**: test learning provenance, poisoning, rollback and cross-epoch consequences |
| [UK AISI Inspect Evals v0.27.0 (2026-10-30)](https://github.com/UKGovernmentBEIS/inspect_evals/releases/tag/v0.27.0) | AgentDojo is already integrated into Inspect; changes to decoding/scoring can change comparability | **Prioritize an Inspect-compatible adapter** that records exact eval/task versions. Do not rebuild their runner or silently trust imported verdicts |
| [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) and [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10) | Goal hijacking, unsafe tool access, identity, memory, MCP metadata and audit gaps matter | Map tested control boundaries to published risk IDs, with explicit unsupported cases |
| [CrowdStrike agent-planning taxonomy (2026-10-29)](https://www.crowdstrike.com/en-us/blog/new-prompt-injection-techniques-cover-agent-planning-attacks/) | Adversarial activity increasingly targets plans, tool choice and authority reasoning | Include outcome-based tests beyond keyword-triggering prompts |

Avoid implying an AgentDojo *result importer* is an AgentDojo/Inspect *execution adapter*. Likewise, Promptfoo case interchange is not an end-to-end live test integration. LangGraph is a useful target runtime, **not the primary agent-security evaluation standard**.

## Current reality — research-review baseline, no inflated milestones

**Implemented:** offline deterministic invoice and synthetic support-ticket benches, strict tool schema/gateway, request-to-effect lineage, separate-process verifier, 40 authored ticket cases / 80 guard-arm trials, default $0 model spend, experimental Docker isolation for *invoice toy only*, Promptfoo case interchange, AgentDojo result import, CI and docs.

**Not implemented:** a containerized ticket worker, a separate trusted source of effects, independently authenticated/attested evidence, verified live agent tool behavior, native Inspect/AgentDojo runner, adaptive multi-turn adversaries, real dual Dreaming and memory repair, sealed holdouts, preregistration, React operator app, or a peer-reviewed claim.

A file hash proves consistency of the recorded bytes **only**; it does not prove that the source of an event was honest. A separately started verifier process likewise does not prove its inputs originate from trusted execution. Never promote imported model/security scores into OctoberBlue-authoritative findings without independently observable task state.

### Subsequent E1 implementation slice (November 8, 2026)

The fixed ticket proposal worker now supports restricted Docker execution.
Ticket gateway/state also run in a separate trusted witness subprocess, which
seals chained events, action receipts and terminal state with ephemeral HMAC.
The verifier authenticates acquisition against a separately supplied run key
and immutable manifest digest. Docker ticket runs pin the resolved image ID.
This advances E1 but does not close it. Optional acquisition-time Ed25519
signatures and offline ticket audit replay have since been implemented against
external operator keys and manifest anchors. An initial Run/Trace/Guard/Dream
proposal catalog and versioned private service boundaries now exist; future
live-agent/Dream batch contracts, key lifecycle and reviewed hostile-code
containment remain open. Streaming output caps and sanitized verifier startup
now improve the one-shot process boundary, without providing OS privilege
isolation. See [service contracts](SERVICE_CONTRACTS.md) and
[process boundaries](PROCESS_BOUNDARIES.md). See
[signed audit packs](TICKET_AUDIT_PACKS.md). See [the exact trust scope](TRUSTED_TICKET_EVIDENCE.md).

## The three experiments to make publication-worthy

### E1 · Can agent-security evidence be trusted?

Build a **trusted tool-action witness** that records *request, authorization decision, actual execution, and post-action state* outside the target's control. The witness owns an append-only event chain and an independently checkable run manifest (image/tool/policy/schema version, seeds, model/provider versions where relevant). The verifier must reject missing, duplicated, reordered, substituted or invented receipts; a worker-supplied “I refused” statement is never accepted as an effect. Verify outside the target container. Cryptographic hashes/signatures only support claims appropriate to their key/trust placement; they do not make a compromised harness truthful.

**Acceptance:** deliberate evidence corruption gives `indeterminate`, not safe; known sandbox side effects and fully successful legitimate tasks score independently from trusted state. No arbitrary hostile native code runs before containment review.

### E2 · Does a defense protect the agent *without disabling its job*?

Use matched runs: no guard, detector guard, policy gateway, combined defense. Keep the same model/task/payload version/seed and a transparent attack budget. Report a **matrix**, not an ASR-only leaderboard: attempted attacks, completed forbidden effects, legitimate clean utility, utility under attack, false positives, indeterminate runs, runtime and cost per verified successful task. Include helpful third-party content, undetected instruction drift, and adaptive red-team attempts (not just keywords). Compare against documented baselines, with confidence intervals and preregistered evaluation subsets.

**Acceptance:** at least one reproducible real-agent task family using real sandboxed tools; state-based outcome oracle; versioned experimental manifest; explicit missing-data denominators. No public strength claim based only on 40 authored toy cases.

### E3 · Does autonomous red/blue learning create a persistent vulnerability?

Give the red and blue sides isolated memory stores and independent Dreaming cycles between epochs only. Every proposed lesson needs traceable, **verified development-only** evidence, counterexamples, immutable version parent, tests and operator approval. Attack a candidate memory update, test task quality and security after later epochs, then rollback and re-run. Verify no holdout content or one side's private memory crosses the boundary.

**Acceptance:** demonstrated repair, regression gating and reproducible cross-epoch safety/utility measurements, not just a demo of a summarizer remembering attack strings.

## Integration priority (updated)

1. **Inspect AI / AgentDojo**: inspect-native task/scorer or tool-event bridge first, preserving Inspect task version and outcome source; official inspect_evals has AgentDojo already. OctoberBlue verifies only effects it can independently witness; otherwise show external observations.
2. **MCP tools**: instrument an authorized sandbox MCP gateway, including tool schema/metadata change, caller identity, scope, delegation, actual effects and denied attempts.
3. **LangGraph runtime**: optional target adapter supplying trajectories and action receipts; the core verifier stays framework-neutral.
4. **Promptfoo/PyRIT/garak**: retain existing simple Promptfoo data exchange; later ingest attack candidates/traces with labels and provenance but no borrowed authoritative verdicts.

Do **not** spend the next milestone on a broad plugin catalog, a feature-heavy dashboard, new fantasy persona names, or an unmeasured “AI nutrition score.”

## Public release / hiring proof standard

Publish when an unrelated reviewer can:
- Reproduce at least one **real-agent** verified comparison with pinned model and environment versions, and inspect a failed/missing-evidence run.
- See matched **security + utility + false-positive + indeterminate + cost** metrics; explicitly separate synthetic-only results from real agents, and include null/negative results.
- Inspect a short end-to-end demo: untrusted input → target action → trusted gateway receipt → independently checked post-state → pass/fail/indeterminate → regression gate.
- Read a brief threat model and methodology (selection, seeds, repetitions, controls, confidence intervals, known limitations, holdout treatment) and map test cases to OWASP agent risks.
- Find a meaningful technical write-up explaining **what changed in an engineering decision** because of the evidence.

An attention-worthy research hook to test, **not yet assert**, is: *How often does a seemingly successful agent security defense fail to preserve real work or provide enough trusted evidence to substantiate its success rate?* Evidence must establish the answer before a LinkedIn post uses statistics.

## Anti-drift release gates

Preserve the five generic machine role IDs and separate red/blue stores. Stay modular, Python/SQLite-first, $0 paid-model default. Any live provider call requires explicit operator opt-in, verified pricing, reservation and settlement. No unsealed holdout lessons, no external-data reuse without rights assessment, and no framework score quietly upgraded to a state-verified effect. Do not call any milestone “complete” until its source-trust boundary and acceptance tests exist.

## E1 engineering acceptance update (November 9, 2026)

The fixed JSON-only ticket profile now has a separate Docker verifier/replay,
immutable image-bound manifest v2, a deadline-bounded persistent witness, and a
reproducible fail-closed containment/evidence gate. Ubuntu CI passes all 24
container-control probes, 80 determinate paired development trials, immutable
record and deterministic replay checks, gateway denial independent of the guard,
and signature/tamper/offline replay checks. [The scope review and retained CI
evidence](PHASE1_ACCEPTANCE.md) identify exact boundaries and unsupported cases.
This completes the Phase 1 fixed-worker dependency; arbitrary hostile native-code
execution remains unauthorized. E2/E3 and the real-agent publication proof remain
open. No scientific novelty or real-model security finding follows from this gate.
