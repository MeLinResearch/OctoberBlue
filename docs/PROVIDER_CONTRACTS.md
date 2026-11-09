# Provider approval and dispatch design

Use immutable `ModelPinV1`, `PriceQuoteV1` and `ProviderCallRequestV1` records
for operator-owned provider admission. For implementation status see
[ROADMAP.md](ROADMAP.md); for invariant coverage see [REQUIREMENTS.md](REQUIREMENTS.md).
Never infer actual provider pricing or real-model security from fixture tests.

## Operator-owned approval boundary

A model pin records provider ID, exact model ID, snapshot revision (ISO calendar
date or 64-character lowercase digest), adapter ID, exact three-part adapter
version and adapter implementation SHA-256. Common mutable aliases such as
`latest` and `preview` are rejected. A syntactically valid revision does not prove
that a provider honors immutable versions: the operator must review the mapping
and the adapter implementation before retaining the pin's canonical digest.

A pricing quote binds the model pin digest, USD input/output rates per million
tokens, HTTPS source URL and retained source SHA-256, reviewer ID, review time
and exclusive expiry time. It supports only `all_input_all_output_tokens`: the
operator must confirm the rates conservatively bound **all** billed input and
output tokens, including cached inputs and reasoning outputs. Tools, images,
audio, request fees, taxes, minimum charges, discounts, batch service and other
billing schemes are unsupported; do not use this contract if token rates cannot
bound the entire charge. Zero prices do not bypass explicit approval.

The host supplies **independently retained** model and quote digests, a trusted
clock value, explicit boolean opt-in and a ceiling to `admit_call`. Never obtain
those approvals or the clock from model output, a lower-trust request or fixture.
The preflight rejects substitutions, future/expired reviews and a cost bound
above the ceiling. A quote cannot self-approve through its reviewer field.
Price changes require a newly reviewed quote and newly retained approval digest.
Keep source retrieval and price verification outside this admission API. A source
hash proves byte consistency, not honest pricing. Operator approval and source
retention are trusted duties.

## Accounting and invocation boundary

Rates and ceilings are bounded nonnegative decimal strings, never floats.
Input/output counts are bounded integers (booleans rejected); output capacity
must be positive. Bounds use exact decimal arithmetic with a private precision
context and no rounding down, including sub-cent/sub-microdollar values.

`admit_call` is a cost preflight, not an execution capability. Require explicit
boolean opt-in and preserve its $0 default. Use `invoke_provider` to enforce the
host dispatch sequence; never treat the preflight ceiling as remaining balance.

Select the adapter in trusted host code. Bind its pin to the approved model and
hash the adapter class's source file against `adapter_sha256`. Review inherited
code and dependencies separately; a single source-file hash is not a sandbox or
a dependency closure. Adapter preparation must be offline, bind the exact model,
encode the output token limit and count the **complete serialized payload**,
including system text, tools, framing and hidden-token allowances. The host checks
this conservative count against the request's bound before reserving spend.

Commit the reservation and durable dispatch marker before calling the adapter.
Recheck price freshness after preparation and lock waits; use immutable payload
bytes and dispatch only once. Adapters must bound network streams/deadlines,
propagate missing usage as failure and never perform hidden retries or fallbacks.
Read usage and resolved model identity from provider metadata, never output text.
Only matching identity and bounded, well-typed usage can be settled; zero output
is legitimate usage. Freeze ambiguous failures and overruns according to
[the ledger state machine](BUDGET.md). Do not retry a frozen call automatically.

Keep raw output private and out of representations, logs and exported artifacts;
expose only fixed failure reason codes. Persist exact model/adapter and pricing
identities in content-free call records, preserve the gateway and independent
tool-effect verifier, and never treat a provider response as a trusted verdict.
Positive opt-in in unit tests is not authorization for paid calls in a session.

## Wire and reproducibility

Each record has schema version `1.0`, rejects unknown or missing fields, returns
fresh wire dictionaries and hashes canonical JSON. Decode JSON using
`parse_contract_json` before `from_wire` to reject duplicate keys and nonfinite
JSON values. The generated `model-pin.v1.json`, `price-quote.v1.json` and
`provider-call-request.v1.json` describe structural shape; Python admission also
checks calendar dates, URLs, aliases, expiry, approval and cross-record bindings.
JSON Schema validation alone never authorizes a request.

Regenerate with `uv run python scripts/build_service_schemas.py` and
`uv run python scripts/build_dbom.py`. Invariant tests are in
`tests/test_provider_contracts.py` and `tests/test_provider_invocation.py`.
