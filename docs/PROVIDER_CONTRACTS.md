# Offline provider admission contracts

Phase 2 now has strict, immutable `ModelPinV1`, `PriceQuoteV1` and
`ProviderCallRequestV1` records, plus an offline `admit_call` cost preflight.
There is no network adapter, SDK, credential loading, provider invocation, token
counter or live-agent result. The synthetic benchmark and its manifest versions
remain unchanged. All tests use fictional provider IDs and invented test rates;
they do not establish any actual provider price or real-model security finding.

## Operator-owned approval boundary

A model pin records provider ID, exact model ID, snapshot revision (ISO calendar
date or 64-character lowercase digest), adapter ID, exact three-part adapter
version and adapter implementation SHA-256. Common mutable aliases such as
`latest` and `preview` are rejected. A syntactically valid revision does not prove
that a provider honors immutable versions: the operator must review the mapping
and the adapter implementation before retaining the pin's canonical digest.
No provider or adapter is integrated by defining these generic fields.

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
The module does not fetch sources, verify provider prices automatically, sign
approvals or supply a price catalog. A source hash proves byte consistency, not
honest pricing. Operator approval and source retention remain trusted duties.

## Accounting and future invocation boundary

Rates and ceilings are bounded nonnegative decimal strings, never floats.
Input/output counts are bounded integers (booleans rejected); output capacity
must be positive. Bounds use exact decimal arithmetic with a private precision
context and no rounding down, including sub-cent/sub-microdollar values.

`admit_call` returns only a Decimal upper bound. It defaults to no opt-in and a
$0 ceiling, performs no SQLite reservation and grants no execution capability.
It does not check remaining ledger balance. The future host invocation layer
must validate and count the actual provider payload (including system text,
tools, framing and hidden-token allowances), enforce output limits, check fresh
approval immediately before dispatch, and reserve this bound through `Budget`
**before** calling a provider. Requests must not understate input counts.

That layer must then settle authenticated usage/charges, mark ambiguous failures
unknown and halt on overrun, with no unreserved retry or fallback. It must persist
these exact model/adapter identities, quote and approval references in the live
run manifest, redact request/response artifacts, and preserve the gateway and
independent tool-effect verifier. None of those invocation behaviors is enabled
by this contract PR. Positive opt-in in a local unit test is not authorization
for this session to make paid API calls.

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
`tests/test_provider_contracts.py`; no provider endpoints are contacted.
