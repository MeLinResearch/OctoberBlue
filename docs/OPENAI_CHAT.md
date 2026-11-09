# Pinned OpenAI text-chat profile

For implementation status see [ROADMAP.md](ROADMAP.md); for invariant status
see [REQUIREMENTS.md](REQUIREMENTS.md). Use the host-owned
[provider approval and dispatch sequence](PROVIDER_CONTRACTS.md).

## Wire and model identity

Bind the profile to `gpt-5.4-mini-2026-03-17`, revision `2026-03-17`, with the
adapter source-file digest returned by `model_pin()`. Never substitute an alias.
The [official model contract](https://developers.openai.com/api/docs/models/gpt-5.4-mini)
specifies a 400,000-token context and 128,000-token maximum output. Re-review
these limits and snapshot availability before approving a pin; mutable web docs
and syntactically valid snapshot names are not independent execution evidence.

Follow the [Chat Completions request/response contract](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).
Use one developer message from trusted host instructions and one user text
message. Treat JSON inside user text as text, never configuration. Encode the
exact snapshot, one choice, `max_completion_tokens`, `stream=false`, `store=false`,
`service_tier=default` and `reasoning_effort=none`. Reject native tools, audio,
images, multiple choices, streaming and alternate tiers/configuration. Remote
retention obligations extend beyond the `store` flag; obtain data-use approval
separately before sending customer content.

## Conservative spend bounds

Count the complete prepared request by reserving the **entire documented context
window** as the input upper bound, including all text and protocol framing. This
is not a measured token count. It trades budget availability for a conservative
bound; it can reject a request whose eventual charge would be much smaller.
Do not replace it with a guessed text-only or JSON-length tokenizer estimate.

Use separately reviewed quotes that bound all billed input and output tokens,
including cached inputs at the full input rate and any reasoning output. Require
standard-tier response metadata and the exact resolved model ID. Validate usage
as nonnegative integers, including coherent totals within context/output caps;
never infer charges from text. Accept only one text assistant choice ending in
`stop` or `length`. Interpret task utility and forbidden tool effects separately.

## Transport and privacy boundary

Supply transport only from trusted host code and invoke through `invoke_provider`;
never call the adapter directly to bypass reservation or approval. Fix the HTTPS
endpoint in transport code, enforce deadlines/byte caps, reject redirects and
perform no automatic retries. Keep credentials out of payloads, public artifacts,
process arguments and error strings. Return raw output only to trusted callers;
export content-free call records. Authored fixtures establish wire behavior,
not provider availability, verified prices or real-model security.


### Fixed-endpoint worker transport

Construct `OpenAIHTTPTransport(budget, "run_id:call_id", api_key)` only in trusted
host code and pass it as the adapter's `send` callable. Supply independently
reviewed model/pricing digests and explicit opt-in to `invoke_provider`; preserve
the $0 default. Use a matching in-flight journal manifest, full-context input
bound and exact payload fingerprint. Persist the single-send latch before worker
launch; never reuse a call ID even after a timeout or through a new sender object.

Deliver the key and body over private stdin, never argv, environment or temp
files. Run isolated Python in a private cwd with only system/temp, proxy and CA
variables. Trust those host proxy/CA settings; retain TLS verification. Fix the
endpoint to `https://api.openai.com/v1/chat/completions`. Reject redirects, retries,
non-JSON/non-200 responses and compressed bodies. Bound worker stdout and body
at 1 MB, stderr at 1 KiB and total worker lifetime (including DNS, TLS, stalled
writes and slow reads) at the configured deadline, at most 120 seconds. Allow
cleanup time after cancellation. Review transport/worker dependencies alongside
the profile; its source-file pin alone is not a dependency closure or OS sandbox.
