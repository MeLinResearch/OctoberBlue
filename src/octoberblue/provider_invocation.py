"""Host-owned provider dispatch with conservative accounting and private output."""
from __future__ import annotations

import hashlib
import inspect
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .provider_contracts import MAX_TOKENS, ModelPinV1, _integer, admit_call

MAX_PAYLOAD_BYTES = 1_000_000


class ProviderInvocationError(RuntimeError):
    """Expose only a fixed reason code, never adapter exceptions or content."""


@dataclass(frozen=True)
class ProviderReply:
    model_id: str
    model_revision: str
    input_tokens: int
    output_tokens: int
    output: bytes = field(repr=False)


class ProviderAdapter(Protocol):
    pin: ModelPinV1

    def prepare(self, content: bytes, *, output_limit: int) -> bytes: ...

    def count_input_tokens(self, payload: bytes) -> int: ...

    def invoke(self, payload: bytes) -> ProviderReply: ...


def _clock():
    return int(time.time())


def _check_adapter(adapter, pin):
    if adapter.pin != pin:
        raise ValueError("adapter pin mismatch")
    source = inspect.getsourcefile(type(adapter))
    if source is None:
        raise ValueError("adapter implementation source required")
    if hashlib.sha256(Path(source).read_bytes()).hexdigest() != pin.adapter_sha256:
        raise ValueError("adapter implementation mismatch")


def _check_payload(payload):
    if type(payload) is not bytes or len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("invalid provider payload")


def _prepare(adapter, pin, request, content):
    _check_adapter(adapter, pin)
    _check_payload(content)
    payload = adapter.prepare(content, output_limit=request.output_tokens_upper_bound)
    _check_payload(payload)
    count = adapter.count_input_tokens(payload)
    _integer(count, 0, MAX_TOKENS)
    if count > request.input_tokens_upper_bound:
        raise ValueError("complete payload exceeds input bound")
    return payload


def _check_reply(reply, pin, request):
    if type(reply) is not ProviderReply:
        raise ValueError("missing provider usage")
    if (reply.model_id, reply.model_revision) != (pin.model_id, pin.model_revision):
        raise ValueError("provider model mismatch")
    _integer(reply.input_tokens, 0, request.input_tokens_upper_bound)
    _integer(reply.output_tokens, 0, request.output_tokens_upper_bound)
    _check_payload(reply.output)


def _freeze(budget, key):
    try:
        budget.fail_dispatch(key)
    except Exception:
        # A failed settlement can already have made it unknown. If SQLite is
        # unavailable, the previously committed inflight state still freezes it.
        pass


def invoke_provider(budget, request, pin, quote, adapter, content, *,
                    trusted_model_sha256, trusted_price_sha256,
                    paid_calls_approved=False, clock=_clock):
    """Dispatch once through approved host code; never retry an uncertain call."""
    approval = dict(trusted_model_sha256=trusted_model_sha256,
                    trusted_price_sha256=trusted_price_sha256,
                    paid_calls_approved=paid_calls_approved,
                    ceiling_dollars=format(budget.ceiling, "f"))
    try:
        bound = admit_call(request, pin, quote, now=clock(), **approval)
        payload = _prepare(adapter, pin, request, content)
        key = request.run_id + ":" + request.call_id
        budget.reserve(key, bound)
        budget.begin_dispatch(key)
    except Exception:
        raise ProviderInvocationError("provider_preflight_rejected") from None
    try:
        # Recheck freshness after payload preparation and SQLite lock waits.
        admit_call(request, pin, quote, now=clock(), **approval)
        _check_adapter(adapter, pin)
        reply = adapter.invoke(payload)
        _check_reply(reply, pin, request)
        budget.settle_dispatch(key, quote.usage_cost(reply.input_tokens, reply.output_tokens))
    except BaseException:
        _freeze(budget, key)
        raise ProviderInvocationError("provider_call_indeterminate") from None
    return reply
