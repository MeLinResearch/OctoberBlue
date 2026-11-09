"""Offline provider admission contracts. No transport, credentials or model calls.

Operator-retained digests authorize identity and pricing, never model-supplied
flags. A matching digest establishes approval, not the truth of provider billing.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from datetime import date
from decimal import Decimal, localcontext
from urllib.parse import urlsplit

from .service_contracts import _canonical, _keys

VERSION = "1.0"
IDENTITY = r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}"
SHA = r"[a-f0-9]{64}"
REVISION = r"(?:[a-f0-9]{64}|[0-9]{4}-[0-9]{2}-[0-9]{2})"
ADAPTER_VERSION = r"[0-9]+\.[0-9]+\.[0-9]+"
MONEY = r"(?:0|[1-9][0-9]{0,6})(?:\.[0-9]{1,12})?"
MAX_TOKENS = 1_000_000_000
ROLES = ("red_researcher", "red_attacker", "blue_researcher", "blue_guard", "target_agent")


def _text(value, pattern):
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise ValueError("invalid provider contract field")


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid provider contract integer")


def _money(value):
    _text(value, MONEY)
    return Decimal(value)


class _Contract:
    def to_wire(self):
        return asdict(self)

    @classmethod
    def from_wire(cls, value):
        _keys(value, cls.__dataclass_fields__)
        return cls(**value)

    @property
    def sha256(self):
        return hashlib.sha256(_canonical(self.to_wire())).hexdigest()


@dataclass(frozen=True)
class ModelPinV1(_Contract):
    schema_version: str
    provider_id: str
    model_id: str
    model_revision: str
    adapter_id: str
    adapter_version: str
    adapter_sha256: str

    def __post_init__(self):
        if self.schema_version != VERSION:
            raise ValueError("unsupported provider contract version")
        for value in (self.provider_id, self.model_id, self.adapter_id):
            _text(value, IDENTITY)
        _text(self.model_revision, REVISION)
        if len(self.model_revision) == 10:
            date.fromisoformat(self.model_revision)
        _text(self.adapter_version, ADAPTER_VERSION)
        _text(self.adapter_sha256, SHA)
        if any(alias in re.split(r"[_.:/-]", self.model_id.lower())
               for alias in ("latest", "preview", "stable", "default")):
            raise ValueError("mutable model alias")


@dataclass(frozen=True)
class PriceQuoteV1(_Contract):
    schema_version: str
    model_pin_sha256: str
    currency: str
    billing_basis: str
    input_dollars_per_million: str
    output_dollars_per_million: str
    source_url: str
    source_sha256: str
    reviewed_by: str
    verified_at: int
    expires_at: int

    def __post_init__(self):
        if (self.schema_version != VERSION or self.currency != "USD"
                or self.billing_basis != "all_input_all_output_tokens"):
            raise ValueError("unsupported pricing contract")
        _text(self.model_pin_sha256, SHA)
        _text(self.source_sha256, SHA)
        _text(self.reviewed_by, IDENTITY)
        _money(self.input_dollars_per_million)
        _money(self.output_dollars_per_million)
        _integer(self.verified_at, 1, 253402300799)
        _integer(self.expires_at, self.verified_at + 1, 253402300799)
        if type(self.source_url) is not str or len(self.source_url) > 2048:
            raise ValueError("invalid pricing source")
        url = urlsplit(self.source_url)
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.query or url.fragment or any(c.isspace() for c in self.source_url)):
            raise ValueError("invalid pricing source")

    def upper_bound(self, input_tokens, output_tokens):
        """Exact USD arithmetic; no float conversion or rounding down."""
        _integer(output_tokens, 1, MAX_TOKENS)
        return self.usage_cost(input_tokens, output_tokens)

    def usage_cost(self, input_tokens, output_tokens):
        """Price complete billed usage, including legitimate zero-token output."""
        _integer(input_tokens, 0, MAX_TOKENS)
        _integer(output_tokens, 0, MAX_TOKENS)
        with localcontext() as context:
            context.prec = 64
            total = (Decimal(input_tokens) * _money(self.input_dollars_per_million)
                     + Decimal(output_tokens) * _money(self.output_dollars_per_million))
            return total / Decimal(1_000_000)


@dataclass(frozen=True)
class ProviderCallRequestV1(_Contract):
    schema_version: str
    run_id: str
    call_id: str
    role: str
    model_pin_sha256: str
    price_quote_sha256: str
    input_tokens_upper_bound: int
    output_tokens_upper_bound: int

    def __post_init__(self):
        if self.schema_version != VERSION or self.role not in ROLES:
            raise ValueError("invalid provider request version or role")
        for value in (self.run_id, self.call_id):
            _text(value, r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}")
        for value in (self.model_pin_sha256, self.price_quote_sha256):
            _text(value, SHA)
        _integer(self.input_tokens_upper_bound, 0, MAX_TOKENS)
        _integer(self.output_tokens_upper_bound, 1, MAX_TOKENS)


def admit_call(request, pin, quote, *, trusted_model_sha256, trusted_price_sha256,
               now, paid_calls_approved=False, ceiling_dollars="0.00"):
    """Return a cost bound after checking host-owned approvals; never invoke/reserve.

    Even a zero-priced request requires opt-in. The future invocation layer must
    atomically reserve this bound against Budget immediately before dispatch.
    """
    if type(paid_calls_approved) is not bool or not paid_calls_approved:
        raise ValueError("provider execution requires explicit operator opt-in")
    if (type(request) is not ProviderCallRequestV1 or type(pin) is not ModelPinV1
            or type(quote) is not PriceQuoteV1):
        raise ValueError("typed provider contracts required")
    _text(trusted_model_sha256, SHA)
    _text(trusted_price_sha256, SHA)
    _integer(now, 1, 253402300799)
    if (pin.sha256 != trusted_model_sha256 or quote.sha256 != trusted_price_sha256
            or request.model_pin_sha256 != pin.sha256
            or request.price_quote_sha256 != quote.sha256
            or quote.model_pin_sha256 != pin.sha256):
        raise ValueError("unapproved or mismatched provider identity/pricing")
    if not quote.verified_at <= now < quote.expires_at:
        raise ValueError("pricing approval is not current")
    bound = quote.upper_bound(request.input_tokens_upper_bound, request.output_tokens_upper_bound)
    if bound > _money(ceiling_dollars):
        raise ValueError("provider cost bound exceeds ceiling")
    return bound
