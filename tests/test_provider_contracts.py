"""INV-03/09/17/18: offline provider identity, approval and exact cost bounds."""
import json
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal, localcontext
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from octoberblue.provider_contracts import (
    ModelPinV1,
    PriceQuoteV1,
    ProviderCallRequestV1,
    admit_call,
)
from octoberblue.service_contracts import parse_contract_json

NOW = 1_794_225_600


@pytest.fixture
def contracts():
    # Fictional IDs and prices, never a claim about an actual provider's rates.
    pin = ModelPinV1("1.0", "fixture-provider", "fixture-model-2026-11-01", "2026-11-01",
                     "fixture-adapter", "1.2.3", "a" * 64)
    quote = PriceQuoteV1("1.0", pin.sha256, "USD", "all_input_all_output_tokens",
                         "1.25", "5", "https://example.invalid/pricing", "b" * 64,
                         "fixture-operator", NOW - 1, NOW + 60)
    request = ProviderCallRequestV1("1.0", "run-1", "call-1", "target_agent", pin.sha256,
                                   quote.sha256, 1000, 200)
    return request, pin, quote


def admission(contracts, **changes):
    request, pin, quote = contracts
    options = dict(trusted_model_sha256=pin.sha256, trusted_price_sha256=quote.sha256,
                   now=NOW, paid_calls_approved=True, ceiling_dollars="1.00")
    options.update(changes)
    return admit_call(request, pin, quote, **options)


def test_inv18_provider_admission_requires_opt_in_and_keeps_zero_default(contracts):
    request, pin, quote = contracts
    with pytest.raises(ValueError, match="opt-in"):
        admit_call(request, pin, quote, trusted_model_sha256=pin.sha256,
                   trusted_price_sha256=quote.sha256, now=NOW)
    with pytest.raises(ValueError, match="ceiling"):
        admit_call(request, pin, quote, trusted_model_sha256=pin.sha256,
                   trusted_price_sha256=quote.sha256, now=NOW, paid_calls_approved=True)
    assert admission(contracts) == Decimal("0.00225")


@pytest.mark.parametrize("opt_in", [False, None, 1, "true"])
def test_inv18_provider_opt_in_is_strict_boolean(contracts, opt_in):
    with pytest.raises(ValueError, match="opt-in"):
        admission(contracts, paid_calls_approved=opt_in)


@pytest.mark.parametrize("field", ["trusted_model_sha256", "trusted_price_sha256"])
def test_inv03_provider_contracts_cannot_self_approve(contracts, field):
    with pytest.raises(ValueError, match="unapproved"):
        admission(contracts, **{field: "c" * 64})


@pytest.mark.parametrize("index,field", [(0, "model_pin_sha256"),
                                        (0, "price_quote_sha256"),
                                        (2, "model_pin_sha256")])
def test_inv09_provider_request_rejects_substituted_identity_or_price(contracts, index, field):
    changed = list(contracts)
    changed[index] = replace(changed[index], **{field: "d" * 64})
    with pytest.raises(ValueError, match="mismatched"):
        admission(changed)


@pytest.mark.parametrize("offset", [-2, 60, 61])
def test_inv18_provider_pricing_must_be_current(contracts, offset):
    with pytest.raises(ValueError, match="not current"):
        admission(contracts, now=NOW + offset)


def test_inv18_cost_arithmetic_never_rounds_down_with_small_decimal_context(contracts):
    quote = replace(contracts[2], input_dollars_per_million="0.000000000001",
                    output_dollars_per_million="9999999.999999999999")
    with localcontext() as context:
        context.prec = 2
        assert quote.upper_bound(1_000_000_000, 1_000_000_000) == Decimal("10000000000")
        assert quote.upper_bound(1, 1) == Decimal("10")
    assert admission(contracts, ceiling_dollars="0.00225") == Decimal("0.00225")
    with pytest.raises(ValueError, match="ceiling"):
        admission(contracts, ceiling_dollars="0.002249999999")


@pytest.mark.parametrize("bad", ["-1", "NaN", "Infinity", "1e-3", " 1", 0.1, True,
                                 "0.0000000000001", "10000000"])
def test_inv18_provider_rates_and_ceilings_are_bounded_decimal_strings(contracts, bad):
    with pytest.raises(ValueError):
        replace(contracts[2], input_dollars_per_million=bad)
    with pytest.raises(ValueError):
        admission(contracts, ceiling_dollars=bad)


@pytest.mark.parametrize("bad", [True, -1, 1.5, "100", 1_000_000_001])
def test_inv18_provider_token_bounds_reject_invalid_values(contracts, bad):
    with pytest.raises(ValueError):
        replace(contracts[0], input_tokens_upper_bound=bad)
    with pytest.raises(ValueError):
        contracts[2].upper_bound(1, bad)


@pytest.mark.parametrize("field,value", [("model_revision", "latest"),
                                        ("model_revision", "2026-02-30"),
                                        ("model_id", "fixture-latest"),
                                        ("model_id", "fixture-preview"),
                                        ("adapter_version", "1.2"),
                                        ("adapter_sha256", "unversioned")])
def test_inv09_provider_versions_must_be_exact(contracts, field, value):
    with pytest.raises(ValueError):
        replace(contracts[1], **{field: value})


@pytest.mark.parametrize("field,value", [("currency", "EUR"),
                                        ("billing_basis", "tokens_plus_tools"),
                                        ("source_url", "http://example.invalid"),
                                        ("source_url", "https://user:password@example.invalid"),
                                        ("source_url", "https://example.invalid/?key=secret"),
                                        ("source_sha256", "missing"),
                                        ("expires_at", NOW - 1),
                                        ("verified_at", True)])
def test_inv17_inv18_pricing_rejects_unsupported_billing_and_secrets(contracts, field, value):
    with pytest.raises(ValueError):
        replace(contracts[2], **{field: value})


@pytest.mark.parametrize("index,name", [(0, "provider-call-request"), (1, "model-pin"),
                                       (2, "price-quote")])
def test_inv09_provider_contract_round_trip_schema_and_immutable_digest(contracts, index, name):
    contract = contracts[index]
    wire = contract.to_wire()
    assert type(contract).from_wire(parse_contract_json(json.dumps(wire))) == contract
    schema = json.loads((Path(__file__).parents[1] / "schemas" / (name + ".v1.json")).read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(wire)
    digest = contract.sha256
    wire["schema_version"] = "2.0"
    assert contract.sha256 == digest
    with pytest.raises(FrozenInstanceError):
        contract.schema_version = "2.0"
    with pytest.raises(ValueError):
        type(contract).from_wire(wire)
    wire = contract.to_wire() | {"api_key": "untrusted"}
    with pytest.raises(ValueError):
        type(contract).from_wire(wire)
    assert not validator.is_valid(wire)


def test_inv18_zero_rates_still_require_explicit_approval(contracts):
    request, pin, quote = contracts
    quote = replace(quote, input_dollars_per_million="0", output_dollars_per_million="0")
    request = replace(request, price_quote_sha256=quote.sha256)
    assert admission((request, pin, quote), ceiling_dollars="0") == 0
    with pytest.raises(ValueError, match="opt-in"):
        admission((request, pin, quote), paid_calls_approved=False)
