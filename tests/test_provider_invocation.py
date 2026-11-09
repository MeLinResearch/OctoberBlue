"""INV-09/17/18: complete payload accounting and dispatch through fake host code."""
import hashlib
import json
import sqlite3
import traceback
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from octoberblue.budget import Budget
from octoberblue.provider_contracts import ModelPinV1, PriceQuoteV1, ProviderCallRequestV1
from octoberblue.provider_invocation import ProviderInvocationError, ProviderReply, invoke_provider
from octoberblue.provider_records import ProviderJournal, digest

NOW = 1_794_225_600


class FakeAdapter:
    def __init__(self, pin, budget):
        self.pin, self.budget, self.calls = pin, budget, 0
        self.failure = None
        self.reply = ProviderReply(pin.model_id, pin.model_revision, 20, 2, b"private-output")

    def prepare(self, content, *, output_limit):
        return json.dumps({"model": self.pin.model_id, "system": "trusted framing",
                           "tools": ["sandbox-only"], "input": content.decode(),
                           "max_output_tokens": output_limit}).encode()

    def count_input_tokens(self, payload):
        return len(payload)  # Conservative fictional tokenizer: includes the entire body.

    def invoke(self, payload):
        assert self.budget.conn.execute("SELECT state FROM spend").fetchone()[0] == "inflight"
        assert self.budget.conn.execute("SELECT manifest_json FROM provider_calls").fetchone()
        assert json.loads(payload)["max_output_tokens"] == 10
        self.calls += 1
        if self.failure:
            raise self.failure
        return self.reply


@pytest.fixture
def call(tmp_path):
    conn = sqlite3.connect(tmp_path / "spend.sqlite3")
    budget = Budget(conn, "1")
    source_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    pin = ModelPinV1("1.0", "fixture", "fixture-2026-11-01", "2026-11-01",
                     "fake", "1.0.0", source_sha)
    quote = PriceQuoteV1("1.0", pin.sha256, "USD", "all_input_all_output_tokens", "1", "2",
                         "https://example.invalid/prices", "b" * 64, "operator", NOW - 1, NOW + 5)
    request = ProviderCallRequestV1("1.0", "run", "call", "target_agent", pin.sha256,
                                   quote.sha256, 1000, 10)
    adapter = FakeAdapter(pin, budget)
    options = dict(trusted_model_sha256=pin.sha256, trusted_price_sha256=quote.sha256,
                   paid_calls_approved=True, clock=lambda: NOW)
    yield budget, request, pin, quote, adapter, options
    conn.close()


def dispatch(call, **changes):
    budget, request, pin, quote, adapter, options = call
    return invoke_provider(budget, request, pin, quote, adapter, b"private-input",
                           **(options | changes))


def test_inv18_provider_reserves_before_dispatch_and_settles_exact_usage_once(call):
    reply = dispatch(call)
    budget, _, _, quote, adapter, _ = call
    assert str(budget.committed()) == str(quote.usage_cost(20, 2))
    assert reply.output == b"private-output" and adapter.calls == 1
    with pytest.raises(ProviderInvocationError):
        dispatch(call)
    assert adapter.calls == 1
    assert "private-output" not in repr(reply)


def test_inv18_provider_default_opt_out_never_calls_adapter_or_reserves(call):
    with pytest.raises(ProviderInvocationError, match="preflight_rejected"):
        dispatch(call, paid_calls_approved=False)
    assert call[4].calls == 0 and call[0].committed() == 0


def test_inv18_provider_counts_system_tools_and_framing_before_reservation(call):
    budget, request, pin, quote, adapter, options = call
    with pytest.raises(ProviderInvocationError):
        invoke_provider(budget, replace(request, input_tokens_upper_bound=13), pin, quote,
                        adapter, b"private-input", **options)
    assert adapter.calls == 0 and budget.committed() == 0


@pytest.mark.parametrize("failure", [TimeoutError("secret-token"),
                                     KeyboardInterrupt("secret-token")])
def test_inv17_inv18_provider_failure_freezes_and_redacts_exception(call, failure):
    call[4].failure = failure
    with pytest.raises(ProviderInvocationError, match="indeterminate") as caught:
        dispatch(call)
    assert "secret-token" not in "".join(traceback.format_exception(caught.value))
    assert call[0].conn.execute("SELECT state FROM spend").fetchone()[0] == "unknown"
    with pytest.raises(ProviderInvocationError):
        dispatch(call)
    assert call[4].calls == 1


@pytest.mark.parametrize("changes", [dict(model_id="wrong"), dict(model_revision="2026-01-01"),
                                     dict(input_tokens=1001), dict(output_tokens=11),
                                     dict(input_tokens=True), dict(output_tokens=-1)])
def test_inv09_inv18_provider_mismatch_or_overrun_never_settles(call, changes):
    call[4].reply = replace(call[4].reply, **changes)
    with pytest.raises(ProviderInvocationError, match="indeterminate"):
        dispatch(call)
    assert call[0].conn.execute("SELECT state FROM spend").fetchone()[0] == "unknown"


def test_inv18_provider_rechecks_expiry_immediately_before_dispatch(call):
    values = iter((NOW, NOW + 5))
    with pytest.raises(ProviderInvocationError, match="indeterminate"):
        dispatch(call, clock=lambda: next(values))
    assert call[4].calls == 0


def test_inv09_provider_rejects_unapproved_adapter_source_before_reservation(call):
    call[4].pin = replace(call[2], adapter_sha256="c" * 64)
    with pytest.raises(ProviderInvocationError):
        dispatch(call)
    assert call[4].calls == 0 and call[0].committed() == 0


def test_inv18_provider_zero_output_is_valid_billed_usage(call):
    call[4].reply = replace(call[4].reply, output_tokens=0)
    dispatch(call)
    assert str(call[0].committed()) == "0.00002"


def test_inv18_provider_zero_default_budget_cannot_dispatch(call, tmp_path):
    with sqlite3.connect(tmp_path / "default.sqlite3") as conn:
        zero_budget = Budget(conn)
        with pytest.raises(ProviderInvocationError):
            invoke_provider(zero_budget, *call[1:5], b"private-input", **call[5])
        assert call[4].calls == 0 and zero_budget.committed() == 0


def test_inv18_provider_missing_usage_is_unknown(call):
    call[4].reply = None
    with pytest.raises(ProviderInvocationError, match="indeterminate"):
        dispatch(call)
    assert call[0].conn.execute("SELECT state FROM spend").fetchone()[0] == "unknown"


def test_inv09_provider_hashes_source_even_when_adapter_self_reports_approved_pin(call):
    budget, request, pin, quote, adapter, options = call
    pin = replace(pin, adapter_sha256="d" * 64)
    quote = replace(quote, model_pin_sha256=pin.sha256)
    request = replace(request, model_pin_sha256=pin.sha256, price_quote_sha256=quote.sha256)
    adapter.pin = pin
    options |= dict(trusted_model_sha256=pin.sha256, trusted_price_sha256=quote.sha256)
    with pytest.raises(ProviderInvocationError, match="preflight_rejected"):
        invoke_provider(budget, request, pin, quote, adapter, b"private-input", **options)
    assert adapter.calls == 0 and budget.committed() == 0


def test_inv09_inv17_call_records_bind_exact_identity_and_exclude_content(call):
    dispatch(call)
    record = ProviderJournal(call[0]).get("run:call")
    assert record["manifest"]["model_pin"] == call[2].to_wire()
    assert record["manifest"]["pricing"]["quote_sha256"] == call[3].sha256
    assert record["observation"]["output_sha256"] == digest(b"private-output")
    assert record["accounting_state"] == "settled"
    assert all(secret not in json.dumps(record) for secret in
               ("private-input", "private-output", "source_url", "api_key"))
    with sqlite3.connect(call[0].conn.execute("PRAGMA database_list").fetchone()[2]) as conn:
        assert ProviderJournal(Budget(conn, "1")).get("run:call") == record
    registry = Registry()
    schemas = [json.loads(p.read_bytes()) for p in
               (Path(__file__).parents[1] / "schemas").glob("*.json")]
    for schema in schemas:
        if "$id" in schema:
            registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    for field in ("manifest", "observation"):
        schema_id = "octoberblue:provider-call-" + field + ":v1"
        schema = next(s for s in schemas if s.get("$id") == schema_id)
        Draft202012Validator(schema, registry=registry).validate(record[field])


@pytest.mark.parametrize("tamper", ["hash", "run", "observation", "usage", "delete"])
def test_inv09_provider_records_fail_closed_on_corruption_or_substitution(call, tamper):
    dispatch(call)
    journal = ProviderJournal(call[0])
    record = journal.get("run:call")
    field = "manifest" if tamper in ("hash", "run") else "observation"
    value = record[field]
    if tamper == "run":
        value["request"]["run_id"] = "substitute"
    elif tamper == "observation":
        value["manifest_sha256"] = "c" * 64
    elif tamper == "usage":
        value["input_tokens"] = 1001
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
    sha = "d" * 64 if tamper == "hash" else digest(raw.encode())
    if tamper == "delete":
        raw, sha = None, None
    with call[0].conn:
        call[0].conn.execute(
            f"UPDATE provider_calls SET {field}_json=?,{field}_sha256=? WHERE id='run:call'",
            (raw, sha))
    with pytest.raises(ValueError):
        journal.get("run:call")


@pytest.mark.parametrize("stage", ["manifest", "observation"])
def test_inv17_inv18_record_write_failure_prevents_settlement_and_hides_db_error(call, stage):
    journal = ProviderJournal(call[0])
    action = "INSERT" if stage == "manifest" else "UPDATE OF observation_json"
    call[0].conn.execute(f"CREATE TRIGGER reject_record BEFORE {action} ON provider_calls "
                         "BEGIN SELECT RAISE(ABORT, 'secret-db-error'); END")
    call[0].conn.commit()
    with pytest.raises(ProviderInvocationError) as caught:
        dispatch(call)
    assert "secret-db-error" not in "".join(traceback.format_exception(caught.value))
    assert call[4].calls == (stage == "observation")
    if stage == "observation":
        assert journal.get("run:call")["accounting_state"] == "unknown"
    else:
        assert call[0].committed() == 0


def test_inv18_observation_alone_never_means_settled(call, monkeypatch):
    def fail(*args):
        raise OSError("secret-settlement-error")

    monkeypatch.setattr(call[0], "settle_dispatch", fail)
    with pytest.raises(ProviderInvocationError):
        dispatch(call)
    record = ProviderJournal(call[0]).get("run:call")
    assert record["observation"] is not None
    assert record["accounting_state"] == "unknown"
