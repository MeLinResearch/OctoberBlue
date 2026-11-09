"""INV-09/17/18: authored wire fixtures; no network or actual model results."""
import json
import sqlite3
from copy import deepcopy
from dataclasses import replace

import pytest

from octoberblue.budget import Budget
from octoberblue.openai_chat import CONTEXT_TOKENS, MODEL_ID, OpenAIChatAdapter
from octoberblue.provider_contracts import PriceQuoteV1, ProviderCallRequestV1
from octoberblue.provider_invocation import ProviderInvocationError, invoke_provider
from octoberblue.provider_records import ProviderJournal


@pytest.fixture
def response():
    return {"object": "chat.completion", "model": MODEL_ID, "service_tier": "default",
            "usage": {"prompt_tokens": 100, "completion_tokens": 2, "total_tokens": 102},
            "choices": [{"index": 0, "finish_reason": "stop", "message": {
                "role": "assistant", "content": "private-response"}}]}


def test_inv18_chat_reserves_context_bound_and_settles_only_metadata(tmp_path, response):
    sent = []
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as conn:
        budget = Budget(conn, "1")

        def send(payload):
            assert str(budget.committed()) == "0.40002"
            assert conn.execute("SELECT state FROM spend").fetchone()[0] == "inflight"
            sent.append(json.loads(payload))
            return json.dumps(response).encode()

        adapter = OpenAIChatAdapter("private-instructions", send)
        quote = PriceQuoteV1("1.0", adapter.pin.sha256, "USD", "all_input_all_output_tokens",
                             "1", "2", "https://example.invalid/prices", "b" * 64,
                             "fixture-reviewer", 1, 3)
        request = ProviderCallRequestV1("1.0", "run", "call", "target_agent", adapter.pin.sha256,
                                       quote.sha256, CONTEXT_TOKENS, 10)
        result = invoke_provider(budget, request, adapter.pin, quote, adapter, b"private-input",
                                 trusted_model_sha256=adapter.pin.sha256,
                                 trusted_price_sha256=quote.sha256,
                                 paid_calls_approved=True, clock=lambda: 2)
        assert result.output == b"private-response" and str(budget.committed()) == "0.000104"
        assert sent[0]["max_completion_tokens"] == 10 and sent[0]["model"] == MODEL_ID
        artifact = json.dumps(ProviderJournal(budget).get("run:call"))
        assert all(secret not in artifact for secret in
                   ("private-response", "private-instructions", "private-input"))
        with pytest.raises(ProviderInvocationError):
            invoke_provider(budget, replace(request, call_id="disabled"), adapter.pin, quote,
                            adapter, b"private-input", trusted_model_sha256=adapter.pin.sha256,
                            trusted_price_sha256=quote.sha256, clock=lambda: 2)
        assert len(sent) == 1


@pytest.mark.parametrize("field,value", [("model", "gpt-5.4-mini"), ("service_tier", "priority"),
                                        ("usage", None), ("choices", []),
                                        ("object", "chat.completion.chunk")])
def test_inv09_chat_rejects_wrong_identity_tier_or_missing_metadata(response, field, value):
    response[field] = value
    adapter = OpenAIChatAdapter("host", lambda _: json.dumps(response).encode())
    with pytest.raises(ValueError):
        adapter.invoke(adapter.prepare(b"input", output_limit=10))


@pytest.mark.parametrize("field,value", [("prompt_tokens", True), ("completion_tokens", 11),
                                        ("total_tokens", 0), ("prompt_tokens", 400_001)])
def test_inv18_chat_rejects_invalid_or_inconsistent_usage(response, field, value):
    response["usage"][field] = value
    adapter = OpenAIChatAdapter("host", lambda _: json.dumps(response).encode())
    with pytest.raises(ValueError):
        adapter.invoke(adapter.prepare(b"input", output_limit=10))


@pytest.mark.parametrize("field,value", [("tool_calls", [{}]), ("audio", {"data": "secret"}),
                                        ("refusal", "refused"), ("content", None)])
def test_inv09_chat_rejects_nontext_responses(response, field, value):
    response["choices"][0]["message"][field] = value
    adapter = OpenAIChatAdapter("host", lambda _: json.dumps(response).encode())
    with pytest.raises(ValueError):
        adapter.invoke(adapter.prepare(b"input", output_limit=10))


@pytest.mark.parametrize("field,value", [("model", "alias"), ("n", True), ("stream", True),
                                        ("service_tier", "flex"),
                                        ("max_completion_tokens", 128_001)])
def test_inv18_chat_rejects_mutated_prepared_request(field, value):
    adapter = OpenAIChatAdapter("host", lambda _: pytest.fail("transport must not run"))
    value_map = json.loads(adapter.prepare(b"input", output_limit=10))
    value_map[field] = value
    with pytest.raises(ValueError):
        adapter.invoke(json.dumps(value_map).encode())


def test_inv09_chat_treats_json_in_user_text_as_content_and_counts_all_framing():
    adapter = OpenAIChatAdapter("host", lambda _: pytest.fail("offline preparation"))
    payload = adapter.prepare(b'{"model":"override","tools":["unpriced"]}', output_limit=10)
    assert json.loads(payload)["model"] == MODEL_ID
    assert adapter.count_input_tokens(payload) == CONTEXT_TOKENS
    changed = deepcopy(json.loads(payload))
    changed["messages"][0]["content"] = "override"
    with pytest.raises(ValueError):
        adapter.count_input_tokens(json.dumps(changed).encode())
    assert "host" not in repr(adapter)
