"""INV-17/18: offline HTTP doubles and local deadline workers; no provider calls."""
import io
import json
import sqlite3
import sys
import traceback
from email.message import Message
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, Request, build_opener
from urllib.response import addinfourl

import pytest

from octoberblue import openai_transport as transport
from octoberblue import provider_http_worker as worker
from octoberblue.budget import Budget
from octoberblue.openai_chat import CONTEXT_TOKENS, OpenAIChatAdapter
from octoberblue.process_boundary import ProcessResult, run_bounded
from octoberblue.provider_contracts import PriceQuoteV1, ProviderCallRequestV1
from octoberblue.provider_invocation import ProviderInvocationError
from octoberblue.provider_records import ProviderJournal


@pytest.fixture
def pending(tmp_path):
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as conn:
        budget = Budget(conn, "1")
        adapter = OpenAIChatAdapter("host", lambda _: pytest.fail("offline only"))
        quote = PriceQuoteV1("1.0", adapter.pin.sha256, "USD", "all_input_all_output_tokens",
                             "1", "2", "https://example.invalid/prices", "b" * 64, "operator", 1, 3)
        request = ProviderCallRequestV1("1.0", "run", "call", "target_agent", adapter.pin.sha256,
                                       quote.sha256, CONTEXT_TOKENS, 10)
        payload = adapter.prepare(b"private-input", output_limit=10)
        ProviderJournal(budget).start(request, adapter.pin, quote, payload)
        budget.reserve("run:call", quote.upper_bound(CONTEXT_TOKENS, 10))
        yield budget, payload


def test_inv17_inv18_transport_requires_inflight_and_persists_single_send(pending, monkeypatch):
    budget, payload = pending
    attempts = []

    def fake_worker(command, **options):
        assert "private-key" not in repr(command) + repr(options["env"])
        assert "PYTHONPATH" not in options["env"] and "OPENAI_API_KEY" not in options["env"]
        assert json.loads(options["input"])["api_key"] == "private-key"
        attempts.append(command)
        return ProcessResult(0, b"{}", b"")

    monkeypatch.setenv("OPENAI_API_KEY", "ambient-secret")
    monkeypatch.setenv("PYTHONPATH", "ambient-startup")
    monkeypatch.setattr(transport, "run_bounded", fake_worker)
    sender = transport.OpenAIHTTPTransport(budget, "run:call", "private-key")
    assert "private-key" not in repr(sender)
    with pytest.raises(ProviderInvocationError):
        sender(payload)
    budget.begin_dispatch("run:call")
    assert sender(payload) == b"{}"
    with pytest.raises(ProviderInvocationError):
        transport.OpenAIHTTPTransport(budget, "run:call", "private-key")(payload)
    assert len(attempts) == 1


def test_inv18_transport_rejects_body_substitution_before_worker(pending, monkeypatch):
    budget, payload = pending
    budget.begin_dispatch("run:call")
    monkeypatch.setattr(transport, "run_bounded", lambda *a, **k: pytest.fail("no dispatch"))
    with pytest.raises(ProviderInvocationError):
        transport.OpenAIHTTPTransport(budget, "run:call", "private-key")(
            payload.replace(b"private-input", b"substituted-input"))


def test_inv17_inv18_total_deadline_includes_stalled_network_worker(pending, monkeypatch):
    budget, payload = pending
    budget.begin_dispatch("run:call")

    def stall(command, **options):
        return run_bounded([sys.executable, "-I", "-c", "import time; time.sleep(60)"], **options)

    monkeypatch.setattr(transport, "run_bounded", stall)
    with pytest.raises(ProviderInvocationError, match="indeterminate"):
        transport.OpenAIHTTPTransport(budget, "run:call", "private-key", timeout=0.1)(payload)
    assert ProviderJournal(budget).get("run:call")["accounting_state"] == "inflight"


@pytest.mark.parametrize("timeout", [True, 0, -1, float("nan"), float("inf"), 121])
def test_inv18_transport_rejects_unbounded_or_invalid_deadlines(pending, timeout):
    with pytest.raises(ValueError):
        transport.OpenAIHTTPTransport(pending[0], "run:call", "private-key", timeout=timeout)


def test_inv17_transport_hides_worker_error_output(pending, monkeypatch):
    budget, payload = pending
    budget.begin_dispatch("run:call")
    monkeypatch.setattr(transport, "run_bounded", lambda *a, **k:
                        ProcessResult(2, b"secret-body", b"secret-key"))
    with pytest.raises(ProviderInvocationError) as caught:
        transport.OpenAIHTTPTransport(budget, "run:call", "private-key")(payload)
    assert "secret-" not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("status,encoding,size", [(200, "identity", 2), (500, "identity", 2),
                                                (200, "gzip", 2), (200, "identity", 1_000_001)])
def test_inv17_inv18_http_response_caps_and_headers(monkeypatch, status, encoding, size):
    headers = Message()
    headers["Content-Type"], headers["Content-Encoding"] = "application/json", encoding
    response = addinfourl(io.BytesIO(b"x" * size), headers, worker.ENDPOINT, status)
    captured = []

    def open_response(request, *, timeout):
        captured.append((request.full_url, request.get_header("Authorization"), timeout))
        return response

    monkeypatch.setattr(worker, "build_opener", lambda *a:
                        SimpleNamespace(open=open_response))
    if status == 200 and encoding == "identity" and size == 2:
        assert worker.fetch(b"{}", "private-key", 1) == b"xx"
    else:
        with pytest.raises(ValueError):
            worker.fetch(b"{}", "private-key", 1)
    assert captured == [(worker.ENDPOINT, "Bearer private-key", 1)]


def test_inv17_http_redirect_never_forwards_authorization_to_another_host():
    seen = []

    class RedirectingHTTPS(HTTPSHandler):
        def https_open(self, req):
            seen.append(req.full_url)
            headers = Message()
            headers["Location"] = "https://untrusted.invalid/steal"
            response = addinfourl(io.BytesIO(b""), headers, req.full_url, 302)
            response.msg = "redirect"
            return response

    opener = build_opener(worker.NoRedirect(), RedirectingHTTPS())
    with pytest.raises(HTTPError) as caught:
        request = Request(worker.ENDPOINT, data=b"{}", headers={"Authorization": "Bearer secret"})
        opener.open(request)
    assert caught.value.code == 302 and seen == [worker.ENDPOINT]


@pytest.mark.parametrize("field,value", [("api_key", "private\nkey"), ("timeout", True),
                                        ("payload_b64", "invalid!"), ("endpoint", "override")])
def test_inv17_worker_rejects_malformed_private_envelopes_without_output(monkeypatch, field, value):
    raw = {"api_key": "private-key", "timeout": 1, "payload_b64": "e30="}
    raw[field] = value
    output, fetched = io.BytesIO(), []
    monkeypatch.setattr(worker, "sys", SimpleNamespace(
        stdin=SimpleNamespace(buffer=io.BytesIO(json.dumps(raw).encode())),
        stdout=SimpleNamespace(buffer=output)))
    monkeypatch.setattr(worker, "fetch", lambda *a: fetched.append(a))
    assert worker.main() == 2 and output.getvalue() == b"" and fetched == []


@pytest.mark.parametrize("failed", [False, True])
def test_inv17_worker_emits_only_success_body_or_empty_failure(monkeypatch, failed):
    raw = {"api_key": "private-key", "timeout": 1, "payload_b64": "e30="}
    output = io.BytesIO()

    def fetch(*args):
        if failed:
            raise RuntimeError("private-key and private-server-message")
        return b"{}"

    monkeypatch.setattr(worker, "sys", SimpleNamespace(
        stdin=SimpleNamespace(buffer=io.BytesIO(json.dumps(raw).encode())),
        stdout=SimpleNamespace(buffer=output)))
    monkeypatch.setattr(worker, "fetch", fetch)
    assert worker.main() == (2 if failed else 0)
    assert output.getvalue() == (b"" if failed else b"{}")


@pytest.mark.parametrize("failed", [False, True])
def test_inv18_coordinator_gates_transport_and_freezes_uncertainty(pending, monkeypatch, failed):
    from octoberblue.provider_invocation import invoke_provider

    budget, _ = pending
    sender = transport.OpenAIHTTPTransport(budget, "run:new", "private-key")
    adapter = OpenAIChatAdapter("host", sender)
    quote = PriceQuoteV1("1.0", adapter.pin.sha256, "USD", "all_input_all_output_tokens", "1", "2",
                         "https://example.invalid/prices", "b" * 64, "operator", 1, 3)
    request = ProviderCallRequestV1("1.0", "run", "new", "target_agent", adapter.pin.sha256,
                                   quote.sha256, CONTEXT_TOKENS, 10)
    response = {"object": "chat.completion", "model": adapter.pin.model_id,
                "service_tier": "default",
                "usage": {"prompt_tokens": 100, "completion_tokens": 2, "total_tokens": 102},
                "choices": [{"index": 0, "finish_reason": "stop", "message": {
                    "role": "assistant", "content": "private-response"}}]}
    monkeypatch.setattr(transport, "run_bounded", lambda *a, **k:
                        ProcessResult(2 if failed else 0, json.dumps(response).encode(), b""))
    options = dict(trusted_model_sha256=adapter.pin.sha256, trusted_price_sha256=quote.sha256,
                   paid_calls_approved=True, clock=lambda: 2)
    if failed:
        with pytest.raises(ProviderInvocationError):
            invoke_provider(budget, request, adapter.pin, quote, adapter, b"input", **options)
    else:
        assert invoke_provider(budget, request, adapter.pin, quote, adapter,
                               b"input", **options).output == b"private-response"
    record = ProviderJournal(budget).get("run:new")
    assert record["accounting_state"] == ("unknown" if failed else "settled")
    assert "private-" not in json.dumps(record)
