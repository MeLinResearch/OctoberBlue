"""Budget-gated, single-attempt OpenAI transport through a deadline-bounded worker."""
import base64
import os
import sys
import tempfile

from .openai_chat import CONTEXT_TOKENS, _request, model_pin
from .process_boundary import run_bounded, worker_environment
from .provider_http_worker import check_credentials
from .provider_invocation import MAX_PAYLOAD_BYTES, ProviderInvocationError, _check_payload
from .provider_records import ProviderJournal, digest
from .service_contracts import _canonical, parse_contract_json

_NETWORK_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
                "SSL_CERT_FILE", "SSL_CERT_DIR")


class OpenAIHTTPTransport:
    def __init__(self, budget, call_key, api_key, *, timeout=30):
        check_credentials(api_key, timeout)
        self._budget, self._key = budget, call_key
        self._api_key, self._timeout = api_key, timeout

    def _claim(self, payload):
        _check_payload(payload)
        value = parse_contract_json(payload)
        _request(payload, value["messages"][0]["content"])
        journal = ProviderJournal(self._budget)
        with self._budget._transaction():
            record = journal._get_snapshot(self._key)
            manifest = record["manifest"]
            request = manifest["request"]
            if (record["accounting_state"] != "inflight"
                    or manifest["model_pin"] != model_pin().to_wire()
                    or request["input_tokens_upper_bound"] < CONTEXT_TOKENS
                    or request["output_tokens_upper_bound"] != value["max_completion_tokens"]
                    or manifest["payload_sha256"] != digest(payload)):
                raise ValueError("unapproved provider dispatch")
            self._budget.conn.execute(
                "CREATE TABLE IF NOT EXISTS provider_sends (id TEXT PRIMARY KEY)"
            )
            self._budget.conn.execute("INSERT INTO provider_sends VALUES (?)", (self._key,))

    def __call__(self, payload):
        try:
            self._claim(payload)
            envelope = _canonical({"payload_b64": base64.b64encode(payload).decode(),
                                   "api_key": self._api_key, "timeout": self._timeout})
            with tempfile.TemporaryDirectory(prefix="octoberblue-provider-") as workspace:
                env = worker_environment(workspace)
                env.update({name: os.environ[name] for name in _NETWORK_ENV if name in os.environ})
                result = run_bounded(
                    [sys.executable, "-I", "-B", "-m", "octoberblue.provider_http_worker"],
                    input=envelope, timeout=self._timeout, stdout_limit=MAX_PAYLOAD_BYTES,
                    stderr_limit=1024, env=env, cwd=workspace,
                )
            if result.returncode != 0:
                raise ValueError("provider worker failed")
            return result.stdout
        except BaseException:
            raise ProviderInvocationError("provider_transport_indeterminate") from None
