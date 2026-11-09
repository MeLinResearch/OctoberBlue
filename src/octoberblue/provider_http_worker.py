"""Fixed-endpoint HTTPS worker; private input only, bounded response only."""
import base64
import math
import re
import ssl
import sys
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .provider_invocation import MAX_PAYLOAD_BYTES, _check_payload
from .service_contracts import MAX_WIRE_BYTES, _keys, parse_contract_json

ENDPOINT = "https://api.openai.com/v1/chat/completions"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_credentials(api_key, timeout):
    if type(api_key) is not str or re.fullmatch(r"[A-Za-z0-9_.-]{1,4096}", api_key) is None:
        raise ValueError("invalid provider credential")
    if (type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 0 < timeout <= 120):
        raise ValueError("invalid provider deadline")


def fetch(payload, api_key, timeout):
    request = Request(ENDPOINT, data=payload, method="POST", headers={
        "Authorization": "Bearer " + api_key, "Content-Type": "application/json",
        "Accept": "application/json", "Accept-Encoding": "identity",
    })
    opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200 or response.headers.get_content_type() != "application/json":
            raise ValueError("unexpected provider response")
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise ValueError("unsupported provider encoding")
        raw = response.read(MAX_PAYLOAD_BYTES + 1)
    _check_payload(raw)
    return raw


def main():
    try:
        value = parse_contract_json(sys.stdin.buffer.read(MAX_WIRE_BYTES + 1))
        _keys(value, ("payload_b64", "api_key", "timeout"))
        check_credentials(value["api_key"], value["timeout"])
        payload = base64.b64decode(value["payload_b64"], validate=True)
        _check_payload(payload)
        sys.stdout.buffer.write(fetch(payload, value["api_key"], value["timeout"]))
        return 0
    except BaseException:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
