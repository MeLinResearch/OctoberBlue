"""Pinned text-only Chat Completions wire profile for operator-selected transport."""
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .provider_contracts import ModelPinV1, _integer
from .provider_invocation import MAX_PAYLOAD_BYTES, ProviderReply, _check_payload
from .service_contracts import _canonical, _keys, parse_contract_json

MODEL_ID = "gpt-5.4-mini-2026-03-17"
MODEL_REVISION = "2026-03-17"
CONTEXT_TOKENS = 400_000
MAX_OUTPUT_TOKENS = 128_000
_FIXED = {"model": MODEL_ID, "n": 1, "stream": False, "store": False,
          "service_tier": "default", "reasoning_effort": "none"}


def model_pin():
    return ModelPinV1("1.0", "openai", MODEL_ID, MODEL_REVISION, "openai_chat_text", "1.0.0",
                      hashlib.sha256(Path(__file__).read_bytes()).hexdigest())


def _check_text(value):
    if type(value) is not str or len(value.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise ValueError("invalid chat text")


def _request(payload, instructions):
    _check_payload(payload)
    value = parse_contract_json(payload)
    _keys(value, (*_FIXED, "messages", "max_completion_tokens"))
    if any(type(value[key]) is not type(expected) or value[key] != expected
           for key, expected in _FIXED.items()):
        raise ValueError("unsupported chat request configuration")
    _integer(value["max_completion_tokens"], 1, MAX_OUTPUT_TOKENS)
    messages = value["messages"]
    if type(messages) is not list or len(messages) != 2:
        raise ValueError("invalid chat messages")
    for message, role in zip(messages, ("developer", "user"), strict=True):
        _keys(message, ("role", "content"))
        if message["role"] != role:
            raise ValueError("invalid chat message role")
        _check_text(message["content"])
    if messages[0]["content"] != instructions:
        raise ValueError("chat instructions mismatch")
    return value


def _response_choice(value):
    choices = value.get("choices")
    if type(choices) is not list or len(choices) != 1 or type(choices[0]) is not dict:
        raise ValueError("invalid chat choices")
    choice = choices[0]
    if type(choice.get("index")) is not int or choice["index"] != 0:
        raise ValueError("invalid chat choice index")
    if choice.get("finish_reason") not in ("stop", "length"):
        raise ValueError("unsupported chat completion reason")
    message = choice.get("message")
    if type(message) is not dict or message.get("role") != "assistant":
        raise ValueError("invalid chat response message")
    if any(message.get(key) for key in ("tool_calls", "function_call", "refusal", "audio")):
        raise ValueError("unsupported chat response modality")
    _check_text(message.get("content"))
    return message["content"].encode("utf-8")


def parse_response(raw, output_limit):
    _integer(output_limit, 1, MAX_OUTPUT_TOKENS)
    _check_payload(raw)
    value = parse_contract_json(raw)
    if type(value) is not dict or value.get("object") != "chat.completion":
        raise ValueError("invalid chat response")
    if value.get("model") != MODEL_ID or value.get("service_tier") != "default":
        raise ValueError("unapproved chat model or service tier")
    usage = value.get("usage")
    if type(usage) is not dict:
        raise ValueError("missing chat usage")
    for key, limit in (("prompt_tokens", CONTEXT_TOKENS), ("completion_tokens", output_limit),
                       ("total_tokens", CONTEXT_TOKENS)):
        _integer(usage.get(key), 0, limit)
    if usage["total_tokens"] != usage["prompt_tokens"] + usage["completion_tokens"]:
        raise ValueError("inconsistent chat usage")
    return ProviderReply(MODEL_ID, MODEL_REVISION, usage["prompt_tokens"],
                         usage["completion_tokens"], _response_choice(value))


@dataclass(frozen=True)
class OpenAIChatAdapter:
    instructions: str = field(repr=False)
    send: Callable[[bytes], bytes] = field(repr=False)
    pin: ModelPinV1 = field(default_factory=model_pin, init=False)

    def prepare(self, content, *, output_limit):
        _check_payload(content)
        _check_text(self.instructions)
        _integer(output_limit, 1, MAX_OUTPUT_TOKENS)
        payload = _canonical({**_FIXED, "max_completion_tokens": output_limit, "messages": [
            {"role": "developer", "content": self.instructions},
            {"role": "user", "content": content.decode("utf-8")},
        ]})
        _check_payload(payload)
        return payload

    def count_input_tokens(self, payload):
        _request(payload, self.instructions)
        # Reserve the entire documented context, including protocol framing.
        # This is an upper bound, not a tokenizer estimate or measured usage.
        return CONTEXT_TOKENS

    def invoke(self, payload):
        request = _request(payload, self.instructions)
        return parse_response(self.send(payload), request["max_completion_tokens"])
