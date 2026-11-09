"""Content-free host call records; consistency hashes do not attest tool effects."""
import hashlib
from dataclasses import dataclass

from .provider_contracts import (
    MAX_TOKENS,
    SHA,
    ModelPinV1,
    ProviderCallRequestV1,
    _integer,
    _money,
    _text,
)
from .service_contracts import _FrozenWire, _keys, parse_contract_json


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class _ProviderRecord(_FrozenWire):
    @property
    def sha256(self):
        return digest(self._json)


@dataclass(frozen=True)
class ProviderCallManifestV1(_ProviderRecord):
    def _validate(self, value):
        _keys(value, ("schema_version", "request", "model_pin", "pricing", "payload_sha256"))
        if value["schema_version"] != "1.0":
            raise ValueError("unsupported provider manifest version")
        request = ProviderCallRequestV1.from_wire(value["request"])
        pin = ModelPinV1.from_wire(value["model_pin"])
        price = value["pricing"]
        _keys(price, ("quote_sha256", "source_sha256", "input_dollars_per_million",
                      "output_dollars_per_million"))
        for field in ("quote_sha256", "source_sha256"):
            _text(price[field], SHA)
        for field in ("input_dollars_per_million", "output_dollars_per_million"):
            _money(price[field])
        _text(value["payload_sha256"], SHA)
        if (request.model_pin_sha256 != pin.sha256
                or request.price_quote_sha256 != price["quote_sha256"]):
            raise ValueError("provider manifest identity mismatch")


@dataclass(frozen=True)
class ProviderCallObservationV1(_ProviderRecord):
    def _validate(self, value):
        _keys(value, ("schema_version", "manifest_sha256", "input_tokens", "output_tokens",
                      "output_sha256"))
        if value["schema_version"] != "1.0":
            raise ValueError("unsupported provider observation version")
        _text(value["manifest_sha256"], SHA)
        _text(value["output_sha256"], SHA)
        _integer(value["input_tokens"], 0, MAX_TOKENS)
        _integer(value["output_tokens"], 0, MAX_TOKENS)


class ProviderJournal:
    def __init__(self, budget):
        self.budget = budget
        with budget._transaction():
            budget.conn.execute(
                "CREATE TABLE IF NOT EXISTS provider_calls (id TEXT PRIMARY KEY, "
                "manifest_json TEXT NOT NULL, manifest_sha256 TEXT NOT NULL, "
                "observation_json TEXT, observation_sha256 TEXT)"
            )

    def start(self, request, pin, quote, payload):
        manifest = ProviderCallManifestV1.from_wire({
            "schema_version": "1.0", "request": request.to_wire(), "model_pin": pin.to_wire(),
            "pricing": {"quote_sha256": quote.sha256, "source_sha256": quote.source_sha256,
                        "input_dollars_per_million": quote.input_dollars_per_million,
                        "output_dollars_per_million": quote.output_dollars_per_million},
            "payload_sha256": digest(payload),
        })
        key = request.run_id + ":" + request.call_id
        with self.budget._transaction():
            self.budget.conn.execute(
                "INSERT INTO provider_calls VALUES (?,?,?,NULL,NULL)",
                (key, manifest._json.decode(), manifest.sha256),
            )
        return manifest

    def observe(self, key, manifest, reply):
        observation = ProviderCallObservationV1.from_wire({
            "schema_version": "1.0", "manifest_sha256": manifest.sha256,
            "input_tokens": reply.input_tokens, "output_tokens": reply.output_tokens,
            "output_sha256": digest(reply.output),
        })
        with self.budget._transaction():
            changed = self.budget.conn.execute(
                "UPDATE provider_calls SET observation_json=?,observation_sha256=? "
                "WHERE id=? AND manifest_sha256=? AND observation_json IS NULL",
                (observation._json.decode(), observation.sha256, key, manifest.sha256),
            ).rowcount
            if changed != 1:
                raise ValueError("missing or duplicate provider observation")

    def _load(self, raw, expected, contract):
        record = contract.from_wire(parse_contract_json(raw))
        if record.sha256 != expected:
            raise ValueError("provider record hash mismatch")
        return record

    def get(self, key):
        with self.budget._transaction():
            return self._get_snapshot(key)

    def _get_snapshot(self, key):
        row = self.budget.conn.execute("SELECT * FROM provider_calls WHERE id=?", (key,)).fetchone()
        if row is None:
            raise KeyError(key)
        if (row[3] is None) != (row[4] is None):
            raise ValueError("incomplete provider observation")
        manifest = self._load(row[1], row[2], ProviderCallManifestV1)
        observation = None if row[3] is None else self._load(
            row[3], row[4], ProviderCallObservationV1)
        wire = manifest.to_wire()
        if key != wire["request"]["run_id"] + ":" + wire["request"]["call_id"]:
            raise ValueError("provider record run substitution")
        if observation is not None:
            self._check_observation(manifest, observation)
        state = self.budget.conn.execute("SELECT state FROM spend WHERE id=?", (key,)).fetchone()
        accounting = state[0] if state else "not_reserved"
        if accounting not in ("not_reserved", "reserved", "inflight", "settled", "unknown"):
            raise ValueError("invalid provider accounting state")
        if accounting == "settled" and observation is None:
            raise ValueError("settled provider call lacks observation")
        return {"manifest": wire, "observation": observation.to_wire() if observation else None,
                "accounting_state": accounting}

    def _check_observation(self, manifest, observation):
        value = observation.to_wire()
        if value["manifest_sha256"] != manifest.sha256:
            raise ValueError("provider observation substitution")
        request = manifest.to_wire()["request"]
        _integer(value["input_tokens"], 0, request["input_tokens_upper_bound"])
        _integer(value["output_tokens"], 0, request["output_tokens_upper_bound"])
