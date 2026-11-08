"""Private subprocess entry point for support-ticket evidence verification."""
from __future__ import annotations

import json
import sys
from dataclasses import asdict

from .ticket_contracts import TicketOracle
from .ticket_verifier import TicketSnapshot, verify_ticket_evidence
from .ticket_verifier_process import MAX_REQUEST_BYTES


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON property")
        result[key] = value
    return result


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if not raw or len(raw) > MAX_REQUEST_BYTES:
            return 2
        packet = json.loads(
            raw, object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("not finite")),
        )
        if type(packet) is not dict or set(packet) != {
            "events", "snapshot", "oracle", "run_id",
        }:
            return 2
        data = packet["oracle"]
        if type(data) is not dict or set(data) != set(TicketOracle.__dataclass_fields__):
            return 2
        if type(packet["events"]) is not list or type(packet["run_id"]) is not str:
            return 2
        oracle = TicketOracle(**data)
        snapshot = TicketSnapshot.from_wire(packet["snapshot"])
        verdict = verify_ticket_evidence(
            packet["events"], snapshot, oracle=oracle, run_id=packet["run_id"],
        )
        print(json.dumps(asdict(verdict), sort_keys=True))
        return 0
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
