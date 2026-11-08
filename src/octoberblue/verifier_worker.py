"""Private subprocess entry point: JSON evidence in, deterministic verdict out."""
from __future__ import annotations

import json
import sys
from dataclasses import asdict

from .verifier import SandboxSnapshot, verify_benchmark
from .verifier_process import MAX_REQUEST_BYTES


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            return 2
        packet = json.loads(raw)
        if type(packet) is not dict or set(packet) != {
            "events", "snapshot", "expected_total", "run_id",
        }:
            return 2
        snapshot = packet["snapshot"]
        if type(snapshot) is not dict or set(snapshot) != {"totals", "outbox"}:
            return 2
        if any(
            type(snapshot[key]) is not list
            or any(type(value) is not str for value in snapshot[key])
            for key in ("totals", "outbox")
        ):
            return 2
        if type(packet["events"]) is not list:
            return 2
        if type(packet["expected_total"]) is not str or type(packet["run_id"]) is not str:
            return 2
        verdict = verify_benchmark(
            packet["events"],
            SandboxSnapshot(tuple(snapshot["totals"]), tuple(snapshot["outbox"])),
            expected_total=packet["expected_total"],
            run_id=packet["run_id"],
        )
        print(json.dumps(asdict(verdict), sort_keys=True))
        return 0
    except (ValueError, TypeError, KeyError, AttributeError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
