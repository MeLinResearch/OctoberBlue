"""Fail-closed, separate-process verifier transport for support-ticket runs."""
from __future__ import annotations

import json
import subprocess
import sys

from .ticket_contracts import TicketOracle
from .ticket_verifier import TicketSnapshot
from .verifier import Verification

MAX_REQUEST_BYTES = 100_000


def _indeterminate() -> Verification:
    return Verification(False, False, False, "indeterminate")


def verify_ticket_in_subprocess(
    events: list[dict] | tuple[dict, ...],
    snapshot: TicketSnapshot,
    *,
    oracle: TicketOracle,
    run_id: str,
    timeout: float = 5.0,
) -> Verification:
    try:
        request = json.dumps({
            "events": events, "snapshot": snapshot.to_wire(),
            "oracle": oracle.__dict__, "run_id": run_id,
        }, sort_keys=True, allow_nan=False)
        if len(request.encode("utf-8")) > MAX_REQUEST_BYTES:
            return _indeterminate()
        response = subprocess.run(
            [sys.executable, "-m", "octoberblue.ticket_verifier_worker"],
            input=request, text=True, capture_output=True, encoding="utf-8",
            check=False, timeout=timeout,
        )
        if response.returncode != 0 or len(response.stdout) > 2048:
            return _indeterminate()
        value = json.loads(response.stdout)
        if type(value) is not dict or set(value) != {
            "task_success", "attempted", "completed", "verdict",
        }:
            return _indeterminate()
        if any(type(value[x]) is not bool
               for x in ("task_success", "attempted", "completed")):
            return _indeterminate()
        if value["verdict"] not in ("pass", "fail", "indeterminate"):
            return _indeterminate()
        if (
            value["verdict"] == "indeterminate"
            and (value["task_success"] or value["attempted"] or value["completed"])
        ):
            return _indeterminate()
        if (
            value["verdict"] == "pass"
            and (not value["task_success"] or value["completed"])
        ):
            return _indeterminate()
        return Verification(**value)
    except (OSError, ValueError, TypeError, UnicodeError, subprocess.TimeoutExpired):
        return _indeterminate()
