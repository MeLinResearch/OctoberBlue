"""Run the deterministic verifier in a separate Python process.

This isolates scoring from the toy target's Python process. It does NOT attest
the evidence, restrict OS privileges, or sandbox the target. All evidence still
comes from the trusted harness; container isolation is a separate milestone.
"""
from __future__ import annotations

import json
import subprocess

from .process_boundary import ProcessBoundaryError, run_trusted_worker
from .service_contracts import parse_contract_json, validate_verdict
from .verifier import SandboxSnapshot, Verification

MAX_REQUEST_BYTES = 1_000_000


def _indeterminate() -> Verification:
    return Verification(False, False, False, "indeterminate")


def verify_in_subprocess(
    events: list[dict] | tuple[dict, ...],
    snapshot: SandboxSnapshot,
    *,
    expected_total: str,
    run_id: str,
    timeout: float = 5.0,
) -> Verification:
    """Fail closed on invalid wire data, worker errors, and timeouts."""
    try:
        request = json.dumps(
            {
                "events": events,
                "snapshot": {"totals": list(snapshot.totals), "outbox": list(snapshot.outbox)},
                "expected_total": expected_total,
                "run_id": run_id,
            },
            allow_nan=False,
            sort_keys=True,
        )
        if len(request.encode("utf-8")) > MAX_REQUEST_BYTES:
            return _indeterminate()
        completed = run_trusted_worker(
            "octoberblue.verifier_worker", input=request.encode("utf-8"), timeout=timeout,
        )
        if completed.returncode != 0 or len(completed.stdout) > 2048:
            return _indeterminate()
        result = parse_contract_json(completed.stdout)
        if type(result) is not dict or set(result) != {
            "task_success", "attempted", "completed", "verdict",
        }:
            return _indeterminate()
        if any(type(result[key]) is not bool for key in (
            "task_success", "attempted", "completed",
        )):
            return _indeterminate()
        if result["verdict"] not in ("pass", "fail", "indeterminate"):
            return _indeterminate()
        if result["verdict"] == "indeterminate" and any(
            result[key] for key in ("task_success", "attempted", "completed")
        ):
            return _indeterminate()
        validate_verdict(result["task_success"], result["attempted"],
                         result["completed"], result["verdict"])
        return Verification(**result)
    except (OSError, ValueError, TypeError, UnicodeError, subprocess.TimeoutExpired,
            ProcessBoundaryError, RecursionError):
        return _indeterminate()
