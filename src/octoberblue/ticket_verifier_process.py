"""Fail-closed, separate-process verifier transport for support-ticket runs."""
from __future__ import annotations

import json
import secrets
import subprocess

from .contained_runtime import run_contained_worker
from .process_boundary import ProcessBoundaryError, run_trusted_worker
from .service_contracts import service_message, service_payload
from .ticket_contracts import TicketOracle
from .ticket_evidence import MAX_PACKET_BYTES, decode
from .ticket_verifier import TicketSnapshot
from .verifier import Verification

MAX_REQUEST_BYTES = MAX_PACKET_BYTES


def _indeterminate() -> Verification:
    return Verification(False, False, False, "indeterminate")


def verify_ticket_in_subprocess(
    events: list[dict] | tuple[dict, ...],
    snapshot: TicketSnapshot,
    *,
    oracle: TicketOracle,
    run_id: str,
    timeout: float = 5.0,
    evidence: dict | None = None,
    authentication_key: bytes | None = None,
    expected_manifest_sha256: str | None = None,
    runtime: str = "subprocess",
    image_id: str | None = None,
) -> Verification:
    try:
        if evidence is not None or authentication_key is not None or expected_manifest_sha256:
            if type(authentication_key) is not bytes or len(authentication_key) != 32:
                return _indeterminate()
            packet = {"evidence": evidence, "authentication_key": authentication_key.hex(),
                      "expected_manifest_sha256": expected_manifest_sha256,
                      "oracle": oracle.__dict__, "run_id": run_id}
        else:
            # Compatibility-only logical consistency checks, not authenticated acquisition.
            packet = {"events": events, "snapshot": snapshot.to_wire(),
                      "oracle": oracle.__dict__, "run_id": run_id}
        request_id = secrets.token_hex(16)
        request = json.dumps(service_message("verify_ticket", request_id, packet),
                             sort_keys=True, allow_nan=False)
        if len(request.encode("utf-8")) > MAX_REQUEST_BYTES:
            return _indeterminate()
        if runtime == "docker":
            from .ticket_evidence import RunManifestV2, parse_run_manifest
            manifest = parse_run_manifest(evidence["body"]["manifest"])
            if (not isinstance(manifest, RunManifestV2) or image_id is None
                    or manifest.verifier_image_id != image_id):
                return _indeterminate()
            response = run_contained_worker(
                "octoberblue.ticket_verifier_worker", image_id=image_id,
                input=request.encode("utf-8"), timeout=timeout,
            )
        elif runtime == "subprocess":
            response = run_trusted_worker(
                "octoberblue.ticket_verifier_worker", input=request.encode("utf-8"),
                timeout=timeout,
            )
        else:
            return _indeterminate()
        if response.returncode != 0 or len(response.stdout) > 2048:
            return _indeterminate()
        value = service_payload(decode(response.stdout),
                                operation="verify_ticket", request_id=request_id, response=True)
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
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.TimeoutExpired,
            ProcessBoundaryError, RecursionError):
        return _indeterminate()
