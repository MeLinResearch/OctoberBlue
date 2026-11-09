"""Trusted local ticket tool witness; never installed in the target image."""
from __future__ import annotations

import sys

from .benchmark import _Recorder
from .service_contracts import validate_event, witness_request
from .ticket_benchmark import TicketGateway, TicketGatewayPolicy, _TicketState
from .ticket_contracts import digest
from .ticket_evidence import (
    MAX_PACKET_BYTES,
    canonical,
    decode,
    implementation_digest,
    parse_run_manifest,
    seal,
)


class ChainedRecorder(_Recorder):
    def __init__(self, run_id, manifest_sha256):
        super().__init__(run_id)
        self.chain = []
        self.previous = manifest_sha256

    def emit(self, origin, kind, **detail):
        validate_event({"event_id": f"{self.run_id}:{len(self.events) + 1:04}",
                        "origin": origin, "kind": kind, "detail": detail})
        event_id = super().emit(origin, kind, **detail)
        fields = {"sequence": len(self.events), "previous_sha256": self.previous,
                  "event_sha256": digest(self.events[-1])}
        self.previous = digest(fields)
        self.chain.append({**fields, "sha256": self.previous})
        return event_id


def main() -> int:
    try:
        initial = witness_request(
            decode(sys.stdin.buffer.readline(MAX_PACKET_BYTES + 1)), sequence=1,
        )
        if initial["operation"] != "initialize":
            return 2
        manifest = parse_run_manifest(initial["manifest"])
        if manifest.implementation_sha256 != implementation_digest():
            return 2
        key = bytes.fromhex(initial["key"])
        if len(key) != 32:
            return 2
        signing_key = None
        if initial.get("audit_signing_key") is not None:
            signing_key = bytes.fromhex(initial.pop("audit_signing_key"))
            if len(signing_key) != 32:
                return 2
        anchor = digest(manifest.to_wire())
        recorder = ChainedRecorder(manifest.run_id, anchor)
        state = _TicketState(initial["ticket_id"], initial["account_id"])
        gateway = TicketGateway(TicketGatewayPolicy(
            manifest.max_calls, manifest.allow_simulated_breach,
        ), recorder, state)
        receipts = []
        previous = anchor
        _reply({"ready": True}, 1)
        for sequence in range(2, 101):
            raw = sys.stdin.buffer.readline(MAX_PACKET_BYTES + 1)
            if not raw:
                return 2
            command = witness_request(decode(raw), sequence=sequence)
            if type(command) is not dict:
                return 2
            operation = command.get("operation")
            before_index = len(recorder.events)
            if operation == "record" and set(command) == {"operation", "origin", "kind", "detail"}:
                # The private harness pipe cannot manufacture action/effect receipts.
                allowed = {
                    ("execution_harness", "run_started"),
                    ("execution_harness", "input_received"),
                    ("execution_harness", "content_delivered"),
                    ("execution_harness", "target_runtime_failed"),
                    ("blue_guard", "filter"),
                }
                if (command["origin"], command["kind"]) not in allowed:
                    return 2
                recorder.emit(command["origin"], command["kind"], **command["detail"])
            elif operation == "call" and set(command) == {"operation", "tool", "arguments"}:
                if type(command["tool"]) is not str:
                    return 2
                before = state.snapshot().to_wire()
                gateway.call(command["tool"], command["arguments"])
                request, result = recorder.events[-2:]
                fields = {
                    "sequence": len(receipts) + 1, "previous_sha256": previous,
                    "request_event_id": request["event_id"],
                    "result_event_id": result["event_id"],
                    "arguments_sha256": digest(command["arguments"]),
                    "decision": result["kind"], "before": before,
                    "after": state.snapshot().to_wire(),
                }
                previous = digest(fields)
                receipts.append({**fields, "sha256": previous})
            elif operation == "finalize" and set(command) == {"operation"}:
                snapshot = state.snapshot().to_wire()
                recorder.emit("execution_harness", "ticket_snapshot", **snapshot,
                              synthetic_only=True)
                body = {"schema_version": "1.0", "manifest": manifest.to_wire(),
                        "events": recorder.events, "event_chain": recorder.chain,
                        "receipts": receipts, "snapshot": snapshot}
                evidence = seal(body, key)
                if signing_key is not None:
                    from .ticket_audit import _sign_witness_body
                    evidence = {"evidence": evidence,
                                "audit_pack": _sign_witness_body(body, signing_key)}
                _reply(evidence, sequence)
                return 0  # Sealed exactly once; no further mutations are possible.
            else:
                return 2
            _reply({"events": recorder.events[before_index:]}, sequence)
        return 2
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
        return 2


def _reply(value, sequence):
    raw = canonical({"schema_version": "1.0", "sequence": sequence, "result": value}) + b"\n"
    if len(raw) > MAX_PACKET_BYTES:
        raise ValueError("response size limit")
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    raise SystemExit(main())
