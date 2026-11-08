"""Private-pipe client for the trusted state-owning ticket witness."""
from __future__ import annotations

import queue
import secrets
import subprocess
import sys
import threading

from .service_contracts import (
    RunRequestV1,
    validate_event,
    witness_request,
    witness_response,
)
from .ticket_evidence import MAX_PACKET_BYTES, RunManifestV1, canonical, decode


class WitnessError(RuntimeError):
    pass


class TicketWitness:
    def __init__(self, manifest: RunManifestV1, ticket_id: str, account_id: str,
                 *, audit_signing_key: bytes | None = None):
        self.audit_pack = None
        self.audit_public_key = None
        if audit_signing_key is not None:
            from .ticket_audit import public_bytes
            self.audit_public_key = public_bytes(audit_signing_key)
        self.events = []
        self.key = secrets.token_bytes(32)
        self.manifest = manifest
        self.process = None
        self.responses = queue.Queue(maxsize=1)
        self.sealed = False
        self.sequence = 0
        try:
            self.process = subprocess.Popen(
                [sys.executable, "-m", "octoberblue.ticket_witness_worker"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                bufsize=-1,
            )
            threading.Thread(target=self._read, daemon=True).start()
            initial = {"operation": "initialize", "manifest": manifest.to_wire(),
                       "key": self.key.hex(), "ticket_id": ticket_id, "account_id": account_id}
            if audit_signing_key is not None:
                initial["audit_signing_key"] = audit_signing_key.hex()
            response = self._rpc(initial)
            if response != {"ready": True}:
                raise WitnessError("witness_initialization_failed")
        except (OSError, WitnessError):
            self.close()
            raise WitnessError("witness_unavailable") from None

    def _read(self):
        try:
            while True:
                raw = self.process.stdout.readline(MAX_PACKET_BYTES + 1)
                self.responses.put(raw)
                if not raw or len(raw) > MAX_PACKET_BYTES:
                    return
        except (OSError, ValueError):
            self.responses.put(b"")

    def _rpc(self, request):
        if self.sealed:
            raise WitnessError("witness_already_sealed")
        try:
            self.sequence += 1
            operation = request["operation"]
            if operation == "initialize":
                run = RunRequestV1.from_wire({
                    "schema_version": "1.0", "manifest": request["manifest"],
                    "ticket_id": request["ticket_id"], "account_id": request["account_id"],
                })
                parameters = {"run": run.to_wire(), "credentials": {
                    "authentication_key": request["key"],
                    "audit_signing_key": request.get("audit_signing_key"),
                }}
            else:
                parameters = {k: v for k, v in request.items() if k != "operation"}
            envelope = {"schema_version": "1.0", "sequence": self.sequence,
                        "operation": operation, "parameters": parameters}
            witness_request(envelope, sequence=self.sequence)
            raw = canonical(envelope) + b"\n"
            if len(raw) > MAX_PACKET_BYTES:
                raise WitnessError("witness_request_limit")
            self.process.stdin.write(raw)
            self.process.stdin.flush()
            response = decode(self.responses.get(timeout=5))
            return witness_response(response, sequence=self.sequence)
        except (OSError, ValueError, TypeError, queue.Empty, RecursionError):
            raise WitnessError("witness_transport_failed") from None

    def _collect(self, request):
        response = self._rpc(request)
        if type(response) is not dict or set(response) != {"events"}:
            raise WitnessError("invalid_witness_response")
        events = response["events"]
        if type(events) is not list or not 1 <= len(events) <= 2:
            raise WitnessError("invalid_witness_events")
        for index, event in enumerate(events, len(self.events) + 1):
            try:
                validate_event(event)
                if event["event_id"] != f"{self.manifest.run_id}:{index:04}":
                    raise ValueError("uncorrelated trace event")
            except (ValueError, TypeError, KeyError):
                raise WitnessError("invalid_witness_events") from None
        self.events.extend(events)
        return events

    def emit(self, origin, kind, **detail):
        events = self._collect({"operation": "record", "origin": origin,
                                "kind": kind, "detail": detail})
        return events[-1]["event_id"]

    def call(self, tool, args):
        events = self._collect({"operation": "call", "tool": tool, "arguments": args})
        return events[-1]["kind"] == "tool_executed"

    def finalize(self):
        evidence = self._rpc({"operation": "finalize"})
        self.sealed = True
        if self.audit_public_key is not None:
            from .ticket_audit import AuditError, authenticate_pack
            from .ticket_contracts import digest
            try:
                if type(evidence) is not dict or set(evidence) != {"evidence", "audit_pack"}:
                    raise WitnessError("missing_acquisition_signature")
                body = authenticate_pack(evidence["audit_pack"], self.audit_public_key,
                                         digest(self.manifest.to_wire()))
                if body != evidence["evidence"]["body"]:
                    raise WitnessError("acquisition_signature_mismatch")
                self.audit_pack = evidence["audit_pack"]
                evidence = evidence["evidence"]
            except (AuditError, KeyError, TypeError):
                raise WitnessError("invalid_acquisition_signature") from None
        return evidence

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
            for pipe in (self.process.stdin, self.process.stdout):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        # Closing buffered stdin may flush into an already dead
                        # witness. Cleanup must preserve the indeterminate result.
                        pass
        self.key = b""
