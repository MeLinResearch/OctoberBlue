"""Private-pipe client for the trusted state-owning ticket witness."""
from __future__ import annotations

import os
import queue
import secrets
import subprocess
import tempfile
import threading
import time

from .process_boundary import _stop, worker_command, worker_environment
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
                 *, audit_signing_key: bytes | None = None, rpc_timeout: float = 5.0):
        if type(rpc_timeout) not in (int, float) or not 0 < rpc_timeout <= 60:
            raise ValueError("invalid witness deadline")
        self.rpc_timeout = rpc_timeout
        self.workspace = None
        self._closed = False
        self._failed = threading.Event()
        self._read_done = threading.Event()
        self._writers = []
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
            self.workspace = tempfile.TemporaryDirectory(prefix="octoberblue-witness-")
            flags = {"start_new_session": True} if os.name == "posix" else {
                "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP,
            }
            self.process = subprocess.Popen(
                worker_command("octoberblue.ticket_witness_worker"),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                bufsize=0, close_fds=True, cwd=self.workspace.name,
                env=worker_environment(self.workspace.name), **flags,
            )
            self._reader = threading.Thread(target=self._read, daemon=True)
            self._reader.start()
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
                if not raw:
                    return
                if len(raw) > MAX_PACKET_BYTES or not raw.endswith(b"\n"):
                    self._failed.set()
                    return
                self.responses.put_nowait(raw)
        except (OSError, ValueError, queue.Full):
            self._failed.set()
        finally:
            self._read_done.set()

    def _rpc(self, request):
        if self.sealed or self._closed:
            raise WitnessError("witness_already_sealed")
        deadline = time.monotonic() + self.rpc_timeout
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
            written = threading.Event()

            def send():
                try:
                    remaining = memoryview(raw)
                    while remaining:
                        count = self.process.stdin.write(remaining)
                        if not count:
                            raise OSError("closed witness input")
                        remaining = remaining[count:]
                    self.process.stdin.flush()
                except (OSError, ValueError):
                    self._failed.set()
                finally:
                    written.set()

            writer = threading.Thread(target=send, daemon=True)
            self._writers.append(writer)
            writer.start()
            if not written.wait(max(0, deadline - time.monotonic())) or self._failed.is_set():
                raise WitnessError("witness_write_failed")
            while True:
                if self._failed.is_set():
                    raise WitnessError("witness_stream_failed")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WitnessError("witness_deadline")
                try:
                    response = decode(self.responses.get(timeout=min(remaining, 0.05)))
                    break
                except queue.Empty:
                    if self._read_done.is_set():
                        raise WitnessError("witness_early_eof") from None
            result = witness_response(response, sequence=self.sequence)
            if operation == "finalize":
                self.process.wait(timeout=max(0.001, deadline - time.monotonic()))
                if (not self._read_done.wait(max(0, deadline - time.monotonic()))
                        or self.process.returncode != 0 or self._failed.is_set()
                        or not self.responses.empty()):
                    raise WitnessError("witness_unclean_seal")
            return result
        except (OSError, ValueError, TypeError, RecursionError,
                subprocess.TimeoutExpired, WitnessError):
            self.close()
            raise WitnessError("witness_transport_failed") from None

    def _collect(self, request):
        try:
            return self._collect_checked(request)
        except (WitnessError, ValueError, TypeError, KeyError):
            self.close()
            raise

    def _collect_checked(self, request):
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
        if getattr(self, "_closed", False):
            return
        self._closed = True
        try:
            if self.process is not None:
                try:
                    _stop(self.process)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                for pipe in (self.process.stdin, self.process.stdout):
                    if pipe is not None:
                        try:
                            pipe.close()
                        except OSError:
                            pass
            for writer in getattr(self, "_writers", ()):
                writer.join(timeout=0.2)
            reader = getattr(self, "_reader", None)
            if reader is not None:
                reader.join(timeout=0.2)
        finally:
            self.key = b""
            workspace = getattr(self, "workspace", None)
            if workspace is not None:
                workspace.cleanup()
