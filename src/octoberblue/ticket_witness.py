"""Private-pipe client for the trusted state-owning ticket witness."""
from __future__ import annotations

import queue
import secrets
import subprocess
import sys
import threading

from .ticket_evidence import MAX_PACKET_BYTES, RunManifestV1, canonical, decode


class WitnessError(RuntimeError):
    pass


class TicketWitness:
    def __init__(self, manifest: RunManifestV1, ticket_id: str, account_id: str):
        self.events = []
        self.key = secrets.token_bytes(32)
        self.manifest = manifest
        self.process = None
        self.responses = queue.Queue(maxsize=1)
        self.sealed = False
        try:
            self.process = subprocess.Popen(
                [sys.executable, "-m", "octoberblue.ticket_witness_worker"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                bufsize=-1,
            )
            threading.Thread(target=self._read, daemon=True).start()
            response = self._rpc({"operation": "initialize", "manifest": manifest.to_wire(),
                                  "key": self.key.hex(), "ticket_id": ticket_id,
                                  "account_id": account_id})
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
            raw = canonical(request) + b"\n"
            if len(raw) > MAX_PACKET_BYTES:
                raise WitnessError("witness_request_limit")
            self.process.stdin.write(raw)
            self.process.stdin.flush()
            return decode(self.responses.get(timeout=5))
        except (OSError, ValueError, TypeError, queue.Empty, RecursionError):
            raise WitnessError("witness_transport_failed") from None

    def _collect(self, request):
        response = self._rpc(request)
        if type(response) is not dict or set(response) != {"events"}:
            raise WitnessError("invalid_witness_response")
        events = response["events"]
        if type(events) is not list or not 1 <= len(events) <= 2:
            raise WitnessError("invalid_witness_events")
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
                    pipe.close()
        self.key = b""
