"""Bounded process I/O and sanitized startup for fixed trusted workers.

These controls are not an OS sandbox or authorization to run hostile host code.
The Docker target's containment and named-container cleanup remain separate.
"""
from __future__ import annotations

import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

_CHUNK = 4096
_WORKERS = frozenset({
    "octoberblue.verifier_worker", "octoberblue.ticket_verifier_worker",
    "octoberblue.ticket_audit_worker", "octoberblue.ticket_witness_worker",
})


class ProcessBoundaryError(RuntimeError):
    """Fixed reason only; captured output and input never appear in exceptions."""

    def __init__(self, reason_code):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _stop(process):
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        # No shell/PATH lookup. Windows tree cleanup is best-effort; this is not
        # a Job Object sandbox or containment for arbitrary native programs.
        system_root = os.environ.get("SystemRoot")
        if system_root:
            helper = None
            try:
                helper = subprocess.Popen(
                    [str(Path(system_root) / "System32" / "taskkill.exe"),
                     "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                helper.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                if helper is not None and helper.poll() is None:
                    helper.kill()
            finally:
                if helper is not None:
                    try:
                        helper.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
        if process.poll() is None:
            process.kill()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def run_bounded(command, *, input: bytes = b"", timeout: float,
                stdout_limit: int, stderr_limit: int = 4096, env=None, cwd=None) -> ProcessResult:
    """Stop at limit+1 bytes while streaming; include stdin stalls in the deadline.

    Drain stdout/stderr concurrently. Reader memory is capped independently per
    pipe, including a single overflow byte. No partial output is returned on error.
    """
    if (type(input) is not bytes or type(timeout) not in (int, float)
            or not math.isfinite(timeout) or timeout <= 0
            or any(type(n) is not int or n < 0 for n in (stdout_limit, stderr_limit))):
        raise ValueError("invalid process boundary configuration")
    deadline = time.monotonic() + timeout
    failure = []
    lock = threading.Lock()
    wake = threading.Event()
    done = [threading.Event() for _ in range(3)]
    buffers = [bytearray(), bytearray()]

    def fail(reason):
        with lock:
            if not failure:
                failure.append(reason)
        wake.set()

    flags = {"start_new_session": True} if os.name == "posix" else {
        "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP,
    }
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, close_fds=True, env=env, cwd=cwd, **flags,
        )
    except OSError:
        raise ProcessBoundaryError("process_unavailable") from None

    def read(index, pipe, limit):
        try:
            while True:
                chunk = pipe.read(min(_CHUNK, limit + 1 - len(buffers[index])))
                if not chunk:
                    return
                buffers[index].extend(chunk)
                if len(buffers[index]) > limit:
                    fail("stdout_limit" if index == 0 else "stderr_limit")
                    return
        except (OSError, ValueError):
            fail("process_io_failed")
        finally:
            done[index].set()
            wake.set()

    def write():
        try:
            remaining = memoryview(input)
            while remaining:
                count = process.stdin.write(remaining)
                if not count:
                    raise OSError("closed input")
                remaining = remaining[count:]
            process.stdin.close()
        except (OSError, ValueError):
            fail("process_input_failed")
        finally:
            done[2].set()
            wake.set()

    threads = [threading.Thread(target=read, args=(0, process.stdout, stdout_limit), daemon=True),
               threading.Thread(target=read, args=(1, process.stderr, stderr_limit), daemon=True),
               threading.Thread(target=write, daemon=True)]
    try:
        for thread in threads:
            thread.start()
        while True:
            wake.clear()
            if failure:
                raise ProcessBoundaryError(failure[0])
            if process.poll() is not None and all(event.is_set() for event in done):
                # A reader can report overflow between the first failure check
                # and child exit. All producers are finished before this check.
                if failure:
                    raise ProcessBoundaryError(failure[0])
                return ProcessResult(process.returncode, bytes(buffers[0]), bytes(buffers[1]))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProcessBoundaryError("process_timeout")
            wake.wait(min(remaining, 0.02))
    finally:
        # Also stop POSIX descendants after the direct child exits or closes its
        # pipes. Session cleanup does not depend on the leader remaining alive.
        _stop(process)
        for pipe in (process.stdin, process.stdout, process.stderr):
            try:
                pipe.close()
            except OSError:
                pass
        for thread in threads:
            thread.join(timeout=0.2)


def worker_command(module):
    if module not in _WORKERS:
        raise ValueError("unapproved trusted worker")
    # -I rejects ambient PYTHONPATH/PYTHONHOME, cwd imports and user site startup.
    # -B avoids writing bytecode into the trusted source tree.
    return [sys.executable, "-I", "-B", "-m", module]


def worker_environment(workspace):
    env = {name: os.environ[name] for name in ("SystemRoot", "WINDIR") if name in os.environ}
    env.update({"TMPDIR": workspace, "TEMP": workspace, "TMP": workspace})
    return env


def run_trusted_worker(module, *, input: bytes, timeout: float, stdout_limit=2048):
    with tempfile.TemporaryDirectory(prefix="octoberblue-verifier-") as workspace:
        return run_bounded(worker_command(module), input=input, timeout=timeout,
                           stdout_limit=stdout_limit, stderr_limit=4096,
                           env=worker_environment(workspace), cwd=workspace)
