"""Opt-in Docker target execution with a host-owned, policy-checked gateway.

Docker isolates the *toy target proposal generator* from the trusted Python
harness. Target results remain untrusted. There are no host mounts, network
access, privileged flags, Docker-socket mounts, or runtime provider calls.

The Docker daemon/image supply chain and Linux kernel are outside this module's
security proof. This is not authorization to execute arbitrary malicious code.
"""
from __future__ import annotations

import json
import re
import subprocess
import uuid

from .process_boundary import ProcessBoundaryError, run_bounded
from .target_worker import MAX_REQUEST_BYTES, PROTOCOL

MAX_RESPONSE_BYTES = 16_384
_DEFAULT_IMAGE = "octoberblue-target:v0.2"
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
_TOOL = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate response key")
        value[key] = item
    return value


def _reject_constant(_: str) -> None:
    raise ValueError("invalid JSON constant")


class TargetRuntimeError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _cleanup(name: str) -> None:
    # On timeout, the Docker daemon may have retained a running container.
    try:
        subprocess.run(
            ["docker", "rm", "--force", name], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def propose_in_container(
    *,
    visible_payload: str,
    source_total: str,
    run_legitimate_task: bool,
    image: str = _DEFAULT_IMAGE,
    timeout: float = 12.0,
) -> tuple[tuple[str, dict], ...]:
    """Return proposed calls; never execute a returned tool without the gateway."""
    return _propose_request(
        {"protocol": PROTOCOL, "visible_payload": visible_payload,
         "source_total": source_total, "run_legitimate_task": run_legitimate_task},
        image=image, timeout=timeout,
    )


def _propose_request(
    request: dict, *, image: str, timeout: float = 12.0,
    ticket: bool = False,
) -> tuple[tuple[str, dict], ...]:
    """Shared restricted transport; callers select a fixed worker, never target code."""
    if image != _DEFAULT_IMAGE and (
        type(image) is not str or not _DIGEST.fullmatch(image)
    ):
        raise ValueError("use the local tagged image or a pinned sha256 image ID")
    protocol = request["protocol"]
    request = json.dumps(request, allow_nan=False, separators=(",", ":"))
    if len(request.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise TargetRuntimeError("target_input_too_large")

    name = "octoberblue-target-" + uuid.uuid4().hex
    command = [
        "docker", "run", "--rm", "--interactive", "--pull=never",
        "--name=" + name,
        "--network=none", "--ipc=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
        "--security-opt=seccomp=builtin", "--user=65534:65534",
        "--memory=128m", "--memory-swap=128m", "--cpus=0.5",
        "--pids-limit=32", "--ulimit=nofile=64:64",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=8m",
        image, "python", "-m", ("octoberblue.ticket_target_worker" if ticket
                                else "octoberblue.target_worker"),
    ]
    try:
        completed = run_bounded(command, input=request.encode("utf-8"), timeout=timeout,
                                stdout_limit=MAX_RESPONSE_BYTES, stderr_limit=4096)
    except ProcessBoundaryError as error:
        _cleanup(name)
        reason = {"process_timeout": "target_timeout", "stdout_limit": "target_output_too_large",
                  "stderr_limit": "target_stderr_too_large",
                  "process_unavailable": "docker_unavailable"}.get(
                      error.reason_code, "invalid_target_response")
        raise TargetRuntimeError(reason) from None
    if len(completed.stdout) > MAX_RESPONSE_BYTES or len(completed.stderr) > 4096:
        _cleanup(name)
        raise TargetRuntimeError("target_output_too_large")
    if completed.returncode != 0:
        _cleanup(name)
        raise TargetRuntimeError("target_nonzero_exit")

    try:
        response = json.loads(
            completed.stdout, object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
        if type(response) is not dict or set(response) != {"protocol", "proposals"}:
            raise ValueError("invalid target response shape")
        if response["protocol"] != protocol:
            raise ValueError("wrong target protocol")
        proposals = response["proposals"]
        if type(proposals) is not list or len(proposals) > (6 if ticket else 3):
            raise ValueError("invalid proposal count")
        result = []
        for item in proposals:
            if type(item) is not dict or set(item) != {"tool", "arguments"}:
                raise ValueError("invalid proposal shape")
            tool = item["tool"]
            args = item["arguments"]
            if (
                type(tool) is not str or not _TOOL.fullmatch(tool)
                or type(args) is not dict
                or any(type(key) is not str for key in args)
            ):
                raise ValueError("invalid proposed tool")
            result.append((tool, args))
        return tuple(result)
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise TargetRuntimeError("invalid_target_response") from error


def resolve_image_id(image: str) -> str:
    """Resolve the operator-selected local image once; execute only its immutable ID."""
    if image != _DEFAULT_IMAGE and (type(image) is not str or not _DIGEST.fullmatch(image)):
        raise ValueError("use the local tagged image or a pinned sha256 image ID")
    try:
        response = run_bounded(
            ["docker", "image", "inspect", "--format={{.Id}}", image],
            timeout=5, stdout_limit=128, stderr_limit=4096,
        )
        value = response.stdout.decode("utf-8").strip()
        if response.returncode != 0 or not _DIGEST.fullmatch(value):
            raise TargetRuntimeError("image_identity_unavailable")
        return value
    except (ProcessBoundaryError, UnicodeError) as error:
        raise TargetRuntimeError("image_identity_unavailable") from error
