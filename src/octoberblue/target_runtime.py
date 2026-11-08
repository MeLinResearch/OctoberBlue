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

from .target_worker import MAX_REQUEST_BYTES, PROTOCOL

MAX_RESPONSE_BYTES = 16_384
_DEFAULT_IMAGE = "octoberblue-target:v0.2"
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
_TOOL = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class TargetRuntimeError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _cleanup(name: str) -> None:
    # On timeout, the Docker daemon may have retained a running container.
    try:
        subprocess.run(
            ["docker", "rm", "--force", name], capture_output=True, text=True,
            encoding="utf-8", timeout=4, check=False,
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
    if image != _DEFAULT_IMAGE and (
        type(image) is not str or not _DIGEST.fullmatch(image)
    ):
        raise ValueError("use the local tagged image or a pinned sha256 image ID")
    request = json.dumps({
        "protocol": PROTOCOL,
        "visible_payload": visible_payload,
        "source_total": source_total,
        "run_legitimate_task": run_legitimate_task,
    }, allow_nan=False, separators=(",", ":"))
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
        image, "python", "-m", "octoberblue.target_worker",
    ]
    try:
        completed = subprocess.run(
            command, input=request, capture_output=True, text=True,
            encoding="utf-8", check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        _cleanup(name)
        raise TargetRuntimeError("target_timeout") from error
    except OSError as error:
        raise TargetRuntimeError("docker_unavailable") from error
    if completed.returncode != 0:
        raise TargetRuntimeError("target_nonzero_exit")
    if len(completed.stdout.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise TargetRuntimeError("target_output_too_large")

    try:
        response = json.loads(completed.stdout)
        if type(response) is not dict or set(response) != {"protocol", "proposals"}:
            raise ValueError("invalid target response shape")
        if response["protocol"] != PROTOCOL:
            raise ValueError("wrong target protocol")
        proposals = response["proposals"]
        if type(proposals) is not list or len(proposals) > 3:
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
    except (ValueError, TypeError, UnicodeError) as error:
        raise TargetRuntimeError("invalid_target_response") from error
