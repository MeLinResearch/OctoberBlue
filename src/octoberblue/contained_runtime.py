"""Strict no-mount, no-network Docker boundary for fixed trusted verification code."""
from __future__ import annotations

import json
import re
import uuid

from .process_boundary import ProcessBoundaryError, run_bounded
from .target_runtime import _cleanup

TRUSTED_IMAGE = "octoberblue-trusted:v0.2"
PROFILE = "docker-json-v1"
_MODULES = frozenset({"octoberblue.ticket_verifier_worker", "octoberblue.ticket_audit_worker",
                      "octoberblue.containment_probe"})


def container_command(image_id, module, name):
    if (type(image_id) is not str or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id)
            or module not in _MODULES):
        raise ValueError("unapproved contained worker identity")
    args = [
        "docker", "run", "--rm", "--interactive", "--pull=never", "--name=" + name,
        "--network=none", "--ipc=none", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true", "--security-opt=seccomp=builtin",
        "--user=65534:65534", "--memory=256m", "--memory-swap=256m", "--cpus=1",
        "--pids-limit=32", "--ulimit=nofile=64:64", "--tmpfs=/tmp:rw,noexec,nosuid,size=8m",
        "--workdir=/tmp",
    ]
    # Docker client proxy defaults must not introduce credentials/configuration
    # into a runtime that has no authorized outbound network activity.
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                     "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        args.extend(("--env", variable + "="))
    return [*args, image_id, "python", "-I", "-B", "-m", module]


def run_contained_worker(module, *, image_id, input, timeout=12, stdout_limit=2048):
    name = "octoberblue-verifier-" + uuid.uuid4().hex
    command = container_command(image_id, module, name)
    try:
        result = run_bounded(command, input=input, timeout=timeout,
                             stdout_limit=stdout_limit, stderr_limit=4096)
        if result.returncode != 0:
            raise ProcessBoundaryError("contained_worker_failed")
        return result
    finally:
        _cleanup(name)


def probe_container(image_id, *, target, host_sentinel):
    from .target_runtime import target_command

    name = "octoberblue-probe-" + uuid.uuid4().hex
    command = (target_command(image_id, name, "octoberblue.containment_probe") if target else
               container_command(image_id, "octoberblue.containment_probe", name))
    request = {"host_sentinel": str(host_sentinel),
               "memory_limit": (128 if target else 256) * 1024 * 1024,
               "cpu_limit": 0.5 if target else 1}
    try:
        result = run_bounded(command, input=json.dumps(request).encode(), timeout=12,
                             stdout_limit=4096, stderr_limit=4096)
        if result.returncode != 0:
            raise ProcessBoundaryError("containment_probe_failed")
        report = json.loads(result.stdout)
        expected = {"memory_limit_enforced", "pids_limit_enforced", "cpu_limit_enforced",
                    "non_root", "read_only_root", "no_new_privileges",
                    "no_effective_capabilities", "private_tmp_noexec", "outbound_blocked",
                    "host_sentinel_hidden", "docker_socket_hidden", "ambient_secret_absent"}
        if type(report) is not dict or set(report) != expected or any(
            type(value) is not bool for value in report.values()
        ):
            raise ProcessBoundaryError("invalid_containment_probe")
        return report
    finally:
        _cleanup(name)
