"""Read AgentDojo's native per-task result JSON as untrusted external observations.

This module imports neither AgentDojo nor a model provider. Its output is
deliberately not an OctoberBlue Outcome or a verifier-issued verdict. It
discards messages, injection payloads, tool calls, raw errors and other
potentially sensitive trace contents. See docs/COMPATIBILITY.md.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

MAX_FILE_BYTES = 2_000_000
MAX_FILES = 500
MAX_TOTAL_BYTES = 20_000_000
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,254}\Z")


class AgentDojoFormatError(ValueError):
    """A file cannot be admitted as an AgentDojo observation."""


@dataclass(frozen=True)
class AgentDojoObservation:
    schema_version: Literal["1.0"]
    source_framework: Literal["agentdojo"]
    evidence_class: Literal["external_report_only"]
    verifier_verdict: Literal["indeterminate"]
    source_sha256: str
    source_file: str
    suite_name: str
    pipeline_name: str
    user_task_id: str
    injection_task_id: str | None
    attack_type: str | None
    has_injection: bool
    has_error: bool
    reported_utility: bool | None
    reported_security: bool | None
    reported_attack_success: bool | None

    def to_wire(self) -> dict:
        return asdict(self)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AgentDojoFormatError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_number(_: str) -> None:
    raise AgentDojoFormatError("invalid JSON number")


def _name(record: dict, key: str, *, nullable: bool = False) -> str | None:
    value = record.get(key)
    if nullable and value is None:
        return None
    if type(value) is not str or not _NAME.fullmatch(value):
        raise AgentDojoFormatError(f"invalid {key}")
    return value


def parse_agentdojo_result(raw: bytes, *, source_file: str) -> AgentDojoObservation:
    """Summarize one native TaskResults JSON file, without regrading any claims."""
    if not 0 < len(raw) <= MAX_FILE_BYTES:
        raise AgentDojoFormatError("result exceeds import size limit")
    try:
        record = json.loads(raw, object_pairs_hook=_unique_keys, parse_constant=_invalid_number)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AgentDojoFormatError("malformed result JSON") from error
    if type(record) is not dict:
        raise AgentDojoFormatError("result must be a JSON object")
    required = {
        "suite_name", "pipeline_name", "user_task_id", "injection_task_id",
        "attack_type", "injections", "messages", "error",
    }
    if not required <= set(record):
        raise AgentDojoFormatError("missing native AgentDojo result fields")
    if type(record["injections"]) is not dict or type(record["messages"]) is not list:
        raise AgentDojoFormatError("invalid native AgentDojo evidence structure")
    if any(type(value) is not str for value in record["injections"].values()):
        raise AgentDojoFormatError("malformed injection payload references")
    error = record["error"]
    if error is not None and type(error) is not str:
        raise AgentDojoFormatError("invalid error field")
    suite = _name(record, "suite_name")
    pipeline = _name(record, "pipeline_name")
    user = _name(record, "user_task_id")
    injection = _name(record, "injection_task_id", nullable=True)
    attack = _name(record, "attack_type", nullable=True)
    if (injection is None) != (attack is None):
        raise AgentDojoFormatError("inconsistent injection task and attack type")
    if injection is None and record["injections"]:
        raise AgentDojoFormatError("injections supplied for clean task")
    utility = record.get("utility")
    security = record.get("security")
    if utility is not None and type(utility) is not bool:
        raise AgentDojoFormatError("invalid utility score")
    if security is not None and type(security) is not bool:
        raise AgentDojoFormatError("invalid security score")
    # Partial and errored logs are not scored. Never turn absent evidence into True/False.
    scored = error is None and type(utility) is bool and type(security) is bool
    has_injection = injection is not None
    return AgentDojoObservation(
        schema_version="1.0",
        source_framework="agentdojo",
        evidence_class="external_report_only",
        verifier_verdict="indeterminate",
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_file=source_file,
        suite_name=suite,
        pipeline_name=pipeline,
        user_task_id=user,
        injection_task_id=injection,
        attack_type=attack,
        has_injection=has_injection,
        has_error=error is not None or not scored,
        reported_utility=utility if scored else None,
        reported_security=security if scored else None,
        reported_attack_success=(not security) if scored and has_injection else None,
    )


def import_agentdojo_results(path: str | Path) -> tuple[AgentDojoObservation, ...]:
    """Read one result JSON or a bounded directory tree without following symlinks."""
    root = Path(path)
    if root.is_symlink() or not root.exists():
        raise AgentDojoFormatError("missing or linked result path")
    if root.is_file():
        if root.suffix.lower() != ".json":
            raise AgentDojoFormatError("expected JSON result file")
        candidates = [root]
    elif root.is_dir():
        # rglob does not traverse a symlink to a directory; reject symlink files too.
        candidates = sorted(root.rglob("*.json"))
    else:
        raise AgentDojoFormatError("unsupported source path")
    if not 1 <= len(candidates) <= MAX_FILES:
        raise AgentDojoFormatError("empty or excessive result collection")
    observations = []
    seen = set()
    total_bytes = 0
    for file in candidates:
        if file.is_symlink() or not file.is_file():
            raise AgentDojoFormatError("linked or invalid result file")
        size = file.stat().st_size
        total_bytes += size
        if size > MAX_FILE_BYTES or total_bytes > MAX_TOTAL_BYTES:
            raise AgentDojoFormatError("result collection exceeds import size limit")
        raw = file.read_bytes()
        relative = file.name if root.is_file() else file.relative_to(root).as_posix()
        observation = parse_agentdojo_result(raw, source_file=relative)
        key = (observation.suite_name, observation.pipeline_name,
               observation.user_task_id, observation.injection_task_id,
               observation.attack_type)
        if key in seen:
            raise AgentDojoFormatError("duplicate native AgentDojo run identity")
        seen.add(key)
        observations.append(observation)
    return tuple(observations)
