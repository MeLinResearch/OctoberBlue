"""Strict v1 attack/defense wire contracts for offline synthetic evaluation.

The JSON Schema files in schemas/ describe the same fields. Parsing is deliberately
implemented with the standard library so the zero-dollar core has no dependencies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from .contracts import Defense

VERSION = "1.0"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_SOURCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:/._-]{0,255}\Z")
_SURFACES = ("retrieved_document", "tool_result")


def _exact_keys(value: object, keys: set[str]) -> None:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("unknown, missing, or malformed contract fields")


@dataclass(frozen=True)
class AttackWireV1:
    attack_id: str
    surface: Literal["retrieved_document", "tool_result"]
    payload: str
    source_id: str
    schema_version: str = VERSION

    def __post_init__(self) -> None:
        if self.schema_version != VERSION:
            raise ValueError("unsupported attack contract version")
        if type(self.attack_id) is not str or not _IDENTIFIER.fullmatch(self.attack_id):
            raise ValueError("invalid attack_id")
        if self.surface not in _SURFACES:
            raise ValueError("undeclared delivery surface")
        if type(self.payload) is not str or not 1 <= len(self.payload) <= 10_000:
            raise ValueError("invalid attack payload")
        if type(self.source_id) is not str or not _SOURCE.fullmatch(self.source_id):
            raise ValueError("invalid source_id")

    @classmethod
    def from_wire(cls, value: object) -> AttackWireV1:
        _exact_keys(value, {"schema_version", "attack_id", "surface", "payload", "source_id"})
        return cls(
            attack_id=value["attack_id"],
            surface=value["surface"],
            payload=value["payload"],
            source_id=value["source_id"],
            schema_version=value["schema_version"],
        )

    def to_wire(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "attack_id": self.attack_id,
            "surface": self.surface,
            "payload": self.payload,
            "source_id": self.source_id,
        }

    def to_case(self):
        from .benchmark import BenchmarkCase

        return BenchmarkCase(
            self.attack_id, self.surface, self.payload, source_id=self.source_id,
        )


@dataclass(frozen=True)
class DefenseWireV1:
    defense_id: str
    suspicious_markers: tuple[str, ...]
    schema_version: str = VERSION

    def __post_init__(self) -> None:
        if self.schema_version != VERSION:
            raise ValueError("unsupported defense contract version")
        if type(self.defense_id) is not str or not _IDENTIFIER.fullmatch(self.defense_id):
            raise ValueError("invalid defense_id")
        markers = self.suspicious_markers
        if (
            type(markers) is not tuple
            or not 1 <= len(markers) <= 20
            or any(type(m) is not str or not 1 <= len(m) <= 200 for m in markers)
            or len(set(markers)) != len(markers)
        ):
            raise ValueError("invalid defense markers")

    @classmethod
    def from_wire(cls, value: object) -> DefenseWireV1:
        _exact_keys(value, {"schema_version", "defense_id", "suspicious_markers"})
        if type(value["suspicious_markers"]) is not list:
            raise ValueError("markers must be an array")
        return cls(
            defense_id=value["defense_id"],
            suspicious_markers=tuple(value["suspicious_markers"]),
            schema_version=value["schema_version"],
        )

    def to_wire(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "defense_id": self.defense_id,
            "suspicious_markers": list(self.suspicious_markers),
        }

    def to_defense(self) -> Defense:
        return Defense(self.defense_id, suspicious_markers=self.suspicious_markers)
