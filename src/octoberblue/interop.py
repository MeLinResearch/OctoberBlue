"""Conservative data-only interchange with Promptfoo test-case JSON.

This does NOT transfer trusted verdicts, grant tool permissions, create a
provider configuration, or execute a third-party evaluator. A human must
configure an authorized external target before running exported fixtures.
"""
from __future__ import annotations

from collections.abc import Iterable

from .wire import AttackWireV1


def to_promptfoo_tests(attacks: Iterable[AttackWireV1]) -> list[dict]:
    """Export tagged test cases accepted by Promptfoo's JSON test loader."""
    rows = []
    seen = set()
    for attack in attacks:
        if type(attack) is not AttackWireV1:
            raise ValueError("expected validated AttackWireV1 objects")
        if attack.attack_id in seen:
            raise ValueError("duplicate attack_id")
        seen.add(attack.attack_id)
        rows.append({
            "description": f"OctoberBlue fixture: {attack.attack_id}",
            "vars": {"input": attack.payload},
            "metadata": {"octoberblue": {
                "schema_version": attack.schema_version,
                "attack_id": attack.attack_id,
                "surface": attack.surface,
                "source_id": attack.source_id,
                "untrusted": True,
            }},
        })
    if not rows:
        raise ValueError("at least one attack required")
    return rows


def from_promptfoo_tests(rows: object) -> tuple[AttackWireV1, ...]:
    """Import only OctoberBlue-tagged tests, never external assertion/verdict claims."""
    if type(rows) is not list or not 1 <= len(rows) <= 1000:
        raise ValueError("invalid Promptfoo tests array")
    result = []
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row) != {"description", "vars", "metadata"}:
            raise ValueError("unsupported Promptfoo test structure")
        variables = row["vars"]
        meta = row["metadata"]
        if type(variables) is not dict or set(variables) != {"input"}:
            raise ValueError("unsupported Promptfoo variables")
        if type(meta) is not dict or set(meta) != {"octoberblue"}:
            raise ValueError("missing OctoberBlue metadata")
        data = meta["octoberblue"]
        if type(data) is not dict or set(data) != {
            "schema_version", "attack_id", "surface", "source_id", "untrusted",
        } or data["untrusted"] is not True:
            raise ValueError("invalid OctoberBlue provenance metadata")
        artifact = AttackWireV1.from_wire({
            "schema_version": data["schema_version"],
            "attack_id": data["attack_id"],
            "surface": data["surface"],
            "source_id": data["source_id"],
            "payload": variables["input"],
        })
        if artifact.attack_id in seen:
            raise ValueError("duplicate attack_id")
        seen.add(artifact.attack_id)
        result.append(artifact)
    return tuple(result)
