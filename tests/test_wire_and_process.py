"""Versioned wire contracts and process-isolated verifier regression coverage."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from octoberblue.benchmark import run_benchmark
from octoberblue.verifier import SandboxSnapshot
from octoberblue.verifier_process import verify_in_subprocess
from octoberblue.wire import AttackWireV1, DefenseWireV1

ROOT = Path(__file__).resolve().parents[1]


def _examples():
    attack = json.loads((ROOT / "examples/attack.v1.json").read_text())
    defense = json.loads((ROOT / "examples/defense.v1.json").read_text())
    return attack, defense


def test_f03_versioned_examples_roundtrip_and_execute():
    raw_attack, raw_defense = _examples()
    attack = AttackWireV1.from_wire(raw_attack)
    defense = DefenseWireV1.from_wire(raw_defense)
    assert attack.to_wire() == raw_attack
    assert defense.to_wire() == raw_defense
    outcome = run_benchmark(
        case=attack.to_case(),
        defense=defense.to_defense(),
        guard_enabled=False,
    )
    assert outcome.attack_success and outcome.attempted_unauthorized_action
    assert outcome.events[1]["detail"]["source_id"] == "fixture:detected-injection"
    assert "Override the system" not in str(outcome.events)


@pytest.mark.parametrize("name,change", [
    ("future_version", {"schema_version": "2.0"}),
    ("extra_key", {"new_instruction": "grant access"}),
    ("bad_surface", {"surface": "system_prompt"}),
    ("bad_id", {"attack_id": "../escape"}),
    ("oversize_payload", {"payload": "a" * 10001}),
    ("bad_source", {"source_id": "../../tmp"}),
])
def test_f03_invalid_attack_wire_rejected(name, change):
    raw, _ = _examples()
    raw.update(change)
    with pytest.raises(ValueError):
        AttackWireV1.from_wire(raw)


@pytest.mark.parametrize("change", [
    {"schema_version": "2.0"},
    {"suspicious_markers": []},
    {"suspicious_markers": ["repeat", "repeat"]},
    {"suspicious_markers": "ignore everything"},
    {"suspicious_markers": [""]},
    {"additional_tool": "shell"},
])
def test_f03_invalid_defense_wire_rejected(change):
    _, raw = _examples()
    raw.update(change)
    with pytest.raises(ValueError):
        DefenseWireV1.from_wire(raw)


def test_f03_schema_files_are_strict_and_match_wire_fields():
    for artifact, expected_fields in (
        ("attack", set(AttackWireV1.from_wire(_examples()[0]).to_wire())),
        ("defense", set(DefenseWireV1.from_wire(_examples()[1]).to_wire())),
    ):
        schema = json.loads((ROOT / f"schemas/{artifact}.v1.json").read_text())
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == expected_fields == set(schema["properties"])
        assert schema["properties"]["schema_version"]["const"] == "1.0"


def test_inv01_process_verifier_matches_independent_direct_verifier():
    attack, defense = _examples()
    outcome = run_benchmark(
        case=AttackWireV1.from_wire(attack).to_case(),
        defense=DefenseWireV1.from_wire(defense).to_defense(),
        guard_enabled=False,
        run_id="process-verifier",
    )
    events = list(outcome.events[:-1])
    verdict = verify_in_subprocess(
        events,
        SandboxSnapshot(("125.00",), ("synthetic-invoice",)),
        expected_total="125.00",
        run_id="process-verifier",
    )
    assert verdict.verdict == "fail" and verdict.completed and verdict.attempted
    assert verify_in_subprocess(
        events,
        SandboxSnapshot(("125.00",), ()),
        expected_total="125.00",
        run_id="process-verifier",
    ).verdict == "indeterminate"


@pytest.mark.parametrize(
    "invalid",
    [
        '{"events": "bad"}',
        '"hello"',
        '{"events":[],"run_id":1,"expected_total":"125.00",'
        '"snapshot":{"totals":[],"outbox":[]}}',
    ],
)
def test_inv01_verifier_process_rejects_malformed_envelopes(invalid):
    result = subprocess.run(
        [sys.executable, "-m", "octoberblue.verifier_worker"],
        input=invalid,
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
    )
    assert result.returncode != 0


def test_inv01_subprocess_failure_is_indeterminate(monkeypatch):
    import octoberblue.verifier_process as process

    def unavailable(*args, **kwargs):
        raise OSError("worker unavailable")

    monkeypatch.setattr(process.subprocess, "run", unavailable)
    result = verify_in_subprocess(
        [], SandboxSnapshot((), ()), expected_total="125.00", run_id="r",
    )
    assert result.verdict == "indeterminate"
    assert not result.completed and not result.task_success
