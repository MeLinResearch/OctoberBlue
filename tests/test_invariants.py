"""Checks for the security invariants that v0.1 implements.

Each test name starts with the invariant ID it covers (see docs/REQUIREMENTS.md).
These run in one Python process; they check the behavior, not a security boundary.
"""

import dataclasses
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from octoberblue.budget import Budget, BudgetExceeded
from octoberblue.cli import main
from octoberblue.engine import execute
from octoberblue.memory import Memory

ROOT = Path(__file__).resolve().parents[1]


def kinds(outcome):
    return [e["kind"] for e in outcome.events]


# INV-01 trusted harness and independent verifier -----------------------------
def test_inv01_verdict_comes_from_verifier_last(task, attack, defense):
    run = execute(task=task, attack=attack, defense=defense, guard_enabled=False)
    last = run.events[-1]
    assert last["origin"] == "independent_verifier"
    assert last["kind"] == "verdict"
    assert last["detail"]["verdict"] == run.verdict
    # No agent role ever emits a verdict.
    assert all(e["origin"] == "independent_verifier" for e in run.events if e["kind"] == "verdict")


# INV-02 / INV-09 restricted surfaces, provenance and trust labels ------------
def test_inv02_inv09_attack_enters_as_untrusted_hashed_input(task, attack, defense):
    run = execute(task=task, attack=attack, defense=defense, guard_enabled=True)
    first = run.events[0]
    assert first["origin"] == "execution_harness"
    assert first["kind"] == "input_received"
    assert first["detail"]["trust"] == "untrusted"
    expected = hashlib.sha256(attack.payload.encode()).hexdigest()
    assert first["detail"]["payload_sha256"] == expected
    # The raw payload itself is never copied into the event log.
    assert attack.payload not in json.dumps(run.events)


# INV-04 gateway-mediated consequential tools ---------------------------------
def test_inv04_gateway_denies_unauthorized_tool_with_guard_off(task, attack, defense):
    off = execute(task=task, attack=attack, defense=defense, guard_enabled=False)
    assert "tool_request" in kinds(off)
    denied = [e for e in off.events if e["kind"] == "tool_denied"]
    assert denied and denied[0]["origin"] == "execution_harness"
    assert "tool_executed" not in kinds(off)


# INV-05 frozen defense during execution --------------------------------------
def test_inv05_defense_is_immutable(defense):
    with pytest.raises(dataclasses.FrozenInstanceError):
        defense.suspicious_markers = ()


# INV-07 separate red/blue private memory -------------------------------------
def test_inv07_red_memory_is_invisible_to_blue(store, task, attack, defense):
    run = execute(task=task, attack=attack, defense=defense, guard_enabled=True)
    store.save(run)
    red, blue = Memory(store, "red"), Memory(store, "blue")
    red.approve(red.propose(run.run_id, "evidence-based insight"))
    assert red.latest()["body"] == "evidence-based insight"
    assert blue.latest() is None


def test_inv07_memory_side_must_be_red_or_blue(store):
    with pytest.raises(ValueError):
        Memory(store, "shared")


# INV-08 no holdout leakage ---------------------------------------------------
def test_inv08_holdout_runs_cannot_become_lessons(store, task, attack, defense):
    hold = execute(
        task=task, attack=attack, defense=defense, guard_enabled=True, partition="holdout"
    )
    store.save(hold)
    for side in ("red", "blue"):
        with pytest.raises(PermissionError):
            Memory(store, side).propose(hold.run_id, "leak")


def test_inv08_unknown_partition_is_rejected(task, attack, defense):
    with pytest.raises(ValueError):
        execute(task=task, attack=attack, defense=defense, guard_enabled=True, partition="eval")


# INV-10 evidence-supported verification --------------------------------------
def test_inv10_verdicts_follow_recorded_events(task, attack, clean, defense):
    for a in (attack, clean):
        for guard in (False, True):
            run = execute(task=task, attack=a, defense=defense, guard_enabled=guard)
            attempted = any(e["kind"] == "tool_request" for e in run.events)
            denied = any(e["kind"] == "tool_denied" for e in run.events)
            assert run.attempted_unauthorized_action == attempted
            assert run.verdict == ("indeterminate" if attempted and not denied else "pass")


# INV-13 immutable, versioned memory ------------------------------------------
def test_inv13_stale_proposal_cannot_be_promoted(store, task, attack, defense):
    run = execute(task=task, attack=attack, defense=defense, guard_enabled=True)
    store.save(run)
    red = Memory(store, "red")
    v1, v2 = red.propose(run.run_id, "first"), red.propose(run.run_id, "second")
    red.approve(v1)
    with pytest.raises(ValueError):
        red.approve(v2)  # its parent is no longer the latest approved version
    with pytest.raises(ValueError):
        red.approve(v1)  # already approved; versions are not re-promoted


def test_inv13_empty_lessons_are_rejected(store, task, attack, defense):
    run = execute(task=task, attack=attack, defense=defense, guard_enabled=True)
    store.save(run)
    with pytest.raises(ValueError):
        Memory(store, "blue").propose(run.run_id, "   ")


# INV-15 attempted and completed attacks are separate -------------------------
def test_inv15_attempt_is_recorded_without_a_completed_effect(task, attack, defense):
    off = execute(task=task, attack=attack, defense=defense, guard_enabled=False)
    on = execute(task=task, attack=attack, defense=defense, guard_enabled=True)
    assert off.attempted_unauthorized_action and not off.completed_unauthorized_effect
    assert not on.attempted_unauthorized_action and not on.completed_unauthorized_effect


# INV-16 legitimate completion stays measurable -------------------------------
def test_inv16_clean_input_is_not_blocked_and_task_succeeds(task, clean, defense):
    for guard in (False, True):
        run = execute(task=task, attack=clean, defense=defense, guard_enabled=guard)
        assert run.task_success
        assert "filter" not in kinds(run)  # no false positive on legitimate input


def test_inv16_task_succeeds_under_attack_with_guard_on(task, attack, defense):
    run = execute(task=task, attack=attack, defense=defense, guard_enabled=True)
    assert run.task_success
    assert "filter" in kinds(run)


# INV-17 no exposed secrets ---------------------------------------------------
SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
]


def test_inv17_tracked_files_contain_no_credentials():
    try:
        out = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    for name in out:
        path = ROOT / name
        if path.suffix in {".svg", ".lock"} or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pat in SECRET_PATTERNS:
            assert not pat.search(text), f"possible credential in {name}"


# INV-18 enforceable spending limits ------------------------------------------
def test_inv18_default_budget_is_zero_dollars(store):
    budget = Budget(store.conn)
    with pytest.raises(BudgetExceeded):
        budget.reserve("call", "0.0001")


def test_inv18_reservation_settlement_and_overrun(store):
    budget = Budget(store.conn, "0.05")
    budget.reserve("a", "0.03")
    with pytest.raises(BudgetExceeded):
        budget.reserve("b", "0.03")
    budget.settle("a", "0.02")
    budget.reserve("b", "0.03")
    with pytest.raises(BudgetExceeded):
        budget.settle("b", "0.04")
    state = store.conn.execute("SELECT state FROM spend WHERE id='b'").fetchone()[0]
    assert state == "unknown"  # an overrun is never silently settled
    with pytest.raises(BudgetExceeded):
        budget.reserve("c", "0.01")  # the unknown charge still counts at its reserved bound


@pytest.mark.parametrize("bad", ["-1", "NaN", "Infinity", "ten dollars"])
def test_inv18_invalid_money_is_rejected(store, bad):
    with pytest.raises(ValueError):
        Budget(store.conn, bad)


def test_inv18_settling_without_reservation_fails(store):
    with pytest.raises(ValueError):
        Budget(store.conn, "1.00").settle("never-reserved", "0.01")


# Run records ----------------------------------------------------------------
def test_run_records_detect_tampering(store, task, attack, defense):
    run = execute(task=task, attack=attack, defense=defense, guard_enabled=True)
    store.save(run)
    assert store.get(run.run_id)["run_id"] == run.run_id
    with store.conn:
        store.conn.execute("UPDATE runs SET sha256='tampered' WHERE run_id=?", (run.run_id,))
    with pytest.raises(ValueError):
        store.get(run.run_id)


def test_demo_is_offline_and_zero_cost(tmp_path, capsys):
    main(["demo", "--db", str(tmp_path / "demo.sqlite3")])
    report = json.loads(capsys.readouterr().out)
    assert report["mode"] == "synthetic_offline"
    assert report["paid_model_calls"] == 0
    assert report["budget_ceiling_dollars"] == "0.00"
    assert len(report["results"]) == 4


def test_cli_entry_point_runs():
    out = subprocess.run(
        [sys.executable, "-m", "octoberblue.cli", "--help"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert out.returncode == 0
