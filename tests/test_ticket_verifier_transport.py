"""Adversarial transport tests for the ticket verifier worker."""
import json
import subprocess
import sys

from octoberblue.contracts import Defense
from octoberblue.ticket_benchmark import run_ticket_benchmark
from octoberblue.ticket_contracts import TicketOracle, load_ticket_cases
from octoberblue.ticket_verifier import TicketSnapshot
from octoberblue.ticket_verifier_process import verify_ticket_in_subprocess


def _sample():
    case = load_ticket_cases()[20]
    result = run_ticket_benchmark(
        case=case, defense=Defense("marker-v1"),
        guard_enabled=False, run_id="transport-ticket",
    )
    events = list(result.events[:-1])
    record = dict(events[-1]["detail"])
    record.pop("synthetic_only")
    return case, events, TicketSnapshot.from_wire(record)


def test_inv01_ticket_worker_is_separate_process():
    case, events, snapshot = _sample()
    result = verify_ticket_in_subprocess(
        events, snapshot, oracle=TicketOracle.for_case(case),
        run_id="transport-ticket",
    )
    assert result.verdict == "fail" and result.completed
    assert result.task_success and result.attempted


def test_inv01_ticket_worker_rejects_malformed_packets():
    for payload in [
        b"not json",
        b'{"events": [], "events": []}',
        b'{"events":[],"snapshot":{},"oracle":{},"run_id":"fake"}',
        b'{"events":[],"snapshot":{},"oracle":{},"run_id":"fake","extra":1}',
    ]:
        process = subprocess.run(
            [sys.executable, "-m", "octoberblue.ticket_verifier_worker"],
            input=payload, capture_output=True, check=False, timeout=5,
        )
        assert process.returncode != 0


def test_inv01_ticket_worker_failure_is_indeterminate(monkeypatch):
    case, events, snapshot = _sample()

    def absent(*args, **kwargs):
        raise OSError("process unavailable")

    monkeypatch.setattr(
        "octoberblue.ticket_verifier_process.subprocess.run", absent,
    )
    result = verify_ticket_in_subprocess(
        events, snapshot, oracle=TicketOracle.for_case(case),
        run_id="transport-ticket",
    )
    assert result.verdict == "indeterminate"
    assert not result.task_success and not result.completed


def test_inv10_ticket_snapshot_parser_rejects_extra_fields():
    _, events, _ = _sample()
    record = dict(events[-1]["detail"])
    record.pop("synthetic_only")
    record["verdict"] = "pass"
    try:
        TicketSnapshot.from_wire(record)
    except ValueError:
        pass
    else:
        raise AssertionError("snapshot must reject attacker-authored verdict")
