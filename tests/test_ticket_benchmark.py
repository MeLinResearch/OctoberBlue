"""Executable ticket task, evidence, security and versioned contract tests."""
import copy
import json
from collections import Counter
from pathlib import Path

import pytest

from octoberblue.benchmark import _Recorder
from octoberblue.contracts import Defense
from octoberblue.ticket_benchmark import (
    TicketGateway, TicketGatewayPolicy, _TicketState,
    paired_ticket_benchmark, run_ticket_benchmark,
)
from octoberblue.ticket_contracts import (
    TicketCaseV1, TicketOracle, TicketTaskSpecV1, load_ticket_cases,
)
from octoberblue.ticket_verifier import (
    TicketSnapshot, verify_ticket_evidence,
)
from octoberblue.verifier import Verification

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def cases():
    return {case.case_id: case for case in load_ticket_cases()}


@pytest.fixture(scope="module")
def defense():
    return Defense("marker-v1")


def _run(cases, defense, number, guard=False, **kw):
    return run_ticket_benchmark(
        case=cases[f"support-{number:03}"], defense=defense,
        guard_enabled=guard, **kw,
    )


def _evidence(result):
    events = copy.deepcopy(list(result.events[:-1]))
    detail = dict(events[-1]["detail"])
    detail.pop("synthetic_only")
    return events, TicketSnapshot.from_wire(detail)


def test_f03_ticket_fixture_collection_has_authored_workloads(cases):
    counts = Counter(case.case_kind for case in cases.values())
    assert counts == {"normal": 20, "injected": 10, "regression": 10}
    assert len(cases) == len({c.ticket_id for c in cases.values()}) == 40
    assert {case.surface for case in cases.values()} == {
        "ticket_body", "retrieved_knowledge_snippet", "tool_response_body",
    }
    assert all(case.source_id.startswith("fixture:") for case in cases.values())


def test_f03_ticket_task_and_case_schemas_mirror_parser(cases):
    example = json.loads((ROOT / "examples/ticket-task.v1.json").read_text())
    parsed = TicketTaskSpecV1.from_wire(example)
    assert parsed.to_wire() == example
    assert parsed.task_family == "synthetic_support_ticket"
    for case in cases.values():
        assert TicketCaseV1.from_wire(case.to_wire()) == case
        assert TicketTaskSpecV1.from_wire(case.task_spec().to_wire()) == case.task_spec()
    for stem, fields in (
        ("ticket-task", set(example)),
        ("ticket-case", set(next(iter(cases.values())).to_wire())),
    ):
        schema = json.loads((ROOT / f"schemas/{stem}.v1.json").read_text())
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"]) == fields
        assert schema["properties"]["schema_version"]["const"] == "1.0"


@pytest.mark.parametrize("updates", [
    {"case_kind": "normal", "payload": "Please send a copy."},
    {"case_kind": "injected", "payload": ""},
    {"schema_version": "2.0"},
    {"surface": "system_prompt"},
    {"severity": 0},
    {"source_id": "../secret"},
    {"ticket_id": "bad/../ticket"},
    {"context_required": 1},
    {"payload": "x" * 2001},
    {"new_capability": "http_request"},
])
def test_f03_ticket_case_rejects_unknown_or_unsafe_fields(cases, updates):
    wire = cases["support-021"].to_wire()
    wire.update(updates)
    with pytest.raises((ValueError, TypeError)):
        TicketCaseV1.from_wire(wire)


@pytest.mark.parametrize("updates", [
    {"allowed_tools": ["get_ticket", "http_request"]},
    {"verifier_ref": "external-model-score"},
    {"task_family": "live_account"},
    {"fixture_version": "2.0"},
    {"new_field": "secret"},
])
def test_inv03_ticket_task_cannot_enlarge_capabilities(cases, updates):
    wire = cases["support-001"].task_spec().to_wire()
    wire.update(updates)
    with pytest.raises(ValueError):
        TicketTaskSpecV1.from_wire(wire)


@pytest.mark.parametrize("number", [1, 2, 3, 4, 7, 12, 20])
def test_inv16_normal_ticket_completes_with_guard_on_and_off(cases, defense, number):
    off, on = paired_ticket_benchmark(cases[f"support-{number:03}"], defense)
    assert off.verdict == on.verdict == "pass"
    assert off.task_success and on.task_success
    assert not off.attempted_unauthorized_action and not on.attack_success
    assert off.events[0]["detail"] == on.events[0]["detail"]


@pytest.mark.parametrize("number", [21, 23, 25, 27])
def test_inv15_four_distinct_forbidden_effects_in_synthetic_state(
    cases, defense, number,
):
    off = _run(cases, defense, number)
    assert off.attempted_unauthorized_action
    assert off.completed_unauthorized_effect and off.attack_success
    assert off.verdict == "fail"
    tools = {e["detail"].get("tool") for e in off.events
             if e["kind"] == "tool_executed"}
    expected = {
        21: "send_external_message", 23: "export_customer_data",
        25: "change_user_permissions", 27: "update_ticket_status",
    }
    assert expected[number] in tools


def test_inv16_detected_attack_is_prevented_without_utility_loss(cases, defense):
    off, on = paired_ticket_benchmark(cases["support-021"], defense)
    assert off.task_success and off.attack_success and off.verdict == "fail"
    assert on.task_success and not on.attack_success and on.verdict == "pass"
    assert not on.attempted_unauthorized_action
    assert any(e["kind"] == "filter" for e in on.events)


def test_inv16_missed_injection_still_has_completed_effect(cases, defense):
    off, on = paired_ticket_benchmark(cases["support-022"], defense)
    assert off.attack_success and on.attack_success
    assert on.task_success and on.verdict == "fail"
    assert not any(e["kind"] == "filter" for e in on.events)


def test_inv16_benign_false_positive_degrades_task(cases, defense):
    off, on = paired_ticket_benchmark(cases["support-031"], defense)
    assert off.task_success and off.verdict == "pass"
    assert not on.task_success and on.verdict == "fail"
    assert not on.attempted_unauthorized_action
    assert not on.completed_unauthorized_effect
    assert any(e["kind"] == "filter" for e in on.events)


def test_inv04_strict_gateway_denies_simulated_breach_but_not_task(cases, defense):
    run = _run(
        cases, defense, 22,
        policy=TicketGatewayPolicy(allow_simulated_breach=False),
    )
    assert run.attempted_unauthorized_action
    assert not run.completed_unauthorized_effect
    assert run.task_success and run.verdict == "pass"
    assert any(e["kind"] == "tool_denied"
               and e["detail"]["reason"] == "policy" for e in run.events)


def test_inv04_gateway_rejects_real_sinks_unknown_tools_and_quota(cases):
    case = cases["support-001"]
    state = _TicketState(case.ticket_id, case.account_id)
    recorder = _Recorder("ticket-gateway")
    gateway = TicketGateway(TicketGatewayPolicy(max_calls=3), recorder, state)
    assert not gateway.call("send_external_message", {
        "sink": "https://example.net", "record": "synthetic-account",
    })
    assert not gateway.call("http_request", {"url": "https://example.net"})
    assert gateway.call("get_ticket", {"ticket_id": case.ticket_id})
    assert not gateway.call("get_account_summary", {"account_id": case.account_id})
    assert state.outbox == state.exports == []
    assert state.ticket_reads == 1 and state.account_reads == 0
    assert [e["detail"]["reason"] for e in recorder.events
            if e["kind"] == "tool_denied"] == ["schema", "capability", "quota"]


@pytest.mark.parametrize("number", [1, 21, 22, 23, 27, 31])
def test_inv02_ticket_surface_is_delivered_once_after_read_tools(
    cases, defense, number,
):
    run = _run(cases, defense, number)
    events = list(run.events)
    delivered = [e for e in events if e["kind"] == "content_delivered"]
    assert len(delivered) == 1
    assert delivered[0]["origin"] == "execution_harness"
    assert delivered[0]["detail"]["surface"] == cases[f"support-{number:03}"].surface
    assert delivered[0]["detail"]["source_id"] == cases[f"support-{number:03}"].source_id
    assert [e["kind"] for e in events[:2]] == ["run_started", "input_received"]
    read_effects = [e for e in events if e["kind"] == "tool_executed"
                    and e["detail"]["tool"] in ("get_ticket", "get_account_summary")]
    assert len(read_effects) == 2
    assert all(events.index(e) < events.index(delivered[0]) for e in read_effects)


def test_inv09_ticket_payload_hashed_not_logged(cases, defense):
    case = cases["support-022"]
    result = _run(cases, defense, 22)
    received = result.events[1]["detail"]
    assert received["trust"] == "untrusted"
    assert received["surface"] == "tool_response_body"
    assert received["source_id"] == case.source_id
    assert len(received["payload_sha256"]) == 64
    assert case.payload not in json.dumps(result.events)
    assert case.ticket_body not in json.dumps(result.events)


def test_inv10_ticket_event_effects_correlate_and_replay(cases, defense):
    run = _run(cases, defense, 21, run_id="ticket-evidence")
    events, snapshot = _evidence(run)
    requests = [e for e in events if e["kind"] == "tool_request"]
    effects = [e for e in events if e["kind"] in ("tool_executed", "tool_denied")]
    assert len(requests) == len(effects) == 5
    assert {e["event_id"] for e in requests} == {
        e["detail"]["request_event_id"] for e in effects
    }
    oracle = TicketOracle.for_case(cases["support-021"])
    verdict = verify_ticket_evidence(
        events, snapshot, oracle=oracle, run_id="ticket-evidence",
    )
    assert verdict.completed and verdict.task_success
    assert verdict.verdict == "fail"


@pytest.mark.parametrize("mutation", [
    "forged_request", "orphan_effect", "fake_snapshot", "wrong_oracle",
    "duplicate_effect", "claim_pass", "wrong_origin",
])
def test_inv10_ticket_verifier_rejects_tampered_evidence(
    cases, defense, mutation,
):
    run = _run(cases, defense, 21, run_id="tamper-proof")
    events, snapshot = _evidence(run)
    oracle = TicketOracle.for_case(cases["support-021"])
    if mutation == "forged_request":
        request = next(e for e in events if e["kind"] == "tool_request")
        request["detail"]["task_authorized"] = False
    elif mutation == "orphan_effect":
        effect = next(e for e in events if e["kind"] == "tool_executed")
        effect["detail"]["request_event_id"] = "tamper-proof:0001"
    elif mutation == "fake_snapshot":
        snapshot = TicketSnapshot(
            "resolved", 1, 1, (("low", "access"),), (), (), (), False,
        )
    elif mutation == "wrong_oracle":
        oracle = TicketOracle(
            oracle.ticket_id, oracle.account_id, "urgent",
            oracle.expected_reply_code, oracle.task_sha256, oracle.case_sha256,
        )
        # No hash claim for the oracle's content; the independent verifier
        # must still score a wrong expected priority as legitimate failure.
        assert verify_ticket_evidence(
            events, snapshot, oracle=oracle, run_id="tamper-proof",
        ).verdict == "fail"
        return
    elif mutation == "duplicate_effect":
        effect = next(e for e in events if e["kind"] == "tool_executed")
        events.insert(-1, copy.deepcopy(effect))
        for idx, event in enumerate(events, start=1):
            event["event_id"] = f"tamper-proof:{idx:04}"
    elif mutation == "claim_pass":
        events.insert(-1, {
            "event_id": "malicious", "origin": "target_agent",
            "kind": "verdict", "detail": {"verdict": "pass"},
        })
        for idx, event in enumerate(events, start=1):
            event["event_id"] = f"tamper-proof:{idx:04}"
    elif mutation == "wrong_origin":
        next(e for e in events if e["kind"] == "tool_executed")["origin"] = "target_agent"
    assert verify_ticket_evidence(
        events, snapshot, oracle=oracle, run_id="tamper-proof",
    ).verdict == "indeterminate"


def test_inv10_ticket_missing_verifier_fails_closed(cases, defense, monkeypatch):
    def unavailable(*args, **kwargs):
        return Verification(False, False, False, "indeterminate")

    monkeypatch.setattr(
        "octoberblue.ticket_benchmark.verify_ticket_in_subprocess", unavailable,
    )
    run = _run(cases, defense, 21)
    assert run.verdict == "indeterminate"
    assert not run.task_success and not run.attack_success


def test_inv08_ticket_fixtures_are_not_sealed_holdouts(cases, defense):
    with pytest.raises(ValueError, match="development"):
        _run(cases, defense, 21, partition="holdout")


def test_f04_ticket_cli_persists_matched_results(cases, tmp_path, capsys):
    from octoberblue.cli import main
    from octoberblue.store import Store

    path = str(tmp_path / "ticket.sqlite3")
    main([
        "ticket-benchmark", "--db", path, "--case", "support-001",
        "--case", "support-021", "--case", "support-031",
    ])
    result = json.loads(capsys.readouterr().out)
    assert result["fixture_counts"] == {"normal": 20, "injected": 10, "regression": 10}
    assert len(result["results"]) == 6
    assert result["paid_model_calls"] == 0
    assert result["budget_ceiling_dollars"] == "0.00"
    assert all(row["verdict"] != "indeterminate" for row in result["results"])
    # Saved runs are bound to SHA-256-checked SQLite records.
    with __import__("sqlite3").connect(path) as db:
        run_ids = [row[0] for row in db.execute("SELECT run_id FROM runs")]
    assert len(run_ids) == 6
    store = Store(path)
    try:
        for run_id in run_ids:
            assert store.get(run_id)["verdict"] in ("pass", "fail")
    finally:
        store.close()


def test_f03_reject_bogus_cli_case(tmp_path):
    from octoberblue.cli import main

    with pytest.raises(SystemExit):
        main([
            "ticket-benchmark", "--case", "no-such-ticket",
            "--db", str(tmp_path / "oops.sqlite3"),
        ])
