"""INV-10: gateway effects require an unambiguous linked request and state."""
from copy import deepcopy

import pytest

from octoberblue.benchmark import GatewayPolicy, example_cases, run_benchmark
from octoberblue.contracts import Defense
from octoberblue.verifier import SandboxSnapshot, verify_benchmark


def _successful_evidence():
    result = run_benchmark(
        case=example_cases()[1], defense=Defense("marker-v1"),
        guard_enabled=False, run_id="audit",
    )
    return deepcopy(list(result.events[:-1])), SandboxSnapshot(
        ("125.00",), ("synthetic-invoice",),
    )


def _verify(events, snapshot):
    return verify_benchmark(
        events, snapshot, expected_total="125.00", run_id="audit",
    )


def _reindex(events):
    for index, event in enumerate(events, start=1):
        event["event_id"] = f"audit:{index:04}"
    return events


def test_inv10_gateway_results_link_to_unique_requests():
    events, snapshot = _successful_evidence()
    requests = [e for e in events if e["kind"] == "tool_request"]
    results = [e for e in events if e["kind"] in {"tool_executed", "tool_denied"}]
    assert len(requests) == len(results) == 2
    assert {r["event_id"] for r in requests} == {
        e["detail"]["request_event_id"] for e in results
    }
    assert _verify(events, snapshot).completed


@pytest.mark.parametrize("mutation", [
    "orphan_effect", "wrong_request_ref", "wrong_tool", "wrong_origin",
    "missing_result", "duplicate_result", "unexpected_event",
])
def test_inv10_inconsistent_gateway_ledgers_are_indeterminate(mutation):
    events, snapshot = _successful_evidence()
    effect = next(e for e in events if e["kind"] == "tool_executed")
    if mutation == "orphan_effect":
        request = next(e for e in events if e["kind"] == "tool_request")
        events.remove(request)
        _reindex(events)
    elif mutation == "wrong_request_ref":
        effect["detail"]["request_event_id"] = "audit:0001"
    elif mutation == "wrong_tool":
        effect["detail"]["tool"] = "sandbox_export"
    elif mutation == "wrong_origin":
        effect["origin"] = "target_agent"
    elif mutation == "missing_result":
        events.remove(effect)
        _reindex(events)
    elif mutation == "duplicate_result":
        events.insert(-1, deepcopy(effect))
        _reindex(events)
    elif mutation == "unexpected_event":
        events.insert(-1, {
            "event_id": "unused", "kind": "verdict",
            "origin": "target_agent", "detail": {"verdict": "pass"},
        })
        _reindex(events)
    assert _verify(events, snapshot).verdict == "indeterminate"


def test_inv15_gateway_denial_also_has_request_reference():
    denied = run_benchmark(
        case=example_cases()[1], defense=Defense("marker-v1"),
        guard_enabled=False, run_id="denied",
        policy=GatewayPolicy(allow_synthetic_export=False),
    )
    request = next(
        e for e in denied.events if e["kind"] == "tool_request"
        and e["detail"]["tool"] == "sandbox_export"
    )
    denial = next(e for e in denied.events if e["kind"] == "tool_denied")
    assert denial["detail"]["request_event_id"] == request["event_id"]
    assert not denied.attack_success
    assert denied.attempted_unauthorized_action


def test_inv10_invalid_ledger_cannot_pass_with_fake_state():
    events, snapshot = _successful_evidence()
    # Removing the recorded export does not make it a pass unless the evidence
    # and snapshot agree, and the request is visibly resolved.
    export = next(
        e for e in events if e["kind"] == "tool_executed"
        and e["detail"]["tool"] == "sandbox_export"
    )
    events.remove(export)
    events[-1]["detail"]["outbox"] = []
    _reindex(events)
    assert _verify(events, SandboxSnapshot(("125.00",), ())).verdict == "indeterminate"
