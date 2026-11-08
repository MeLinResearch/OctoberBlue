"""INV-03/04/11: ticket proposals cross a restricted runtime boundary."""
import json
from types import SimpleNamespace

import pytest

from octoberblue.contracts import Defense
from octoberblue.target_runtime import TargetRuntimeError
from octoberblue.ticket_benchmark import TicketGatewayPolicy, run_ticket_benchmark
from octoberblue.ticket_contracts import load_ticket_cases
from octoberblue.ticket_target_worker import PROTOCOL, propose


@pytest.mark.parametrize('case', load_ticket_cases(), ids=lambda c: c.case_id)
@pytest.mark.parametrize('guard', [False, True])
def test_inv04_ticket_container_protocol_preserves_all_fixture_outcomes(monkeypatch, case, guard):
    calls = []

    def container(command, **kwargs):
        calls.append(command)
        request = json.loads(kwargs['input'])
        assert set(request) == {'protocol', 'content', 'ticket_id', 'account_id',
                                'severity', 'category', 'context_filtered'}
        assert request['protocol'] == PROTOCOL
        return SimpleNamespace(returncode=0, stdout=json.dumps(propose(request)).encode(),
                               stderr=b'')

    # Keep the real verifier subprocess: patch only transport during proposal generation.
    from octoberblue.target_runtime import _propose_request

    def transport(request, **kwargs):
        with monkeypatch.context() as patch:
            patch.setattr('octoberblue.target_runtime.run_bounded', container)
            return _propose_request(request, **kwargs)

    monkeypatch.setattr('octoberblue.ticket_benchmark.resolve_image_id',
                        lambda _: "sha256:" + "1" * 64)
    monkeypatch.setattr('octoberblue.ticket_benchmark._propose_request', transport)
    common = dict(case=case, defense=Defense('marker-v1'), guard_enabled=guard)
    inline = run_ticket_benchmark(**common)
    docker = run_ticket_benchmark(**common, target_runtime='docker')
    fields = ('verdict', 'task_success', 'attack_success', 'attempted_unauthorized_action')
    assert tuple(getattr(docker, k) for k in fields) == tuple(getattr(inline, k) for k in fields)
    assert docker.verdict != 'indeterminate'
    assert calls[0][-1] == 'octoberblue.ticket_target_worker'
    assert '--network=none' in calls[0] and '--read-only' in calls[0]


def test_inv03_ticket_runtime_failure_never_falls_back(monkeypatch):
    monkeypatch.setattr('octoberblue.ticket_benchmark.resolve_image_id',
                        lambda _: "sha256:" + "1" * 64)

    def broken(*args, **kwargs):
        raise TargetRuntimeError('target_timeout')

    monkeypatch.setattr('octoberblue.ticket_benchmark._propose_request', broken)
    outcome = run_ticket_benchmark(case=load_ticket_cases()[20], defense=Defense('v1'),
                                   guard_enabled=False, target_runtime='docker')
    assert outcome.verdict == 'indeterminate'
    assert not outcome.task_success and not outcome.attack_success
    assert not any(e['kind'] == 'tool_executed' and e['detail']['tool'] == 'draft_reply'
                   for e in outcome.events)


def test_inv04_ticket_container_cannot_override_gateway(monkeypatch):
    monkeypatch.setattr('octoberblue.ticket_benchmark.resolve_image_id',
                        lambda _: "sha256:" + "1" * 64)
    monkeypatch.setattr('octoberblue.ticket_benchmark._propose_request', lambda *a, **k: (
        ('send_external_message', {'sink': 'sandbox://external', 'record': 'synthetic-account'}),
    ))
    outcome = run_ticket_benchmark(case=load_ticket_cases()[0], defense=Defense('v1'),
                                   guard_enabled=False, target_runtime='docker',
                                   policy=TicketGatewayPolicy(allow_simulated_breach=False))
    assert outcome.attempted_unauthorized_action and not outcome.attack_success
    assert any(e['kind'] == 'tool_denied' for e in outcome.events)


def test_inv03_ticket_worker_rejects_oracle_and_policy_fields():
    with pytest.raises(ValueError):
        propose({'protocol': PROTOCOL, 'oracle': {}, 'policy': {}})
