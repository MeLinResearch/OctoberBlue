"""INV-01/03/09/10: authenticated acquisition, complete receipts and fail-closed replay."""
from copy import deepcopy
from dataclasses import FrozenInstanceError

import pytest

import octoberblue.ticket_benchmark as benchmark
from octoberblue.contracts import Defense
from octoberblue.ticket_contracts import TicketOracle, digest, load_ticket_cases
from octoberblue.ticket_evidence import (
    RunManifestV1,
    seal,
    verify_acquired_evidence,
)
from octoberblue.ticket_verifier import TicketSnapshot
from octoberblue.ticket_verifier_process import verify_ticket_in_subprocess
from octoberblue.ticket_witness import TicketWitness, WitnessError


@pytest.fixture
def captured(monkeypatch):
    captured = {}
    actual = benchmark.verify_ticket_in_subprocess

    def capture(*args, **kwargs):
        captured.update(kwargs)
        return actual(*args, **kwargs)

    monkeypatch.setattr(benchmark, 'verify_ticket_in_subprocess', capture)
    case = load_ticket_cases()[20]
    outcome = benchmark.run_ticket_benchmark(
        case=case, defense=Defense('v1'), guard_enabled=False, run_id='witness-test',
    )
    assert outcome.verdict == 'fail' and outcome.task_success and outcome.attack_success
    assert outcome.evidence is not None
    # The persisted envelope must remain valid after the parent appends a verdict.
    assert outcome.evidence == captured['evidence']
    return case, outcome, captured


def check(packet, captured, **overrides):
    options = dict(key=captured['authentication_key'],
                   expected_manifest_sha256=captured['expected_manifest_sha256'],
                   oracle=captured['oracle'], run_id=captured['run_id'])
    options.update(overrides)
    return verify_acquired_evidence(packet, **options)


def test_inv10_witness_receipts_independently_replay_attempt_effect_and_utility(captured):
    _, outcome, capture = captured
    packet = outcome.evidence
    assert check(packet, capture).completed
    body = packet['body']
    assert len(body['event_chain']) == len(body['events'])
    assert len(body['receipts']) == 5
    assert body['receipts'][2]['before']['outbox'] == []
    assert body['receipts'][2]['after']['outbox'] == ['synthetic-account']
    assert body['manifest']['paid_model_calls'] == 0
    assert body['manifest']['budget_ceiling_dollars'] == '0.00'
    assert 'authentication_key' not in str(packet)
    assert capture['authentication_key'].hex() not in str(packet)
    assert body['events'][-1]['kind'] == 'ticket_snapshot'
    assert outcome.events[-1]['kind'] == 'verdict'


@pytest.mark.parametrize('mutation', [
    'event_deleted', 'event_duplicated', 'event_reordered', 'effect_substituted',
    'receipt_deleted', 'receipt_duplicated', 'receipt_reordered', 'receipt_forged',
    'snapshot', 'manifest', 'authentication',
])
def test_inv10_corrupted_acquisition_never_becomes_safe(captured, mutation):
    _, outcome, capture = captured
    packet = deepcopy(outcome.evidence)
    body = packet['body']
    if mutation == 'event_deleted':
        del body['events'][3]
    elif mutation == 'event_duplicated':
        body['events'].insert(3, deepcopy(body['events'][3]))
    elif mutation == 'event_reordered':
        body['events'][3:5] = body['events'][3:5][::-1]
    elif mutation == 'effect_substituted':
        body['events'][3]['detail']['ticket_id'] = 'different-ticket'
    elif mutation == 'receipt_deleted':
        del body['receipts'][2]
    elif mutation == 'receipt_duplicated':
        body['receipts'].insert(2, deepcopy(body['receipts'][2]))
    elif mutation == 'receipt_reordered':
        body['receipts'].reverse()
    elif mutation == 'receipt_forged':
        body['receipts'][2]['decision'] = 'tool_denied'
    elif mutation == 'snapshot':
        body['snapshot']['outbox'] = []
    elif mutation == 'manifest':
        body['manifest']['guard_enabled'] = True
    else:
        packet['authentication'] = '0' * 64
    assert check(packet, capture).verdict == 'indeterminate'


@pytest.mark.parametrize('field', ['event_chain', 'receipts'])
def test_inv10_even_authenticated_incomplete_chains_are_rejected(captured, field):
    _, outcome, capture = captured
    body = deepcopy(outcome.evidence['body'])
    body[field].pop()
    # A trusted signer is used only to exercise structural checks behind authentication.
    packet = seal(body, capture['authentication_key'])
    assert check(packet, capture).verdict == 'indeterminate'


def test_inv01_wrong_key_anchor_or_run_cannot_replay_a_valid_packet(captured):
    _, outcome, capture = captured
    assert check(outcome.evidence, capture, key=b'x' * 32).verdict == 'indeterminate'
    assert check(outcome.evidence, capture, run_id='another-run').verdict == 'indeterminate'
    assert check(outcome.evidence, capture,
                 expected_manifest_sha256='0' * 64).verdict == 'indeterminate'
    other = TicketOracle.for_case(load_ticket_cases()[0])
    assert check(outcome.evidence, capture, oracle=other).verdict == 'indeterminate'


def test_inv01_verifier_subprocess_rejects_corrupted_authenticated_packet(captured):
    case, outcome, capture = captured
    packet = deepcopy(outcome.evidence)
    packet['body']['snapshot']['outbox'] = []
    verdict = verify_ticket_in_subprocess(
        packet['body']['events'], TicketSnapshot.from_wire(packet['body']['snapshot']),
        oracle=TicketOracle.for_case(case), run_id=outcome.run_id,
        evidence=packet, authentication_key=capture['authentication_key'],
        expected_manifest_sha256=capture['expected_manifest_sha256'],
    )
    assert verdict.verdict == 'indeterminate'


def test_inv03_witness_state_is_separate_and_finalize_is_irreversible(captured):
    case, outcome, _ = captured
    manifest = RunManifestV1.from_wire(outcome.evidence['body']['manifest'])
    witness = TicketWitness(manifest, case.ticket_id, case.account_id)
    try:
        assert witness.process.pid != __import__('os').getpid()
        witness.call('get_ticket', {'ticket_id': case.ticket_id})
        witness.events.clear()  # Parent mirrors cannot rewrite the witness ledger.
        packet = witness.finalize()
        assert len(packet['body']['events']) == 3
        assert packet['body']['snapshot']['ticket_reads'] == 1
        with pytest.raises(WitnessError, match='sealed'):
            witness.call('get_ticket', {'ticket_id': case.ticket_id})
    finally:
        witness.close()
    assert witness.process.poll() is not None
    assert witness.key == b''


def test_inv03_private_record_api_cannot_fabricate_an_effect(captured):
    case, outcome, _ = captured
    manifest = RunManifestV1.from_wire(outcome.evidence['body']['manifest'])
    witness = TicketWitness(manifest, case.ticket_id, case.account_id)
    try:
        with pytest.raises(WitnessError):
            witness.emit('execution_harness', 'tool_executed', tool='send_external_message')
    finally:
        witness.close()


def test_inv01_witness_crash_never_uses_parent_gateway(monkeypatch):
    class MissingWitness:
        def __init__(self, *args):
            raise WitnessError('missing')

    monkeypatch.setattr(benchmark, 'TicketWitness', MissingWitness)
    result = benchmark.run_ticket_benchmark(
        case=load_ticket_cases()[0], defense=Defense('v1'), guard_enabled=False,
    )
    assert result.verdict == 'indeterminate' and not result.task_success
    assert result.evidence is None
    assert not any(e['kind'] == 'tool_executed' for e in result.events)


def test_inv01_witness_death_during_run_is_indeterminate(monkeypatch):
    class CrashingWitness(TicketWitness):
        def call(self, tool, args):
            self.process.kill()
            return super().call(tool, args)

    monkeypatch.setattr(benchmark, 'TicketWitness', CrashingWitness)
    result = benchmark.run_ticket_benchmark(
        case=load_ticket_cases()[0], defense=Defense('v1'), guard_enabled=False,
    )
    assert result.verdict == 'indeterminate' and not result.task_success


def test_inv05_manifest_is_frozen_and_rejects_contract_drift(captured):
    _, outcome, _ = captured
    wire = deepcopy(outcome.evidence['body']['manifest'])
    manifest = RunManifestV1.from_wire(wire)
    with pytest.raises(FrozenInstanceError):
        manifest.seed = 42
    assert digest(manifest.to_wire()) == digest(wire)
    for updates in ({'new_field': 'allow'}, {'schema_version': '2.0'},
                    {'paid_model_calls': 1}, {'budget_ceiling_dollars': '1.00'},
                    {'max_calls': 2}, {'guard_enabled': 1}):
        with pytest.raises(ValueError):
            RunManifestV1.from_wire({**wire, **updates})


def test_inv10_deterministic_receipt_replay_with_fixed_run_inputs():
    case = load_ticket_cases()[21]
    inputs = dict(case=case, defense=Defense('v1'), guard_enabled=False,
                  run_id='replay-run', seed=42)
    first = benchmark.run_ticket_benchmark(**inputs)
    second = benchmark.run_ticket_benchmark(**inputs)
    assert first.events == second.events
    a, b = first.evidence['body'], second.evidence['body']
    assert a['snapshot'] == b['snapshot']
    assert a['manifest']['nonce'] != b['manifest']['nonce']
    # Fresh acquisition uses a fresh nonce and key; replay compares observed behavior.
    for x, y in zip(a['receipts'], b['receipts'], strict=True):
        for name in ('arguments_sha256', 'decision', 'before', 'after'):
            assert x[name] == y[name]


def test_inv05_manifest_schema_matches_strict_parser(captured):
    import json
    from pathlib import Path

    _, outcome, _ = captured
    schema = json.loads((Path(__file__).parents[1] / 'schemas/run-manifest.v1.json').read_text())
    assert schema['additionalProperties'] is False
    assert set(schema['required']) == set(schema['properties']) == set(
        outcome.evidence['body']['manifest'],
    )


def test_inv10_signed_receipt_cannot_claim_a_different_post_state(captured):
    _, outcome, capture = captured
    body = deepcopy(outcome.evidence['body'])
    body['receipts'][2]['after']['outbox'] = []
    previous = digest(body['manifest'])
    for receipt in body['receipts']:
        receipt['previous_sha256'] = previous
        receipt['sha256'] = digest({k: v for k, v in receipt.items() if k != 'sha256'})
        previous = receipt['sha256']
    assert check(seal(body, capture['authentication_key']), capture).verdict == 'indeterminate'


def test_inv05_persisted_run_manifest_cannot_be_overwritten(captured, tmp_path):
    import sqlite3

    from octoberblue.store import Store

    _, outcome, capture = captured
    store = Store(str(tmp_path / 'evidence.sqlite3'))
    try:
        store.save(outcome)
        with pytest.raises(sqlite3.IntegrityError):
            store.save(outcome)
        saved = store.get(outcome.run_id)
        assert saved['evidence'] == outcome.evidence
        assert capture['authentication_key'].hex() not in str(saved)
    finally:
        store.close()


def test_inv01_missing_acquisition_key_never_falls_back_to_logical_verification(captured):
    case, outcome, capture = captured
    body = outcome.evidence['body']
    verdict = verify_ticket_in_subprocess(
        body['events'], TicketSnapshot.from_wire(body['snapshot']),
        oracle=TicketOracle.for_case(case), run_id=outcome.run_id,
        evidence=outcome.evidence, authentication_key=None,
        expected_manifest_sha256=capture['expected_manifest_sha256'],
    )
    assert verdict.verdict == 'indeterminate'


def test_inv10_self_consistent_forged_safe_history_requires_the_trusted_key(captured):
    from octoberblue.ticket_verifier import verify_ticket_evidence

    _, outcome, capture = captured
    forged = deepcopy(outcome.evidence)
    body = forged['body']
    removed = {e['event_id'] for e in body['events']
               if e['detail'].get('tool') == 'send_external_message'}
    body['events'] = [e for e in body['events'] if e['event_id'] not in removed]
    identities = {e['event_id']: f'{outcome.run_id}:{index:04}'
                  for index, e in enumerate(body['events'], 1)}
    body['snapshot']['outbox'] = []
    previous = digest(body['manifest'])
    body['event_chain'] = []
    for index, event in enumerate(body['events'], 1):
        event['event_id'] = identities[event['event_id']]
        if 'request_event_id' in event['detail']:
            event['detail']['request_event_id'] = identities[event['detail']['request_event_id']]
        if event['kind'] == 'ticket_snapshot':
            event['detail']['outbox'] = []
        fields = dict(sequence=index, previous_sha256=previous, event_sha256=digest(event))
        previous = digest(fields)
        body['event_chain'].append({**fields, 'sha256': previous})
    body['receipts'] = [r for r in body['receipts'] if r['request_event_id'] not in removed]
    previous = digest(body['manifest'])
    for index, receipt in enumerate(body['receipts'], 1):
        receipt.update(sequence=index, previous_sha256=previous,
                       request_event_id=identities[receipt['request_event_id']],
                       result_event_id=identities[receipt['result_event_id']])
        receipt['before']['outbox'] = []
        receipt['after']['outbox'] = []
        receipt['sha256'] = digest({k: v for k, v in receipt.items() if k != 'sha256'})
        previous = receipt['sha256']
    # Internal consistency alone accepts this completely fabricated safe history.
    assert verify_ticket_evidence(
        body['events'], TicketSnapshot.from_wire(body['snapshot']),
        oracle=capture['oracle'], run_id=outcome.run_id,
    ).verdict == 'pass'
    assert check(forged, capture).verdict == 'indeterminate'
    # This explicitly demonstrates the limit: a compromised trusted signer CAN forge it.
    assert check(seal(body, capture['authentication_key']), capture).verdict == 'pass'


def test_inv01_dead_witness_pipe_cleanup_preserves_failure_and_discards_key(monkeypatch):
    from types import SimpleNamespace

    closed = []

    class DeadPipe:
        def close(self):
            closed.append(True)
            raise BrokenPipeError('witness already exited')

    monkeypatch.setattr("octoberblue.ticket_witness._stop", lambda process: None)
    witness = TicketWitness.__new__(TicketWitness)
    witness.key = b'x' * 32
    witness.process = SimpleNamespace(poll=lambda: 0, wait=lambda **kwargs: 0,
                                      stdin=DeadPipe(), stdout=DeadPipe())
    witness.close()
    assert len(closed) == 2 and witness.key == b''
