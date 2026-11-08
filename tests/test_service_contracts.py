"""INV-01/05/07/08/09/10/13: contracts enforced at actual service boundaries."""
import json
import subprocess
import sys
from copy import deepcopy
from dataclasses import FrozenInstanceError, asdict
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from octoberblue.contracts import Defense
from octoberblue.memory import Memory
from octoberblue.service_contracts import (
    DreamProposalV1,
    GuardDecisionV1,
    RunRecordV1,
    RunRequestV1,
    ServiceMessageV1,
    TraceV1,
    service_message,
    service_payload,
    witness_request,
    witness_response,
)
from octoberblue.store import Store
from octoberblue.ticket_benchmark import run_ticket_benchmark
from octoberblue.ticket_contracts import TicketOracle, load_ticket_cases
from octoberblue.ticket_verifier import TicketSnapshot
from octoberblue.ticket_verifier_process import verify_ticket_in_subprocess

ROOT = Path(__file__).parents[1]


@pytest.fixture(scope='module')
def catalog():
    schemas = {p.name: json.loads(p.read_bytes()) for p in (ROOT / 'schemas').glob('*.json')}
    registry = Registry()
    for name, schema in schemas.items():
        resource = Resource.from_contents(schema)
        registry = registry.with_resource(name, resource)
        if '$id' in schema:
            registry = registry.with_resource(schema['$id'], resource)
        Draft202012Validator.check_schema(schema)
    return schemas, registry


def check_schema(name, value, catalog):
    schemas, registry = catalog
    Draft202012Validator(schemas[name + '.v1.json'], registry=registry).validate(value)


@pytest.fixture(scope='module')
def sample():
    case = load_ticket_cases()[20]
    outcome = run_ticket_benchmark(case=case, defense=Defense('v1'), guard_enabled=False,
                                   run_id='contract-case')
    assert outcome.verdict == 'fail' and outcome.task_success
    request = {'schema_version': '1.0', 'manifest': outcome.evidence['body']['manifest'],
               'ticket_id': case.ticket_id, 'account_id': case.account_id}
    trace = {'schema_version': '1.0', 'run_id': outcome.run_id, 'events': list(outcome.events)}
    guard = outcome.events[1]['detail']['guard_decision']
    dream = DreamProposalV1('1.0', 'red', None, outcome.run_id, 'A manual evidence-linked lesson.')
    return case, outcome, {
        'run-request': (RunRequestV1, request),
        'run-record': (RunRecordV1, {'schema_version': '1.0', **asdict(outcome)}),
        'trace': (TraceV1, trace), 'guard-decision': (GuardDecisionV1, guard),
        'dream-proposal': (DreamProposalV1, dream.to_wire()),
    }


@pytest.mark.parametrize('name', ['run-request', 'run-record', 'trace', 'guard-decision',
                                  'dream-proposal'])
def test_inv09_catalog_roundtrips_and_validates_actual_messages(sample, catalog, name):
    _, _, messages = sample
    contract, wire = messages[name]
    parsed = contract.from_wire(wire)
    check_schema(name, parsed.to_wire(), catalog)
    assert contract.from_wire(parsed.to_wire()) == parsed
    with pytest.raises(FrozenInstanceError):
        parsed.extra_authority = 'grant_tools'


@pytest.mark.parametrize('name', ['run-request', 'run-record', 'trace', 'guard-decision',
                                  'dream-proposal'])
@pytest.mark.parametrize('change', [{'schema_version': '2.0'}, {'grant_tools': ['shell']}])
def test_inv03_unknown_versions_and_authority_fields_rejected(sample, catalog, name, change):
    _, _, messages = sample
    contract, original = messages[name]
    wire = deepcopy(original)
    wire.update(change)
    with pytest.raises(ValueError):
        contract.from_wire(wire)
    schemas, registry = catalog
    assert not Draft202012Validator(schemas[name + '.v1.json'], registry=registry).is_valid(wire)


def test_inv05_nested_wire_copies_cannot_mutate_frozen_manifest_or_trace(sample):
    _, _, messages = sample
    request = RunRequestV1.from_wire(messages['run-request'][1])
    trace = TraceV1.from_wire(messages['trace'][1])
    copied = request.to_wire()
    copied['manifest']['max_calls'] = 20
    assert request.to_wire()['manifest']['max_calls'] == 8
    copied = trace.to_wire()
    copied['events'][0]['detail']['seed'] = 42
    assert trace.to_wire()['events'][0]['detail']['seed'] == 0
    with pytest.raises(FrozenInstanceError):
        trace._json = b'{}'


@pytest.mark.parametrize('mutation', ['origin', 'extra', 'duplicate', 'boolean_flag', 'surface'])
def test_inv10_trace_contract_rejects_forged_actor_and_malformed_evidence(sample, mutation):
    _, _, messages = sample
    wire = deepcopy(messages['trace'][1])
    if mutation == 'origin':
        wire['events'][-1]['origin'] = 'target_agent'
    elif mutation == 'extra':
        wire['events'][3]['detail']['grant_tools'] = ['shell']
    elif mutation == 'duplicate':
        wire['events'].insert(3, deepcopy(wire['events'][3]))
    elif mutation == 'boolean_flag':
        wire['events'][-1]['detail']['task_success'] = 1
    else:
        wire['events'][1]['detail']['surface'] = 'system_prompt'
    with pytest.raises(ValueError):
        TraceV1.from_wire(wire)


@pytest.mark.parametrize('change', [
    {'blocked': True}, {'guard_enabled': 0}, {'reason_code': 'operator_approved'},
    {'payload_sha256': 'wrong'}, {'tool_permissions': ['export_customer_data']},
])
def test_inv05_guard_decision_cannot_claim_authority_or_inconsistent_state(sample, change):
    _, _, messages = sample
    wire = {**messages['guard-decision'][1], **change}
    with pytest.raises(ValueError):
        GuardDecisionV1.from_wire(wire)


def test_inv10_store_enforces_run_trace_and_manifest_bindings(sample, tmp_path):
    _, outcome, _ = sample
    store = Store(str(tmp_path / 'runs.sqlite3'))
    try:
        store.save(outcome)
        stored = store.get(outcome.run_id)
        assert stored['schema_version'] == '1.0'
        stored['guard_enabled'] = True
        # Even a recomputed unkeyed SQLite checksum cannot bypass typed bindings.
        import hashlib
        body = json.dumps(stored, sort_keys=True, separators=(',', ':'))
        with store.conn:
            store.conn.execute('UPDATE runs SET body_json=?,sha256=? WHERE run_id=?',
                               (body, hashlib.sha256(body.encode()).hexdigest(), outcome.run_id))
        with pytest.raises(ValueError, match='identity mismatch'):
            store.get(outcome.run_id)
    finally:
        store.close()


def test_inv07_inv13_memory_wire_checks_side_parent_and_never_promotes(sample, tmp_path):
    _, outcome, _ = sample
    store = Store(str(tmp_path / 'memory.sqlite3'))
    try:
        store.save(outcome)
        red, blue = Memory(store, 'red'), Memory(store, 'blue')
        wire = DreamProposalV1('1.0', 'red', None, outcome.run_id,
                               'Verified manual proposal.').to_wire()
        with pytest.raises(PermissionError, match='side'):
            blue.propose_wire(wire)
        version = red.propose_wire(wire)
        assert red.latest() is None and blue.latest() is None
        red.approve(version)
        assert red.latest()['version'] == version and blue.latest() is None
        with pytest.raises(ValueError, match='stale'):
            red.propose_wire(wire)
        with pytest.raises(ValueError):
            red.propose_wire({**wire, 'approval_required': False})
    finally:
        store.close()


def test_inv08_self_labelled_development_cannot_admit_holdouts(store, task, attack, defense):
    from octoberblue.engine import execute

    outcome = execute(task=task, attack=attack, defense=defense,
                      guard_enabled=False, partition='holdout')
    store.save(outcome)
    wire = DreamProposalV1('1.0', 'red', None, outcome.run_id,
                           'Attempted holdout lesson.').to_wire()
    with pytest.raises(PermissionError):
        Memory(store, 'red').propose_wire(wire)
    with pytest.raises(ValueError):
        DreamProposalV1.from_wire({**wire, 'partition': 'holdout'})
    assert store.conn.execute('SELECT COUNT(*) FROM memory').fetchone()[0] == 0


def test_inv01_witness_envelope_sequence_and_responses_are_correlated(sample, catalog):
    _, _, messages = sample
    initial = {'schema_version': '1.0', 'sequence': 1, 'operation': 'initialize',
               'parameters': {'run': messages['run-request'][1], 'credentials': {
                   'authentication_key': 'a' * 64, 'audit_signing_key': None}}}
    check_schema('witness-request', initial, catalog)
    assert witness_request(initial, sequence=1)['ticket_id'] == 'TICKET-021'
    for change in ({'schema_version': '2.0'}, {'sequence': True}, {'sequence': 2},
                   {'capabilities': ['shell']}):
        with pytest.raises(ValueError):
            witness_request({**initial, **change}, sequence=1)
    response = {'schema_version': '1.0', 'sequence': 1, 'result': {'ready': True}}
    check_schema('witness-response', response, catalog)
    assert witness_response(response, sequence=1) == {'ready': True}
    with pytest.raises(ValueError):
        witness_response(response, sequence=2)


@pytest.mark.parametrize('change', [{'sequence': 1}, {'schema_version': '2.0'},
                                  {'sequence': True}, {'extra': 'allow'}])
def test_inv01_witness_process_rejects_rpc_replay_and_drift_before_effects(sample, change):
    _, _, messages = sample
    initial = {'schema_version': '1.0', 'sequence': 1, 'operation': 'initialize',
               'parameters': {'run': messages['run-request'][1], 'credentials': {
                   'authentication_key': 'a' * 64, 'audit_signing_key': None}}}
    command = {'schema_version': '1.0', 'sequence': 2, 'operation': 'call',
               'parameters': {'tool': 'get_ticket', 'arguments': {'ticket_id': 'TICKET-021'}}}
    command.update(change)
    raw = json.dumps(initial) + '\n' + json.dumps(command) + '\n'
    process = subprocess.run([sys.executable, '-m', 'octoberblue.ticket_witness_worker'],
                             input=raw, capture_output=True, text=True, timeout=5)
    assert process.returncode != 0
    response = json.loads(process.stdout)
    assert response['sequence'] == 1 and response['result'] == {'ready': True}


def test_inv01_verifier_and_replay_envelopes_cannot_claim_an_agent_service(sample, catalog):
    case, outcome, _ = sample
    body = outcome.evidence['body']
    message = service_message('verify_ticket', 'request-1', {
        'events': body['events'], 'snapshot': body['snapshot'],
        'oracle': asdict(TicketOracle.for_case(case)), 'run_id': outcome.run_id,
    })
    check_schema('service-message', message, catalog)
    assert ServiceMessageV1.from_wire(message).to_wire() == message
    for change in ({'schema_version': '2.0'}, {'service': 'target_agent'},
                   {'message_type': 'approve'}, {'extra': True}):
        with pytest.raises(ValueError):
            ServiceMessageV1.from_wire({**message, **change})
    response = service_message('verify_ticket', 'request-1', {
        'task_success': True, 'attempted': False, 'completed': False, 'verdict': 'pass',
    }, response=True)
    check_schema('service-message', response, catalog)
    with pytest.raises(ValueError):
        service_payload(response, operation='verify_ticket', request_id='other', response=True)
    with pytest.raises(ValueError):
        service_payload(response, operation='replay_ticket', request_id='request-1', response=True)


def test_inv01_uncorrelated_verifier_output_fails_closed(sample, monkeypatch):
    case, outcome, _ = sample
    body = outcome.evidence['body']

    def substituted(*args, **kwargs):
        response = service_message('verify_ticket', 'different-request', {
            'task_success': True, 'attempted': False, 'completed': False, 'verdict': 'pass',
        }, response=True)
        return SimpleNamespace(returncode=0, stdout=json.dumps(response))

    monkeypatch.setattr('octoberblue.ticket_verifier_process.subprocess.run', substituted)
    result = verify_ticket_in_subprocess(body['events'], TicketSnapshot.from_wire(body['snapshot']),
                                         oracle=TicketOracle.for_case(case), run_id=outcome.run_id)
    assert result.verdict == 'indeterminate'


def test_inv09_signed_run_record_also_matches_catalog(catalog):
    pytest.importorskip('cryptography')
    case = load_ticket_cases()[0]
    outcome = run_ticket_benchmark(case=case, defense=Defense('v1'), guard_enabled=True,
                                   audit_signing_key=b'q' * 32)
    assert outcome.verdict == 'pass' and outcome.audit_pack is not None
    check_schema('run-record', RunRecordV1.from_outcome(outcome).to_wire(), catalog)


def test_inv05_live_input_cannot_omit_versioned_guard_decision(sample, catalog):
    _, outcome, _ = sample
    detail = deepcopy(outcome.events[1]['detail'])
    detail.pop('guard_decision')
    message = {'schema_version': '1.0', 'sequence': 3, 'operation': 'record',
               'parameters': {'origin': 'execution_harness', 'kind': 'input_received',
                              'detail': detail}}
    with pytest.raises(ValueError, match='guard decision'):
        witness_request(message, sequence=3)
    schemas, registry = catalog
    assert not Draft202012Validator(schemas['witness-request.v1.json'],
                                     registry=registry).is_valid(message)


def test_inv09_run_contract_rejects_malformed_receipt_collections(sample):
    _, outcome, _ = sample
    record = {'schema_version': '1.0', **asdict(outcome)}
    record['evidence']['body']['receipts'] = 'not-receipts'
    with pytest.raises(ValueError, match='collections'):
        RunRecordV1.from_wire(record)
