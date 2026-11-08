"""INV-01/05/09/10/17: durable signatures require external trust and replay actual state."""
import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from octoberblue.cli import main
from octoberblue.contracts import Defense
from octoberblue.ticket_audit import (
    AuditError,
    _sign_witness_body,
    export_pack,
    generate_keypair,
    key_id,
    load_pack,
    load_public_key,
    load_signing_seed,
    public_bytes,
    replay_audit_pack,
    replay_in_subprocess,
)
from octoberblue.ticket_benchmark import run_ticket_benchmark
from octoberblue.ticket_contracts import digest, load_ticket_cases
from octoberblue.ticket_evidence import MAX_PACKET_BYTES

pytest.importorskip('cryptography')


@pytest.fixture(scope='module')
def acquisition(tmp_path_factory):
    directory = tmp_path_factory.mktemp('audit-identity')
    private, public = directory / 'private.pem', directory / 'public.pem'
    identity = generate_keypair(private, public)
    seed, trusted = load_signing_seed(private), load_public_key(public)
    result = run_ticket_benchmark(
        case=load_ticket_cases()[20], defense=Defense('marker-v1'), guard_enabled=False,
        run_id='signed-acquisition', audit_signing_key=seed,
    )
    assert result.verdict == 'fail' and result.task_success and result.attack_success
    assert result.audit_pack is not None and result.audit_pack['key_id'] == identity
    anchor = digest(result.evidence['body']['manifest'])
    return result, seed, trusted, anchor


def replay(pack, acquisition, **overrides):
    _, _, public, anchor = acquisition
    options = dict(trusted_public_key=public, expected_manifest_sha256=anchor)
    options.update(overrides)
    return replay_audit_pack(pack, **options)


def test_inv10_acquisition_signature_replays_effect_attempt_and_utility(acquisition):
    result, seed, trusted, anchor = acquisition
    report = replay(result.audit_pack, acquisition)
    assert report.signature_verified and report.reason_code == 'replayed'
    assert report.verification.verdict == result.verdict == 'fail'
    assert report.verification.completed and report.verification.attempted
    assert report.verification.task_success
    assert report.manifest_sha256 == anchor and report.run_id == result.run_id
    assert public_bytes(seed) == trusted
    assert 'authentication' not in result.audit_pack
    assert seed.hex() not in json.dumps(result.audit_pack)


@pytest.mark.parametrize('field', ['signature', 'algorithm', 'key_id', 'schema_version',
                                   'effect', 'snapshot', 'manifest', 'receipt', 'extra_key'])
def test_inv10_tampered_signed_pack_fails_closed(acquisition, field):
    result, _, _, _ = acquisition
    pack = deepcopy(result.audit_pack)
    if field == 'signature':
        pack[field] = '0' * 128
    elif field == 'algorithm':
        pack[field] = 'none'
    elif field == 'key_id':
        pack[field] = '0' * 64
    elif field == 'schema_version':
        pack[field] = '2.0'
    elif field == 'effect':
        pack['evidence_body']['events'][3]['detail']['ticket_id'] = 'other-ticket'
    elif field == 'snapshot':
        pack['evidence_body']['snapshot']['outbox'] = []
    elif field == 'manifest':
        pack['evidence_body']['manifest']['guard_enabled'] = True
    elif field == 'receipt':
        del pack['evidence_body']['receipts'][2]
    else:
        pack['trusted_public_key'] = 'attacker-owned-key'
    report = replay(pack, acquisition)
    assert not report.signature_verified and report.verification.verdict == 'indeterminate'


def test_inv01_embedded_or_replaced_signing_identity_is_not_a_trust_anchor(acquisition):
    result, _, public, _ = acquisition
    attacker = b'z' * 32
    replacement = _sign_witness_body(result.evidence['body'], attacker)
    assert replacement['key_id'] != key_id(public)
    assert replay(replacement, acquisition).verification.verdict == 'indeterminate'
    assert replay(result.audit_pack, acquisition,
                  trusted_public_key=public_bytes(attacker)).verification.verdict == 'indeterminate'


def test_inv05_valid_signature_cannot_substitute_another_run_context(acquisition):
    result, seed, _, _ = acquisition
    body = deepcopy(result.evidence['body'])
    body['manifest']['nonce'] = '0' * 64
    other = _sign_witness_body(body, seed)
    assert replay(other, acquisition).verification.verdict == 'indeterminate'
    assert replay(other, acquisition).reason_code == 'audit_manifest_mismatch'


def test_inv10_signature_alone_does_not_make_incomplete_evidence_safe(acquisition):
    result, seed, _, _ = acquisition
    body = deepcopy(result.evidence['body'])
    body['receipts'].pop()
    report = replay(_sign_witness_body(body, seed), acquisition)
    assert report.signature_verified
    assert report.verification.verdict == 'indeterminate'
    assert report.reason_code == 'audit_insufficient_evidence'


@pytest.mark.parametrize('change,reason', [
    ('implementation_sha256', 'audit_implementation_mismatch'),
    ('case_sha256', 'audit_unknown_fixture'),
    ('oracle_sha256', 'audit_insufficient_evidence'),
])
def test_inv10_replay_requires_pinned_code_fixture_and_oracle(acquisition, change, reason):
    result, seed, _, _ = acquisition
    body = deepcopy(result.evidence['body'])
    body['manifest'][change] = '0' * 64
    report = replay(_sign_witness_body(body, seed), acquisition,
                    expected_manifest_sha256=digest(body['manifest']))
    assert report.signature_verified and report.verification.verdict == 'indeterminate'
    assert report.reason_code == reason


def test_inv01_replay_worker_failure_is_unknown(acquisition, monkeypatch):
    result, _, public, anchor = acquisition
    report = replay_in_subprocess(result.audit_pack, trusted_public_key=public,
                                  expected_manifest_sha256=anchor)
    assert report.verification.verdict == 'fail' and report.signature_verified

    def missing(*args, **kwargs):
        raise OSError('missing worker')

    monkeypatch.setattr('octoberblue.ticket_audit.run_trusted_worker', missing)
    report = replay_in_subprocess(result.audit_pack, trusted_public_key=public,
                                  expected_manifest_sha256=anchor)
    assert report.verification.verdict == 'indeterminate'
    assert not report.signature_verified


def test_inv09_export_requires_original_witness_signature(acquisition, tmp_path):
    from dataclasses import asdict

    result, _, public, anchor = acquisition
    saved = asdict(result)
    saved['verdict'] = 'pass'  # A database claim is not part of the replay oracle.
    output = tmp_path / 'pack.json'
    assert export_pack(saved, output, trusted_public_key=public) == anchor
    assert replay(load_pack(output), acquisition).verification.verdict == 'fail'
    with pytest.raises(AuditError, match='output'):
        export_pack(saved, output, trusted_public_key=public)
    saved['audit_pack'] = None
    with pytest.raises(AuditError, match='no_acquisition_signature'):
        export_pack(saved, tmp_path / 'unsigned.json', trusted_public_key=public)
    assert not (tmp_path / 'unsigned.json').exists()


def test_inv05_export_rejects_row_substitution(acquisition, tmp_path):
    from dataclasses import asdict

    result, _, public, _ = acquisition
    saved = asdict(result)
    saved['run_id'] = 'different-row'
    with pytest.raises(AuditError, match='record_mismatch'):
        export_pack(saved, tmp_path / 'mismatch.json', trusted_public_key=public)


def test_inv17_keypair_is_exclusive_private_and_never_exported(tmp_path):
    private, public = tmp_path / 'private.pem', tmp_path / 'public.pem'
    identity = generate_keypair(private, public)
    before = private.read_bytes(), public.read_bytes()
    assert identity == key_id(load_public_key(public))
    if os.name != 'nt':
        assert private.stat().st_mode & 0o077 == 0
    with pytest.raises(AuditError, match='exists'):
        generate_keypair(private, public)
    assert before == (private.read_bytes(), public.read_bytes())
    with pytest.raises(AuditError):
        generate_keypair(private, private)


def test_inv17_existing_public_key_does_not_leave_new_private_key(tmp_path):
    private, public = tmp_path / 'private.pem', tmp_path / 'public.pem'
    public.write_text('existing operator file')
    with pytest.raises(AuditError, match='exists'):
        generate_keypair(private, public)
    assert not private.exists() and public.read_text() == 'existing operator file'


@pytest.mark.skipif(os.name == 'nt', reason='POSIX mode checks; Windows ACLs are operator-managed')
def test_inv17_private_key_with_broad_permissions_is_rejected(tmp_path):
    private, public = tmp_path / 'private.pem', tmp_path / 'public.pem'
    generate_keypair(private, public)
    private.chmod(0o644)
    with pytest.raises(AuditError, match='permissions'):
        load_signing_seed(private)


def test_inv09_pack_bounds_duplicate_json_and_symlinks_are_rejected(tmp_path):
    oversized = tmp_path / 'large.json'
    oversized.write_bytes(b'x' * (MAX_PACKET_BYTES + 1))
    duplicate = tmp_path / 'duplicate.json'
    duplicate.write_text('{"schema_version":"1.0","schema_version":"2.0"}')
    for path in (oversized, duplicate):
        with pytest.raises(AuditError):
            load_pack(path)
    link = tmp_path / 'link.json'
    try:
        link.symlink_to(duplicate)
    except (OSError, NotImplementedError):
        pytest.skip('symlinks unavailable')
    with pytest.raises(AuditError):
        load_pack(link)


def test_inv10_cli_offline_replay_survives_private_key_and_database_removal(tmp_path, capsys):
    private, public = tmp_path / 'private.pem', tmp_path / 'public.pem'
    db = tmp_path / 'runs.sqlite3'
    assert main(['audit-keygen', '--private-key', str(private), '--public-key', str(public)]) == 0
    assert 'PRIVATE' not in capsys.readouterr().out
    main(['ticket-benchmark', '--case', 'support-001', '--db', str(db),
          '--audit-signing-key', str(private)])
    summary = json.loads(capsys.readouterr().out)
    assert len(summary['audit_runs']) == 2 and summary['paid_model_calls'] == 0
    run = summary['audit_runs'][0]
    pack = tmp_path / 'pack.json'
    assert main(['audit-export', '--db', str(db), '--run-id', run['run_id'],
                 '--trusted-public-key', str(public), '--output', str(pack)]) == 0
    exported = json.loads(capsys.readouterr().out)
    assert exported['manifest_sha256'] == run['manifest_sha256']
    private.unlink()
    db.unlink()
    arguments = ['audit-replay', '--input', str(pack), '--trusted-public-key', str(public),
                 '--expected-manifest-sha256', run['manifest_sha256']]
    assert main(arguments) == 0
    replayed = json.loads(capsys.readouterr().out)
    assert replayed['signature_verified'] and replayed['verdict'] == 'pass'
    assert replayed['task_success'] and not replayed['completed']
    body = json.loads(pack.read_bytes())
    body['evidence_body']['snapshot']['status'] = 'closed'
    pack.write_text(json.dumps(body))
    assert main(arguments) == 2
    assert json.loads(capsys.readouterr().out)['verdict'] == 'indeterminate'


def test_inv01_optional_crypto_failure_is_closed_and_default_run_still_works(monkeypatch):
    import octoberblue.ticket_audit as audit

    def unavailable():
        raise AuditError('audit_dependency_missing')

    monkeypatch.setattr(audit, '_crypto', unavailable)
    report = replay_audit_pack({}, trusted_public_key=b'p' * 32,
                               expected_manifest_sha256='0' * 64)
    assert report.verification.verdict == 'indeterminate'
    outcome = run_ticket_benchmark(case=load_ticket_cases()[0], defense=Defense('v1'),
                                   guard_enabled=False)
    assert outcome.verdict == 'pass' and outcome.audit_pack is None


def test_inv09_pack_schema_matches_strict_signed_contract(acquisition):
    result, _, _, _ = acquisition
    path = Path(__file__).parents[1] / 'schemas/ticket-audit-pack.v1.json'
    schema = json.loads(path.read_text())
    assert schema['additionalProperties'] is False
    assert set(schema['required']) == set(schema['properties']) == set(result.audit_pack)
    body = schema['properties']['evidence_body']
    assert body['additionalProperties'] is False
    assert set(body['required']) == set(result.audit_pack['evidence_body'])


def test_inv01_requested_signature_cannot_be_silently_omitted(acquisition, monkeypatch):
    import octoberblue.ticket_benchmark as benchmark
    from octoberblue.ticket_witness import TicketWitness

    class DroppingSignatureWitness(TicketWitness):
        def _rpc(self, request):
            response = super()._rpc(request)
            if request['operation'] == 'finalize':
                return response['evidence']
            return response

    monkeypatch.setattr(benchmark, 'TicketWitness', DroppingSignatureWitness)
    _, seed, _, _ = acquisition
    outcome = benchmark.run_ticket_benchmark(
        case=load_ticket_cases()[0], defense=Defense('v1'), guard_enabled=False,
        audit_signing_key=seed,
    )
    assert outcome.verdict == 'indeterminate' and not outcome.task_success
    assert outcome.audit_pack is None
