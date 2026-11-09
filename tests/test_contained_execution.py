"""INV-01/03/10/11: contained identity, no fallback, poisoned witness channels."""
import json
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from octoberblue.contained_runtime import container_command
from octoberblue.contracts import Defense
from octoberblue.ticket_benchmark import run_ticket_benchmark
from octoberblue.ticket_contracts import TicketOracle, digest, load_ticket_cases
from octoberblue.ticket_evidence import RunManifestV1, RunManifestV2, parse_run_manifest
from octoberblue.ticket_verifier import TicketSnapshot
from octoberblue.ticket_verifier_process import verify_ticket_in_subprocess
from octoberblue.ticket_witness import TicketWitness, WitnessError

IMAGE = 'sha256:' + 'a' * 64


@pytest.fixture(scope='module')
def baseline():
    case = load_ticket_cases()[0]
    result = run_ticket_benchmark(case=case, defense=Defense('v1'), guard_enabled=False)
    return case, result, parse_run_manifest(result.evidence['body']['manifest'])


def test_inv09_explicit_manifest_versions_preserve_v1(baseline):
    _, _, old = baseline
    assert type(old) is RunManifestV1
    wire = dict(old.to_wire(), schema_version='2.0', target_runtime='docker', image_id=IMAGE,
                execution_profile='docker-json-v1', verifier_image_id=IMAGE)
    assert type(parse_run_manifest(wire)) is RunManifestV2
    with pytest.raises(ValueError):
        RunManifestV1.from_wire(wire)
    for key, value in [('execution_profile', 'unknown'), ('schema_version', '3.0'),
                       ('target_runtime', 'in_memory'), ('verifier_image_id', 'latest')]:
        with pytest.raises(ValueError):
            parse_run_manifest(dict(wire, **{key: value}))


@pytest.mark.parametrize('runtime', ['docker', 'unknown'])
def test_inv01_missing_contained_identity_never_falls_back(monkeypatch, baseline, runtime):
    import octoberblue.ticket_verifier_process as transport
    case, result, _ = baseline

    def forbidden(*args, **kwargs):
        pytest.fail('must not launch or fall back with an unbound verifier identity')

    monkeypatch.setattr(transport, 'run_trusted_worker', forbidden)
    monkeypatch.setattr(transport, 'run_contained_worker', forbidden)
    verdict = verify_ticket_in_subprocess(
        [], TicketSnapshot.from_wire(result.evidence['body']['snapshot']),
        oracle=TicketOracle.for_case(case), run_id=result.run_id,
        evidence=result.evidence, authentication_key=b'a' * 32,
        expected_manifest_sha256=digest(result.evidence['body']['manifest']),
        runtime=runtime, image_id=IMAGE)
    assert verdict.verdict == 'indeterminate'


def test_inv11_contained_worker_has_no_mount_network_or_dynamic_module():
    command = container_command(IMAGE, 'octoberblue.ticket_verifier_worker', 'test-worker')
    for control in ('--network=none', '--read-only', '--cap-drop=ALL', '--pids-limit=32',
                    '--user=65534:65534', '--security-opt=no-new-privileges=true',
                    '--memory=256m', '--cpus=1', '--pull=never'):
        assert control in command
    assert not any(arg.startswith(('--volume', '--mount', '--privileged')) for arg in command)
    assert command[-6:] == [IMAGE, 'python', '-I', '-B', '-m',
                            'octoberblue.ticket_verifier_worker']
    with pytest.raises(ValueError):
        container_command('latest', 'octoberblue.ticket_verifier_worker', 'test')
    with pytest.raises(ValueError):
        container_command(IMAGE, 'arbitrary.module', 'test')


@pytest.mark.parametrize('behavior', ['write_stall', 'read_stall', 'early_eof',
                                     'truncated', 'extra_seal_frame', 'nonzero_seal'])
def test_inv01_witness_deadline_poison_and_clean_seal(monkeypatch, baseline, behavior):
    import octoberblue.ticket_witness as client
    _, _, manifest = baseline
    # A controlled test worker: ready, then a specific transport fault. No network.
    prefix = (
        "import sys,json,time\n"
        "sys.stdin.buffer.readline()\n"
        "print(json.dumps({'schema_version':'1.0','sequence':1,'result':{'ready':True}}),"
        "flush=True)\n")
    if behavior == 'write_stall':
        body = 'time.sleep(30)\n'
    else:
        body = 'request=json.loads(sys.stdin.buffer.readline())\n'
        if behavior == 'read_stall':
            body += 'time.sleep(30)\n'
        elif behavior == 'early_eof':
            body += 'sys.exit(2)\n'
        elif behavior == 'truncated':
            body += "sys.stdout.write('{');sys.stdout.flush()\n"
        else:
            body += ("print(json.dumps({'schema_version':'1.0','sequence':2,'result':{}}),"
                     "flush=True)\n")
            body += ("print('{}',flush=True)\n" if behavior == 'extra_seal_frame'
                     else 'sys.exit(2)\n')
    monkeypatch.setattr(client, 'worker_command', lambda _: [sys.executable, '-I', '-c',
                                                           prefix + body])
    witness = TicketWitness(replace(manifest, run_id='transport-fault'), 'ticket', 'account',
                            rpc_timeout=3)
    witness.rpc_timeout = 0.25
    started = time.monotonic()
    with pytest.raises(WitnessError):
        if behavior in ('extra_seal_frame', 'nonzero_seal'):
            witness.finalize()
        else:
            witness.call('get_ticket', {'ticket_id': 'x' * 200_000})
    assert time.monotonic() - started < 5
    assert witness.process.poll() is not None
    assert witness.key == b'' and not Path(witness.workspace.name).exists()
    with pytest.raises(WitnessError):
        witness.call('get_ticket', {'ticket_id': 'ticket'})


def test_inv11_gate_refuses_missing_cgroup_controls(monkeypatch, tmp_path):
    import octoberblue.phase1 as gate
    monkeypatch.setattr(gate, 'resolve_image_id', lambda _: IMAGE)
    monkeypatch.setattr(gate, 'probe_container', lambda *a, **kw: {'memory_limit_enforced': False})
    monkeypatch.setattr(gate, 'run_ticket_benchmark', lambda **kw: pytest.fail('unsafe matrix'))
    report = gate.accept(tmp_path, target_image=IMAGE, verifier_image=IMAGE)
    assert report['passed'] is False
    assert report['checks']['containment_controls'] is False
    assert report['results'] == [] and report['paid_model_calls'] == 0
    assert json.loads(json.dumps(report)) == report
