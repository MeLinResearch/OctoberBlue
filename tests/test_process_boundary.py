"""INV-01/03/11: bounded streams, deadlines and sanitized trusted worker startup."""
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from octoberblue import process_boundary as boundary
from octoberblue.contracts import Defense
from octoberblue.process_boundary import (
    ProcessBoundaryError,
    run_bounded,
    run_trusted_worker,
    worker_command,
)
from octoberblue.target_runtime import TargetRuntimeError, propose_in_container
from octoberblue.ticket_benchmark import run_ticket_benchmark
from octoberblue.ticket_contracts import load_ticket_cases


def python(code):
    return [sys.executable, '-I', '-c', code]


def test_inv11_stdout_and_stderr_are_drained_concurrently_at_exact_limits():
    result = run_bounded(python(
        "import sys; sys.stdin.buffer.read(); "
        "sys.stdout.buffer.write(b'x'*65536); sys.stdout.buffer.flush(); "
        "sys.stderr.buffer.write(b'y'*65536); sys.stderr.buffer.flush()"
    ), input=b'bounded-input', timeout=5, stdout_limit=65536, stderr_limit=65536)
    assert result.returncode == 0
    assert result.stdout == b'x' * 65536 and result.stderr == b'y' * 65536


@pytest.mark.parametrize('stream,reason', [(1, 'stdout_limit'), (2, 'stderr_limit')])
def test_inv11_output_flood_is_stopped_after_one_overflow_byte(monkeypatch, stream, reason):
    original = boundary.subprocess.Popen
    children = []
    read_bytes = [0, 0]

    class Spy:
        def __init__(self, pipe, index):
            self.pipe, self.index = pipe, index

        def read(self, count):
            value = self.pipe.read(count)
            read_bytes[self.index] += len(value)
            return value

        def close(self):
            return self.pipe.close()

    def tracked(*args, **kwargs):
        process = original(*args, **kwargs)
        if kwargs.get('stdout') == subprocess.PIPE:
            process.stdout = Spy(process.stdout, 0)
            process.stderr = Spy(process.stderr, 1)
        children.append(process)
        return process

    monkeypatch.setattr(boundary.subprocess, 'Popen', tracked)
    with pytest.raises(ProcessBoundaryError, match=reason):
        run_bounded(python(f"import os\nwhile True: os.write({stream}, b'x'*65536)"),
                    timeout=5, stdout_limit=1024, stderr_limit=1024)
    assert read_bytes[stream - 1] == 1025
    assert all(n <= 1025 for n in read_bytes)
    assert all(child.poll() is not None for child in children)


@pytest.mark.parametrize('code,input_bytes', [
    ('import time; time.sleep(30)', b'x' * 1_000_000),
    ('import os,time; os.close(1); os.close(2); time.sleep(30)', b''),
])
def test_inv11_deadline_includes_stalled_input_and_closed_output_pipes(code, input_bytes):
    started = time.monotonic()
    with pytest.raises(ProcessBoundaryError, match='process_timeout'):
        run_bounded(python(code), input=input_bytes, timeout=0.3,
                    stdout_limit=1024, stderr_limit=1024)
    assert time.monotonic() - started < 8


@pytest.mark.skipif(os.name != 'posix', reason='POSIX session cleanup only')
def test_inv11_descendant_held_pipes_cannot_extend_deadline_after_leader_exit():
    code = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(30)']); "
        "sys.exit(0)"
    )
    started = time.monotonic()
    with pytest.raises(ProcessBoundaryError, match='process_timeout'):
        run_bounded(python(code), timeout=0.4, stdout_limit=1024, stderr_limit=1024)
    assert time.monotonic() - started < 5


def test_inv11_nonzero_exit_and_invalid_bytes_are_returned_without_decoding():
    result = run_bounded(python("import os,sys; os.write(1,b'\\xff'); sys.exit(7)"),
                         timeout=5, stdout_limit=1)
    assert result.returncode == 7 and result.stdout == b'\xff'


@pytest.mark.parametrize('options', [
    {'timeout': float('nan')}, {'timeout': float('inf')}, {'timeout': 0},
    {'timeout': True}, {'stdout_limit': -1}, {'stderr_limit': True}, {'input': 'text'},
])
def test_inv11_invalid_limits_are_rejected_before_launch(options):
    config = dict(timeout=1, stdout_limit=1024)
    config.update(options)
    with pytest.raises(ValueError):
        run_bounded(python('pass'), **config)


def test_inv03_verifier_startup_drops_ambient_secrets_and_import_injection(monkeypatch, tmp_path):
    original = boundary.subprocess.Popen
    launches = []
    sentinel = tmp_path / 'injection-ran'
    (tmp_path / 'sitecustomize.py').write_text(f"open({str(sentinel)!r},'w').write('bad')")
    fake = tmp_path / 'octoberblue'
    fake.mkdir()
    (fake / '__init__.py').write_text(f"open({str(sentinel)!r},'w').write('bad')")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('PYTHONPATH', str(tmp_path))
    monkeypatch.setenv('PYTHONHOME', str(tmp_path))
    monkeypatch.setenv('GH_TOKEN', 'fixture-secret-not-a-credential')
    monkeypatch.setenv('OPENAI_API_KEY', 'fixture-secret-not-a-credential')

    def tracked(command, **kwargs):
        launches.append((command, kwargs))
        assert Path(kwargs['cwd']).is_dir()
        return original(command, **kwargs)

    monkeypatch.setattr(boundary.subprocess, 'Popen', tracked)
    result = run_trusted_worker('octoberblue.ticket_audit_worker', input=b'not JSON', timeout=5)
    assert result.returncode == 2 and result.stdout == b''
    command, options = launches[0]
    assert command[1:4] == ['-I', '-B', '-m']
    assert set(options['env']) <= {'SystemRoot', 'WINDIR', 'TMPDIR', 'TEMP', 'TMP'}
    assert options['cwd'] != str(tmp_path) and not Path(options['cwd']).exists()
    assert not sentinel.exists()
    with pytest.raises(ValueError):
        worker_command('attacker.module')


@pytest.mark.parametrize('reason,code', [
    ('stdout_limit', 'target_output_too_large'),
    ('stderr_limit', 'target_stderr_too_large'),
    ('process_timeout', 'target_timeout'),
])
def test_inv11_docker_transport_failure_always_cleans_named_container(monkeypatch, reason, code):
    cleaned = []

    def failed(*args, **kwargs):
        raise ProcessBoundaryError(reason)

    monkeypatch.setattr('octoberblue.target_runtime.run_bounded', failed)
    monkeypatch.setattr('octoberblue.target_runtime._cleanup', cleaned.append)
    with pytest.raises(TargetRuntimeError, match=code):
        propose_in_container(visible_payload='', source_total='125.00', run_legitimate_task=True)
    assert len(cleaned) == 1 and cleaned[0].startswith('octoberblue-target-')


def test_inv01_valid_target_prefix_followed_by_flood_never_executes_proposals(monkeypatch):
    actual = run_bounded
    cleaned = []
    prefix = b'{"protocol":"octoberblue.ticket.proposals.v1","proposals":[]}'

    def flooding_target(command, **kwargs):
        code = f"import os; os.write(1,{prefix!r})\nwhile True: os.write(1,b'x'*65536)"
        return actual(python(code), input=kwargs['input'], timeout=5,
                      stdout_limit=kwargs['stdout_limit'], stderr_limit=kwargs['stderr_limit'])

    monkeypatch.setattr('octoberblue.ticket_benchmark.resolve_image_id', lambda _: 'sha256:'+'a'*64)
    monkeypatch.setattr('octoberblue.target_runtime.run_bounded', flooding_target)
    monkeypatch.setattr('octoberblue.target_runtime._cleanup', cleaned.append)
    result = run_ticket_benchmark(case=load_ticket_cases()[20], defense=Defense('v1'),
                                   guard_enabled=False, target_runtime='docker')
    assert result.verdict == 'indeterminate' and not result.task_success
    assert len(cleaned) == 1
    assert not any(e['kind'] == 'tool_executed' and e['detail']['tool'] == 'draft_reply'
                   for e in result.events)
    assert any(e['kind'] == 'target_runtime_failed'
               and e['detail']['reason_code'] == 'target_output_too_large' for e in result.events)


@pytest.mark.parametrize('stream,reason', [(1, 'stdout_limit'), (2, 'stderr_limit')])
def test_inv11_finite_overflow_cannot_pass_when_child_exits_normally(stream, reason):
    with pytest.raises(ProcessBoundaryError, match=reason):
        run_bounded(python(f"import os; os.write({stream}, b'x'*1025)"), timeout=5,
                    stdout_limit=1024, stderr_limit=1024)


def test_inv01_deeply_nested_evidence_is_indeterminate_before_worker_launch():
    from octoberblue.ticket_contracts import TicketOracle
    from octoberblue.ticket_verifier import TicketSnapshot
    from octoberblue.ticket_verifier_process import verify_ticket_in_subprocess
    from octoberblue.verifier import SandboxSnapshot
    from octoberblue.verifier_process import verify_in_subprocess

    nested = {}
    for _ in range(1200):
        nested = {'nested': nested}
    case = load_ticket_cases()[0]
    snapshot = TicketSnapshot('open', 0, 0, (), (), (), (), False)
    result = verify_ticket_in_subprocess(
        [], snapshot, oracle=TicketOracle.for_case(case), run_id='nested-evidence',
        evidence=nested, authentication_key=b'a' * 32, expected_manifest_sha256='0' * 64,
    )
    assert result.verdict == 'indeterminate'
    result = verify_in_subprocess([nested], SandboxSnapshot((), ()),
                                  expected_total='125.00', run_id='nested-evidence')
    assert result.verdict == 'indeterminate'


def test_inv04_deeply_nested_target_json_is_rejected_without_interpreter_error(monkeypatch):
    from octoberblue.process_boundary import ProcessResult

    monkeypatch.setattr('octoberblue.target_runtime.run_bounded', lambda *a, **k: ProcessResult(
        0, b'[' * 2000 + b']' * 2000, b'',
    ))
    with pytest.raises(TargetRuntimeError, match='invalid_target_response'):
        propose_in_container(visible_payload='', source_total='125.00', run_legitimate_task=True)


@pytest.mark.parametrize('raw', [
    b'{"task_success":false,"attempted":false,"completed":false,"verdict":"pass"}',
    b'{"task_success":true,"attempted":false,"completed":true,"verdict":"fail"}',
    b'{"task_success":true,"attempted":false,"completed":false,"verdict":"fail","verdict":"pass"}',
])
def test_inv01_legacy_verifier_rejects_inconsistent_and_duplicate_verdicts(monkeypatch, raw):
    from octoberblue.process_boundary import ProcessResult
    from octoberblue.verifier import SandboxSnapshot
    from octoberblue.verifier_process import verify_in_subprocess

    monkeypatch.setattr('octoberblue.verifier_process.run_trusted_worker',
                        lambda *a, **k: ProcessResult(0, raw, b''))
    result = verify_in_subprocess([], SandboxSnapshot((), ()),
                                  expected_total='125.00', run_id='invalid-verdict')
    assert result.verdict == 'indeterminate'
