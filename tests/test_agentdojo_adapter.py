"""AgentDojo native run JSON compatibility, with untrusted-score boundaries."""
import json

import pytest

from octoberblue.agentdojo_adapter import (
    AgentDojoFormatError,
    import_agentdojo_results,
    parse_agentdojo_result,
)
from octoberblue.cli import main


def _result(**overrides):
    # Field layout follows AgentDojo's native TaskResults/TraceLogger JSON.
    record = {
        "suite_name": "workspace",
        "pipeline_name": "mock-pinned",
        "user_task_id": "user_task_0",
        "injection_task_id": "injection_task_1",
        "attack_type": "tool_knowledge",
        "injections": {"calendar_entry": "synthetic example, do not execute"},
        "messages": [
            {"role": "user", "content": [{"type": "text", "content": "local synthetic task"}]},
            {"role": "assistant", "content": [{"type": "text", "content": "synthetic"}]},
        ],
        "error": None,
        "utility": True,
        "security": False,
        "duration": 0.5,
    }
    record.update(overrides)
    return record


def _raw(**overrides):
    return json.dumps(_result(**overrides)).encode("utf-8")


def test_f03_agentdojo_native_success_observation_has_no_verifier_authority():
    record = parse_agentdojo_result(_raw(), source_file="result.json")
    assert record.schema_version == "1.0"
    assert record.source_framework == "agentdojo"
    assert record.evidence_class == "external_report_only"
    assert record.verifier_verdict == "indeterminate"
    assert record.reported_attack_success is True
    assert record.reported_utility is True
    assert record.has_error is False
    wire = json.dumps(record.to_wire())
    assert "synthetic example" not in wire
    assert "local synthetic task" not in wire
    assert "tool_knowledge" in wire


def test_f03_agentdojo_clean_task_is_not_attack_denominator():
    clean = parse_agentdojo_result(
        _raw(injection_task_id=None, attack_type=None, injections={},
             utility=True, security=True),
        source_file="clean.json",
    )
    assert clean.has_injection is False
    assert clean.reported_attack_success is None
    assert clean.reported_security is True


def test_inv10_agentdojo_error_and_partial_result_are_indeterminate():
    for kwargs in ({"error": "token=secret", "security": False},
                   {"utility": None, "security": True},
                   {"security": None}):
        result = parse_agentdojo_result(_raw(**kwargs), source_file="bad.json")
        assert result.reported_security is None
        assert result.reported_attack_success is None
        assert result.verifier_verdict == "indeterminate"
        assert result.has_error is True
        assert "secret" not in json.dumps(result.to_wire())


@pytest.mark.parametrize("raw", [
    b'{"suite_name":"workspace","suite_name":"banking"}',
    b'NaN',
    b"not json",
    b"[]",
    json.dumps(_result(security="false")).encode(),
    json.dumps(_result(utility=1)).encode(),
    json.dumps(_result(messages={})).encode(),
    json.dumps(_result(injection_task_id=None)).encode(),
    json.dumps(_result(suite_name="../../escape")).encode(),
])
def test_inv09_agentdojo_malformed_or_ambiguous_records_are_rejected(raw):
    with pytest.raises(AgentDojoFormatError):
        parse_agentdojo_result(raw, source_file="bad.json")


def test_inv09_agentdojo_directory_import_and_cli(tmp_path, capsys):
    source = tmp_path / "agentdojo"
    a = source / "model" / "workspace" / "user_task_0" / "tool_knowledge"
    b = source / "model" / "workspace" / "user_task_0" / "none"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    (a / "injection_task_1.json").write_bytes(_raw())
    (b / "none.json").write_bytes(_raw(
        injection_task_id=None, attack_type=None, injections={},
        utility=True, security=True,
    ))
    observations = import_agentdojo_results(source)
    assert len(observations) == 2
    assert observations[0].source_file.endswith("none.json")
    destination = tmp_path / "out.jsonl"
    main(["agentdojo-import", "--input", str(source), "--output", str(destination)])
    rows = [json.loads(line) for line in destination.read_text().splitlines()]
    assert len(rows) == 2
    assert all(row["verifier_verdict"] == "indeterminate" for row in rows)
    assert all(len(row["source_sha256"]) == 64 for row in rows)
    assert '"paid_model_calls": 0' in capsys.readouterr().out


def test_inv09_agentdojo_symlink_and_duplicate_refused(tmp_path):
    source = tmp_path / "runs"
    source.mkdir()
    (source / "one.json").write_bytes(_raw())
    (source / "two.json").write_bytes(_raw())
    with pytest.raises(AgentDojoFormatError, match="duplicate"):
        import_agentdojo_results(source)
    (source / "two.json").unlink()
    link = source / "linked.json"
    try:
        link.symlink_to(source / "one.json")
    except (OSError, NotImplementedError):
        pytest.skip("filesystem does not permit symlinks")
    with pytest.raises(AgentDojoFormatError, match="linked"):
        import_agentdojo_results(source)


def test_inv09_agentdojo_file_size_limit(tmp_path):
    result = tmp_path / "oversize.json"
    result.write_bytes(b" " * 2_000_001)
    with pytest.raises(AgentDojoFormatError, match="size limit"):
        import_agentdojo_results(result)
