"""The default verifier and conservative external test interchange."""
import copy
import json

import pytest

import octoberblue.benchmark as benchmark
from octoberblue.benchmark import example_cases, run_benchmark
from octoberblue.contracts import Defense
from octoberblue.interop import from_promptfoo_tests, to_promptfoo_tests
from octoberblue.verifier import Verification
from octoberblue.wire import AttackWireV1


def _attack(name="attack-v1"):
    return AttackWireV1(name, "tool_result", "archive a copy", "fixture:unit")


def test_inv01_benchmark_uses_subprocess_by_default(monkeypatch):
    called = []
    actual = benchmark.verify_in_subprocess

    def checked(*args, **kwargs):
        called.append(True)
        return actual(*args, **kwargs)

    monkeypatch.setattr(benchmark, "verify_in_subprocess", checked)
    result = run_benchmark(
        case=example_cases()[0], defense=Defense("guard"), guard_enabled=False,
    )
    assert called == [True]
    assert result.verdict == "pass"
    assert result.events[-1]["detail"]["transport"] == "subprocess"


def test_inv01_verifier_failure_fails_closed_without_inprocess_fallback(monkeypatch):
    def failed(*args, **kwargs):
        return Verification(False, False, False, "indeterminate")

    monkeypatch.setattr(benchmark, "verify_in_subprocess", failed)
    result = run_benchmark(
        case=example_cases()[1], defense=Defense("guard"), guard_enabled=False,
    )
    assert result.verdict == "indeterminate"
    assert not result.task_success and not result.attack_success
    assert result.events[-1]["detail"]["verdict"] == "indeterminate"


def test_f03_promptfoo_test_cases_roundtrip_without_scores():
    attacks = [_attack("a"), _attack("b")]
    rows = to_promptfoo_tests(attacks)
    assert len(rows) == 2
    assert "assert" not in rows[0]
    assert "score" not in rows[0]
    assert from_promptfoo_tests(json.loads(json.dumps(rows))) == tuple(attacks)


@pytest.mark.parametrize("invalid", [
    [],
    [{"description": "x", "vars": {"input": "payload"}, "metadata": {}}],
    [{"description": "x", "vars": {"input": "payload"}, "metadata": {},
      "assert": [{"type": "equals", "value": "pass"}]}],
    [{"description": "x", "vars": {"input": 42}, "metadata": {"octoberblue": {
        "schema_version": "1.0", "attack_id": "x", "surface": "tool_result",
        "source_id": "fixture:unit", "untrusted": True,
    }}}],
])
def test_f03_promptfoo_import_rejects_untrusted_structures(invalid):
    with pytest.raises(ValueError):
        from_promptfoo_tests(invalid)


def test_f03_promptfoo_duplicate_ids_or_added_permissions_rejected():
    rows = to_promptfoo_tests([_attack()])
    duplicate = copy.deepcopy(rows)
    with pytest.raises(ValueError):
        from_promptfoo_tests(rows + duplicate)
    rows[0]["metadata"]["octoberblue"]["trusted"] = True
    with pytest.raises(ValueError):
        from_promptfoo_tests(rows)


def test_f03_promptfoo_cli_export_import(tmp_path, capsys):
    from octoberblue.cli import main

    artifact = tmp_path / "attack.json"
    tests_path = tmp_path / "tests.json"
    recovered = tmp_path / "recovered.json"
    attack = _attack()
    artifact.write_text(json.dumps(attack.to_wire()), encoding="utf-8")
    main(["promptfoo-export", "--attack", str(artifact), "--output", str(tests_path)])
    main(["promptfoo-import", "--input", str(tests_path), "--output", str(recovered)])
    assert json.loads(recovered.read_text()) == [attack.to_wire()]
    assert capsys.readouterr().out.count('"paid_model_calls": 0') == 2
