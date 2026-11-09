"""Reproducible, zero-model-cost acceptance gate for fixed Docker JSON workers.

Run: python -m octoberblue.phase1 --output NEW_DIRECTORY
Requires locally built target/trusted images and the optional audit dependency.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

from .contained_runtime import PROFILE, TRUSTED_IMAGE, probe_container
from .contracts import Defense
from .store import Store
from .target_runtime import resolve_image_id
from .ticket_audit import (
    export_pack,
    generate_keypair,
    load_pack,
    load_public_key,
    load_signing_seed,
    replay_in_subprocess,
    write_new,
)
from .ticket_benchmark import TicketGatewayPolicy, run_ticket_benchmark
from .ticket_contracts import digest, load_ticket_cases
from .ticket_evidence import implementation_digest


def outcome(result):
    return {key: getattr(result, key) for key in (
        'task_success', 'attempted_unauthorized_action', 'attack_success', 'verdict')}


def receipt_decisions(result):
    # Fresh nonces deliberately change the cryptographic chains between runs.
    return [{k: v for k, v in receipt.items() if k not in {'sha256', 'previous_sha256'}}
            for receipt in result.evidence['body']['receipts']]


def accept(directory: Path, *, target_image, verifier_image, jobs=4):
    """No partial acceptance: missing controls or indeterminate evidence fail."""
    target, verifier = resolve_image_id(target_image), resolve_image_id(verifier_image)
    report = {'schema_version': '1.0', 'profile': PROFILE, 'synthetic_only': True,
              'implementation_sha256': implementation_digest(), 'target_image_id': target,
              'verifier_image_id': verifier, 'paid_model_calls': 0,
              'budget_ceiling_dollars': '0.00', 'checks': {}, 'results': []}
    checks = report['checks']
    with tempfile.TemporaryDirectory(prefix='octoberblue-acceptance-') as temporary:
        workspace = Path(temporary)
        sentinel = workspace / 'host-only-sentinel'
        sentinel.write_text('host-only acceptance canary', encoding='utf-8')
        # Only this explicit canary is used; no real environment secrets are read.
        previous = os.environ.get('OCTOBERBLUE_CONTAINMENT_SECRET')
        os.environ['OCTOBERBLUE_CONTAINMENT_SECRET'] = 'acceptance-canary'
        try:
            report['probes'] = {
                'target': probe_container(target, target=True, host_sentinel=sentinel),
                'verifier': probe_container(verifier, target=False, host_sentinel=sentinel),
            }
        finally:
            if previous is None:
                os.environ.pop('OCTOBERBLUE_CONTAINMENT_SECRET', None)
            else:
                os.environ['OCTOBERBLUE_CONTAINMENT_SECRET'] = previous
        checks['containment_controls'] = all(
            all(probe.values()) for probe in report['probes'].values())
        # Refuse to execute the matrix on a runtime without enforceable controls.
        if not checks['containment_controls']:
            report['passed'] = False
            return report
        private, public_path = workspace / 'private.pem', directory / 'public.pem'
        generate_keypair(private, public_path)
        seed, public = load_signing_seed(private), load_public_key(public_path)
        defense = Defense('marker-v1')
        common = dict(defense=defense, target_runtime='docker', target_image=target,
                      verifier_runtime='docker', verifier_image=verifier,
                      audit_signing_key=seed, seed=0)
        cases = load_ticket_cases()

        def trial(item):
            case, guard = item
            contained = run_ticket_benchmark(case=case, guard_enabled=guard, **common)
            reference = run_ticket_benchmark(case=case, defense=defense, guard_enabled=guard)
            return case, guard, contained, reference

        store_path = workspace / 'runs.sqlite3'
        store = Store(str(store_path))
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            trials = list(pool.map(trial, [(case, guard) for case in cases
                                           for guard in (False, True)]))
        checks['matrix_80_determinate'] = len(trials) == 80 and all(
            row.verdict in {'pass', 'fail'} for _, _, row, _ in trials)
        checks['reference_parity'] = all(outcome(row) == outcome(reference)
                                         for _, _, row, reference in trials)
        packs = directory / 'packs'
        packs.mkdir()
        for case, guard, row, _ in trials:
            store.save(row)
            row_anchor = export_pack(store.get(row.run_id), packs / f'{row.run_id}.json',
                                     trusted_public_key=public)
            report['results'].append({'case_id': case.case_id, 'guard_enabled': guard,
                                      'run_id': row.run_id, 'manifest_sha256': row_anchor,
                                      **outcome(row)})
        first = trials[0][2]
        try:
            store.save(first)
        except sqlite3.IntegrityError:
            checks['immutable_run_id'] = True
        else:
            checks['immutable_run_id'] = False
        anchor = export_pack(store.get(first.run_id), directory / 'pack.json',
                             trusted_public_key=public)
        report['manifest_sha256'] = anchor
        repeat = run_ticket_benchmark(case=cases[0], guard_enabled=False,
                                      run_id=first.run_id, **common)
        checks['deterministic_events_and_state'] = (
            first.evidence['body']['events'] == repeat.evidence['body']['events']
            and first.evidence['body']['snapshot'] == repeat.evidence['body']['snapshot']
            and receipt_decisions(first) == receipt_decisions(repeat)
            and outcome(first) == outcome(repeat)
            and first.evidence['body']['manifest']['nonce']
            != repeat.evidence['body']['manifest']['nonce'])
        denied = run_ticket_benchmark(case=cases[20], guard_enabled=False,
                                     policy=TicketGatewayPolicy(allow_simulated_breach=False),
                                     **common)
        checks['gateway_independent_of_guard'] = (
            denied.verdict == 'pass' and denied.attempted_unauthorized_action
            and not denied.attack_success and denied.task_success)
        store.close()
        private.unlink()
        store_path.unlink()
        common.clear()
        del seed, trials, repeat
        pack = load_pack(directory / 'pack.json')
        replay_options = dict(trusted_public_key=public, expected_manifest_sha256=anchor,
                              runtime='docker', image_id=verifier, timeout=12)
        replay = replay_in_subprocess(pack, **replay_options)
        checks['offline_replay_after_key_and_database_removal'] = (
            replay.signature_verified and replay.reason_code == 'replayed'
            and replay.verification.verdict == first.verdict
            and replay.verification.task_success == first.task_success
            and replay.verification.completed == first.attack_success)
        tamper = []
        for field in ('events', 'receipts', 'snapshot', 'manifest'):
            damaged = deepcopy(pack)
            body = damaged['evidence_body']
            if field in ('events', 'receipts'):
                body[field].pop()
            elif field == 'snapshot':
                body[field]['status'] = 'forged'
            else:
                body[field]['seed'] += 1
            result = replay_in_subprocess(damaged, **replay_options)
            tamper.append(result.verification.verdict == 'indeterminate')
        checks['tampered_evidence_fails_closed'] = all(tamper)
        checks['manifest_identity'] = anchor == digest(pack['evidence_body']['manifest'])
    report['passed'] = all(checks.values())
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--target-image', default='octoberblue-target:v0.2')
    parser.add_argument('--verifier-image', default=TRUSTED_IMAGE)
    parser.add_argument('--jobs', type=int, choices=range(1, 5), default=4)
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False)
    try:
        report = accept(args.output, target_image=args.target_image,
                        verifier_image=args.verifier_image, jobs=args.jobs)
    except Exception as error:
        # Fixed failure class only: never dump potentially sensitive worker output.
        report = {'schema_version': '1.0', 'passed': False,
                  'error_type': type(error).__name__, 'paid_model_calls': 0,
                  'budget_ceiling_dollars': '0.00'}
    write_new(args.output / 'report.json', json.dumps(report, sort_keys=True, indent=2).encode())
    print(json.dumps(report, sort_keys=True))
    return 0 if report['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
