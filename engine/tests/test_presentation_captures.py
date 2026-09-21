"""Presentation labels must agree with the actual parser, rules and evidence."""
import hashlib
import json
from pathlib import Path

import pytest

from mailsentinel.pipeline import analyse_capture

PACK = Path(__file__).resolve().parents[2] / 'demo captures'
MANIFEST = json.loads((PACK / 'manifest.json').read_text())


@pytest.mark.parametrize('sample', MANIFEST['captures'], ids=lambda s: s['filename'])
def test_presentation_capture_matches_manifest(sample):
    capture = PACK / sample['filename']
    assert hashlib.sha256(capture.read_bytes()).hexdigest() == sample['sha256']
    report = analyse_capture(str(capture), run_ml=False)
    assert report.overall_grade == sample['expected_grade']
    assert len(report.sessions) == sample['sessions']
    expected_grades = sample.get('session_grades', [sample['expected_grade']] * sample['sessions'])
    assert sorted(s.grade.letter for s in report.sessions) == sorted(expected_grades)
    rules = {f.rule_id for s in report.sessions for f in s.findings}
    assert rules == set(sample['observed_rules'])
    assert set(sample['expected_rules']) <= rules
    assert sample['synthetic'] is True


def test_before_after_snapshots_match_servers_and_show_remediation():
    pair = {r['phase']: r for r in MANIFEST['captures'] if r.get('comparison_pair') == 'mail-server-remediation'}
    before = analyse_capture(str(PACK / pair['before']['filename']), run_ml=False)
    after = analyse_capture(str(PACK / pair['after']['filename']), run_ml=False)
    identity = lambda s: (s.protocol, s.server_name, s.server.ip, s.server.port)
    assert {identity(s) for s in before.sessions} == {identity(s) for s in after.sessions}
    assert len({identity(s) for s in before.sessions}) == 3
    assert before.capture.last_packet_time < after.capture.first_packet_time
    assert before.capture.sha256 != after.capture.sha256
    assert all(s.server_name == 'example.com' for s in before.sessions + after.sessions)
    assert all(len([t for t in before.sessions if identity(t) == identity(s)]) == 2 for s in before.sessions)
    assert any(f.severity.value != 'info' for s in before.sessions for f in s.findings)
    assert not any(f.severity.value != 'info' for s in after.sessions for f in s.findings)
    assert all(s.chain_valid and s.forward_secrecy and s.tls_version == '1.2' for s in after.sessions)
