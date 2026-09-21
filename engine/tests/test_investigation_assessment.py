import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from mailsentinel.pipeline import analyse_capture
from mailsentinel.models import to_dict
from mailsentinel.history import annotate_history
from mailsentinel.ml.captured_dataset import build, load

ROOT = Path(__file__).resolve().parents[2]


def test_coverage_never_calls_hidden_certificate_verified():
    report = analyse_capture(str(ROOT / 'demo-pcaps/synthetic-imaps-tls13.pcap'), run_ml=False)
    s = report.sessions[0]
    assert s.grade.letter == 'A+'
    checks = {c['check']: c for c in s.coverage['checks']}
    assert checks['certificate']['status'] == 'unknown'
    assert s.coverage['label'] == 'limited'
    assert len(report.provenance['engine_source_sha256']) == 64
    assert len(report.provenance['rules_sha256']) == 64


def history_fixture():
    report = analyse_capture(str(ROOT / 'demo-pcaps/synthetic-imaps-tls13.pcap'), run_ml=False)
    now = datetime(2026, 1, 3, tzinfo=timezone.utc)
    report.capture.first_packet_time = now
    report.sessions[0].server_name = 'mail.lab'
    base = to_dict(report)
    previous = []
    for n in range(2):
        old = copy.deepcopy(base)
        old['capture'].update(sha256=f'previous-{n}', first_packet_time=(now - timedelta(days=2-n)).isoformat(), last_packet_time=(now - timedelta(days=2-n)).isoformat())
        old['sessions'] = [copy.deepcopy(old['sessions'][0]) for _ in range(4)]
        previous.append(old)
    return report, previous


def test_history_uses_prior_distinct_captures_and_keeps_verdicts():
    report, previous = history_fixture()
    original = copy.deepcopy(to_dict(report)['sessions'])
    result = annotate_history(report, previous)
    s = result['servers'][0]
    assert s['status'] == 'established'
    assert s['prior_captures'] == 2 and s['prior_sessions'] == 8
    assert s['ml_status'] == 'evaluated_against_prior_sessions'
    assert to_dict(report)['sessions'] == original


def test_history_excludes_future_duplicate_and_current_evidence():
    report, previous = history_fixture()
    previous[1]['capture']['first_packet_time'] = '2027-01-01T00:00:00+00:00'
    previous[1]['capture']['last_packet_time'] = '2027-01-01T00:00:00+00:00'
    result = annotate_history(report, previous + [previous[0], to_dict(report)])
    assert result['servers'][0]['prior_sessions'] == 4
    assert result['servers'][0]['status'] == 'baseline_not_established'


def test_no_hostname_means_provisional_not_trusted_baseline():
    report, previous = history_fixture()
    report.sessions[0].server_name = None
    for p in previous:
        for s in p['sessions']: s['server_name'] = None
    result = annotate_history(report, previous)['servers'][0]
    assert result['status'] == 'baseline_not_established'
    assert result['identity_confidence'] == 'provisional_endpoint_only'


def test_changed_endpoint_not_silently_merged():
    report, previous = history_fixture()
    report.sessions[0].server.ip = '192.0.2.99'
    assert annotate_history(report, previous)['servers'][0]['prior_sessions'] == 0


def test_progress_events_are_real_pipeline_boundaries():
    stages = []
    analyse_capture(str(ROOT / 'demo-pcaps/smtp.pcap'), run_ml=False, progress=stages.append)
    assert stages[0] == 'READING' and stages[-1] == 'HISTORY_COMPARISON'
    assert stages.index('REASSEMBLING') < stages.index('RULES_AND_COVERAGE')


def test_captured_dataset_uses_parser_and_independent_labels(tmp_path):
    manifest = {'captures': [{'path': str(ROOT / 'demo-pcaps/smtp.pcap'), 'configuration_id': 'smtp-config',
                             'label': 'critical', 'ground_truth': {'tls': False}}]}
    source = tmp_path / 'manifest.json'; source.write_text(json.dumps(manifest))
    output = tmp_path / 'dataset.jsonl'
    assert build(source, output) > 0
    row = json.loads(output.read_text().splitlines()[0])
    assert row['label'] == 'critical' and row['features']['tls_version'] == 0
    assert len(row['capture_sha256']) == 64
    manifest['captures'].append(manifest['captures'][0])
    source.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='Duplicate'): build(source, output)


def test_dataset_rejects_same_evidence_in_different_groups(tmp_path):
    report, _ = history_fixture()
    s = report.sessions[0]
    rows = [{'features': s.features, 'label': 'secure', 'capture_sha256': 'same', 'session_id': str(i),
             'configuration_id': str(i), 'cert_masked': True} for i in range(3)]
    path = tmp_path / 'dataset.jsonl'
    path.write_text('\n'.join(json.dumps(r) for r in rows))
    with pytest.raises(ValueError, match='multiple evaluation groups'): load(path)
