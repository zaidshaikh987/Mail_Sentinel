"""Extract features from captured traffic, with labels supplied by lab ground truth.
Usage: python -m mailsentinel.ml.captured_dataset manifest.json dataset.jsonl
"""
import argparse
import json
from pathlib import Path
from .dataset import GeneratedDataset, CLASSES
from ..features import FEATURE_NAMES, to_row
from ..pipeline import analyse_capture
from ..models import CertVisibility


def build(manifest_path, destination):
    manifest_path = Path(manifest_path).resolve()
    manifest = json.loads(manifest_path.read_text())
    rows = []
    hashes = set()
    for entry in manifest['captures']:
        if entry.get('label') not in CLASSES or not entry.get('configuration_id') or not entry.get('ground_truth'):
            raise ValueError('Each capture requires a valid label, configuration_id and independent ground_truth')
        path = (manifest_path.parent / entry['path']).resolve()
        report = analyse_capture(str(path), run_ml=False)
        if report.capture.sha256 in hashes:
            raise ValueError('Duplicate capture evidence in dataset; remove repeated files')
        hashes.add(report.capture.sha256)
        if not report.sessions:
            raise ValueError(f'No email sessions found in {path}')
        for session in report.sessions:
            severities = {f.severity.value for f in session.findings}
            baseline = 'critical' if 'critical' in severities else 'vulnerable' if 'high' in severities else 'weak' if 'medium' in severities or 'low' in severities else 'secure'
            rows.append({'schema_version': 1, 'features': session.features, 'label': entry['label'],
                         'configuration_id': entry['configuration_id'], 'capture_sha256': report.capture.sha256,
                         'session_id': session.session_id, 'ground_truth': entry['ground_truth'],
                         'cert_masked': session.cert_visibility == CertVisibility.ENCRYPTED_TLS13,
                         'rules_baseline_class': baseline, 'provenance': report.provenance})
    Path(destination).write_text(''.join(json.dumps(row) + '\n' for row in rows))
    return len(rows)


def load(path):
    rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    if not rows:
        raise ValueError('Captured dataset is empty')
    ds = GeneratedDataset()
    evidence_groups = {}
    seen = set()
    for row in rows:
        if row['label'] not in CLASSES or set(row['features']) != set(FEATURE_NAMES):
            raise ValueError('Invalid class or feature schema')
        key = (row['capture_sha256'], row['session_id'])
        if key in seen:
            raise ValueError('Repeated session evidence')
        seen.add(key)
        previous = evidence_groups.setdefault(row['capture_sha256'], row['configuration_id'])
        if previous != row['configuration_id']:
            raise ValueError('Same capture appears in multiple evaluation groups')
        ds.X.append(to_row(row['features'])); ds.y.append(row['label']); ds.groups.append(row['configuration_id'])
        ds.cert_masked.append(row['cert_masked'])
    if len(set(ds.groups)) < 3:
        raise ValueError('At least three independent configuration groups are required')
    return ds, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest'); parser.add_argument('output')
    args = parser.parse_args()
    print(f'Extracted {build(args.manifest, args.output)} captured sessions')

if __name__ == '__main__':
    main()
