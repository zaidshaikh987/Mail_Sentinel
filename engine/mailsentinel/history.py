"""Conservative, investigation-scoped comparisons with earlier capture evidence.
No cross-host guesses, duplicate-capture learning or attack claims.
"""
from collections import defaultdict
from datetime import datetime


def identity(s):
    server = s.get('server') or {}
    hostname = (s.get('server_name') or '').lower().rstrip('.')
    return '|'.join([str(s.get('protocol')), hostname, str(server.get('ip')), str(server.get('port'))])


def annotate_history(report, earlier_reports):
    from .models import to_dict
    current = to_dict(report)
    history = defaultdict(list)
    used = set()
    now = (current.get('capture') or {}).get('first_packet_time')
    if not now:
        return {'status': 'baseline_not_established', 'servers': [], 'reason': 'Capture timestamp unavailable.'}
    for previous in earlier_reports:
        cap = previous.get('capture') or {}
        sha = cap.get('sha256')
        when = cap.get('last_packet_time') or cap.get('first_packet_time')
        if not sha or sha == report.capture.sha256 or sha in used or not when:
            continue
        if datetime.fromisoformat(when) >= datetime.fromisoformat(now):
            continue
        used.add(sha)
        for s in previous.get('sessions', []):
            if s.get('coverage', {}).get('gap_count', 1) or s.get('coverage', {}).get('truncated_capture', True):
                continue
            history[identity(s)].append((sha, s))
    grouped = defaultdict(list)
    for s in current['sessions']:
        grouped[identity(s)].append(s)
    servers = []
    for key, sessions in grouped.items():
        rows = history[key]
        captures = len({sha for sha, _ in rows})
        established = len(rows) >= 8 and captures >= 2 and bool(sessions[0].get('server_name'))
        changes = []
        if rows:
            for field in ('tls_version', 'cipher_suite', 'starttls_accepted'):
                known = {str(s[field]) for _, s in rows if s.get(field) is not None}
                observed = {str(s[field]) for s in sessions if s.get(field) is not None}
                if known and observed - known:
                    changes.append({'field': field, 'previous': sorted(known), 'new': sorted(observed - known)})
            old_fps = {c.get('sha256_fingerprint') for _, s in rows for c in s.get('chain', []) if c.get('sha256_fingerprint')}
            new_fps = {c.get('sha256_fingerprint') for s in sessions for c in s.get('chain', []) if c.get('sha256_fingerprint')}
            if old_fps and new_fps - old_fps:
                changes.append({'field': 'certificate_sha256', 'previous': sorted(old_fps), 'new': sorted(new_fps - old_fps)})
        result = {'identity': key, 'host': sessions[0].get('server_name') or sessions[0]['server']['ip'],
                  'port': sessions[0]['server']['port'], 'identity_confidence': 'corroborated_hostname_and_endpoint' if sessions[0].get('server_name') else 'provisional_endpoint_only',
                  'status': 'established' if established else 'baseline_not_established',
                  'prior_captures': captures, 'prior_sessions': len(rows), 'changes': changes,
                  'anomalies': [], 'ml_status': 'insufficient_history',
                  'note': 'Observational deviations are not proof of an attack. Hostname and endpoint must both match; address changes are not auto-merged.'}
        if established:
            try:
                import numpy as np
                from sklearn.ensemble import IsolationForest
                from .features import to_row
                model = IsolationForest(n_estimators=100, contamination='auto', random_state=26159, n_jobs=1)
                model.fit(np.asarray([to_row(s['features']) for _, s in rows]))
                scores = model.decision_function(np.asarray([to_row(s['features']) for s in sessions]))
                result['anomalies'] = [{'session_id': s['session_id'], 'score': round(float(score), 5), 'unusual': bool(score < 0)} for s, score in zip(sessions, scores)]
                result['ml_status'] = 'evaluated_against_prior_sessions'
            except (ImportError, ValueError, KeyError) as exc:
                result['ml_status'] = 'unavailable'
                result['note'] += f' Historical model unavailable: {exc}'
        servers.append(result)
    return {'status': 'assessed', 'servers': servers, 'minimum_sessions': 8, 'minimum_distinct_captures': 2,
            'baseline_capture_hashes': sorted(used)}
