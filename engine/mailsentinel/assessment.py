"""Evidence coverage and reproducibility metadata, independent of security grades."""
import hashlib
import platform
from pathlib import Path
from .models import CertVisibility, TlsMode


def digest(path):
    path = Path(path)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def provenance(model_path=None):
    root = Path(__file__).parent
    from .analyze.certs import load_trust_store
    from cryptography.hazmat.primitives import serialization
    roots = sorted(c.public_bytes(serialization.Encoding.DER) for c in load_trust_store())
    source = hashlib.sha256()
    for path in sorted(root.rglob('*.py')):
        source.update(str(path.relative_to(root)).encode())
        source.update(path.read_bytes())
    return {
        'engine_version': '1.1.0', 'engine_source_sha256': source.hexdigest(),
        'rules_sha256': digest(root / 'kb/rules.yaml'),
        'cipher_registry_sha256': digest(root / 'kb/cipher_suites.json'),
        'model_sha256': digest(model_path or root / 'ml/artifacts/posture_model.joblib'),
        'trust_store_sha256': hashlib.sha256(b''.join(roots)).hexdigest(),
        'python_version': platform.python_version(),
    }


def coverage(session, gaps, truncated=False):
    tls_expected = session.tls_mode != TlsMode.CLEARTEXT
    checks = []
    def add(name, status, reason):
        checks.append({'check': name, 'status': status, 'reason': reason})
    add('stream', 'limited' if gaps or truncated else 'observed',
        'Missing segments or truncated packets limit reconstruction.' if gaps or truncated else
        'No detected internal gaps; capture boundaries may still omit traffic.')
    add('protocol', 'inferred' if session.tls_mode == TlsMode.IMPLICIT else 'observed',
        'Implicit TLS classification uses the server port.' if session.tls_mode == TlsMode.IMPLICIT else
        'Email protocol identified from recorded dialogue.')
    add('tls_negotiation', 'observed' if session.handshake_complete else 'unknown' if tls_expected else 'not_applicable',
        'Recorded handshake completion indicators found; encrypted Finished messages are not verified.' if session.handshake_complete else
        'Negotiation unavailable or incomplete.' if tls_expected else 'No TLS upgrade observed.')
    add('certificate', 'observed' if session.chain else 'unknown' if tls_expected else 'not_applicable',
        'Certificate extracted.' if session.chain else 'TLS 1.3 encrypts certificates.' if session.cert_visibility == CertVisibility.ENCRYPTED_TLS13 else
        'Certificate not present in the observed traffic.')
    add('chain_validation', 'assessed' if session.chain_valid is not None else 'unknown' if tls_expected else 'not_applicable',
        'Signature and trust-anchor checks; full RFC 5280 policy processing is not implemented.' if session.chain_valid is not None else 'Insufficient observable certificate evidence.')
    add('hostname_validation', 'assessed' if session.name_match is not None else 'unknown' if tls_expected else 'not_applicable',
        'Certificate name compared with observed hostname.' if session.name_match is not None else 'Hostname or certificate unavailable.')
    add('revocation', 'not_applicable' if not tls_expected else 'unknown' if session.revocation.value == 'unknown_offline' else 'assessed',
        'Offline: no live responder queried. Only recorded stapled responses can be evaluated.')
    applicable = [c for c in checks if c['status'] != 'not_applicable']
    assessed = sum(c['status'] in ('observed', 'assessed') for c in applicable)
    return {'label': 'limited' if any(c['status'] in ('unknown', 'limited', 'inferred') for c in checks) else 'observed',
            'assessed_checks': assessed, 'applicable_checks': len(applicable),
            'gap_count': gaps, 'truncated_capture': truncated, 'checks': checks,
            'skipped_checks': [c['check'] for c in checks if c['status'] == 'unknown']}
