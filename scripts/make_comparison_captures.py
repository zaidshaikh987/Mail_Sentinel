#!/usr/bin/env python3
"""Create two independent synthetic snapshots of the same three mail servers."""
import hashlib
import json
import struct
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from make_demo_capture import capture_time_for
from make_judge_captures import ROOT, tls12, self_signed
from mailsentinel.pipeline import analyse_capture

PACK = ROOT / 'demo captures'


def main():
    chain = [bytes.fromhex(v) for v in json.loads((PACK / 'public-certificate-chain.json').read_text())]
    base = capture_time_for(chain)
    rsa_leaf = isinstance(x509.load_der_x509_certificate(chain[0]).public_key(), rsa.RSAPublicKey)
    modern, cbc, legacy = (0xC030, 0xC027, 0xC014) if rsa_leaf else (0xC02C, 0xC023, 0xC00A)
    expired = self_signed(base - 400 * 86400, 'example.com')
    rows = []
    for after in (False, True):
        name = ('After - Remediated mail servers - 6 sessions.pcap' if after else
                'Before - Weak mail servers - 6 sessions.pcap')
        path = PACK / name
        # Concatenate classic-PCAP packet records, retaining one global header.
        # Sequential timestamps and unique TCP endpoints preserve all six streams.
        data = bytearray()
        with tempfile.TemporaryDirectory() as temp:
            for server in range(3):
                for client in range(2):
                    index = server * 2 + client
                    single = Path(temp) / f'{index}.pcap'
                    tls12(single, expired if not after and server == 2 else chain,
                          base + (86400 if after else 0) + index,
                          modern if after or server == 2 else (cbc if server == 0 else legacy),
                          version=0x0301 if not after and server == 1 else 0x0303,
                          server_ip=f'203.0.113.{40 + server}',
                          client_ip=f'192.0.2.{10 + client}', client_port=53000 + index)
                    packet_data = single.read_bytes()
                    assert packet_data[:4] == struct.pack('<I', 0xA1B2C3D4)
                    data.extend(packet_data if not data else packet_data[24:])
        path.write_bytes(data)
        report = analyse_capture(str(path), run_ml=False)
        expected = 'A+' if after else 'F'
        assert report.overall_grade == expected
        assert len(report.sessions) == 6 and len(report.assets) == 3
        grades = sorted(s.grade.letter for s in report.sessions)
        assert grades == (['A+'] * 6 if after else ['B', 'B', 'C', 'C', 'F', 'F'])
        rows.append(dict(filename=name, expected_grade=expected, synthetic=True,
                         scenario='Three matching IMAPS servers, two clients each; ' +
                         ('trusted certificates and TLS 1.2 AEAD after remediation.' if after else
                          'CBC, TLS 1.0 and expired self-signed certificates before remediation.'),
                         sha256=hashlib.sha256(data).hexdigest(), sessions=6,
                         session_grades=grades, comparison_pair='mail-server-remediation',
                         phase='after' if after else 'before',
                         expected_rules=['SMS-OK-001'] if after else
                         ['SMS-CIPH-005', 'MS-PROTO-001', 'SMS-CERT-001', 'SMS-CERT-003'],
                         observed_rules=sorted({f.rule_id for s in report.sessions for f in s.findings})))
        print(f'{expected}: {name} ({len(report.sessions)} sessions, {len(report.assets)} servers)')
    manifest_path = PACK / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['captures'] = [r for r in manifest['captures'] if r.get('comparison_pair') != 'mail-server-remediation'] + rows
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
