#!/usr/bin/env python3
"""Generate and verify synthetic presentation PCAPs; never inserts database rows.

Public certificates are a frozen example.com chain, not private keys. Packet
payloads simulate negotiations; ciphertext and handshake signatures are filler.
These fixtures demonstrate parser/rule behavior, not completed live TLS sessions.
"""
from __future__ import annotations

import argparse
import json
import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from make_demo_capture import (
    PcapWriter, Flow, record, handshake, client_hello, server_hello,
    certificate_message, server_key_exchange_ecdhe, server_hello_done,
    build_tls13, opaque, capture_time_for, chain_is_publicly_trusted,
    GROUP_X25519, CT_HANDSHAKE, CT_CHANGE_CIPHER_SPEC, CT_APPLICATION_DATA,
)
from mailsentinel.pipeline import analyse_capture

ROOT = Path(__file__).resolve().parents[1]


def tls12(path, chain, when, suite, host='example.com', version=0x0303,
          server_ip='203.0.113.25', client_ip='192.0.2.10', client_port=52000):
    with PcapWriter(str(path)) as writer:
        flow = Flow(writer, client_ip, server_ip, client_port, 993, when)
        flow.handshake()
        hello = client_hello(host, [suite], [GROUP_X25519], False, GROUP_X25519)
        flow.client(record(CT_HANDSHAKE, hello[:4] + struct.pack('!H', version) + hello[6:], version))
        hello = server_hello(suite, False)
        hello = hello[:4] + struct.pack('!H', version) + hello[6:]
        # Match the simulated signature scheme to the certificate key type.
        ske = server_key_exchange_ecdhe(GROUP_X25519)
        if isinstance(x509.load_der_x509_certificate(chain[0]).public_key(), ec.EllipticCurvePublicKey):
            ske = ske[:40] + b'\x04\x03' + ske[42:]
        flow.server(record(CT_HANDSHAKE, hello + certificate_message(chain, False)
                           + ske + server_hello_done(), version))
        flow.client(record(CT_HANDSHAKE, handshake(16, b'\x20' + opaque(32)), version)
                    + record(CT_CHANGE_CIPHER_SPEC, b'\x01', version)
                    + record(CT_HANDSHAKE, opaque(40), version))
        flow.server(record(CT_CHANGE_CIPHER_SPEC, b'\x01', version)
                    + record(CT_HANDSHAKE, opaque(40, 9), version))
        flow.client(record(CT_APPLICATION_DATA, opaque(80), version))
        flow.server(record(CT_APPLICATION_DATA, opaque(160), version))
        flow.close()


def stripped_starttls(path, when):
    with PcapWriter(str(path)) as writer:
        flow = Flow(writer, '192.0.2.11', '203.0.113.26', 52001, 587, when)
        flow.handshake()
        flow.server(b'220 mail.demo.example ESMTP\r\n')
        flow.client(b'EHLO client.demo.example\r\n')
        flow.server(b'250-mail.demo.example\r\n250-XXXXXXXX\r\n250 AUTH LOGIN\r\n')
        flow.client(b'AUTH LOGIN\r\n')
        flow.server(b'334 VXNlcm5hbWU6\r\n')
        flow.client(b'ZGVtby11c2Vy\r\n')
        flow.server(b'334 UGFzc3dvcmQ6\r\n')
        flow.client(b'ZGVtby1vbmx5LXBhc3N3b3Jk\r\n')
        flow.server(b'235 Authentication successful\r\n')
        flow.client(b'QUIT\r\n')
        flow.server(b'221 Bye\r\n')
        flow.close()


def self_signed(when, host='mail.demo.example'):
    # A disposable fixture identity; the private key is never written to disk.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.fromtimestamp(when, timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(26159)
            .not_valid_before(now - timedelta(days=30)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), False)
            .sign(key, hashes.SHA256()))
    return [cert.public_bytes(serialization.Encoding.DER)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'demo captures')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    chain = [bytes.fromhex(v) for v in json.loads((ROOT / 'demo captures/public-certificate-chain.json').read_text())]
    when = capture_time_for(chain)
    valid, reason = chain_is_publicly_trusted(chain, 'example.com', when)
    if not valid:
        raise RuntimeError(f'Frozen public chain is no longer accepted by this trust store: {reason}')
    leaf = x509.load_der_x509_certificate(chain[0])
    rsa_leaf = isinstance(leaf.public_key(), rsa.RSAPublicKey)
    gcm = 0xC030 if rsa_leaf else 0xC02C
    cbc128 = 0xC027 if rsa_leaf else 0xC023
    cbc256 = 0xC028 if rsa_leaf else 0xC024
    legacy = 0xC014 if rsa_leaf else 0xC00A
    rows = []

    def add(name, grade, scenario, make, required=()):
        path = args.out / name
        make(path)
        report = analyse_capture(str(path), run_ml=False)
        rules = sorted({f.rule_id for s in report.sessions for f in s.findings})
        assert report.overall_grade == grade, (name, grade, report.overall_grade, rules)
        assert set(required).issubset(rules), (name, required, rules)
        assert len(report.sessions) == 1, (name, len(report.sessions))
        rows.append(dict(filename=name, expected_grade=grade, scenario=scenario,
                         synthetic=True, sha256=report.capture.sha256, sessions=1,
                         expected_rules=list(required), observed_rules=rules))
        print(f'{grade:2} {name}')

    add('A-plus - Normal configuration - TLS 1.3 IMAPS.pcap', 'A+',
        'Modern TLS 1.3 with X25519 and AES-256-GCM. Certificate is encrypted and cannot be validated passively.',
        lambda p: build_tls13(str(p)), ['SMS-OK-001', 'SMS-VIS-001'])
    add('A-plus - Normal configuration - Trusted TLS 1.2 IMAPS.pcap', 'A+',
        'TLS 1.2 ECDHE and AES-256-GCM with a genuine public certificate chain valid at capture time.',
        lambda p: tls12(p, chain, when, gcm), ['SMS-OK-001'])
    add('A - Certificate renewal due soon.pcap', 'A',
        'Strong TLS 1.2 but the public leaf certificate expires in ten days at capture time.',
        lambda p: tls12(p, chain, leaf.not_valid_after_utc.timestamp() - 10 * 86400, gcm), ['SMS-CERT-007'])
    for bits, suite in [(128, cbc128), (256, cbc256)]:
        add(f'B - Legacy AES-{bits} CBC cipher.pcap', 'B',
            f'TLS 1.2 with forward secrecy and a trusted chain, but AES-{bits}-CBC rather than AEAD.',
            lambda p, suite=suite: tls12(p, chain, when, suite), ['SMS-CIPH-005'])
    add('C - Self-signed mail server certificate.pcap', 'C',
        'Modern TLS 1.2 encryption with an untrusted self-signed mail certificate.',
        lambda p: tls12(p, self_signed(when), when, 0xC02B, 'mail.demo.example'), ['SMS-CERT-003'])
    add('C - Deprecated TLS 1.0 configuration.pcap', 'C',
        'TLS 1.0 with ECDHE and CBC. The protocol version is deprecated.',
        lambda p: tls12(p, chain, when, legacy, version=0x0301), ['MS-PROTO-001'])
    add('F - STARTTLS stripping attack simulation.pcap', 'F',
        'Synthetic STARTTLS-to-XXXXXXXX substitution followed by dummy cleartext AUTH. Detector reports evidence consistent with stripping, not proof of a real attack.',
        lambda p: stripped_starttls(p, when), ['MS-STRIP-001', 'SMS-AUTH-001'])
    add('F - Expired mail server certificate.pcap', 'F',
        'TLS 1.2 with a public certificate that expired ten days before capture time.',
        lambda p: tls12(p, chain, leaf.not_valid_after_utc.timestamp() + 10 * 86400, gcm), ['SMS-CERT-001'])
    previous = args.out / 'manifest.json'
    if previous.exists():
        rows.extend(r for r in json.loads(previous.read_text())['captures'] if r.get('comparison_pair'))
    manifest = dict(synthetic=True, ml_used_for_verification=False,
                    limitation='D and E are not reachable for meaningful complete sessions under the current rule/score combination; grades were not modified for demos.',
                    captures=rows)
    (args.out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
