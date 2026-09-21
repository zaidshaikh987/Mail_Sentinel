"""
Certificate analysis — above all, that validity is judged against the capture
clock rather than the wall clock.

This is the single most consequential correctness property in the tool.  A
forensic analyser works on old evidence; comparing ``not_valid_after`` to
``datetime.now()`` would report every certificate in a 2015 capture as expired
and make the whole analysis wrong.
"""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from mailsentinel.analyze import certs as certmod
from mailsentinel.models import Revocation

UTC = dt.timezone.utc


def make_cert(
    subject="mail.example.com",
    issuer=None,
    not_before=dt.datetime(2015, 1, 1, tzinfo=UTC),
    not_after=dt.datetime(2016, 1, 1, tzinfo=UTC),
    key_size=2048,
    hash_alg=None,
    san=None,
):
    """Build a real self-signed certificate for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, issuer or subject)]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before.replace(tzinfo=None))
        .not_valid_after(not_after.replace(tzinfo=None))
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False
        )
    cert = builder.sign(key, hash_alg or hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


# --------------------------------------------------------------------------
# the capture-clock property
# --------------------------------------------------------------------------

def test_certificate_valid_at_capture_but_expired_today():
    """
    The defining case.  A certificate valid in 2015 and expired by now must be
    reported as valid *at capture* — otherwise every historical capture is full
    of false criticals.
    """
    der = make_cert(
        not_before=dt.datetime(2015, 1, 1, tzinfo=UTC),
        not_after=dt.datetime(2016, 1, 1, tzinfo=UTC),
    )
    capture_time = dt.datetime(2015, 6, 1, tzinfo=UTC)
    a = certmod.analyse([der], capture_time, "mail.example.com")

    assert a.expired_at_capture is False, "was valid when the traffic was recorded"
    assert a.expired_now is True, "has lapsed since"
    assert a.days_to_expiry == 214


def test_certificate_already_expired_when_captured():
    der = make_cert(
        not_before=dt.datetime(2010, 1, 1, tzinfo=UTC),
        not_after=dt.datetime(2012, 1, 1, tzinfo=UTC),
    )
    a = certmod.analyse([der], dt.datetime(2015, 6, 1, tzinfo=UTC), None)
    assert a.expired_at_capture is True
    assert a.days_to_expiry < 0


def test_certificate_not_yet_valid_at_capture():
    der = make_cert(
        not_before=dt.datetime(2020, 1, 1, tzinfo=UTC),
        not_after=dt.datetime(2021, 1, 1, tzinfo=UTC),
    )
    a = certmod.analyse([der], dt.datetime(2015, 6, 1, tzinfo=UTC), None)
    assert a.not_yet_valid_at_capture is True


def test_real_demo_certificates_are_valid_at_capture(analysed):
    """
    Both pcapng demo captures carry certificates that were valid when recorded
    in 2015 and have expired since.  Neither may produce SMS-CERT-001.
    """
    for key in ("pop3_starttls", "smtp_starttls"):
        session = analysed[key].sessions[0]
        assert session.chain, key
        leaf = session.chain[0]
        assert leaf.expired_at_capture is False, key
        fired = {f.rule_id for f in session.findings}
        assert "SMS-CERT-001" not in fired, f"{key} must not report a false expiry"


# --------------------------------------------------------------------------
# structural properties
# --------------------------------------------------------------------------

def test_self_signed_is_detected_and_chain_fails():
    der = make_cert()
    a = certmod.analyse([der], dt.datetime(2015, 6, 1, tzinfo=UTC), None)
    assert a.leaf_self_signed is True
    assert a.chain_valid is False
    assert "self-signed" in (a.chain_error or "")


def test_weak_signature_hash_and_small_key_on_a_real_legacy_certificate():
    """
    Uses a genuine SHA-1 / RSA-1024 certificate stored under tests/fixtures.

    It has to be a fixture rather than something built here: `cryptography`
    refuses to *sign* with SHA-1 (correctly — SHA-1 collisions are practical),
    while still parsing such certificates, which is exactly the asymmetry a
    forensic tool needs. The fixture was produced with
    `openssl req -x509 -sha1 -newkey rsa:1024`.
    """
    import os

    path = os.path.join(os.path.dirname(__file__), "fixtures", "legacy_sha1_rsa1024.der")
    if not os.path.exists(path):
        pytest.skip("legacy certificate fixture not present")
    der = open(path, "rb").read()

    a = certmod.analyse([der], dt.datetime(2027, 1, 1, tzinfo=UTC), "mail.legacy-corp.in")
    leaf = a.chain[0]
    assert leaf.signature_hash == "sha1"
    assert leaf.key_bits == 1024
    assert leaf.key_algorithm == "RSA"
    assert a.smallest_key_bits == 1024
    assert a.name_match is True
    assert a.expired_at_capture is False, "valid at the 2027 reference time"

    # The same certificate judged against a later capture clock is expired.
    later = certmod.analyse([der], dt.datetime(2030, 6, 1, tzinfo=UTC), None)
    assert later.expired_at_capture is True

    # And against an earlier one it is not yet valid.
    earlier = certmod.analyse([der], dt.datetime(2020, 1, 1, tzinfo=UTC), None)
    assert earlier.not_yet_valid_at_capture is True


def test_weak_signature_triggers_the_rule():
    """SMS-CERT-005 must fire for a SHA-1 end-entity certificate."""
    from mailsentinel.models import (
        CertInfo, CertVisibility, Endpoint, Protocol, Role, Session, TlsMode,
    )
    from mailsentinel.scoring.rules import apply_rules

    s = Session(
        session_id="t", tcp_stream=0,
        client=Endpoint("10.0.0.1", 5000), server=Endpoint("10.0.0.2", 587),
        capture_time=dt.datetime(2020, 1, 1, tzinfo=UTC),
        protocol=Protocol.SMTP, role=Role.SUBMISSION_ACCESS, tls_mode=TlsMode.STARTTLS,
        tls_version="1.2", cipher_suite_id=0xC02F, kex_bits=3072, forward_secrecy=True,
        cert_visibility=CertVisibility.OBSERVED,
        chain=[CertInfo(subject="a", issuer="CA", serial="1",
                        not_before=dt.datetime(2019, 1, 1, tzinfo=UTC),
                        not_after=dt.datetime(2021, 1, 1, tzinfo=UTC),
                        key_algorithm="RSA", key_bits=2048,
                        signature_hash="sha1", expired_at_capture=False,
                        days_to_expiry_at_capture=366)],
        chain_valid=True,
    )
    assert "SMS-CERT-005" in {f.rule_id for f in apply_rules(s)}


def test_small_key_reported():
    der = make_cert(key_size=1024)
    a = certmod.analyse([der], dt.datetime(2015, 6, 1, tzinfo=UTC), None)
    assert a.smallest_key_bits == 1024


def test_hostname_match_against_san():
    der = make_cert(subject="other.example.com", san=["mail.example.com"])
    a = certmod.analyse([der], dt.datetime(2015, 6, 1, tzinfo=UTC), "mail.example.com")
    assert a.name_match is True

    b = certmod.analyse([der], dt.datetime(2015, 6, 1, tzinfo=UTC), "evil.example.com")
    assert b.name_match is False


def test_wildcard_matches_one_label_only():
    der = make_cert(subject="wild", san=["*.example.com"])
    ok = certmod.analyse([der], dt.datetime(2015, 6, 1, tzinfo=UTC), "mail.example.com")
    assert ok.name_match is True
    # RFC 6125 §6.4.3: a wildcard matches exactly one left-most label.
    deep = certmod.analyse([der], dt.datetime(2015, 6, 1, tzinfo=UTC), "a.b.example.com")
    assert deep.name_match is False


def test_no_server_name_means_no_match_verdict():
    der = make_cert()
    a = certmod.analyse([der], dt.datetime(2015, 6, 1, tzinfo=UTC), None)
    assert a.name_match is None, "unknown must not be reported as a failure"


def test_revocation_is_unknown_without_a_staple():
    der = make_cert()
    a = certmod.analyse([der], dt.datetime(2015, 6, 1, tzinfo=UTC), None)
    assert a.revocation == Revocation.UNKNOWN_OFFLINE


def test_unparsable_certificate_is_handled():
    a = certmod.analyse([b"not a certificate"], dt.datetime(2015, 6, 1, tzinfo=UTC), None)
    assert a.chain == []
    assert a.chain_valid is None
