"""
Grading arithmetic.

These tests exist mostly to pin one behaviour: the weighted average is *not*
what produces a grade — the caps are.  The worked example below is the one from
the design deck, and it is the case a reviewer is most likely to probe.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from mailsentinel.models import (
    CertInfo,
    CertVisibility,
    Endpoint,
    Finding,
    Protocol,
    Role,
    Session,
    Severity,
    TlsMode,
)
from mailsentinel.scoring.grade import (
    band_for,
    cipher_score,
    grade_session,
    key_exchange_score,
    protocol_score,
)
from mailsentinel.scoring.rules import apply_rules


def make_session(**kw) -> Session:
    s = Session(
        session_id="test-0",
        tcp_stream=0,
        client=Endpoint("10.0.0.1", 40000),
        server=Endpoint("10.0.0.2", 587),
        first_frame=1,
        last_frame=20,
        capture_time=datetime(2020, 6, 1, tzinfo=timezone.utc),
        protocol=Protocol.SMTP,
        role=Role.SUBMISSION_ACCESS,
        tls_mode=TlsMode.STARTTLS,
    )
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def cert(**kw) -> CertInfo:
    base = dict(
        subject="mail.example.com",
        issuer="Example CA",
        serial="01",
        not_before=datetime(2019, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2021, 1, 1, tzinfo=timezone.utc),
        key_algorithm="RSA",
        key_bits=2048,
        signature_algorithm="sha256WithRSAEncryption",
        signature_hash="sha256",
        self_signed=False,
        is_ca=False,
        expired_at_capture=False,
        not_yet_valid_at_capture=False,
        days_to_expiry_at_capture=214,
    )
    base.update(kw)
    return CertInfo(**base)


# --------------------------------------------------------------------------
# component tables (Qualys SSL Server Rating Guide)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("version,expected", [
    ("SSL2.0", 0), ("SSL3.0", 80), ("1.0", 90), ("1.1", 95), ("1.2", 100), ("1.3", 100),
])
def test_protocol_component(version, expected):
    assert protocol_score(version) == expected


@pytest.mark.parametrize("bits,expected", [
    (0, 0), (256, 20), (768, 40), (1024, 80), (2048, 90), (4096, 100), (8192, 100),
])
def test_key_exchange_component(bits, expected):
    assert key_exchange_score(bits, anonymous=False, export=False) == expected


def test_anonymous_key_exchange_scores_zero():
    assert key_exchange_score(4096, anonymous=True, export=False) == 0


@pytest.mark.parametrize("bits,expected", [(0, 0), (40, 20), (128, 80), (256, 100)])
def test_cipher_component(bits, expected):
    assert cipher_score(bits) == expected


@pytest.mark.parametrize("score,letter", [
    (100, "A"), (80, "A"), (79, "B"), (65, "B"), (50, "C"), (35, "D"), (20, "E"), (0, "F"),
])
def test_bands(score, letter):
    assert band_for(score) == letter


# --------------------------------------------------------------------------
# the worked example — the whole point of the cap engine
# --------------------------------------------------------------------------

def test_broken_session_scores_83_before_caps_and_F_after():
    """
    TLS 1.0 + RSA_WITH_RC4_128_SHA + self-signed RSA-1024 + SHA-1, expired.

        protocol      TLS 1.0   ->  90 x 0.30 = 27.0
        key exchange  RSA-1024  ->  80 x 0.30 = 24.0
        cipher        RC4-128   ->  80 x 0.40 = 32.0
                                          raw = 83  -> band "A"

    An expired, self-signed, RC4-over-TLS-1.0 session comes out of the weighted
    average as an A.  That is how the published methodology behaves, and it is
    exactly why the caps exist.
    """
    s = make_session(
        tls_version="1.0",
        cipher_suite_id=0x0005,              # TLS_RSA_WITH_RC4_128_SHA
        cipher_suite="TLS_RSA_WITH_RC4_128_SHA",
        kex="RSA",
        kex_bits=1024,
        forward_secrecy=False,
        cert_visibility=CertVisibility.OBSERVED,
        chain=[cert(key_bits=1024, signature_hash="sha1", self_signed=True,
                    issuer="mail.example.com", expired_at_capture=True,
                    days_to_expiry_at_capture=-1800)],
        chain_valid=False,
    )
    findings = apply_rules(s)
    g = grade_session(s, findings)

    assert g.components.protocol == 90
    assert g.components.key_exchange == 80
    assert g.components.cipher == 80
    assert g.raw_score == pytest.approx(83.0)
    assert band_for(g.raw_score) == "A", "the uncapped band really is an A"

    assert g.letter == "F", "caps must override the weighted average"
    assert g.capped_by is not None
    assert not g.trusted

    fired = {f.rule_id for f in findings}
    assert "SMS-CIPH-002" in fired      # RC4
    assert "MS-PROTO-001" in fired     # TLS 1.0
    assert "SMS-CERT-001" in fired      # expired at capture
    assert "SMS-CERT-003" in fired      # self-signed
    assert "SMS-KEY-002" in fired       # RSA-1024
    assert "SMS-FS-001" in fired        # no forward secrecy


def test_lowest_cap_wins():
    # kex_bits must be set so the *base* grade is high; otherwise the score is
    # already F and no cap has anything to lower.
    s = make_session(tls_version="1.2", cipher_suite_id=0xC02F,
                     kex_bits=3072, forward_secrecy=True)
    findings = [
        Finding("X-1", "cap to C", Severity.HIGH, "std", "fix", cap_grade="C"),
        Finding("X-2", "cap to F", Severity.CRITICAL, "std", "fix", cap_grade="F"),
        Finding("X-3", "cap to B", Severity.MEDIUM, "std", "fix", cap_grade="B"),
    ]
    g = grade_session(s, findings)
    assert g.letter == "F"
    assert g.capped_by == "X-2"


def test_zero_in_any_category_forces_zero():
    """A zero in any component pushes the overall score to zero (rating guide)."""
    s = make_session(
        tls_version="1.2",
        cipher_suite_id=0x0034,          # TLS_DH_anon_WITH_AES_128_CBC_SHA
        kex_bits=2048,
        forward_secrecy=True,
    )
    g = grade_session(s, apply_rules(s))
    assert g.components.key_exchange == 0
    assert g.raw_score == 0.0
    assert g.zero_category == "key_exchange"
    assert g.letter == "F"


def test_clean_modern_session_reaches_a_plus():
    s = make_session(
        tls_version="1.3",
        cipher_suite_id=0x1302,          # TLS_AES_256_GCM_SHA384
        kex="TLS13",
        kex_bits=3072,
        forward_secrecy=True,
        cert_visibility=CertVisibility.OBSERVED,
        chain=[cert()],
        chain_valid=True,
        name_match=True,
        handshake_complete=True,
        starttls_offered=True,
        starttls_requested=True,
        starttls_accepted=True,
    )
    findings = apply_rules(s)
    g = grade_session(s, findings)
    # protocol 100 x .30 + key exchange 90 x .30 + cipher 100 x .40 = 97.
    # 90 is the rating guide's band for a 3072-bit-equivalent group; only a
    # >= 4096-bit equivalent reaches 100.
    assert g.raw_score == pytest.approx(97.0)
    assert g.components.key_exchange == 90
    assert g.letter == "A+"
    assert g.trusted
    assert g.capped_by is None


def test_cleartext_session_is_zero_and_F():
    s = make_session(tls_mode=TlsMode.CLEARTEXT)
    g = grade_session(s, apply_rules(s))
    assert g.raw_score == 0.0
    assert g.letter == "F"
