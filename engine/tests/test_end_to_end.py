"""
End-to-end expectations for every demo capture.

These are the golden tests.  Each capture exercises a distinct path through the
tool, and the expected findings were verified by hand against the raw dialogue
before being written down here.
"""

from __future__ import annotations

import json

import pytest

from mailsentinel.models import CertVisibility, Protocol, Role, TlsMode
from mailsentinel.report import html_report, json_report


# --------------------------------------------------------------------------
# imap.cap — cleartext IMAP on 143, LOGIN in the clear, no STARTTLS offered
# --------------------------------------------------------------------------

def test_imap_cleartext(analysed):
    r = analysed["imap_cleartext"]
    # Two DCE/RPC conversations on port 1065 share this capture and must be
    # excluded: they are not email.
    assert len(r.sessions) == 1
    s = r.sessions[0]
    assert s.protocol == Protocol.IMAP
    assert s.role == Role.SUBMISSION_ACCESS
    assert s.tls_mode == TlsMode.CLEARTEXT
    assert s.server.port == 143

    fired = {f.rule_id for f in s.findings}
    assert "SMS-AUTH-001" in fired          # credentials in the clear
    assert "MS-PROTO-003" in fired         # never encrypted on an access port
    assert "MS-STRIP-004" in fired         # server never advertised STARTTLS
    assert "MS-STRIP-001" not in fired, "LITERAL+ must not read as a stripped keyword"

    assert s.cleartext_auth is not None
    assert s.cleartext_auth.username == "n*********"
    assert r.overall_grade == "F"


# --------------------------------------------------------------------------
# smtp.pcap — server offered STARTTLS, client ignored it, then authenticated
# --------------------------------------------------------------------------

def test_smtp_relay_client_declined_starttls(analysed):
    r = analysed["smtp_relay_cleartext"]
    s = r.sessions[0]
    assert s.protocol == Protocol.SMTP
    assert s.role == Role.MTA_RELAY, "port 25 is relay, graded on RFC 7435 terms"
    assert s.starttls_offered is True
    assert s.starttls_requested is False

    fired = {f.rule_id for f in s.findings}
    assert "MS-STRIP-002" in fired         # offered but unused
    assert "SMS-AUTH-001" in fired
    assert "MS-PROTO-004" in fired         # relay cleartext: high, not critical
    assert "MS-PROTO-003" not in fired, "relay must not be graded as submission"
    assert s.cleartext_auth.username == "g********@patriots.in"


def test_relay_and_submission_are_graded_differently(analysed):
    """
    The same failure — cleartext — is critical on a submission port and high on
    an MTA relay hop, because RFC 8314 governs one and RFC 7435 the other.
    """
    relay = analysed["smtp_relay_cleartext"].sessions[0]
    submission = analysed["smtp_submission_cleartext"].sessions[0]

    relay_rules = {f.rule_id: f.severity.value for f in relay.findings}
    sub_rules = {f.rule_id: f.severity.value for f in submission.findings}

    assert relay_rules.get("MS-PROTO-004") == "high"
    assert sub_rules.get("MS-PROTO-003") == "critical"


# --------------------------------------------------------------------------
# sample-imf.pcap.gz — SMTP submission on 587, no STARTTLS at all
# --------------------------------------------------------------------------

def test_smtp_submission_cleartext(analysed):
    r = analysed["smtp_submission_cleartext"]
    s = r.sessions[0]
    assert s.server.port == 587
    assert s.role == Role.SUBMISSION_ACCESS
    assert s.starttls_offered is False

    fired = {f.rule_id for f in s.findings}
    assert "MS-PROTO-003" in fired
    assert "SMS-AUTH-001" in fired
    assert r.overall_grade == "F"


# --------------------------------------------------------------------------
# smtp-ssl.pcapng / pop-ssl.pcapng — successful STARTTLS upgrades
# --------------------------------------------------------------------------

def test_pop3_starttls_upgrade(analysed):
    r = analysed["pop3_starttls"]
    s = r.sessions[0]
    assert s.protocol == Protocol.POP3
    assert s.tls_mode == TlsMode.STARTTLS
    assert s.starttls_requested and s.starttls_accepted
    assert s.tls_version == "1.2"
    assert s.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert s.forward_secrecy is True
    assert s.cert_visibility == CertVisibility.OBSERVED

    fired = {f.rule_id for f in s.findings}
    assert "SMS-CERT-003" in fired          # self-signed Dovecot certificate
    assert "SMS-OK-001" in fired            # modern TLS with FS + AEAD
    assert "SMS-CIPH-005" not in fired      # it IS AEAD
    assert s.grade.letter == "C"            # capped by the self-signed cert
    assert s.grade.raw_score == 100.0       # but the crypto itself is sound
    assert s.grade.capped_by == "SMS-CERT-003"


def test_smtp_starttls_upgrade_non_aead(analysed):
    r = analysed["smtp_starttls"]
    s = r.sessions[0]
    assert s.tls_mode == TlsMode.STARTTLS
    assert s.starttls_offered and s.starttls_accepted
    assert s.cipher_suite == "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
    assert s.kex == "DHE"
    assert s.kex_bits == 2048

    fired = {f.rule_id for f in s.findings}
    assert "SMS-CIPH-005" in fired          # CBC, not AEAD
    assert "SMS-CIPH-006" in fired          # not IANA recommended
    assert "SMS-CERT-003" in fired


# --------------------------------------------------------------------------
# cross-cutting guarantees
# --------------------------------------------------------------------------

def test_every_finding_cites_a_standard_and_evidence(analysed):
    for key, report in analysed.items():
        for s in report.sessions:
            for f in s.findings:
                assert f.standard, f"{key} {f.rule_id} has no standard reference"
                assert f.remediation, f"{key} {f.rule_id} has no remediation"
                assert f.evidence.frames, f"{key} {f.rule_id} cites no frames"
                assert f.evidence.tcp_stream is not None


def test_capture_hash_is_recorded(analysed):
    for report in analysed.values():
        assert len(report.capture.sha256) == 64


def test_every_session_has_a_grade_and_features(analysed):
    for report in analysed.values():
        for s in report.sessions:
            assert s.grade is not None
            assert len(s.features) == 26
            assert s.grade.letter in ("A+", "A", "B", "C", "D", "E", "F")


def test_assets_are_ordered_by_exposure(analysed):
    for report in analysed.values():
        scores = [a.exposure_score for a in report.assets]
        assert scores == sorted(scores, reverse=True)


def test_remediation_plan_is_ordered_by_severity(analysed):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for report in analysed.values():
        ranks = [order[m["severity"]] for m in report.remediation]
        assert ranks == sorted(ranks)


# --------------------------------------------------------------------------
# report rendering
# --------------------------------------------------------------------------

def test_json_report_is_serialisable_and_stable(analysed):
    for report in analysed.values():
        payload = json_report.dumps(report)
        parsed = json.loads(payload)
        assert parsed["schema_version"]
        assert "capture" in parsed and "sessions" in parsed and "assets" in parsed
        # datetimes must survive as ISO strings, not repr() of objects
        assert "datetime.datetime" not in payload


def test_html_report_renders(analysed):
    for key, report in analysed.items():
        html = html_report.render(report)
        assert html.lstrip().startswith("<!DOCTYPE html>"), key
        assert report.capture.sha256 in html
        assert "</html>" in html


def test_html_report_does_not_leak_passwords(analysed):
    """The report must contain the credential *hash*, never the secret."""
    for report in analysed.values():
        html = html_report.render(report)
        for s in report.sessions:
            if s.cleartext_auth:
                assert s.cleartext_auth.secret_sha256[:24] in html
                assert "punjab@123" not in html
                assert "cHVuamFiQDEyMw==" not in html


# --------------------------------------------------------------------------
# synthetic-imaps-tls13.pcap — the good end of the scale
#
# Every other demo capture is real traffic and all of it is broken, so before
# this file existed nothing tested a passing grade. It is also the regression
# guard for a bug that made the tool worst-in-class exactly where it should
# have been best: see test_tls13_key_exchange_strength_is_read below.
# --------------------------------------------------------------------------

def test_tls13_imaps_earns_the_top_grade(analysed):
    r = analysed["imaps_tls13"]
    assert len(r.sessions) == 1
    s = r.sessions[0]

    assert s.protocol == Protocol.IMAP
    assert s.tls_mode == TlsMode.IMPLICIT
    assert s.server.port == 993
    assert s.tls_version == "1.3"
    assert s.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert s.forward_secrecy is True

    # The certificate is encrypted under handshake keys and genuinely cannot be
    # read. The tool must say so rather than guess.
    assert s.cert_visibility == CertVisibility.ENCRYPTED_TLS13
    assert s.chain == []
    fired = {f.rule_id for f in s.findings}
    assert "SMS-VIS-001" in fired, "must state that certificate checks do not apply"
    assert "SMS-OK-001" in fired, "modern TLS with FS and AEAD is a positive finding"

    # Nothing at medium or worse.
    assert not [f for f in s.findings if f.severity.rank <= 2], \
        [f.rule_id for f in s.findings]

    assert s.grade.letter == "A+"
    assert s.grade.raw_score == 97.0
    assert r.overall_grade == "A+"


def test_tls13_key_exchange_strength_is_read(analysed):
    """
    TLS 1.3 sends no ServerKeyExchange — the negotiated group appears *only* in
    the ServerHello ``key_share`` extension.

    While that extension went unparsed, ``kex_bits`` stayed None, the key
    exchange component scored 0, and the zero-in-any-category rule drove a
    flawless TLS 1.3 session to **raw 0.0 and grade F**. The best possible
    configuration scored worse than cleartext. This asserts the number the
    grade is built on, not just the letter, so the failure cannot come back
    disguised as a cap.
    """
    s = analysed["imaps_tls13"].sessions[0]
    assert s.kex_bits == 3072, "X25519 is 3072-bit equivalent (NIST SP 800-57)"
    assert s.grade.components.key_exchange == 90.0
    assert s.grade.zero_category is None


def test_tls13_key_share_extension_parsing():
    """Both shapes the extension takes must yield the group."""
    import struct

    from mailsentinel.analyze.tls import parse_server_hello

    def server_hello_body(ext_payload: bytes) -> bytes:
        body = struct.pack("!H", 0x0303) + bytes(32)
        body += bytes([32]) + bytes(32)          # legacy_session_id_echo
        body += struct.pack("!H", 0x1301)        # cipher suite
        body += bytes([0])                       # compression
        exts = struct.pack("!HH", 43, 2) + struct.pack("!H", 0x0304)
        exts += struct.pack("!HH", 51, len(ext_payload)) + ext_payload
        return body + struct.pack("!H", len(exts)) + exts

    # ServerHello: group + key_exchange
    key = bytes(range(32))
    sh = parse_server_hello(server_hello_body(
        struct.pack("!HH", 0x001D, len(key)) + key))
    assert sh is not None and sh.key_share_group == 0x001D

    # HelloRetryRequest: the group on its own
    sh = parse_server_hello(server_hello_body(struct.pack("!H", 0x0017)))
    assert sh is not None and sh.key_share_group == 0x0017


# --------------------------------------------------------------------------
# packaging: the knowledge base must be reachable on every supported Python
# --------------------------------------------------------------------------

def test_knowledge_base_is_a_real_package_not_a_namespace_one():
    """
    `mailsentinel/kb/` must contain an `__init__.py`.

    Without it the directory is a *namespace* package, whose spec has
    ``origin is None``. Python 3.9 — the version Apple ships with the macOS
    Command Line Tools — resolves ``importlib.resources.files(pkg)`` by doing
    ``pathlib.Path(spec.origin).parent``, which then raises

        TypeError: expected str, bytes or os.PathLike object, not NoneType

    and every analysis dies before the first rule is read. Python 3.10+ handles
    namespace packages there, so the whole suite passed on a newer interpreter
    while the engine was broken for anyone on 3.9 — and a container and a
    laptop ran byte-identical code with different results.

    The assertion below performs 3.9's exact operation, so it fails on any
    version if the `__init__.py` ever goes missing again.
    """
    import importlib.util
    import pathlib

    spec = importlib.util.find_spec("mailsentinel.kb")
    assert spec is not None, "the knowledge base package is missing entirely"
    assert spec.origin is not None, (
        "mailsentinel.kb is a namespace package; add an __init__.py. "
        "This breaks importlib.resources on Python 3.9."
    )
    # The line that raised on 3.9. It must simply work.
    assert pathlib.Path(spec.origin).parent.is_dir()


def test_knowledge_base_files_load_without_importlib_resources():
    """
    The data files are found relative to __file__, not through
    ``importlib.resources`` — an API whose behaviour differs across the
    versions this project supports, for a capability (reading from zipped
    imports) the engine never uses.
    """
    import os

    from mailsentinel.analyze.ciphers import properties
    from mailsentinel.kb import CIPHER_SUITES_FILE, RULES_FILE, kb_path
    from mailsentinel.scoring.rules import load_rules

    for name in (RULES_FILE, CIPHER_SUITES_FILE):
        path = kb_path(name)
        assert os.path.isfile(path), path
        assert os.path.getsize(path) > 0, path

    assert len(load_rules()) >= 30
    assert properties(0xC030).name == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"


def test_a_missing_knowledge_base_says_so():
    """A packaging mistake must name the problem, not surface as a KeyError."""
    import pytest as _pytest

    from mailsentinel.kb import kb_path

    with _pytest.raises(FileNotFoundError) as caught:
        kb_path("not-a-real-file.yaml")
    assert "scripts/setup.sh" in str(caught.value)
