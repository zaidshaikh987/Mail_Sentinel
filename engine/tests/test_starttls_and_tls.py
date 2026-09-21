"""
Cleartext-phase analysis, downgrade detection, and TLS handshake parsing.
"""

from __future__ import annotations

import pytest

from mailsentinel.analyze import tls
from mailsentinel.analyze.ciphers import properties, suite_name
from mailsentinel.analyze.starttls import (
    DialogueLine,
    analyse,
    detect_cleartext_auth,
    detect_mangling,
)
from mailsentinel.models import Protocol


def lines(*pairs) -> list[DialogueLine]:
    return [DialogueLine(d, t, 1, 0) for d, t in pairs]


# --------------------------------------------------------------------------
# downgrade detection — and the false positives it must NOT produce
# --------------------------------------------------------------------------

@pytest.mark.parametrize("caps,protocol,token", [
    (["SIZE", "PIPELINING", "XXXXXXXX", "HELP"], Protocol.SMTP, "XXXXXXXX"),
    (["SIZE", "STAR", "HELP"], Protocol.SMTP, "STAR"),
    (["SIZE", "TTLS", "HELP"], Protocol.SMTP, "TTLS"),
    (["TOP", "USER", "XXXX"], Protocol.POP3, "XXXX"),
])
def test_known_substitution_variants_are_detected(caps, protocol, token):
    mangled, found = detect_mangling(caps, protocol)
    assert mangled
    assert found == token


@pytest.mark.parametrize("caps,protocol", [
    # Regression: LITERAL+ is a real IMAP capability and is exactly eight
    # characters, the length of STARTTLS.  An early version of the rule flagged
    # it as a downgrade attack.  A false positive here would be far worse than
    # a missed detection.
    (["IMAP4", "IMAP4REV1", "IDLE", "LITERAL+", "LOGIN-REFERRALS",
      "MAILBOX-REFERRALS", "NAMESPACE", "AUTH=NTLM"], Protocol.IMAP),
    (["SIZE", "PIPELINING", "SMTPUTF8", "8BITMIME", "HELP"], Protocol.SMTP),
    (["SIZE", "AUTH", "CHUNKING", "DSN", "ENHANCEDSTATUSCODES"], Protocol.SMTP),
    (["TOP", "USER", "UIDL", "RESP-CODES", "PIPELINING"], Protocol.POP3),
])
def test_legitimate_capabilities_are_not_flagged(caps, protocol):
    mangled, token = detect_mangling(caps, protocol)
    assert not mangled, f"false positive on {token}"


def test_present_starttls_is_never_mangled():
    caps = ["SIZE", "STARTTLS", "XXXXXXXX"]
    mangled, _ = detect_mangling(caps, Protocol.SMTP)
    assert not mangled, "keyword present means no substitution happened"


# --------------------------------------------------------------------------
# capability parsing
# --------------------------------------------------------------------------

def test_smtp_greeting_line_is_not_a_capability():
    """RFC 5321 §4.1.1.1: the first EHLO reply line is the domain greeting."""
    res = analyse(Protocol.SMTP, lines(
        ("client", "EHLO client.example.net"),
        ("server", "220 mail.example.com ESMTP"),
        ("server", "250-mail.example.com Hello client [10.0.0.1]"),
        ("server", "250-SIZE 52428800"),
        ("server", "250-STARTTLS"),
        ("server", "250 HELP"),
    ), tls_started=False)
    assert "MAIL.EXAMPLE.COM" not in res.capabilities
    assert res.capabilities == ["SIZE", "STARTTLS", "HELP"]
    assert res.offered


def test_imap_capability_response():
    res = analyse(Protocol.IMAP, lines(
        ("server", "* OK server ready"),
        ("server", "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN"),
    ), tls_started=False)
    assert res.offered
    assert "STARTTLS" in res.capabilities


def test_starttls_requested_and_completed():
    res = analyse(Protocol.SMTP, lines(
        ("client", "EHLO x"),
        ("client", "STARTTLS"),
        ("server", "220 mail ESMTP"),
        ("server", "250-mail Hello"),
        ("server", "250 STARTTLS"),
        ("server", "220 TLS go ahead"),
    ), tls_started=True)
    assert res.offered and res.requested and res.accepted


def test_starttls_requested_but_no_handshake():
    res = analyse(Protocol.SMTP, lines(
        ("client", "EHLO x"),
        ("client", "STARTTLS"),
        ("server", "250-mail Hello"),
        ("server", "250 STARTTLS"),
    ), tls_started=False)
    assert res.requested
    assert not res.accepted


def test_pop3_stls_keyword():
    res = analyse(Protocol.POP3, lines(
        ("server", "+OK Dovecot ready."),
        ("client", "STLS"),
        ("server", "+OK Begin TLS negotiation now."),
    ), tls_started=True)
    assert res.requested and res.accepted


# --------------------------------------------------------------------------
# credential exposure
# --------------------------------------------------------------------------

def test_smtp_auth_login_extracts_user_and_redacts():
    auth = detect_cleartext_auth(lines(
        ("client", "AUTH LOGIN"),
        ("client", "Z3VycGFydGFwQHBhdHJpb3RzLmlu"),   # gurpartap@patriots.in
        ("client", "cHVuamFiQDEyMw=="),               # punjab@123
    ), Protocol.SMTP)
    assert auth is not None
    assert auth.mechanism == "LOGIN"
    assert auth.username == "g********@patriots.in"
    assert auth.username_redacted
    assert len(auth.secret_sha256) == 64


def test_password_is_never_stored_in_the_clear():
    secret = "punjab@123"
    auth = detect_cleartext_auth(lines(
        ("client", "AUTH LOGIN"),
        ("client", "dXNlcg=="),
        ("client", secret),
    ), Protocol.SMTP)
    assert secret not in (auth.secret_sha256 or "")
    assert secret not in (auth.username or "")


def test_smtp_auth_plain_inline():
    import base64
    blob = base64.b64encode(b"\x00alice@example.com\x00hunter2").decode()
    auth = detect_cleartext_auth(lines(("client", f"AUTH PLAIN {blob}")), Protocol.SMTP)
    assert auth.mechanism == "PLAIN"
    assert auth.username == "a****@example.com"


def test_imap_login_command():
    auth = detect_cleartext_auth(
        lines(("client", 'a001 LOGIN "neulingern" "secret"')), Protocol.IMAP
    )
    assert auth is not None
    assert auth.username == "n*********"


def test_pop3_user_pass():
    auth = detect_cleartext_auth(lines(
        ("client", "USER bob"),
        ("client", "PASS s3cret"),
    ), Protocol.POP3)
    assert auth.mechanism == "USER/PASS"
    assert auth.username == "b**"


def test_no_auth_means_none():
    assert detect_cleartext_auth(lines(("client", "EHLO x"), ("client", "QUIT")),
                                 Protocol.SMTP) is None


# --------------------------------------------------------------------------
# TLS record / handshake layer
# --------------------------------------------------------------------------

def test_find_tls_start_ignores_random_payload():
    # A message body containing a byte that looks like a record header.
    blob = b"Subject: test\r\n\r\n" + bytes([0x16, 0x03, 0x01, 0xFF, 0xFF]) + b"junk"
    assert tls.find_tls_start(blob) is None


def test_find_tls_start_locates_a_real_handshake(captures):
    from mailsentinel.net.reassembly import reassemble
    from mailsentinel.pcap.reader import CaptureReader

    reader = CaptureReader(captures["smtp_starttls"])
    st = reassemble(reader.tcp_segments())[0]
    offset = tls.find_tls_start(st.client_to_server.data)
    assert offset == len(b"EHLO openssl.client.net\r\nSTARTTLS\r\n")


def test_handshake_parsing_on_demo_capture(captures):
    from mailsentinel.net.reassembly import reassemble
    from mailsentinel.pcap.reader import CaptureReader

    reader = CaptureReader(captures["pop3_starttls"])
    st = reassemble(reader.tcp_segments())[0]
    hs = tls.analyse_handshake(st.client_to_server.data, st.server_to_client.data)
    assert tls.version_name(hs.negotiated_version) == "1.2"
    assert hs.cipher_suite == 0xC030          # ECDHE_RSA_AES_256_GCM_SHA384
    assert len(hs.certificates) == 1
    assert hs.complete
    assert hs.ja3 and len(hs.ja3) == 32
    assert hs.ja4 and hs.ja4.startswith("t12i")


def test_no_alerts_are_invented_from_encrypted_records(captures):
    """
    Records after ChangeCipherSpec are ciphertext.  An earlier version parsed
    them as alerts and reported alert level 143, which does not exist.
    """
    from mailsentinel.net.reassembly import reassemble
    from mailsentinel.pcap.reader import CaptureReader

    reader = CaptureReader(captures["pop3_starttls"])
    st = reassemble(reader.tcp_segments())[0]
    hs = tls.analyse_handshake(st.client_to_server.data, st.server_to_client.data)
    for level, _desc in hs.alerts:
        assert level in (1, 2), "alert level must be warning(1) or fatal(2)"


# --------------------------------------------------------------------------
# cipher property derivation
# --------------------------------------------------------------------------

@pytest.mark.parametrize("suite_id,name,kex,bits,aead,fs,broken", [
    (0x1302, "TLS_AES_256_GCM_SHA384", "TLS13", 256, True, True, False),
    (0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", 256, True, True, False),
    (0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", 128, False, True, False),
    (0x0005, "TLS_RSA_WITH_RC4_128_SHA", "RSA", 128, False, False, True),
    (0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", 112, False, False, False),
    (0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", "DH", 128, False, False, True),
    (0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RSA", 40, False, False, True),
    (0x0002, "TLS_RSA_WITH_NULL_SHA", "RSA", 0, False, False, True),
])
def test_cipher_properties(suite_id, name, kex, bits, aead, fs, broken):
    p = properties(suite_id)
    assert p.name == name
    assert p.kex == kex
    assert p.key_bits == bits
    assert p.aead is aead
    assert p.forward_secrecy is fs
    assert p.broken is broken


def test_3des_is_flagged_small_block():
    assert properties(0x000A).small_block is True
    assert properties(0xC030).small_block is False


def test_unknown_suite_does_not_crash():
    p = properties(0xDEAD)
    assert "UNKNOWN" in p.name
    assert p.recommended is False


@pytest.mark.parametrize('hostname,expected', [
    (b'example.com', 'example.com'),
    (b'xn--bcher-kva.example', 'bücher.example'),
    (b'\xff.invalid', None),
])
def test_sni_decoding_preserves_client_hello(hostname, expected):
    import struct
    name = b'\x00' + struct.pack('!H', len(hostname)) + hostname
    sni = struct.pack('!H', len(name)) + name
    extensions = struct.pack('!HH', 0, len(sni)) + sni
    versions = b'\x02\x03\x04'
    extensions += struct.pack('!HH', 43, len(versions)) + versions
    body = (b'\x03\x03' + bytes(32) + b'\x00' + b'\x00\x02\x13\x02'
            + b'\x01\x00' + struct.pack('!H', len(extensions)) + extensions)
    hello = tls.parse_client_hello(body)
    assert hello is not None
    assert hello.server_name == expected
    assert hello.supported_versions == [0x0304]
