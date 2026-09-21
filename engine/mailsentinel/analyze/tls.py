"""
TLS record and handshake parsing, plus JA3 / JA4 client fingerprints.

Everything here operates on the reassembled byte stream, so it works
identically for implicit TLS and for a session upgraded mid-stream by STARTTLS.

What survives encryption
------------------------
The ClientHello is always cleartext: offered cipher suites, extensions,
supported groups, signature algorithms, ALPN and SNI.  The ServerHello reveals
the negotiated version and suite.  On TLS 1.2 and below the Certificate message
is also cleartext.  On TLS 1.3 (RFC 8446 §4.4) it is encrypted under handshake
keys, so a passive sensor cannot read it — that is a property of the protocol,
not a limitation of this implementation, and the session is marked
``cert_visibility = encrypted_tls13`` rather than guessed at.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional

from .ciphers import group_name

# record content types
CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

# handshake message types
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_NEW_SESSION_TICKET = 4
HS_CERTIFICATE = 11
HS_SERVER_KEY_EXCHANGE = 12
HS_CERTIFICATE_REQUEST = 13
HS_SERVER_HELLO_DONE = 14
HS_CERTIFICATE_STATUS = 22

# extensions we care about
EXT_SERVER_NAME = 0
EXT_STATUS_REQUEST = 5
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51

# GREASE values (RFC 8701) must be excluded from fingerprints.
GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

VERSION_NAMES = {
    0x0300: "SSL3.0", 0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3",
}


def version_name(raw: Optional[int]) -> Optional[str]:
    if raw is None:
        return None
    return VERSION_NAMES.get(raw, f"unknown(0x{raw:04X})")


# --------------------------------------------------------------------------
# record layer
# --------------------------------------------------------------------------

@dataclass
class TlsRecord:
    content_type: int
    version: int
    payload: bytes
    offset: int


def looks_like_record(data: bytes, pos: int) -> bool:
    """Cheap plausibility test for a TLS record header at `pos`."""
    if pos + 5 > len(data):
        return False
    ct = data[pos]
    ver = struct.unpack("!H", data[pos + 1:pos + 3])[0]
    ln = struct.unpack("!H", data[pos + 3:pos + 5])[0]
    return (
        ct in (CT_CHANGE_CIPHER_SPEC, CT_ALERT, CT_HANDSHAKE, CT_APPLICATION_DATA)
        and 0x0300 <= ver <= 0x0304
        and 0 < ln <= 0x4800
    )


def find_tls_start(data: bytes, limit: int = 65536) -> Optional[int]:
    """
    Offset of the first TLS record in a reassembled direction.

    Requires two chained plausible records (or one record that runs to the end
    of the stream) so a random byte pattern in message content cannot be
    mistaken for a handshake.
    """
    end = min(len(data), limit)
    for pos in range(0, end):
        if not looks_like_record(data, pos):
            continue
        ln = struct.unpack("!H", data[pos + 3:pos + 5])[0]
        nxt = pos + 5 + ln
        if nxt >= len(data):
            # last record in the stream — accept if it is a handshake start
            if data[pos] == CT_HANDSHAKE and pos + 5 < len(data) and data[pos + 5] in (
                HS_CLIENT_HELLO, HS_SERVER_HELLO
            ):
                return pos
            continue
        if looks_like_record(data, nxt):
            return pos
    return None


def parse_records(data: bytes, start: int = 0) -> list[TlsRecord]:
    records: list[TlsRecord] = []
    pos = start
    while pos + 5 <= len(data):
        ct = data[pos]
        ver = struct.unpack("!H", data[pos + 1:pos + 3])[0]
        ln = struct.unpack("!H", data[pos + 3:pos + 5])[0]
        if ct not in (CT_CHANGE_CIPHER_SPEC, CT_ALERT, CT_HANDSHAKE, CT_APPLICATION_DATA):
            break
        if not (0x0300 <= ver <= 0x0304):
            break
        body = data[pos + 5:pos + 5 + ln]
        records.append(TlsRecord(ct, ver, body, pos))
        pos += 5 + ln
        if len(body) < ln:
            break
    return records


def handshake_messages(records: list[TlsRecord]) -> list[tuple[int, bytes]]:
    """
    Defragment handshake messages across records.

    Only records before the first ChangeCipherSpec are usable; after that the
    handshake is encrypted.
    """
    buf = bytearray()
    for r in records:
        if r.content_type == CT_CHANGE_CIPHER_SPEC:
            break
        if r.content_type == CT_HANDSHAKE:
            buf += r.payload
    out: list[tuple[int, bytes]] = []
    pos = 0
    while pos + 4 <= len(buf):
        mtype = buf[pos]
        mlen = int.from_bytes(buf[pos + 1:pos + 4], "big")
        body = bytes(buf[pos + 4:pos + 4 + mlen])
        if len(body) < mlen:
            break
        out.append((mtype, body))
        pos += 4 + mlen
    return out


# --------------------------------------------------------------------------
# hello parsing
# --------------------------------------------------------------------------

@dataclass
class ClientHello:
    legacy_version: int = 0
    cipher_suites: list[int] = field(default_factory=list)
    compression: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    server_name: Optional[str] = None
    alpn: list[str] = field(default_factory=list)
    session_id_len: int = 0
    status_request: bool = False

    @property
    def max_version(self) -> int:
        real = [v for v in self.supported_versions if v not in GREASE]
        return max(real) if real else self.legacy_version


@dataclass
class ServerHello:
    legacy_version: int = 0
    cipher_suite: Optional[int] = None
    compression: Optional[int] = None
    extensions: list[int] = field(default_factory=list)
    supported_version: Optional[int] = None
    session_id_len: int = 0
    alpn: Optional[str] = None
    # TLS 1.3 carries the agreed key-exchange group here instead of in a
    # ServerKeyExchange message, which it no longer sends at all.
    key_share_group: Optional[int] = None

    @property
    def negotiated_version(self) -> Optional[int]:
        return self.supported_version or self.legacy_version or None


def _u16_list(b: bytes) -> list[int]:
    return [struct.unpack("!H", b[i:i + 2])[0] for i in range(0, len(b) - 1, 2)]


def _parse_extensions(data: bytes, pos: int) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    if pos + 2 > len(data):
        return out
    total = struct.unpack("!H", data[pos:pos + 2])[0]
    pos += 2
    end = min(pos + total, len(data))
    while pos + 4 <= end:
        etype, elen = struct.unpack("!HH", data[pos:pos + 4])
        pos += 4
        out.append((etype, data[pos:pos + elen]))
        pos += elen
    return out


def parse_client_hello(body: bytes) -> Optional[ClientHello]:
    try:
        ch = ClientHello()
        pos = 0
        ch.legacy_version = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2 + 32                                  # version + random
        sid_len = body[pos]; pos += 1
        ch.session_id_len = sid_len
        pos += sid_len
        cs_len = struct.unpack("!H", body[pos:pos + 2])[0]; pos += 2
        ch.cipher_suites = _u16_list(body[pos:pos + cs_len]); pos += cs_len
        comp_len = body[pos]; pos += 1
        ch.compression = list(body[pos:pos + comp_len]); pos += comp_len

        for etype, edata in _parse_extensions(body, pos):
            ch.extensions.append(etype)
            if etype == EXT_SERVER_NAME and len(edata) >= 5:
                # server_name_list -> first entry, type 0 = host_name
                nlen = struct.unpack("!H", edata[3:5])[0]
                if edata[2] == 0 and nlen > 0 and 5 + nlen <= len(edata):
                    try:
                        # The IDNA codec supports strict decoding only. An invalid
                        # hostname must not discard the rest of the ClientHello.
                        ch.server_name = edata[5:5 + nlen].decode("idna")
                    except UnicodeError:
                        pass
            elif etype == EXT_SUPPORTED_GROUPS and len(edata) >= 2:
                ch.supported_groups = _u16_list(edata[2:])
            elif etype == EXT_EC_POINT_FORMATS and len(edata) >= 1:
                ch.ec_point_formats = list(edata[1:])
            elif etype == EXT_SIGNATURE_ALGORITHMS and len(edata) >= 2:
                ch.signature_algorithms = _u16_list(edata[2:])
            elif etype == EXT_SUPPORTED_VERSIONS and len(edata) >= 1:
                ch.supported_versions = _u16_list(edata[1:])
            elif etype == EXT_ALPN and len(edata) >= 3:
                p = 2
                while p < len(edata):
                    ln = edata[p]; p += 1
                    ch.alpn.append(edata[p:p + ln].decode("ascii", "replace")); p += ln
            elif etype == EXT_STATUS_REQUEST:
                ch.status_request = True
        return ch
    except (struct.error, IndexError, UnicodeError):
        return None


def parse_server_hello(body: bytes) -> Optional[ServerHello]:
    try:
        sh = ServerHello()
        pos = 0
        sh.legacy_version = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2 + 32
        sid_len = body[pos]; pos += 1
        sh.session_id_len = sid_len
        pos += sid_len
        sh.cipher_suite = struct.unpack("!H", body[pos:pos + 2])[0]; pos += 2
        sh.compression = body[pos]; pos += 1
        for etype, edata in _parse_extensions(body, pos):
            sh.extensions.append(etype)
            if etype == EXT_SUPPORTED_VERSIONS and len(edata) >= 2:
                sh.supported_version = struct.unpack("!H", edata[:2])[0]
            elif etype == EXT_KEY_SHARE and len(edata) >= 2:
                # Both shapes start with the group: a ServerHello share is
                # {group, length, key_exchange}; a HelloRetryRequest names the
                # group alone. Reading the first two bytes covers both.
                sh.key_share_group = struct.unpack("!H", edata[:2])[0]
            elif etype == EXT_ALPN and len(edata) >= 3:
                ln = edata[2]
                sh.alpn = edata[3:3 + ln].decode("ascii", "replace")
        return sh
    except (struct.error, IndexError):
        return None


def parse_certificates(body: bytes, tls13: bool) -> list[bytes]:
    """
    Extract DER certificates from a Certificate handshake message.

    TLS 1.3 prefixes a certificate_request_context and appends per-entry
    extensions; TLS 1.2 and below is a plain list of length-prefixed certs.
    """
    try:
        pos = 0
        if tls13:
            ctx_len = body[pos]; pos += 1 + ctx_len
        list_len = int.from_bytes(body[pos:pos + 3], "big"); pos += 3
        end = min(pos + list_len, len(body))
        certs: list[bytes] = []
        while pos + 3 <= end:
            clen = int.from_bytes(body[pos:pos + 3], "big"); pos += 3
            certs.append(body[pos:pos + clen]); pos += clen
            if tls13:
                if pos + 2 > end:
                    break
                ext_len = struct.unpack("!H", body[pos:pos + 2])[0]
                pos += 2 + ext_len
        return [c for c in certs if c]
    except (struct.error, IndexError):
        return []


def parse_server_key_exchange_group(body: bytes) -> Optional[int]:
    """
    For ECDHE, the ServerKeyExchange begins with curve_type(1) + named_curve(2).
    Returns the named group id when the curve is a named one.
    """
    try:
        if len(body) >= 3 and body[0] == 3:  # named_curve
            return struct.unpack("!H", body[1:3])[0]
    except (struct.error, IndexError):
        return None
    return None


def parse_dhe_prime_bits(body: bytes) -> Optional[int]:
    """For plain DHE, the ServerKeyExchange starts with a length-prefixed prime."""
    try:
        if len(body) < 2:
            return None
        plen = struct.unpack("!H", body[0:2])[0]
        if 0 < plen <= len(body) - 2:
            p = body[2:2 + plen].lstrip(b"\x00")
            return len(p) * 8
    except (struct.error, IndexError):
        return None
    return None


# --------------------------------------------------------------------------
# fingerprints
# --------------------------------------------------------------------------

def ja3(ch: ClientHello) -> tuple[str, str]:
    """
    JA3 (Salesforce): MD5 of
      version,ciphers,extensions,supported_groups,ec_point_formats
    GREASE values are excluded.  Returned as (md5, source_string).
    """
    def clean(xs: list[int]) -> list[int]:
        return [x for x in xs if x not in GREASE]

    parts = [
        str(ch.legacy_version),
        "-".join(str(c) for c in clean(ch.cipher_suites)),
        "-".join(str(e) for e in clean(ch.extensions)),
        "-".join(str(g) for g in clean(ch.supported_groups)),
        "-".join(str(p) for p in ch.ec_point_formats),
    ]
    s = ",".join(parts)
    return hashlib.md5(s.encode()).hexdigest(), s


def ja4(ch: ClientHello, transport: str = "t") -> str:
    """
    JA4 client fingerprint (FoxIO), BSD-3-Clause portion of the JA4+ suite.

    Layout:  q|t + version + d|i (SNI present) + ciphercount + extcount +
             alpn(2) _ sha256(sorted ciphers)[:12] _ sha256(sorted exts + sigalgs)[:12]

    Sorting is what makes JA4 resistant to the extension-order randomisation
    that made JA3 evadable.
    """
    def clean(xs: list[int]) -> list[int]:
        return [x for x in xs if x not in GREASE]

    ver_map = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}
    ver = ver_map.get(ch.max_version, "00")
    sni = "d" if ch.server_name else "i"
    ciphers = clean(ch.cipher_suites)
    # SNI (0) and ALPN (16) are excluded from the extension count/hash by spec.
    exts = [e for e in clean(ch.extensions) if e not in (EXT_SERVER_NAME, EXT_ALPN)]
    nc = min(len(ciphers), 99)
    ne = min(len(clean(ch.extensions)), 99)
    alpn = "00"
    if ch.alpn:
        a = ch.alpn[0]
        alpn = (a[0] + a[-1]) if len(a) >= 2 else "00"

    a_part = f"{transport}{ver}{sni}{nc:02d}{ne:02d}{alpn}"
    b_src = ",".join(f"{c:04x}" for c in sorted(ciphers))
    b_part = hashlib.sha256(b_src.encode()).hexdigest()[:12] if ciphers else "000000000000"
    sig = ",".join(f"{s:04x}" for s in clean(ch.signature_algorithms))
    c_src = ",".join(f"{e:04x}" for e in sorted(exts)) + (f"_{sig}" if sig else "")
    c_part = hashlib.sha256(c_src.encode()).hexdigest()[:12] if exts else "000000000000"
    return f"{a_part}_{b_part}_{c_part}"


# --------------------------------------------------------------------------
# top-level handshake analysis
# --------------------------------------------------------------------------

@dataclass
class HandshakeResult:
    client_hello: Optional[ClientHello] = None
    server_hello: Optional[ServerHello] = None
    negotiated_version: Optional[int] = None
    cipher_suite: Optional[int] = None
    certificates: list[bytes] = field(default_factory=list)
    ocsp_response: Optional[bytes] = None
    named_group: Optional[int] = None
    dhe_bits: Optional[int] = None
    resumed: bool = False
    complete: bool = False
    alerts: list[tuple[int, int]] = field(default_factory=list)
    ja3: Optional[str] = None
    ja3_string: Optional[str] = None
    ja4: Optional[str] = None
    server_name: Optional[str] = None
    alpn: Optional[str] = None


def analyse_handshake(client_data: bytes, server_data: bytes) -> HandshakeResult:
    """Parse both halves of a TLS session from their reassembled byte streams."""
    res = HandshakeResult()

    c_start = find_tls_start(client_data)
    s_start = find_tls_start(server_data)
    if c_start is None and s_start is None:
        return res

    if c_start is not None:
        c_records = parse_records(client_data, c_start)
        for mtype, body in handshake_messages(c_records):
            if mtype == HS_CLIENT_HELLO:
                ch = parse_client_hello(body)
                if ch:
                    res.client_hello = ch
                    res.server_name = ch.server_name
                    res.ja3, res.ja3_string = ja3(ch)
                    res.ja4 = ja4(ch)
                break

    if s_start is not None:
        s_records = parse_records(server_data, s_start)
        # Only records before the first ChangeCipherSpec are readable; after it
        # the payload is ciphertext and must not be interpreted as alerts.
        for r in s_records:
            if r.content_type == CT_CHANGE_CIPHER_SPEC:
                break
            if r.content_type == CT_ALERT and len(r.payload) >= 2 and r.payload[0] in (1, 2):
                res.alerts.append((r.payload[0], r.payload[1]))
        msgs = handshake_messages(s_records)
        tls13 = False
        for mtype, body in msgs:
            if mtype == HS_SERVER_HELLO:
                sh = parse_server_hello(body)
                if sh:
                    res.server_hello = sh
                    res.negotiated_version = sh.negotiated_version
                    res.cipher_suite = sh.cipher_suite
                    res.alpn = sh.alpn
                    tls13 = sh.negotiated_version == 0x0304
                    # TLS 1.3 sends no ServerKeyExchange, so the key_share
                    # extension is the *only* place the negotiated group
                    # appears. Without it the key-exchange component scores
                    # zero, and the zero-in-any-category rule grades a perfect
                    # TLS 1.3 session F. A TLS 1.2 ServerKeyExchange, parsed
                    # below, still takes precedence where one is sent.
                    if sh.key_share_group is not None:
                        res.named_group = sh.key_share_group
        for mtype, body in msgs:
            if mtype == HS_CERTIFICATE:
                res.certificates = parse_certificates(body, tls13)
            elif mtype == HS_CERTIFICATE_STATUS and len(body) > 4:
                # status_type(1) + response length(3) + DER OCSP response
                if body[0] == 1:
                    ln = int.from_bytes(body[1:4], "big")
                    res.ocsp_response = body[4:4 + ln]
            elif mtype == HS_SERVER_KEY_EXCHANGE:
                res.named_group = parse_server_key_exchange_group(body)
                if res.named_group is None or group_name(res.named_group).startswith("group_0x"):
                    res.dhe_bits = parse_dhe_prime_bits(body)
            elif mtype == HS_SERVER_HELLO_DONE:
                res.complete = True

        # A TLS 1.3 server sends no ServerHelloDone; reaching application data
        # (or ChangeCipherSpec) is the completion signal instead.
        if any(r.content_type == CT_APPLICATION_DATA for r in s_records):
            res.complete = True
        if res.server_hello and not res.certificates and tls13:
            res.complete = res.complete or bool(
                [r for r in s_records if r.content_type == CT_CHANGE_CIPHER_SPEC]
            )
        # Session resumption: server echoes a session id it was offered, or the
        # abbreviated handshake carries no Certificate on TLS 1.2.
        if res.server_hello and res.negotiated_version != 0x0304:
            if not res.certificates and res.server_hello.session_id_len > 0:
                res.resumed = True

    return res
