#!/usr/bin/env python3
"""
Build the "good configuration" demo captures.

Every capture in ``demo-pcaps/`` is real traffic, and all of it is bad — the
best any of them earns is a C. That is fine for showing what the tool finds and
useless for showing what a healthy server looks like, so the top of the scale
went undemonstrated and untested.

Real traffic in that shape is not something we can go and record: a passive
capture of a correctly configured mail server is exactly the file nobody
publishes. So these two are synthesised, and honestly labelled as such
(``synthetic-*.pcap``). Everything in them that the engine judges is real:

  * the TLS records, handshake messages and extensions are byte-accurate;
  * the TLS 1.2 capture carries a **genuine public certificate chain**, fetched
    from the live host, so ``chain_valid`` is a real cryptographic result
    verified against the Mozilla root bundle rather than a fixture that claims
    to be valid.

No private key is involved and none is needed: the engine is a passive parser.
It never verifies a handshake signature — it reads what was sent and validates
the certificate chain, which is genuine here.

**Why the verdicts are stable.** Certificate validity is judged against the
capture clock (the packet timestamps baked into the file), never against today,
so these files grade the same in a year as they do now. The one external
dependency is that the chain's root stays in ``certifi``.

    python scripts/make_demo_capture.py --out demo-pcaps
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# pcap container
# --------------------------------------------------------------------------

PCAP_MAGIC_US = 0xA1B2C3D4
DLT_EN10MB = 1


class PcapWriter:
    """Classic pcap, little-endian, microsecond resolution, Ethernet."""

    def __init__(self, path: str):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, 262144, DLT_EN10MB))

    def write(self, ts: float, frame: bytes) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:          # rounding can carry
            sec += 1
            usec -= 1_000_000
        self.fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.fh.write(frame)

    def close(self) -> None:
        self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _ipv4_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_str_to_bytes(ip: str) -> bytes:
    return bytes(int(p) for p in ip.split("."))


def build_frame(
    src_mac: bytes, dst_mac: bytes,
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    seq: int, ack: int, flags: int,
    payload: bytes = b"",
    window: int = 64240,
) -> bytes:
    tcp_header_len = 20
    tcp = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack,
        (tcp_header_len // 4) << 4, flags, window, 0, 0,
    )
    # The engine never verifies the TCP checksum (a passive tool sees plenty of
    # captures with checksum offload), so leaving it zero is honest and keeps
    # this generator readable.
    total_len = 20 + tcp_header_len + len(payload)
    ip_no_ck = struct.pack(
        "!BBHHHBBH", 0x45, 0, total_len, 0, 0x4000, 64, 6, 0
    ) + ipv4_str_to_bytes(src_ip) + ipv4_str_to_bytes(dst_ip)
    ck = _ipv4_checksum(ip_no_ck)
    ip = ip_no_ck[:10] + struct.pack("!H", ck) + ip_no_ck[12:]
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + ip + tcp + payload


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class Flow:
    """One TCP conversation, emitting frames in order with correct sequencing."""

    writer: PcapWriter
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    ts: float
    client_mac: bytes = b"\x02\x00\x00\x00\x00\x01"
    server_mac: bytes = b"\x02\x00\x00\x00\x00\x02"
    cseq: int = 1000
    sseq: int = 5000
    _step: float = 0.004

    def _tick(self) -> float:
        self.ts += self._step
        return self.ts

    def handshake(self) -> None:
        self.writer.write(self._tick(), build_frame(
            self.client_mac, self.server_mac, self.client_ip, self.server_ip,
            self.client_port, self.server_port, self.cseq, 0, SYN))
        self.writer.write(self._tick(), build_frame(
            self.server_mac, self.client_mac, self.server_ip, self.client_ip,
            self.server_port, self.client_port, self.sseq, self.cseq + 1, SYN | ACK))
        self.cseq += 1
        self.sseq += 1
        self.writer.write(self._tick(), build_frame(
            self.client_mac, self.server_mac, self.client_ip, self.server_ip,
            self.client_port, self.server_port, self.cseq, self.sseq, ACK))

    def _send(self, from_client: bool, payload: bytes, mss: int = 1400) -> None:
        """Send a payload, segmented at ``mss`` so large certificate chains
        cross several frames exactly as they do on the wire."""
        for i in range(0, len(payload), mss):
            chunk = payload[i:i + mss]
            if from_client:
                self.writer.write(self._tick(), build_frame(
                    self.client_mac, self.server_mac, self.client_ip, self.server_ip,
                    self.client_port, self.server_port, self.cseq, self.sseq, PSH | ACK, chunk))
                self.cseq += len(chunk)
            else:
                self.writer.write(self._tick(), build_frame(
                    self.server_mac, self.client_mac, self.server_ip, self.client_ip,
                    self.server_port, self.client_port, self.sseq, self.cseq, PSH | ACK, chunk))
                self.sseq += len(chunk)

    def client(self, payload: bytes) -> None:
        self._send(True, payload)

    def server(self, payload: bytes) -> None:
        self._send(False, payload)

    def close(self) -> None:
        self.writer.write(self._tick(), build_frame(
            self.client_mac, self.server_mac, self.client_ip, self.server_ip,
            self.client_port, self.server_port, self.cseq, self.sseq, FIN | ACK))
        self.cseq += 1
        self.writer.write(self._tick(), build_frame(
            self.server_mac, self.client_mac, self.server_ip, self.client_ip,
            self.server_port, self.client_port, self.sseq, self.cseq, FIN | ACK))
        self.sseq += 1
        self.writer.write(self._tick(), build_frame(
            self.client_mac, self.server_mac, self.client_ip, self.server_ip,
            self.client_port, self.server_port, self.cseq, self.sseq, ACK))


# --------------------------------------------------------------------------
# TLS message construction
# --------------------------------------------------------------------------

CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE, CT_APPLICATION_DATA = 20, 22, 23

GROUP_X25519 = 0x001D
GROUP_SECP256R1 = 0x0017

SUITE_TLS13_AES256 = 0x1302
SUITE_TLS13_AES128 = 0x1301
SUITE_ECDHE_RSA_AES256_GCM = 0xC030


def record(content_type: int, payload: bytes, version: int = 0x0303) -> bytes:
    return struct.pack("!BHH", content_type, version, len(payload)) + payload


def handshake(msg_type: int, body: bytes) -> bytes:
    return struct.pack("!B", msg_type) + len(body).to_bytes(3, "big") + body


def _ext(etype: int, data: bytes) -> bytes:
    return struct.pack("!HH", etype, len(data)) + data


def _ext_block(exts: list[bytes]) -> bytes:
    joined = b"".join(exts)
    return struct.pack("!H", len(joined)) + joined


def ext_server_name(host: str) -> bytes:
    name = host.encode()
    entry = struct.pack("!BH", 0, len(name)) + name
    return _ext(0, struct.pack("!H", len(entry)) + entry)


def ext_supported_groups(groups: list[int]) -> bytes:
    body = struct.pack("!H", len(groups) * 2) + b"".join(struct.pack("!H", g) for g in groups)
    return _ext(10, body)


def ext_signature_algorithms(algs: list[int]) -> bytes:
    body = struct.pack("!H", len(algs) * 2) + b"".join(struct.pack("!H", a) for a in algs)
    return _ext(13, body)


def ext_alpn(protocols: list[str]) -> bytes:
    inner = b"".join(bytes([len(p)]) + p.encode() for p in protocols)
    return _ext(16, struct.pack("!H", len(inner)) + inner)


def ext_client_supported_versions(versions: list[int]) -> bytes:
    body = bytes([len(versions) * 2]) + b"".join(struct.pack("!H", v) for v in versions)
    return _ext(43, body)


def ext_server_supported_version(version: int) -> bytes:
    return _ext(43, struct.pack("!H", version))


def ext_client_key_share(group: int, key: bytes) -> bytes:
    entry = struct.pack("!HH", group, len(key)) + key
    return _ext(51, struct.pack("!H", len(entry)) + entry)


def ext_server_key_share(group: int, key: bytes) -> bytes:
    return _ext(51, struct.pack("!HH", group, len(key)) + key)


def client_hello(
    host: str,
    suites: list[int],
    groups: list[int],
    tls13: bool,
    key_share_group: int,
    alpn: list[str] | None = None,
) -> bytes:
    body = struct.pack("!H", 0x0303)                     # legacy_version
    body += bytes(range(32))                             # random (deterministic)
    session_id = bytes(range(32, 64))
    body += bytes([len(session_id)]) + session_id
    body += struct.pack("!H", len(suites) * 2)
    body += b"".join(struct.pack("!H", s) for s in suites)
    body += bytes([1, 0])                                # compression: null

    exts = [
        ext_server_name(host),
        ext_supported_groups(groups),
        _ext(11, bytes([1, 0])),                         # ec_point_formats: uncompressed
        ext_signature_algorithms([0x0804, 0x0805, 0x0806, 0x0403, 0x0503]),
        _ext(5, bytes([1, 0, 0, 0, 0])),                 # status_request (OCSP)
    ]
    if alpn:
        exts.append(ext_alpn(alpn))
    if tls13:
        exts.append(ext_client_supported_versions([0x0304, 0x0303]))
        exts.append(ext_client_key_share(key_share_group, bytes(range(1, 33))))
    body += _ext_block(exts)
    return handshake(1, body)


def server_hello(
    suite: int,
    tls13: bool,
    group: int | None = None,
    alpn: str | None = None,
) -> bytes:
    body = struct.pack("!H", 0x0303)
    body += bytes(range(64, 96))                         # random
    session_id = bytes(range(32, 64))                    # echo the client's
    body += bytes([len(session_id)]) + session_id
    body += struct.pack("!H", suite)
    body += bytes([0])                                   # compression: null

    exts: list[bytes] = []
    if tls13:
        exts.append(ext_server_supported_version(0x0304))
        exts.append(ext_server_key_share(group or GROUP_X25519, bytes(range(33, 65))))
    if alpn:
        exts.append(ext_alpn([alpn]))
    body += _ext_block(exts)
    return handshake(2, body)


def certificate_message(chain: list[bytes], tls13: bool) -> bytes:
    if tls13:
        entries = b"".join(
            len(c).to_bytes(3, "big") + c + struct.pack("!H", 0) for c in chain
        )
        body = bytes([0]) + len(entries).to_bytes(3, "big") + entries
    else:
        entries = b"".join(len(c).to_bytes(3, "big") + c for c in chain)
        body = len(entries).to_bytes(3, "big") + entries
    return handshake(11, body)


def server_key_exchange_ecdhe(group: int) -> bytes:
    """curve_type(3 = named_curve) + named_curve + pubkey + signature."""
    pub = bytes(range(65, 97))
    body = bytes([3]) + struct.pack("!H", group) + bytes([len(pub)]) + pub
    sig = bytes(range(96, 128)) * 8                      # opaque; never verified
    body += struct.pack("!H", 0x0804) + struct.pack("!H", len(sig)) + sig
    return handshake(12, body)


def server_hello_done() -> bytes:
    return handshake(14, b"")


def opaque(n: int, seed: int = 7) -> bytes:
    """Deterministic filler standing in for ciphertext."""
    out = bytearray(n)
    x = seed
    for i in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out[i] = (x >> 16) & 0xFF
    return bytes(out)


# --------------------------------------------------------------------------
# fetching a genuine certificate chain
# --------------------------------------------------------------------------

def fetch_chain(host: str, port: int = 443, timeout: float = 15.0) -> list[bytes]:
    """
    Retrieve the DER chain a real server presents.

    ``SSLSocket.get_verified_chain`` arrived in Python 3.10; on anything older,
    or if the platform build lacks it, fall back to the ``openssl`` CLI, which
    prints the chain the server actually sent.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                getter = getattr(tls, "get_verified_chain", None)
                if getter is not None:
                    return [ssl.PEM_cert_to_DER_cert(
                        ssl.DER_cert_to_PEM_cert(c) if isinstance(c, bytes) else c
                    ) for c in _normalise(getter())]
    except Exception as exc:  # noqa: BLE001 - fall through to the CLI
        print(f"  python ssl path unavailable ({exc}); trying openssl", file=sys.stderr)

    out = subprocess.run(
        ["openssl", "s_client", "-connect", f"{host}:{port}",
         "-servername", host, "-showcerts"],
        input=b"", capture_output=True, timeout=timeout,
    ).stdout.decode("utf-8", "replace")

    chain: list[bytes] = []
    marker = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    pos = 0
    while True:
        a = out.find(marker, pos)
        if a < 0:
            break
        b = out.find(end, a)
        if b < 0:
            break
        pem = out[a:b + len(end)]
        chain.append(ssl.PEM_cert_to_DER_cert(pem))
        pos = b + len(end)
    return chain


def _normalise(certs) -> list:
    out = []
    for c in certs:
        out.append(c.public_bytes() if hasattr(c, "public_bytes") else c)
    return out


def chain_is_publicly_trusted(chain: list[bytes], host: str, when: float) -> tuple[bool, str]:
    """
    Check the fetched chain with the engine's own validator before using it.

    Corporate networks, sandboxes and CI runners very often terminate TLS at a
    proxy, so what comes back is a certificate minted by a private CA rather
    than the one the real server presents. Embedding that would produce a demo
    capture claiming to be a well-configured public mail server while carrying
    a chain that reaches no public root — the exact opposite of what this file
    is for. Better to refuse and say why.
    """
    from datetime import datetime, timezone

    from mailsentinel.analyze import certs as certmod

    result = certmod.analyse(chain, datetime.fromtimestamp(when, timezone.utc), host, None)
    if not result.chain_valid:
        return False, result.chain_error or "chain does not reach a trusted root"
    if result.name_match is False:
        return False, f"certificate does not match {host}"
    return True, "chain builds to a trusted public root"


# --------------------------------------------------------------------------
# the two captures
# --------------------------------------------------------------------------

# Frozen so the files — and therefore the graded verdicts — are reproducible.
BASE_TIME = 1756000000.0        # 2025-08-24T02:26:40Z


def capture_time_for(chain: list[bytes]) -> float:
    """
    A capture clock that sits inside the leaf certificate's validity window.

    Certificate validity is judged against the capture's own timestamps, so a
    fixture whose packets predate the certificate it carries reports "not yet
    valid" — which is correct behaviour and a useless demo. Deriving the clock
    from the certificate keeps the verdict stable forever *and* keeps the file
    deterministic: regenerate it with the same chain and you get the same bytes.
    """
    from cryptography import x509

    leaf = x509.load_der_x509_certificate(chain[0])
    try:
        start = leaf.not_valid_before_utc
        end = leaf.not_valid_after_utc
    except AttributeError:                      # cryptography < 42
        from datetime import timezone as _tz
        start = leaf.not_valid_before.replace(tzinfo=_tz.utc)
        end = leaf.not_valid_after.replace(tzinfo=_tz.utc)

    # A week in, so the file is unambiguously inside the window at both ends.
    target = start.timestamp() + 7 * 86400
    return min(target, (start.timestamp() + end.timestamp()) / 2)


def build_tls13(path: str, host: str = "imap.example.net") -> None:
    """
    IMAPS on 993, TLS 1.3, X25519, AES-256-GCM.

    The certificate is encrypted under handshake keys and genuinely cannot be
    read, which is the point: this is the session where the rule engine has to
    abstain on every certificate question and say so.
    """
    with PcapWriter(path) as w:
        f = Flow(w, "10.20.30.40", "203.0.113.25", 51894, 993, BASE_TIME)
        f.handshake()

        f.client(record(CT_HANDSHAKE, client_hello(
            host,
            suites=[SUITE_TLS13_AES256, SUITE_TLS13_AES128, SUITE_ECDHE_RSA_AES256_GCM],
            groups=[GROUP_X25519, GROUP_SECP256R1],
            tls13=True,
            key_share_group=GROUP_X25519,
        ), version=0x0301))

        f.server(
            record(CT_HANDSHAKE, server_hello(
                SUITE_TLS13_AES256, tls13=True, group=GROUP_X25519))
            + record(CT_CHANGE_CIPHER_SPEC, b"\x01")
            # EncryptedExtensions, Certificate, CertificateVerify and Finished
            # are all inside this — unreadable, exactly as on the wire.
            + record(CT_APPLICATION_DATA, opaque(3600, seed=11))
        )
        f.client(record(CT_CHANGE_CIPHER_SPEC, b"\x01")
                 + record(CT_APPLICATION_DATA, opaque(64, seed=13)))

        # A short IMAP session's worth of encrypted traffic.
        for i in range(4):
            f.client(record(CT_APPLICATION_DATA, opaque(120 + i * 20, seed=17 + i)))
            f.server(record(CT_APPLICATION_DATA, opaque(400 + i * 260, seed=23 + i)))
        f.close()


def build_tls12(path: str, host: str, chain: list[bytes], base_time: float) -> None:
    """
    IMAPS on 993, TLS 1.2, ECDHE/X25519, AES-256-GCM, with the real chain.

    This is the one that exercises certificate validation end to end: chain
    building to a Mozilla root, hostname matching, key size and signature hash.
    """
    with PcapWriter(path) as w:
        f = Flow(w, "10.20.30.41", "203.0.113.26", 52310, 993, base_time)
        f.handshake()

        f.client(record(CT_HANDSHAKE, client_hello(
            host,
            suites=[SUITE_ECDHE_RSA_AES256_GCM, 0xC02F, 0xC02C],
            groups=[GROUP_X25519, GROUP_SECP256R1],
            tls13=False,
            key_share_group=GROUP_X25519,
        ), version=0x0301))

        f.server(
            record(CT_HANDSHAKE,
                   server_hello(SUITE_ECDHE_RSA_AES256_GCM, tls13=False)
                   + certificate_message(chain, tls13=False)
                   + server_key_exchange_ecdhe(GROUP_X25519)
                   + server_hello_done())
        )
        f.client(record(CT_HANDSHAKE, handshake(16, opaque(70, seed=29)))
                 + record(CT_CHANGE_CIPHER_SPEC, b"\x01")
                 + record(CT_HANDSHAKE, opaque(40, seed=31)))
        f.server(record(CT_CHANGE_CIPHER_SPEC, b"\x01")
                 + record(CT_HANDSHAKE, opaque(40, seed=37)))

        for i in range(4):
            f.client(record(CT_APPLICATION_DATA, opaque(130 + i * 18, seed=41 + i)))
            f.server(record(CT_APPLICATION_DATA, opaque(380 + i * 240, seed=47 + i)))
        f.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="demo-pcaps", help="output directory")
    ap.add_argument("--chain-host", default="outlook.office365.com",
                    help="host whose real certificate chain to embed")
    ap.add_argument("--no-fetch", action="store_true",
                    help="build only the TLS 1.3 capture; make no network connection")
    args = ap.parse_args()

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "engine"))

    os.makedirs(args.out, exist_ok=True)

    # 1. The TLS 1.3 capture needs no network and no certificate at all.
    tls13 = os.path.join(args.out, "synthetic-imaps-tls13.pcap")
    build_tls13(tls13)
    print(f"wrote {tls13}  ({os.path.getsize(tls13)} bytes)   → expect A+")

    if args.no_fetch:
        return 0

    # 2. The TLS 1.2 capture needs a genuine public chain.
    print(f"\nfetching the certificate chain for {args.chain_host} …")
    try:
        chain = fetch_chain(args.chain_host)
    except Exception as exc:                              # noqa: BLE001
        print(f"  could not connect: {exc}", file=sys.stderr)
        chain = []
    if not chain:
        print(_no_chain_message(args.chain_host), file=sys.stderr)
        return 0

    print(f"  got {len(chain)} certificate(s), {sum(len(c) for c in chain)} bytes")
    base = capture_time_for(chain)
    print(f"  capture clock {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(base))} "
          f"— inside the leaf's validity window")

    ok, why = chain_is_publicly_trusted(chain, args.chain_host, base)
    if not ok:
        from cryptography import x509
        root = x509.load_der_x509_certificate(chain[-1])
        print(
            f"\n  REFUSING to build the TLS 1.2 capture: {why}.\n"
            f"  The chain that came back is issued by "
            f"{root.subject.rfc4514_string()[:60]!r},\n"
            f"  which is not a public root — this network is terminating TLS at a\n"
            f"  proxy, so that is not {args.chain_host}'s real certificate.\n"
            f"  Writing it would produce a demo that contradicts its own point.\n"
            f"  Re-run this on a network without TLS interception.",
            file=sys.stderr,
        )
        return 0

    print(f"  {why}")
    tls12 = os.path.join(args.out, "synthetic-imaps-tls12.pcap")
    build_tls12(tls12, args.chain_host, chain, base)
    print(f"wrote {tls12}  ({os.path.getsize(tls12)} bytes)   → expect A+ with a trusted chain")
    return 0


def _no_chain_message(host: str) -> str:
    return (
        f"  no chain retrieved for {host}; skipping the TLS 1.2 capture.\n"
        f"  The TLS 1.3 capture above is complete and needs no network."
    )


if __name__ == "__main__":
    raise SystemExit(main())
