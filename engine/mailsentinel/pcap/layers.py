"""
Link-, network- and transport-layer decoding.

Deliberately dependency-free: the subset of the stack an email-forensics tool
needs is small and well-specified, and hand-decoding it keeps the engine
installable with `pip install -e .` and nothing else.

Supported link types (DLT):
    0    NULL / loopback (BSD)
    1    Ethernet          (+ 802.1Q / QinQ VLAN tags)
    101  RAW IP
    113  Linux cooked (SLL)
    276  Linux cooked v2 (SLL2)
    228  IPv4, 229 IPv6
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

# ---- DLT constants -------------------------------------------------------
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 101
DLT_RAW_ALT = 12
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
DLT_IPV4 = 228
DLT_IPV6 = 229

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8

IPPROTO_TCP = 6
IPPROTO_UDP = 17

# TCP flag bits
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


@dataclass
class TcpSegment:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload: bytes
    ip_version: int

    @property
    def syn(self) -> bool:
        return bool(self.flags & SYN)

    @property
    def fin(self) -> bool:
        return bool(self.flags & FIN)

    @property
    def rst(self) -> bool:
        return bool(self.flags & RST)

    @property
    def ack_flag(self) -> bool:
        return bool(self.flags & ACK)


@dataclass
class UdpDatagram:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes


def _ipv4_str(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _ipv6_str(raw: bytes) -> str:
    parts = [f"{raw[i] << 8 | raw[i + 1]:x}" for i in range(0, 16, 2)]
    # RFC 5952 :: compression of the longest run of zero groups
    best_start, best_len = -1, 0
    run_start, run_len = -1, 0
    for i, p in enumerate(parts):
        if p == "0":
            if run_start < 0:
                run_start, run_len = i, 1
            else:
                run_len += 1
            if run_len > best_len:
                best_start, best_len = run_start, run_len
        else:
            run_start, run_len = -1, 0
    if best_len > 1:
        return ":".join(parts[:best_start]) + "::" + ":".join(parts[best_start + best_len:])
    return ":".join(parts)


def strip_link_layer(data: bytes, dlt: int) -> tuple[Optional[bytes], Optional[int]]:
    """
    Remove the link-layer header.

    Returns ``(network_payload, ethertype)`` where ethertype is ETH_P_IP or
    ETH_P_IPV6, or ``(None, None)`` when the frame is not IP.
    """
    try:
        if dlt == DLT_EN10MB:
            if len(data) < 14:
                return None, None
            etype = struct.unpack("!H", data[12:14])[0]
            off = 14
            # Walk any number of stacked VLAN tags.
            while etype in (ETH_P_8021Q, ETH_P_8021AD):
                if len(data) < off + 4:
                    return None, None
                etype = struct.unpack("!H", data[off + 2:off + 4])[0]
                off += 4
            if etype in (ETH_P_IP, ETH_P_IPV6):
                return data[off:], etype
            return None, None

        if dlt == DLT_NULL:
            if len(data) < 4:
                return None, None
            # Host byte order; AF_INET=2. AF_INET6 is 24/28/30 depending on OS.
            fam = struct.unpack("<I", data[:4])[0]
            if fam > 0xFFFF:
                fam = struct.unpack(">I", data[:4])[0]
            if fam == 2:
                return data[4:], ETH_P_IP
            if fam in (24, 28, 30):
                return data[4:], ETH_P_IPV6
            return None, None

        if dlt in (DLT_RAW, DLT_RAW_ALT):
            if not data:
                return None, None
            v = data[0] >> 4
            if v == 4:
                return data, ETH_P_IP
            if v == 6:
                return data, ETH_P_IPV6
            return None, None

        if dlt == DLT_IPV4:
            return data, ETH_P_IP
        if dlt == DLT_IPV6:
            return data, ETH_P_IPV6

        if dlt == DLT_LINUX_SLL:
            if len(data) < 16:
                return None, None
            etype = struct.unpack("!H", data[14:16])[0]
            if etype in (ETH_P_IP, ETH_P_IPV6):
                return data[16:], etype
            return None, None

        if dlt == DLT_LINUX_SLL2:
            if len(data) < 20:
                return None, None
            etype = struct.unpack("!H", data[0:2])[0]
            if etype in (ETH_P_IP, ETH_P_IPV6):
                return data[20:], etype
            return None, None
    except (struct.error, IndexError):
        return None, None
    return None, None


def parse_ip_tcp(data: bytes, ethertype: int) -> Optional[TcpSegment]:
    """Decode IPv4/IPv6 + TCP.  Returns None for anything else or on truncation."""
    try:
        if ethertype == ETH_P_IP:
            if len(data) < 20:
                return None
            ihl = (data[0] & 0x0F) * 4
            if ihl < 20 or len(data) < ihl:
                return None
            total_len = struct.unpack("!H", data[2:4])[0]
            proto = data[9]
            frag_off = struct.unpack("!H", data[6:8])[0] & 0x1FFF
            src = _ipv4_str(data[12:16])
            dst = _ipv4_str(data[16:20])
            # Only the first fragment carries the TCP header.
            if frag_off != 0 or proto != IPPROTO_TCP:
                return None
            # Trust total_len when it is sane; captures are often padded.
            end = total_len if 0 < total_len <= len(data) else len(data)
            payload = data[ihl:end]
            ver = 4
        elif ethertype == ETH_P_IPV6:
            if len(data) < 40:
                return None
            payload_len = struct.unpack("!H", data[4:6])[0]
            nxt = data[6]
            src = _ipv6_str(data[8:24])
            dst = _ipv6_str(data[24:40])
            off = 40
            end = min(40 + payload_len, len(data)) if payload_len else len(data)
            # Walk extension headers to reach TCP.
            hop_by_hop = {0, 43, 60}
            guard = 0
            while nxt in hop_by_hop and guard < 8:
                if len(data) < off + 8:
                    return None
                ext_len = (data[off + 1] + 1) * 8
                nxt = data[off]
                off += ext_len
                guard += 1
            if nxt != IPPROTO_TCP:
                return None
            payload = data[off:end]
            ver = 6
        else:
            return None

        if len(payload) < 20:
            return None
        src_port, dst_port, seq, ack = struct.unpack("!HHII", payload[:12])
        data_off = (payload[12] >> 4) * 4
        flags = payload[13]
        if data_off < 20 or len(payload) < data_off:
            return None
        return TcpSegment(
            src_ip=src, dst_ip=dst, src_port=src_port, dst_port=dst_port,
            seq=seq, ack=ack, flags=flags, payload=payload[data_off:], ip_version=ver,
        )
    except (struct.error, IndexError):
        return None


def parse_ip_udp(data: bytes, ethertype: int) -> Optional[UdpDatagram]:
    """Decode IPv4/IPv6 + UDP — used only for the DNS policy module."""
    try:
        if ethertype == ETH_P_IP:
            if len(data) < 20:
                return None
            ihl = (data[0] & 0x0F) * 4
            if ihl < 20 or len(data) < ihl or data[9] != IPPROTO_UDP:
                return None
            total_len = struct.unpack("!H", data[2:4])[0]
            src = _ipv4_str(data[12:16])
            dst = _ipv4_str(data[16:20])
            end = total_len if 0 < total_len <= len(data) else len(data)
            payload = data[ihl:end]
        elif ethertype == ETH_P_IPV6:
            if len(data) < 40 or data[6] != IPPROTO_UDP:
                return None
            src = _ipv6_str(data[8:24])
            dst = _ipv6_str(data[24:40])
            payload = data[40:]
        else:
            return None
        if len(payload) < 8:
            return None
        sp, dp, ln = struct.unpack("!HHH", payload[:6])
        body = payload[8:ln] if 8 < ln <= len(payload) else payload[8:]
        return UdpDatagram(src_ip=src, dst_ip=dst, src_port=sp, dst_port=dp, payload=body)
    except (struct.error, IndexError):
        return None
