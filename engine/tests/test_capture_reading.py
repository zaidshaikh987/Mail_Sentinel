"""
Capture parsing and TCP reassembly.

Packet counts are asserted against ground truth produced independently by
tshark, so a regression in the hand-written reader shows up immediately.
"""

from __future__ import annotations

import struct

import pytest

from mailsentinel.net.reassembly import Direction, Reassembler, seq_delta
from mailsentinel.pcap.layers import parse_ip_tcp, strip_link_layer
from mailsentinel.pcap.reader import CaptureFormatError, CaptureReader

# Verified with: tshark -r <file> | wc -l
EXPECTED_PACKETS = {
    "imap_cleartext": 124,
    "pop3_starttls": 38,
    "smtp_submission_cleartext": 78,
    "smtp_starttls": 38,
    "smtp_relay_cleartext": 60,
    # Synthetic; the count is fixed by scripts/make_demo_capture.py.
    "imaps_tls13": 19,
}

EXPECTED_FORMAT = {
    "imap_cleartext": "pcap",
    "pop3_starttls": "pcapng",
    "smtp_submission_cleartext": "pcap.gz",
    "smtp_starttls": "pcapng",
    "smtp_relay_cleartext": "pcap",
    "imaps_tls13": "pcap",
}


def test_all_captures_open(captures):
    for key, path in captures.items():
        reader = CaptureReader(path)
        assert reader.meta.packet_count == EXPECTED_PACKETS[key], key
        assert reader.meta.format == EXPECTED_FORMAT[key], key


def test_gzip_is_transparent(captures):
    """A .pcap.gz must parse identically to its uncompressed form."""
    path = captures["smtp_submission_cleartext"]
    reader = CaptureReader(path)
    assert reader.meta.format.endswith(".gz")
    assert reader.meta.packet_count == 78


def test_corrupt_timestamps_are_detected_not_trusted(captures):
    """
    Both pcapng demo captures carry one frame dated 2063.  The capture clock
    must exclude it, or certificate validity for the whole session is wrong.
    """
    for key in ("pop3_starttls", "smtp_starttls"):
        reader = CaptureReader(captures[key])
        assert reader.meta.suspect_timestamps == 1, key
        # first/last must come from the sane population
        assert reader.meta.first_time is not None
        assert reader.meta.last_time - reader.meta.first_time < 3600, key
        # the outlier itself is recognised
        outliers = [p for p in reader.raw_packets() if reader.is_suspect_time(p.timestamp)]
        assert len(outliers) == 1
        assert reader.sane_time(outliers[0].timestamp) == reader.meta.median_time


def test_rejects_non_capture(tmp_path):
    bad = tmp_path / "not-a-capture.pcap"
    bad.write_bytes(b"this is plainly not a packet capture at all, not even close")
    with pytest.raises(CaptureFormatError):
        CaptureReader(str(bad))


def test_icmp_encapsulated_tcp_is_not_parsed_as_a_segment(captures):
    """
    smtp.pcap contains 4 ICMP error packets that quote a TCP header.  Those are
    not live segments and must not be reassembled into the stream.
    """
    reader = CaptureReader(captures["smtp_relay_cleartext"])
    tcp = list(reader.tcp_segments())
    assert reader.meta.packet_count == 60
    assert len(tcp) == 53


def test_reassembly_has_no_gaps_on_demo_captures(captures):
    for key, path in captures.items():
        reader = CaptureReader(path)
        from mailsentinel.net.reassembly import reassemble

        for st in reassemble(reader.tcp_segments()):
            assert not st.client_to_server.gaps, f"{key} c2s"
            assert not st.server_to_client.gaps, f"{key} s2c"


def test_client_and_server_are_identified_from_the_syn(captures):
    from mailsentinel.net.reassembly import reassemble

    reader = CaptureReader(captures["smtp_starttls"])
    st = reassemble(reader.tcp_segments())[0]
    assert st.saw_syn
    assert st.server_port == 25
    assert st.client_port != 25


# --------------------------------------------------------------------------
# unit-level reassembly behaviour
# --------------------------------------------------------------------------

class FakePacket:
    def __init__(self, number, timestamp=1.0):
        self.number = number
        self.timestamp = timestamp


class FakeSeg:
    def __init__(self, seq, payload, syn=False, src=("1.1.1.1", 1000), dst=("2.2.2.2", 25)):
        self.seq = seq
        self.payload = payload
        self.flags = 0x02 if syn else 0x10
        self.src_ip, self.src_port = src
        self.dst_ip, self.dst_port = dst
        self.ack = 0
        self.ip_version = 4

    syn = property(lambda self: bool(self.flags & 0x02))
    fin = property(lambda self: bool(self.flags & 0x01))
    rst = property(lambda self: bool(self.flags & 0x04))
    ack_flag = property(lambda self: bool(self.flags & 0x10))


def _assemble(segs) -> bytes:
    r = Reassembler()
    for i, s in enumerate(segs, start=1):
        r.add(FakePacket(i), s)
    streams = r.finalise()
    return streams[0].client_to_server.data


def test_out_of_order_segments_are_ordered():
    data = _assemble([
        FakeSeg(1000, b"", syn=True),
        FakeSeg(1007, b"WORLD"),      # arrives first, but belongs second
        FakeSeg(1001, b"HELLO "),
    ])
    assert data == b"HELLO WORLD"


def test_retransmission_first_write_wins():
    data = _assemble([
        FakeSeg(1000, b"", syn=True),
        FakeSeg(1001, b"HELLO"),
        FakeSeg(1001, b"XXXXX"),      # retransmission with different bytes
        FakeSeg(1006, b" THERE"),
    ])
    assert data == b"HELLO THERE"


def test_overlapping_segment_does_not_corrupt_earlier_bytes():
    data = _assemble([
        FakeSeg(1000, b"", syn=True),
        FakeSeg(1001, b"ABCDEF"),
        FakeSeg(1004, b"XXXGHI"),     # overlaps DEF, extends with GHI
    ])
    assert data == b"ABCDEFGHI"


def test_gap_is_recorded():
    r = Reassembler()
    for i, s in enumerate([FakeSeg(1000, b"", syn=True),
                           FakeSeg(1001, b"AAA"),
                           FakeSeg(1010, b"BBB")], start=1):
        r.add(FakePacket(i), s)
    d = r.finalise()[0].client_to_server
    assert d.gaps == [(3, 9)]


def test_sequence_wraparound():
    base = 0xFFFFFFF0
    data = _assemble([
        FakeSeg(base, b"", syn=True),
        FakeSeg((base + 1) % (1 << 32), b"AAAA"),
        FakeSeg((base + 5) % (1 << 32), b"BBBB"),   # wraps past 2^32
    ])
    assert data == b"AAAABBBB"


@pytest.mark.parametrize("a,b,expected", [
    (100, 50, 50),
    (50, 100, -50),
    (5, 0xFFFFFFFF, 6),          # forward across the wrap
    (0xFFFFFFFF, 5, -6),         # backward across the wrap
])
def test_seq_delta(a, b, expected):
    assert seq_delta(a, b) == expected


def test_frame_index_maps_offsets_back_to_packets():
    r = Reassembler()
    for i, s in enumerate([FakeSeg(1000, b"", syn=True),
                           FakeSeg(1001, b"HELLO"),
                           FakeSeg(1006, b"WORLD")], start=1):
        r.add(FakePacket(i), s)
    d = r.finalise()[0].client_to_server
    assert d.frame_at(0) == 2
    assert d.frame_at(7) == 3
    assert set(d.frames_for_range(0, 10)) == {2, 3}


# --------------------------------------------------------------------------
# link layer
# --------------------------------------------------------------------------

def test_vlan_tags_are_stripped():
    eth = b"\xff" * 12 + struct.pack("!H", 0x8100) + b"\x00\x64" + struct.pack("!H", 0x0800)
    payload = b"\x45" + b"\x00" * 19
    net, etype = strip_link_layer(eth + payload, 1)
    assert etype == 0x0800
    assert net == payload


def test_non_ip_ethertype_is_ignored():
    eth = b"\xff" * 12 + struct.pack("!H", 0x0806) + b"payload"   # ARP
    net, etype = strip_link_layer(eth, 1)
    assert net is None and etype is None


def test_truncated_frame_does_not_raise():
    assert strip_link_layer(b"\x00\x01", 1) == (None, None)
    assert parse_ip_tcp(b"\x45\x00", 0x0800) is None
