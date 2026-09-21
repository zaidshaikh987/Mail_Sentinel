"""
TCP stream reassembly.

Scope note (be honest about this in the viva): this is *forensic* reassembly of
completed conversations from a file, not an IDS-grade reassembler defending
against evasion.  It handles the cases that occur in real captures —
out-of-order delivery, retransmission, overlap, sequence-number wraparound and
missing segments — but it deliberately does not model OS-specific overlap
resolution policies, which only matter when an attacker is actively trying to
desynchronise a monitor.

Every reassembled byte keeps a link back to the frame it came from, because
every finding the tool emits must cite the packets that produced it.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..pcap.layers import TcpSegment
from ..pcap.reader import RawPacket

SEQ_MOD = 1 << 32
# Relative offsets above this are interpreted as "before the base" (wrapped).
SEQ_BACKWARD_WINDOW = 1 << 31
# Refuse to allocate an absurd buffer from a corrupt sequence number.
MAX_STREAM_BYTES = 64 * 1024 * 1024


def seq_delta(a: int, b: int) -> int:
    """Signed distance a - b in TCP sequence space."""
    d = (a - b) % SEQ_MOD
    return d - SEQ_MOD if d >= SEQ_BACKWARD_WINDOW else d


@dataclass
class Chunk:
    offset: int
    data: bytes
    frame: int
    timestamp: float


@dataclass
class Direction:
    """One half of a conversation, reassembled."""
    base_seq: Optional[int] = None
    chunks: list[Chunk] = field(default_factory=list)
    data: bytes = b""
    # sorted list of (byte_offset, frame_number) for evidence lookup
    frame_index: list[tuple[int, int]] = field(default_factory=list)
    gaps: list[tuple[int, int]] = field(default_factory=list)
    bytes_seen: int = 0

    def frame_at(self, offset: int) -> Optional[int]:
        """Which frame carried the byte at this offset in the reassembled stream?"""
        if not self.frame_index:
            return None
        i = bisect.bisect_right(self.frame_index, (offset, 1 << 62)) - 1
        if i < 0:
            return self.frame_index[0][1]
        return self.frame_index[i][1]

    def frames_for_range(self, start: int, end: int) -> list[int]:
        """
        Frames carrying any byte in [start, end).

        A chunk starting at or before `start` still counts when it extends into
        the range, so the frame index is walked with its successor in hand.
        """
        if not self.frame_index:
            return []
        out: list[int] = []
        for i, (off, frame) in enumerate(self.frame_index):
            nxt = self.frame_index[i + 1][0] if i + 1 < len(self.frame_index) else len(self.data)
            if off < end and nxt > start:
                out.append(frame)
        return _dedupe(out)


def _dedupe(xs: Iterable[int]) -> list[int]:
    seen: set[int] = set()
    out: list[int] = []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


@dataclass
class TcpStream:
    stream_id: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_to_server: Direction = field(default_factory=Direction)
    server_to_client: Direction = field(default_factory=Direction)
    first_frame: int = 0
    last_frame: int = 0
    first_time: float = 0.0
    last_time: float = 0.0
    packets: int = 0
    saw_syn: bool = False
    saw_fin: bool = False
    saw_rst: bool = False
    # chronological interleaving: (direction, frame, timestamp, payload)
    events: list[tuple[str, int, float, bytes]] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_time - self.first_time)


class Reassembler:
    """Groups TCP segments into bidirectional streams and reassembles both halves."""

    def __init__(self) -> None:
        self._streams: dict[tuple, TcpStream] = {}
        self._order: list[tuple] = []
        # segments buffered per (key, direction) until finalise()
        self._pending: dict[tuple, list[tuple[int, bytes, int, float, bool]]] = {}

    @staticmethod
    def _key(seg: TcpSegment) -> tuple:
        a = (seg.src_ip, seg.src_port)
        b = (seg.dst_ip, seg.dst_port)
        return (a, b) if a <= b else (b, a)

    def add(self, pkt: RawPacket, seg: TcpSegment) -> None:
        key = self._key(seg)
        st = self._streams.get(key)
        if st is None:
            # Client is whoever sends the SYN without ACK.  Without a SYN we
            # fall back to "first talker is the client", which is right for the
            # overwhelming majority of captures that begin mid-conversation.
            if seg.syn and not seg.ack_flag:
                c_ip, c_port, s_ip, s_port = seg.src_ip, seg.src_port, seg.dst_ip, seg.dst_port
            elif seg.syn and seg.ack_flag:
                c_ip, c_port, s_ip, s_port = seg.dst_ip, seg.dst_port, seg.src_ip, seg.src_port
            else:
                c_ip, c_port, s_ip, s_port = seg.src_ip, seg.src_port, seg.dst_ip, seg.dst_port
            st = TcpStream(
                stream_id=len(self._order),
                client_ip=c_ip, client_port=c_port,
                server_ip=s_ip, server_port=s_port,
                first_frame=pkt.number, first_time=pkt.timestamp,
            )
            self._streams[key] = st
            self._order.append(key)
            self._pending[(key, "c")] = []
            self._pending[(key, "s")] = []

        to_server = (seg.src_ip, seg.src_port) == (st.client_ip, st.client_port)
        d = "c" if to_server else "s"

        st.packets += 1
        st.last_frame = max(st.last_frame, pkt.number)
        st.last_time = max(st.last_time, pkt.timestamp)
        if st.first_time == 0.0 or pkt.timestamp < st.first_time:
            st.first_time = pkt.timestamp
        st.first_frame = min(st.first_frame or pkt.number, pkt.number)
        if seg.syn:
            st.saw_syn = True
        if seg.fin:
            st.saw_fin = True
        if seg.rst:
            st.saw_rst = True

        direction = st.client_to_server if to_server else st.server_to_client
        # SYN consumes one sequence number; data starts at seq+1.
        if seg.syn and direction.base_seq is None:
            direction.base_seq = (seg.seq + 1) % SEQ_MOD

        if seg.payload:
            self._pending[(key, d)].append(
                (seg.seq, seg.payload, pkt.number, pkt.timestamp, seg.syn)
            )
            st.events.append(("client" if to_server else "server",
                              pkt.number, pkt.timestamp, seg.payload))

    def finalise(self) -> list[TcpStream]:
        for key in self._order:
            st = self._streams[key]
            for d, direction in (("c", st.client_to_server), ("s", st.server_to_client)):
                self._assemble(direction, self._pending[(key, d)])
            st.events.sort(key=lambda e: e[1])
        return [self._streams[k] for k in self._order]

    @staticmethod
    def _assemble(direction: Direction, segs: list[tuple[int, bytes, int, float, bool]]) -> None:
        if not segs:
            return
        if direction.base_seq is None:
            direction.base_seq = min(s[0] for s in segs)
        base = direction.base_seq

        placed: list[Chunk] = []
        for seq, payload, frame, ts, _syn in segs:
            off = seq_delta(seq, base)
            if off < 0:
                # Data before our base (capture started mid-stream): re-base.
                shift = -off
                base = (base - shift) % SEQ_MOD
                for c in placed:
                    c.offset += shift
                off = 0
            if off > MAX_STREAM_BYTES:
                continue
            placed.append(Chunk(offset=off, data=payload, frame=frame, timestamp=ts))

        direction.base_seq = base
        if not placed:
            return
        placed.sort(key=lambda c: (c.offset, c.frame))
        total = max(c.offset + len(c.data) for c in placed)
        if total > MAX_STREAM_BYTES:
            total = MAX_STREAM_BYTES

        buf = bytearray(total)
        filled = bytearray(total)  # 1 where a byte has been written
        index: list[tuple[int, int]] = []

        for c in placed:
            start = c.offset
            end = min(start + len(c.data), total)
            if start >= total:
                continue
            wrote_any = False
            for i in range(start, end):
                if not filled[i]:
                    buf[i] = c.data[i - start]
                    filled[i] = 1
                    wrote_any = True
            if wrote_any:
                index.append((start, c.frame))
            direction.bytes_seen += len(c.data)

        # Record holes so downstream stages know the stream is incomplete.
        gaps: list[tuple[int, int]] = []
        run_start = None
        for i in range(total):
            if not filled[i]:
                if run_start is None:
                    run_start = i
            elif run_start is not None:
                gaps.append((run_start, i))
                run_start = None
        if run_start is not None:
            gaps.append((run_start, total))

        direction.chunks = placed
        direction.data = bytes(buf)
        direction.frame_index = sorted(set(index))
        direction.gaps = gaps


def reassemble(packets: Iterable[tuple[RawPacket, TcpSegment]]) -> list[TcpStream]:
    r = Reassembler()
    for pkt, seg in packets:
        r.add(pkt, seg)
    return r.finalise()
