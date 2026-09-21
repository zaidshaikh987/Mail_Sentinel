"""
Policy-versus-reality detection from DNS carried in the same capture.

Captures of real mail traffic usually contain the DNS that preceded them.  That
lets the tool answer a question no other passive analyser asks and no online
scanner can ask offline:

    "This domain publishes an MTA-STS policy — so the operator's stated intent
     is that mail to it must be encrypted.  Why did this session to it fall
     back to cleartext?"

That is a policy violation established entirely from one file, with no network
access at all.

Limits, stated precisely (the precision is the point)
-----------------------------------------------------
* The MTA-STS *policy body* is fetched over HTTPS from
  ``mta-sts.<domain>/.well-known/mta-sts.txt`` and is therefore unreadable
  passively.  We can prove a policy is **published** (the ``_mta-sts`` TXT
  record carries the policy id) but not whether its mode is ``enforce`` or
  ``testing``.  Findings say exactly that.
* TLSA records prove DANE is published.  We do not attempt DNSSEC validation,
  so a TLSA record observed in cleartext DNS is evidence of intent, not proof
  of authenticity.
* MX and A/AAAA records are also collected, because they give real hostnames
  for servers on port 25 where no SNI is present.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..pcap.layers import UdpDatagram
from ..pcap.reader import RawPacket

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_TLSA = 52


@dataclass
class DnsPolicy:
    """Everything the capture's own DNS told us."""
    mta_sts_domains: set[str] = field(default_factory=set)
    tls_rpt_domains: set[str] = field(default_factory=set)
    tlsa_records: dict[str, list[str]] = field(default_factory=dict)   # domain -> records
    mx_hosts: dict[str, list[str]] = field(default_factory=dict)       # domain -> mx names
    host_to_ips: dict[str, list[str]] = field(default_factory=dict)
    ip_to_host: dict[str, str] = field(default_factory=dict)
    queries_seen: int = 0

    def policy_for_ip(self, ip: str) -> tuple[Optional[bool], list[str], Optional[bool]]:
        """
        Resolve an observed server IP back to a domain and report its policy.

        Returns (mta_sts_published, tlsa_records, tls_rpt_published); each is
        None/empty when the capture gave us nothing to say.
        """
        host = self.ip_to_host.get(ip)
        if not host:
            return None, [], None
        candidates = _parent_domains(host)
        mta = any(d in self.mta_sts_domains for d in candidates) or None
        rpt = any(d in self.tls_rpt_domains for d in candidates) or None
        tlsa: list[str] = []
        for d, recs in self.tlsa_records.items():
            if any(d.endswith(c) for c in candidates):
                tlsa.extend(recs)
        return mta, tlsa, rpt


def _parent_domains(host: str) -> list[str]:
    parts = host.lower().rstrip(".").split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def _read_name(data: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    """Decode a DNS name, following compression pointers."""
    labels: list[str] = []
    jumped = False
    end = pos
    guard = 0
    while pos < len(data) and guard < 128:
        guard += 1
        ln = data[pos]
        if ln == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        if ln & 0xC0 == 0xC0:
            if pos + 2 > len(data) or depth > 8:
                return ".".join(labels), pos + 2
            ptr = struct.unpack("!H", data[pos:pos + 2])[0] & 0x3FFF
            if not jumped:
                end = pos + 2
            jumped = True
            pos = ptr
            continue
        pos += 1
        labels.append(data[pos:pos + ln].decode("ascii", "replace"))
        pos += ln
        if not jumped:
            end = pos
    return ".".join(labels), end


def parse_dns(payload: bytes) -> Optional[dict]:
    """Minimal DNS message parser — enough for the record types above."""
    try:
        if len(payload) < 12:
            return None
        tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
        pos = 12
        questions = []
        for _ in range(min(qd, 16)):
            name, pos = _read_name(payload, pos)
            if pos + 4 > len(payload):
                return None
            qtype, qclass = struct.unpack("!HH", payload[pos:pos + 4])
            pos += 4
            questions.append((name, qtype))

        answers = []
        for _ in range(min(an + ns + ar, 64)):
            if pos >= len(payload):
                break
            name, pos = _read_name(payload, pos)
            if pos + 10 > len(payload):
                break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", payload[pos:pos + 10])
            pos += 10
            rdata = payload[pos:pos + rdlen]
            answers.append((name, rtype, rdata, pos))
            pos += rdlen
        return {"id": tid, "flags": flags, "questions": questions,
                "answers": answers, "raw": payload}
    except (struct.error, IndexError):
        return None


def collect(datagrams: Iterable[tuple[RawPacket, UdpDatagram]]) -> DnsPolicy:
    policy = DnsPolicy()
    for _pkt, dg in datagrams:
        if 53 not in (dg.src_port, dg.dst_port):
            continue
        msg = parse_dns(dg.payload)
        if not msg:
            continue
        policy.queries_seen += 1
        raw = msg["raw"]

        for qname, _qtype in msg["questions"]:
            low = qname.lower()
            if low.startswith("_mta-sts."):
                policy.mta_sts_domains.add(low[len("_mta-sts."):])
            elif low.startswith("_smtp._tls."):
                policy.tls_rpt_domains.add(low[len("_smtp._tls."):])

        # CNAME chains mean the owner name of an A record is often not the name
        # that was looked up: `mail.example.com CNAME example.com A 1.2.3.4`
        # leaves the address owned by `example.com`, while the useful label for
        # an asset is the name the client actually resolved.  Collect aliases
        # first, then prefer the queried name when labelling an address.
        cnames: dict[str, str] = {}
        for name, rtype, rdata, rpos in msg["answers"]:
            if rtype == TYPE_CNAME:
                target, _ = _read_name(raw, rpos)
                cnames[name.lower().rstrip(".")] = target.lower().rstrip(".")
        queried = msg["questions"][0][0].lower().rstrip(".") if msg["questions"] else None

        for name, rtype, rdata, rpos in msg["answers"]:
            low = name.lower().rstrip(".")
            if rtype == TYPE_TXT and rdata:
                txt = _decode_txt(rdata)
                if low.startswith("_mta-sts.") and "v=STSv1" in txt:
                    policy.mta_sts_domains.add(low[len("_mta-sts."):])
                elif low.startswith("_smtp._tls.") and "v=TLSRPTv1" in txt:
                    policy.tls_rpt_domains.add(low[len("_smtp._tls."):])
            elif rtype == TYPE_TLSA and len(rdata) >= 3:
                usage, selector, mtype = rdata[0], rdata[1], rdata[2]
                digest = rdata[3:].hex()
                policy.tlsa_records.setdefault(low, []).append(
                    f"{usage} {selector} {mtype} {digest[:32]}…"
                )
            elif rtype == TYPE_MX and len(rdata) >= 3:
                host, _ = _read_name(raw, rpos + 2)
                domain = low
                policy.mx_hosts.setdefault(domain, []).append(host.lower().rstrip("."))
            elif rtype in (TYPE_A, TYPE_AAAA) and len(rdata) in (4, 16):
                if rtype == TYPE_A:
                    ip = ".".join(str(b) for b in rdata)
                else:
                    from ..pcap.layers import _ipv6_str
                    ip = _ipv6_str(rdata)
                policy.host_to_ips.setdefault(low, []).append(ip)
                # Prefer the name the client asked for when it aliases to this
                # record's owner; otherwise fall back to the owner name.
                label = low
                if queried and _resolves_to(queried, low, cnames):
                    label = queried
                policy.ip_to_host[ip] = label
    return policy


def _resolves_to(start: str, target: str, cnames: dict[str, str], depth: int = 6) -> bool:
    """Does following the CNAME chain from `start` reach `target`?"""
    seen = start
    for _ in range(depth):
        if seen == target:
            return True
        nxt = cnames.get(seen)
        if nxt is None:
            return False
        seen = nxt
    return False


def _decode_txt(rdata: bytes) -> str:
    out: list[str] = []
    pos = 0
    while pos < len(rdata):
        ln = rdata[pos]
        pos += 1
        out.append(rdata[pos:pos + ln].decode("utf-8", "replace"))
        pos += ln
    return "".join(out)
