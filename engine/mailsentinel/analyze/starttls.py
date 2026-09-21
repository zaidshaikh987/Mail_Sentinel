"""
The cleartext phase: capability advertisement, the STARTTLS upgrade, downgrade
evidence, and credentials exposed before encryption.

This is the module that has no equivalent in any online TLS grader, because an
active scanner connects and negotiates its own session — it never sees the
conversation an attacker interfered with.  Everything here is derived from the
plaintext bytes that precede the first TLS record.

Downgrade evidence we look for
------------------------------
1. A capability token of the right length in the right place that is not the
   keyword — the equal-length substitution (``STARTTLS`` -> ``XXXXXXXX``)
   measured in the wild by Durumeric et al., IMC 2015.
2. A server that advertised STARTTLS where the client never issued it.
3. A STARTTLS command that was issued but never produced a handshake.
4. Authentication credentials sent on a channel that never became encrypted.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from ..models import AuthExposure, Protocol

# Keywords by protocol, and the token length an equal-length substitution
# would have to match.
STARTTLS_KEYWORD = {
    Protocol.SMTP: "STARTTLS",
    Protocol.IMAP: "STARTTLS",
    Protocol.POP3: "STLS",
}

# A capability token that is the same length as the keyword but is not a
# plausible capability name.
#
# The character class here matters more than it looks.  Real capability
# keywords are richer than plain alphanumerics: ESMTP has `8BITMIME` and
# `SMTPUTF8`, IMAP has `LITERAL+`, `AUTH=NTLM`, `LOGIN-REFERRALS` and
# `IMAP4rev1`.  An early version of this rule flagged `LITERAL+` — a perfectly
# ordinary IMAP capability that happens to be exactly eight characters, the
# length of STARTTLS — as a downgrade attack.  A false positive of that kind is
# far more damaging than a missed detection, so the shape test is permissive and
# the real signal comes from `_REPEATED_CHAR` and the known-variant list below.
_REPEATED_CHAR = re.compile(r"^(.)\1{2,}$")
_PLAUSIBLE_KEYWORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-_=+./*]*$")

# Substitution variants directly observed in the wild by Durumeric et al.,
# "Neither Snow Nor Rain Nor MITM", IMC 2015, Table 11: of responding hosts,
# 617,093 returned "STARTTLS" mangled, 5,750 returned "XXXXXXXX" and 786
# responded with "STAR" or "TTLS".
KNOWN_STRIP_VARIANTS = {"XXXXXXXX", "STAR", "TTLS", "XXXX"}

_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


@dataclass
class DialogueLine:
    direction: str      # "client" | "server"
    text: str
    frame: Optional[int]
    offset: int


@dataclass
class StarttlsResult:
    banner: Optional[str] = None
    capability_line: Optional[str] = None
    capabilities: list[str] = field(default_factory=list)
    offered: bool = False
    requested: bool = False
    accepted: bool = False
    injection_suspected: bool = False
    mangled: bool = False
    mangled_token: Optional[str] = None
    request_refused: bool = False
    auth: Optional[AuthExposure] = None
    transcript: list[str] = field(default_factory=list)
    evidence_frames: list[int] = field(default_factory=list)


def build_dialogue(
    client_clear: bytes,
    server_clear: bytes,
    client_dir,
    server_dir,
    max_lines_per_direction: int = 600,
) -> list[DialogueLine]:
    """
    Split both cleartext halves into lines, keeping the frame each line came
    from so findings can cite packets.  Ordering is per-direction; the STARTTLS
    state machine below only needs relative order within a direction plus the
    fact that a server reply follows the command it answers.

    The line budget is applied **per direction**.  It was originally shared,
    and a 14 KB message body on the client side consumed the whole allowance
    before the server's ``250-STARTTLS`` line was ever reached — so a server
    that did advertise STARTTLS was reported as not advertising it.  Client
    payload is unbounded; the control dialogue must never compete with it.
    """
    lines: list[DialogueLine] = []
    for direction, blob, dirobj in (
        ("client", client_clear, client_dir),
        ("server", server_clear, server_dir),
    ):
        offset = 0
        count = 0
        for raw in blob.split(b"\r\n"):
            ln = raw.decode("utf-8", "replace")
            if ln.strip():
                frame = dirobj.frame_at(offset) if dirobj else None
                lines.append(DialogueLine(direction, ln, frame, offset))
                count += 1
            offset += len(raw) + 2
            if count >= max_lines_per_direction:
                break
    return lines


# --------------------------------------------------------------------------
# capability extraction
# --------------------------------------------------------------------------

def _smtp_capabilities(server_lines: list[DialogueLine]) -> tuple[list[str], Optional[str], list[int]]:
    """
    EHLO response: a run of ``250-KEYWORD`` lines closed by ``250 KEYWORD``.

    Per RFC 5321 §4.1.1.1 the *first* line of the reply is the server's domain
    greeting, not a capability keyword, so it is recorded but not counted as
    one — otherwise ``250-mail.example.com Hello client`` would enter the
    capability list as the token ``MAIL.EXAMPLE.COM``.
    """
    caps: list[str] = []
    frames: list[int] = []
    raw: list[str] = []
    started = False
    first = True
    for ln in server_lines:
        t = ln.text
        if re.match(r"^250[ -]", t):
            started = True
            body = t[4:].strip()
            raw.append(t)
            if ln.frame is not None:
                frames.append(ln.frame)
            if body and not first:
                caps.append(body.split()[0].upper())
            first = False
            if t.startswith("250 "):
                break
        elif started:
            break
    return caps, ("\n".join(raw) if raw else None), frames


def _imap_capabilities(server_lines: list[DialogueLine]) -> tuple[list[str], Optional[str], list[int]]:
    """`* CAPABILITY ...` untagged response, or a `[CAPABILITY ...]` response code."""
    for ln in server_lines:
        t = ln.text
        m = re.match(r"^\*\s+CAPABILITY\s+(.*)$", t, re.IGNORECASE)
        if m:
            return [c.upper() for c in m.group(1).split()], t, [ln.frame] if ln.frame else []
        m = re.search(r"\[CAPABILITY\s+([^\]]*)\]", t, re.IGNORECASE)
        if m:
            return [c.upper() for c in m.group(1).split()], t, [ln.frame] if ln.frame else []
    return [], None, []


def _pop_capabilities(server_lines: list[DialogueLine]) -> tuple[list[str], Optional[str], list[int]]:
    """CAPA response: `+OK` then one capability per line until a lone `.`."""
    caps: list[str] = []
    frames: list[int] = []
    raw: list[str] = []
    collecting = False
    for ln in server_lines:
        t = ln.text.strip()
        if not collecting and t.upper().startswith("+OK") and len(raw) == 0:
            # Only start collecting if a CAPA listing follows; the greeting also
            # begins with +OK, so we require subsequent non-status lines.
            collecting = True
            raw.append(t)
            if ln.frame is not None:
                frames.append(ln.frame)
            continue
        if collecting:
            if t == ".":
                break
            if t.startswith("+OK") or t.startswith("-ERR"):
                break
            raw.append(t)
            caps.append(t.split()[0].upper() if t.split() else "")
            if ln.frame is not None:
                frames.append(ln.frame)
    caps = [c for c in caps if c]
    return caps, ("\n".join(raw) if len(raw) > 1 else None), frames


# --------------------------------------------------------------------------
# downgrade detection
# --------------------------------------------------------------------------

def detect_mangling(capabilities: list[str], protocol: Protocol) -> tuple[bool, Optional[str]]:
    """
    Look for an equal-length substitution of the STARTTLS keyword.

    The attack preserves packet length, so the replacement token has exactly the
    keyword's length.  We flag a token of that length which is implausible as a
    real capability name: a repeated single character (``XXXXXXXX``), or a
    string that is not a valid keyword shape at all.

    Deliberately conservative — a legitimate 8-character capability such as
    ``PIPELINING`` (10) or ``SMTPUTF8`` (8) must not trip this.  ``SMTPUTF8``
    passes the plausibility test, so only genuine garbage is reported.
    """
    keyword = STARTTLS_KEYWORD.get(protocol)
    if not keyword or keyword in capabilities:
        return False, None

    # Variants measured in the wild take priority and are reported by name.
    for token in capabilities:
        if token.upper() in KNOWN_STRIP_VARIANTS:
            return True, token

    for token in capabilities:
        if len(token) != len(keyword) or token == keyword:
            continue
        if _REPEATED_CHAR.match(token):
            return True, token
        if not _PLAUSIBLE_KEYWORD.match(token):
            return True, token
    return False, None


# --------------------------------------------------------------------------
# cleartext credential exposure
# --------------------------------------------------------------------------

def _redact(user: Optional[str]) -> Optional[str]:
    if not user:
        return None
    if "@" in user:
        local, _, domain = user.partition("@")
        keep = local[:1]
        return f"{keep}{'*' * max(1, len(local) - 1)}@{domain}"
    return f"{user[:1]}{'*' * max(1, len(user) - 1)}"


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def detect_cleartext_auth(
    lines: list[DialogueLine], protocol: Protocol
) -> Optional[AuthExposure]:
    """
    Extract evidence of credentials sent before encryption.

    The password is never retained — only a SHA-256, so an investigator can
    correlate reuse across sessions without the report becoming a credential
    leak of its own.
    """
    client = [l for l in lines if l.direction == "client"]

    if protocol == Protocol.SMTP:
        for i, ln in enumerate(client):
            t = ln.text.strip()
            m = re.match(r"^AUTH\s+PLAIN\s*(\S+)?$", t, re.IGNORECASE)
            if m:
                blob = m.group(1)
                if not blob and i + 1 < len(client):
                    blob = client[i + 1].text.strip()
                user = None
                secret = blob or ""
                if blob and _B64.match(blob):
                    try:
                        dec = base64.b64decode(blob + "=" * (-len(blob) % 4))
                        parts = dec.split(b"\x00")
                        if len(parts) >= 3:
                            user = parts[1].decode("utf-8", "replace")
                            secret = parts[2].decode("utf-8", "replace")
                    except Exception:
                        pass
                return AuthExposure("PLAIN", _redact(user), True, _sha256(secret), ln.frame)
            if re.match(r"^AUTH\s+LOGIN\s*$", t, re.IGNORECASE):
                user = None
                secret = ""
                # The next two client lines are base64 username then password.
                if i + 1 < len(client) and _B64.match(client[i + 1].text.strip()):
                    try:
                        b = client[i + 1].text.strip()
                        user = base64.b64decode(b + "=" * (-len(b) % 4)).decode("utf-8", "replace")
                    except Exception:
                        pass
                if i + 2 < len(client):
                    secret = client[i + 2].text.strip()
                return AuthExposure("LOGIN", _redact(user), True, _sha256(secret), ln.frame)

    elif protocol == Protocol.IMAP:
        for i, ln in enumerate(client):
            t = ln.text.strip()
            m = re.match(
                r'^\S+\s+LOGIN\s+"?([^"\s]+)"?\s+"?([^"]*)"?\s*$', t, re.IGNORECASE
            )
            if m:
                return AuthExposure(
                    "LOGIN", _redact(m.group(1)), True, _sha256(m.group(2)), ln.frame
                )
            if re.match(r"^\S+\s+AUTHENTICATE\s+PLAIN\s*$", t, re.IGNORECASE):
                secret = client[i + 1].text.strip() if i + 1 < len(client) else ""
                user = None
                if secret and _B64.match(secret):
                    try:
                        dec = base64.b64decode(secret + "=" * (-len(secret) % 4))
                        parts = dec.split(b"\x00")
                        if len(parts) >= 3:
                            user = parts[1].decode("utf-8", "replace")
                            secret = parts[2].decode("utf-8", "replace")
                    except Exception:
                        pass
                return AuthExposure("PLAIN", _redact(user), True, _sha256(secret), ln.frame)

    elif protocol == Protocol.POP3:
        user = None
        user_frame = None
        for ln in client:
            t = ln.text.strip()
            m = re.match(r"^USER\s+(\S+)", t, re.IGNORECASE)
            if m:
                user, user_frame = m.group(1), ln.frame
            m = re.match(r"^PASS\s+(.*)$", t, re.IGNORECASE)
            if m:
                return AuthExposure(
                    "USER/PASS", _redact(user), True, _sha256(m.group(1)), user_frame or ln.frame
                )
            m = re.match(r"^APOP\s+(\S+)\s+(\S+)", t, re.IGNORECASE)
            if m:
                # APOP is a digest, not a plaintext secret, but it is still a
                # credential exchanged without confidentiality.
                return AuthExposure(
                    "APOP", _redact(m.group(1)), True, _sha256(m.group(2)), ln.frame
                )
    return None


# --------------------------------------------------------------------------
# main entry point
# --------------------------------------------------------------------------

def analyse(
    protocol: Protocol,
    lines: list[DialogueLine],
    tls_started: bool,
    client_dir: Optional[Any] = None,
) -> StarttlsResult:
    res = StarttlsResult()
    server_lines = [l for l in lines if l.direction == "server"]
    client_lines = [l for l in lines if l.direction == "client"]

    if server_lines:
        res.banner = server_lines[0].text[:300]

    if protocol == Protocol.SMTP:
        caps, raw, frames = _smtp_capabilities(server_lines)
    elif protocol == Protocol.IMAP:
        caps, raw, frames = _imap_capabilities(server_lines)
    elif protocol == Protocol.POP3:
        caps, raw, frames = _pop_capabilities(server_lines)
    else:
        caps, raw, frames = [], None, []

    res.capabilities = caps
    res.capability_line = raw
    res.evidence_frames = frames

    keyword = STARTTLS_KEYWORD.get(protocol)
    if keyword:
        res.offered = keyword in caps
        res.mangled, res.mangled_token = detect_mangling(caps, protocol)

        # Did the client ask?
        cmd = re.compile(rf"^(?:\S+\s+)?{keyword}\s*$", re.IGNORECASE)
        for ln in client_lines:
            if cmd.match(ln.text.strip()):
                res.requested = True
                if ln.frame is not None and ln.frame not in res.evidence_frames:
                    res.evidence_frames.append(ln.frame)
                
                # Check for pipelined command injection (USENIX Sec'21)
                if client_dir:
                    cmd_end_offset = ln.offset + len(ln.text.encode('utf-8')) + 2
                    pos = 0
                    for chunk in getattr(client_dir, "chunks", []):
                        chunk_end = pos + len(chunk.data)
                        if pos < cmd_end_offset <= chunk_end:
                            extra = chunk.data[cmd_end_offset - pos:]
                            if extra.strip():
                                res.injection_suspected = True
                        pos = chunk_end
                
                break

        # Did the server agree, and did a handshake actually follow?
        if res.requested:
            ok = re.compile(r"^(220\b|\+OK\b|\S+\s+OK\b)", re.IGNORECASE)
            bad = re.compile(r"^(4\d\d\b|5\d\d\b|-ERR\b|\S+\s+(NO|BAD)\b)", re.IGNORECASE)
            for ln in server_lines:
                if bad.match(ln.text.strip()) and keyword.lower() in ln.text.lower():
                    res.request_refused = True
            res.accepted = tls_started and not res.request_refused

    res.auth = detect_cleartext_auth(lines, protocol)
    res.transcript = redact_transcript(lines, protocol)
    return res


def redact_transcript(
    lines: list[DialogueLine], protocol: Protocol, limit: int = 60
) -> list[str]:
    """
    Build the display transcript with credential material masked.

    The report exists to prove that credentials were exposed — it must not
    become a second copy of them.  ``AuthExposure`` already stores only a
    SHA-256, but the raw dialogue carries the base64 blobs verbatim, so the
    transcript needs its own redaction pass or the deliverable leaks the
    password it is warning about.
    """
    secret_offsets: set[int] = set()
    client = [l for l in lines if l.direction == "client"]

    for i, ln in enumerate(client):
        t = ln.text.strip()
        if protocol == Protocol.SMTP:
            if re.match(r"^AUTH\s+LOGIN\s*$", t, re.IGNORECASE):
                # next two client lines are base64 username then password
                for j in (i + 1, i + 2):
                    if j < len(client):
                        secret_offsets.add(id(client[j]))
            elif re.match(r"^AUTH\s+PLAIN\b", t, re.IGNORECASE):
                secret_offsets.add(id(ln))
                if i + 1 < len(client) and _B64.match(client[i + 1].text.strip()):
                    secret_offsets.add(id(client[i + 1]))
        elif protocol == Protocol.IMAP:
            if re.match(r"^\S+\s+LOGIN\s+", t, re.IGNORECASE):
                secret_offsets.add(id(ln))
            elif re.match(r"^\S+\s+AUTHENTICATE\b", t, re.IGNORECASE):
                if i + 1 < len(client):
                    secret_offsets.add(id(client[i + 1]))
        elif protocol == Protocol.POP3:
            if re.match(r"^(PASS|APOP)\b", t, re.IGNORECASE):
                secret_offsets.add(id(ln))

    out: list[str] = []
    for ln in lines[:limit]:
        prefix = "C" if ln.direction == "client" else "S"
        text = ln.text
        if id(ln) in secret_offsets:
            text = _mask_line(text, protocol)
        out.append(f"{prefix}: {text}")
    return out


def _mask_line(text: str, protocol: Protocol) -> str:
    """Keep the command visible, replace the credential with a marker."""
    stripped = text.strip()
    m = re.match(r"^(AUTH\s+PLAIN)\s+\S+$", stripped, re.IGNORECASE)
    if m:
        return f"{m.group(1)} <redacted>"
    m = re.match(r"^(\S+\s+LOGIN)\s+.*$", stripped, re.IGNORECASE)
    if m and protocol == Protocol.IMAP:
        return f"{m.group(1)} <redacted> <redacted>"
    m = re.match(r"^(PASS|APOP)\b.*$", stripped, re.IGNORECASE)
    if m:
        return f"{m.group(1)} <redacted>"
    return "<redacted credential>"
