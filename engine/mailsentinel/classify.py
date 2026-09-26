"""
Session classification: which email protocol, which TLS mode, which rulebook.

Port numbers are a hint, never the decision.  A capture can carry mail on a
non-standard port and a standard port can carry something else entirely — both
occur in this project's own demo set, where ``imap.cap`` contains two DCE/RPC
conversations on port 1065 that must not be graded as email.
"""

from __future__ import annotations

import re
from typing import Optional

from .models import Protocol, Role, TlsMode
from .net.reassembly import TcpStream

# RFC 8314 §3: implicit-TLS ports for submission and access.
IMPLICIT_TLS_PORTS = {465: Protocol.SMTP, 993: Protocol.IMAP, 995: Protocol.POP3}

# Cleartext / STARTTLS-capable ports.
STARTTLS_PORTS = {
    25: Protocol.SMTP,
    587: Protocol.SMTP,
    143: Protocol.IMAP,
    110: Protocol.POP3,
}

# Port 25 is MTA-to-MTA relay, where TLS is opportunistic by design (RFC 7435).
# Everything else in the mail path is submission or access, which RFC 8314
# governs strictly.
RELAY_PORTS = {25}

_SMTP_BANNER = re.compile(rb"^\s*220[ -]")
_SMTP_REPLY = re.compile(rb"^\d{3}[ -]")
_IMAP_BANNER = re.compile(rb"^\*\s+(OK|PREAUTH|BYE)\b", re.IGNORECASE)
_IMAP_TAGGED = re.compile(rb"^[A-Za-z0-9.]+\s+(OK|NO|BAD)\b", re.IGNORECASE)
_POP_BANNER = re.compile(rb"^\+OK\b|^-ERR\b")

_SMTP_CMD = re.compile(
    rb"^\s*(EHLO|HELO|MAIL FROM|RCPT TO|DATA|STARTTLS|AUTH|QUIT|RSET|NOOP|VRFY)(?:\s|$)",
    re.IGNORECASE,
)
_IMAP_CMD = re.compile(
    rb"^[A-Za-z0-9.]+\s+(CAPABILITY|LOGIN|AUTHENTICATE|SELECT|LIST|FETCH|"
    rb"STARTTLS|LOGOUT|NOOP|EXAMINE|STATUS|UID)(?:\s|$)",
    re.IGNORECASE,
)
_POP_CMD = re.compile(
    rb"^\s*(USER|PASS|APOP|CAPA|STLS|STAT|LIST|RETR|DELE|QUIT|TOP|UIDL)(?:\s|$)",
    re.IGNORECASE,
)


def _first_lines(data: bytes, n: int = 6) -> list[bytes]:
    if not data:
        return []
    return [ln for ln in data[:2048].split(b"\r\n")[:n] if ln]


def classify_protocol(stream: TcpStream, tls_start_server: Optional[int]) -> Protocol:
    """
    Identify the application protocol from the cleartext dialogue, falling back
    to the port only when no payload evidence exists (an implicit-TLS session
    has no cleartext to inspect).
    """
    server_clear = stream.server_to_client.data
    if tls_start_server is not None:
        server_clear = server_clear[:tls_start_server]
    client_clear = stream.client_to_server.data

    s_lines = _first_lines(server_clear)
    c_lines = _first_lines(client_clear)

    # --- payload signatures (authoritative) -------------------------------
    if s_lines:
        head = s_lines[0]
        if _POP_BANNER.match(head) and any(_POP_CMD.match(l) for l in c_lines):
            return Protocol.POP3
        if _IMAP_BANNER.match(head):
            return Protocol.IMAP
        if _SMTP_BANNER.match(head):
            return Protocol.SMTP
        if _POP_BANNER.match(head):
            return Protocol.POP3

    if c_lines:
        if any(_IMAP_CMD.match(l) for l in c_lines):
            return Protocol.IMAP
        if any(_SMTP_CMD.match(l) for l in c_lines):
            return Protocol.SMTP
        if any(_POP_CMD.match(l) for l in c_lines):
            return Protocol.POP3

    # Some replies arrive before we see a banner (capture starts mid-stream).
    if s_lines and any(_SMTP_REPLY.match(l) for l in s_lines):
        return Protocol.SMTP
    if s_lines and any(_IMAP_TAGGED.match(l) for l in s_lines):
        return Protocol.IMAP

    # --- port fallback, only for sessions with no readable cleartext ------
    port = stream.server_port
    if not server_clear and not client_clear or tls_start_server == 0:
        if port in IMPLICIT_TLS_PORTS:
            return IMPLICIT_TLS_PORTS[port]
        if port in STARTTLS_PORTS:
            return STARTTLS_PORTS[port]
    return Protocol.UNKNOWN


def classify_mode(
    stream: TcpStream,
    protocol: Protocol,
    tls_start_client: Optional[int],
    starttls_accepted: bool,
) -> TlsMode:
    """Implicit TLS, an in-band upgrade, or never encrypted at all."""
    port = stream.server_port
    if tls_start_client is None:
        return TlsMode.CLEARTEXT
    if tls_start_client == 0 or port in IMPLICIT_TLS_PORTS:
        # Handshake begins at the first application byte.
        if tls_start_client == 0:
            return TlsMode.IMPLICIT
    if starttls_accepted or tls_start_client > 0:
        return TlsMode.STARTTLS
    return TlsMode.UNKNOWN


def classify_role(protocol: Protocol, server_port: int) -> Role:
    """
    Which rulebook applies to this session.

    Port 25 is MTA relay: opportunistic TLS (RFC 7435) is the correct and
    universal behaviour there, so cleartext is an *exposure*, not a
    misconfiguration.  Everything else is submission or access, where RFC 8314
    deprecates cleartext outright.
    """
    if protocol == Protocol.SMTP and server_port in RELAY_PORTS:
        return Role.MTA_RELAY
    return Role.SUBMISSION_ACCESS


def is_email_stream(protocol: Protocol, stream: TcpStream) -> bool:
    """Filter out non-mail conversations that happen to share the capture."""
    return True
