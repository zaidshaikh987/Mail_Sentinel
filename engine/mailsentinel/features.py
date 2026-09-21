"""
The per-session feature vector: 18 core features plus 8 auxiliary.

Two design rules, both load-bearing:

1. **Missingness is encoded, never imputed.**  A value of ``-1`` means "a
   passive observer could not see this", and that is one of the most
   informative signals available.  Imputing a plausible value would destroy it.

2. **Seven of the eighteen vanish on TLS 1.3.**  Features 9–15 all derive from
   the certificate, which RFC 8446 encrypts.  That is precisely the argument
   for having a model at all: the rule engine must abstain on those sessions,
   while a model trained across configurations can still estimate posture from
   the eleven features that survive.
"""

from __future__ import annotations

from .analyze.ciphers import properties
from .models import CertVisibility, Protocol, Session

MISSING = -1.0

# Ordered — the model depends on this ordering being stable.
FEATURE_NAMES = [
    # -- visible on every session, TLS 1.3 included -----------------------
    "tls_version",              # 1
    "cipher_iana_recommended",  # 2
    "cipher_key_bits",          # 3
    "cipher_mode",              # 4
    "kex_family",               # 5
    "kex_bits_equiv",           # 6
    "forward_secrecy",          # 7
    "cert_visible",             # 8   <- the missingness flag itself
    # -- certificate-derived: unavailable on TLS 1.3 ----------------------
    "cert_key_bits",            # 9
    "cert_key_algo",            # 10
    "cert_sig_hash",            # 11
    "cert_days_to_expiry",      # 12
    "cert_self_signed",         # 13
    "chain_valid",              # 14
    "name_match",               # 15
    # -- pre-TLS phase, always visible ------------------------------------
    "starttls_offered",         # 16
    "starttls_completed",       # 17
    "cleartext_auth",           # 18
    # -- auxiliary ---------------------------------------------------------
    "offered_cipher_count",     # 19
    "extension_count",          # 20
    "alpn_present",             # 21
    "session_resumed",          # 22
    "duration_seconds",         # 23
    "bytes_ratio",              # 24
    "protocol",                 # 25
    "role_is_relay",            # 26
]

CORE_FEATURE_COUNT = 18

_TLS_VERSION_CODE = {"SSL2.0": 2.0, "SSL3.0": 3.0, "1.0": 10.0, "1.1": 11.0,
                     "1.2": 12.0, "1.3": 13.0}
_CIPHER_MODE_CODE = {"GCM": 4.0, "CCM": 4.0, "CCM_8": 4.0, "POLY1305": 4.0,
                     "CBC": 2.0, "STREAM": 1.0, "NULL": 0.0}
_KEX_CODE = {"TLS13": 5.0, "ECDHE": 4.0, "DHE": 3.0, "ECDH": 2.0, "DH": 2.0,
             "RSA": 1.0, "PSK": 1.0}
_KEY_ALGO_CODE = {"EC": 3.0, "Ed25519": 3.0, "Ed448": 3.0, "RSA": 2.0, "DSA": 1.0}
_SIG_HASH_CODE = {"sha512": 4.0, "sha384": 4.0, "sha256": 3.0, "sha224": 2.0,
                  "sha1": 1.0, "md5": 0.0, "md2": 0.0}
_PROTOCOL_CODE = {Protocol.SMTP: 1.0, Protocol.IMAP: 2.0, Protocol.POP3: 3.0,
                  Protocol.UNKNOWN: 0.0}


def extract(s: Session) -> dict[str, float]:
    props = properties(s.cipher_suite_id) if s.cipher_suite_id is not None else None
    leaf = s.chain[0] if s.chain else None
    cert_visible = s.cert_visibility == CertVisibility.OBSERVED

    def cert(value, transform=lambda v: float(v)):
        """Certificate features are MISSING whenever the cert was not observable."""
        if not cert_visible or value is None:
            return MISSING
        return transform(value)

    kex_bits = s.kex_bits or (leaf.key_bits if leaf and leaf.key_bits else None)

    f: dict[str, float] = {
        "tls_version": _TLS_VERSION_CODE.get(s.tls_version or "", 0.0),
        "cipher_iana_recommended": 1.0 if (props and props.recommended) else 0.0,
        "cipher_key_bits": float(props.key_bits) if props else 0.0,
        "cipher_mode": _CIPHER_MODE_CODE.get(props.mode, MISSING) if props else 0.0,
        "kex_family": _KEX_CODE.get(props.kex, 0.0) if props else 0.0,
        "kex_bits_equiv": float(kex_bits) if kex_bits else 0.0,
        "forward_secrecy": 1.0 if s.forward_secrecy else 0.0,
        "cert_visible": 1.0 if cert_visible else 0.0,

        "cert_key_bits": cert(leaf.key_bits if leaf else None),
        "cert_key_algo": cert(leaf.key_algorithm if leaf else None,
                              lambda v: _KEY_ALGO_CODE.get(v, 0.0)),
        "cert_sig_hash": cert(leaf.signature_hash if leaf else None,
                              lambda v: _SIG_HASH_CODE.get(str(v).lower(), 0.0)),
        "cert_days_to_expiry": cert(leaf.days_to_expiry_at_capture if leaf else None),
        "cert_self_signed": cert(leaf.self_signed if leaf else None,
                                 lambda v: 1.0 if v else 0.0),
        "chain_valid": cert(s.chain_valid, lambda v: 1.0 if v else 0.0),
        "name_match": cert(s.name_match, lambda v: 1.0 if v else 0.0),

        "starttls_offered": 1.0 if s.starttls_offered else 0.0,
        "starttls_completed": 1.0 if s.starttls_accepted else 0.0,
        "cleartext_auth": 1.0 if s.cleartext_auth else 0.0,

        "offered_cipher_count": float(len(s.offered_ciphers)),
        "extension_count": float(len(s.extensions)),
        "alpn_present": 1.0 if s.alpn else 0.0,
        "session_resumed": 1.0 if s.resumed else 0.0,
        "duration_seconds": round(float(s.duration_seconds), 3),
        "bytes_ratio": round(
            (s.bytes_client_to_server / s.bytes_server_to_client)
            if s.bytes_server_to_client else 0.0, 4
        ),
        "protocol": _PROTOCOL_CODE.get(s.protocol, 0.0),
        "role_is_relay": 1.0 if s.role.value == "mta_relay" else 0.0,
    }
    return f


def to_row(features: dict[str, float]) -> list[float]:
    """Feature dict -> ordered vector, for the model."""
    return [float(features.get(name, MISSING)) for name in FEATURE_NAMES]
