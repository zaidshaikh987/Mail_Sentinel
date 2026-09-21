"""
Cipher-suite properties, derived from the suite name.

TLS suite names are fully self-describing —
``TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`` states its key exchange, its
authentication, its bulk cipher, its key size and its mode.  Storing only the
IANA id->name mapping and deriving the rest keeps the vendored knowledge base
small and removes a whole class of hand-transcription errors.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

from ..kb import CIPHER_SUITES_FILE, kb_path

# Bulk ciphers considered broken or forbidden outright.
BROKEN_CIPHERS = {"RC4", "DES", "DES40", "RC2", "IDEA", "NULL"}
# 64-bit block ciphers — Sweet32 (CVE-2016-2183).
SMALL_BLOCK_CIPHERS = {"3DES", "DES", "IDEA", "RC2"}
AEAD_MODES = {"GCM", "CCM", "CCM_8", "POLY1305"}
FORWARD_SECRET_KEX = {"ECDHE", "DHE", "ECDHE_PSK", "DHE_PSK"}


@dataclass(frozen=True)
class CipherProperties:
    id: int
    name: str
    kex: str                  # ECDHE | DHE | RSA | ECDH | DH | PSK | ANON | TLS13
    auth: str                 # RSA | ECDSA | DSS | PSK | ANON | TLS13
    bulk: str                 # AES | CHACHA20 | 3DES | RC4 | CAMELLIA | NULL ...
    key_bits: int             # symmetric key size
    mode: str                 # GCM | CBC | CCM | POLY1305 | STREAM | NULL
    mac: str                  # SHA256 | SHA | MD5 ...
    forward_secrecy: bool
    anonymous: bool
    export_grade: bool
    aead: bool
    broken: bool
    small_block: bool
    recommended: bool

    @property
    def is_null(self) -> bool:
        return self.bulk == "NULL" or self.key_bits == 0


@lru_cache(maxsize=1)
def _registry() -> tuple[dict[int, str], set[int]]:
    with open(kb_path(CIPHER_SUITES_FILE), "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    suites = {int(k, 16): v for k, v in raw["suites"].items()}
    recommended = {int(k, 16) for k in raw.get("iana_recommended", [])}
    return suites, recommended


def suite_name(suite_id: int) -> str:
    suites, _ = _registry()
    return suites.get(suite_id, f"UNKNOWN_CIPHER_SUITE_0x{suite_id:04X}")


_KEY_BITS = {
    "AES_128": 128, "AES_256": 256, "AES_192": 192,
    "CAMELLIA_128": 128, "CAMELLIA_256": 256,
    "ARIA_128": 128, "ARIA_256": 256,
    "CHACHA20": 256, "SEED": 128, "IDEA": 128,
    "3DES_EDE": 112,          # effective strength of 3DES, not its 168-bit key
    "DES40": 40, "RC4_40": 40, "RC2_CBC_40": 40,
    "RC4_128": 128, "DES": 56, "NULL": 0,
}


def _extract_key_bits(name: str) -> tuple[str, int]:
    for token, bits in _KEY_BITS.items():
        if f"_{token}_" in f"_{name}_" or f"WITH_{token}" in name:
            bulk = token.split("_")[0]
            return bulk, bits
    m = re.search(r"WITH_([A-Z0-9]+)_(\d{2,3})", name)
    if m:
        return m.group(1), int(m.group(2))
    if "WITH_NULL" in name or name.endswith("_NULL_NULL"):
        return "NULL", 0
    return "UNKNOWN", 0


def _extract_mode(name: str) -> str:
    if "CHACHA20_POLY1305" in name:
        return "POLY1305"
    for mode in ("GCM", "CCM_8", "CCM", "CBC"):
        if f"_{mode}_" in name or name.endswith(f"_{mode}"):
            return mode
    if "TLS_AES" in name or "TLS_CHACHA20" in name:
        return "GCM"
    if "RC4" in name:
        return "STREAM"
    if "NULL" in name:
        return "NULL"
    return "UNKNOWN"


def _extract_kex_auth(name: str) -> tuple[str, str]:
    # TLS 1.3 suites carry no key-exchange in the name; it is negotiated
    # separately and is always (EC)DHE, hence always forward secret.
    if re.match(r"^TLS_(AES|CHACHA20)", name):
        return "TLS13", "TLS13"
    body = name[len("TLS_"):] if name.startswith("TLS_") else name
    body = body.split("_WITH_")[0]
    if "anon" in body or "ANON" in body:
        return ("ECDH" if body.startswith("ECDH") else "DH"), "ANON"
    for kex in ("ECDHE_PSK", "DHE_PSK", "ECDHE", "ECDH", "DHE", "DH", "PSK", "SRP", "KRB5"):
        if body.startswith(kex):
            rest = body[len(kex):].strip("_")
            auth = rest if rest else ("PSK" if "PSK" in kex else "RSA")
            if kex in ("ECDHE", "ECDH") and not rest:
                auth = "ECDSA"
            if kex in ("DH", "DHE") and not rest:
                auth = "RSA"
            return kex, auth or "RSA"
    return "RSA", "RSA"


def _extract_mac(name: str) -> str:
    for mac in ("SHA384", "SHA256", "SHA", "MD5"):
        if name.endswith(f"_{mac}"):
            return mac
    return "AEAD"


@lru_cache(maxsize=1024)
def properties(suite_id: int) -> CipherProperties:
    name = suite_name(suite_id)
    _, recommended = _registry()
    kex, auth = _extract_kex_auth(name)
    bulk, bits = _extract_key_bits(name)
    mode = _extract_mode(name)
    mac = _extract_mac(name)
    anonymous = auth == "ANON"
    export_grade = "EXPORT" in name or bits in (40, 56)
    aead = mode in AEAD_MODES
    fs = kex in FORWARD_SECRET_KEX or kex == "TLS13"
    broken = bulk in BROKEN_CIPHERS or anonymous or export_grade or bits == 0
    small_block = bulk in SMALL_BLOCK_CIPHERS

    return CipherProperties(
        id=suite_id, name=name, kex=kex, auth=auth, bulk=bulk, key_bits=bits,
        mode=mode, mac=mac, forward_secrecy=fs, anonymous=anonymous,
        export_grade=export_grade, aead=aead, broken=broken,
        small_block=small_block, recommended=suite_id in recommended,
    )


# --- named curve / group registry (subset used for key-exchange strength) ---
# Maps the TLS supported_groups value to an approximate symmetric-equivalent
# strength in bits, per NIST SP 800-57 Part 1 Rev 5 Table 2.
NAMED_GROUPS: dict[int, tuple[str, int]] = {
    19: ("secp192r1", 1024), 21: ("secp224r1", 2048),
    23: ("secp256r1", 3072), 24: ("secp384r1", 7680), 25: ("secp521r1", 15360),
    29: ("x25519", 3072), 30: ("x448", 7680),
    256: ("ffdhe2048", 2048), 257: ("ffdhe3072", 3072),
    258: ("ffdhe4096", 4096), 259: ("ffdhe6144", 6144), 260: ("ffdhe8192", 8192),
    # post-quantum hybrids seen in modern stacks
    25497: ("X25519Kyber768Draft00", 3072), 4588: ("X25519MLKEM768", 3072),
}


def group_name(gid: int) -> str:
    return NAMED_GROUPS.get(gid, (f"group_0x{gid:04X}", 0))[0]


def group_strength_bits(gid: int) -> int:
    return NAMED_GROUPS.get(gid, (None, 0))[1]
