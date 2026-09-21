"""
Labelled training data from ground-truth server configurations.

Why this exists
---------------
There is no public capture corpus labelled by *cryptographic posture*.  The
malware-TLS datasets (CTU-13, Stratosphere, MTA) are labelled by maliciousness,
which is a different question entirely.  So the labels are generated, exactly
as the problem statement anticipates.

The rule that keeps this honest
-------------------------------
The label never comes from the rule engine.  It is a property of the **server
configuration** — full information, the equivalent of reading ``main.cf`` and
the certificate off the server itself.  The feature row is what a **passive
observer** would have recorded — strictly less information, and on TLS 1.3
dramatically less, because RFC 8446 encrypts the Certificate message and seven
of the eighteen core features disappear.

The learning problem is therefore inverting a lossy observation, not restating
a rule.  ``posture_of()`` below is a *definition* of what a configuration is;
it is never applied to observations, only to the hidden ground truth.

Configurations are **sampled**, not enumerated.  An earlier version used a
fixed list of 31 servers, which made grouped cross-validation meaningless:
holding out whole profiles left the model facing points it had no neighbours
for, and macro-F1 sat near 0.35.  Sampling a continuous configuration space
produces hundreds of distinct servers, so the model learns the mapping rather
than memorising a handful of points — and grouped CV measures something real.

Honest limitation, repeated in the README: these are synthesised at the
*feature* level, not captured from live Postfix/Dovecot instances, so they do
not reproduce correlations that only emerge from real server behaviour.
Retraining on real captures is a drop-in replacement.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

from ..features import FEATURE_NAMES, MISSING

# Posture classes, worst to best.  These describe the SERVER, not the session.
CLASSES = ["critical", "vulnerable", "weak", "secure"]


@dataclass
class ServerProfile:
    """One mail-server configuration — the hidden ground truth."""
    name: str
    tls_version: float            # 0 cleartext, 3 SSLv3, 10/11/12/13
    cipher_bits: int
    cipher_mode: float            # 4 AEAD, 2 CBC, 1 stream, 0 none
    cipher_recommended: int
    kex_family: float             # 5 tls13, 4 ECDHE, 3 DHE, 2 ECDH/DH, 1 static RSA
    kex_bits: int
    forward_secrecy: int
    cert_key_bits: int
    cert_key_algo: float          # 3 EC, 2 RSA, 1 DSA
    cert_sig_hash: float          # 3 sha256+, 1 sha1, 0 md5
    cert_days_to_expiry: int
    cert_self_signed: int
    chain_valid: int
    name_match: int
    starttls_offered: int
    starttls_completed: int
    cleartext_auth: int
    role_is_relay: int = 0
    posture: str = "secure"


def posture_of(p: ServerProfile) -> str:
    """
    Ground-truth posture of a *configuration*.

    A severity ladder applied top-down, anchored to the same published
    standards the rule engine cites — but evaluated against the server's full
    configuration, which a passive observer does not get to see.  This is a
    definition of the label, never a predictor over observations.
    """
    encrypted = p.tls_version > 0

    # --- critical: the traffic is readable, or the crypto is broken --------
    if not encrypted:
        return "critical"
    if p.cleartext_auth:
        return "critical"
    if p.starttls_offered and not p.starttls_completed:
        return "critical"
    if p.tls_version <= 3:                       # SSLv2/SSLv3
        return "critical"
    if p.cipher_bits < 112 or p.cipher_mode == 1:  # export/DES, or RC4 stream
        return "critical"
    if p.cert_days_to_expiry < 0:                 # expired at capture
        return "critical"
    if p.cert_key_bits < 1024 or p.kex_bits < 1024:
        return "critical"

    # --- vulnerable: standards-violating but not trivially breakable -------
    if p.tls_version <= 11:                       # RFC 8996
        return "vulnerable"
    if not p.forward_secrecy:                     # RFC 9325 §4.1
        return "vulnerable"
    if p.cipher_bits < 128:                       # 3DES / Sweet32
        return "vulnerable"
    if p.cert_sig_hash <= 1:                      # SHA-1 / MD5
        return "vulnerable"
    if p.cert_key_bits < 2048 or p.kex_bits < 2048:   # SP 800-131A floor
        return "vulnerable"

    # --- weak: sound primitives, defective deployment ----------------------
    if p.cipher_mode < 4:                         # non-AEAD
        return "weak"
    if p.cert_self_signed or not p.chain_valid or not p.name_match:
        return "weak"
    if p.cert_days_to_expiry < 30:
        return "weak"
    if not p.cipher_recommended:
        return "weak"

    return "secure"


# --------------------------------------------------------------------------
# configuration sampling
# --------------------------------------------------------------------------

def sample_profile(rng: random.Random, index: int) -> ServerProfile:
    """
    Draw one plausible mail-server configuration.

    Choices are correlated the way real deployments are — a box still speaking
    TLS 1.0 tends to have an old certificate and a static key exchange — so the
    space is realistic rather than uniform noise.
    """
    # 12% of the estate never encrypts at all.
    if rng.random() < 0.12:
        offered = int(rng.random() < 0.45)
        p = ServerProfile(
            name=f"cfg-{index:04d}", tls_version=0, cipher_bits=0, cipher_mode=0,
            cipher_recommended=0, kex_family=0, kex_bits=0, forward_secrecy=0,
            cert_key_bits=0, cert_key_algo=0, cert_sig_hash=0,
            cert_days_to_expiry=0, cert_self_signed=0, chain_valid=0, name_match=0,
            starttls_offered=offered, starttls_completed=0,
            cleartext_auth=int(rng.random() < 0.6),
            role_is_relay=int(rng.random() < 0.4),
        )
        p.posture = posture_of(p)
        return p

    era = rng.choices(
        ["modern", "current", "legacy", "ancient"],
        weights=[0.30, 0.38, 0.22, 0.10],
    )[0]

    if era == "modern":
        tls = 13.0
        kex_family, kex_bits = 5.0, rng.choice([3072, 3072, 7680])
        mode, bits = 4.0, rng.choice([128, 256, 256])
        recommended, fs = 1, 1
    elif era == "current":
        tls = 12.0
        kex_family = rng.choice([4.0, 4.0, 3.0, 1.0])
        kex_bits = (rng.choice([3072, 7680]) if kex_family == 4.0
                    else rng.choice([1024, 2048, 2048, 4096]) if kex_family == 3.0
                    else rng.choice([2048, 4096]))
        mode = rng.choice([4.0, 4.0, 2.0])
        bits = rng.choice([128, 256, 256])
        recommended = int(mode == 4.0 and kex_family in (4.0, 3.0))
        fs = int(kex_family in (3.0, 4.0, 5.0))
    elif era == "legacy":
        tls = rng.choice([10.0, 11.0, 12.0])
        kex_family = rng.choice([1.0, 1.0, 3.0, 4.0])
        kex_bits = rng.choice([1024, 1024, 2048])
        mode = rng.choice([2.0, 2.0, 1.0])
        bits = rng.choice([112, 128, 256])
        recommended, fs = 0, int(kex_family in (3.0, 4.0))
    else:  # ancient
        tls = rng.choice([3.0, 10.0])
        kex_family = 1.0
        kex_bits = rng.choice([512, 1024])
        mode = rng.choice([1.0, 2.0])
        bits = rng.choice([40, 56, 112, 128])
        recommended, fs = 0, 0

    # Certificate quality, correlated with era but not determined by it.
    if era in ("modern", "current"):
        cert_bits = rng.choice([2048, 2048, 3072, 4096, 256])
        cert_algo = 3.0 if cert_bits == 256 else 2.0
        sig = 3.0 if rng.random() < 0.95 else 1.0
        expiry = rng.choices(
            [rng.randint(30, 800), rng.randint(1, 29), rng.randint(-200, -1)],
            weights=[0.78, 0.12, 0.10],
        )[0]
        self_signed = int(rng.random() < 0.10)
    else:
        cert_bits = rng.choice([1024, 1024, 2048, 512])
        cert_algo = 2.0
        sig = rng.choice([1.0, 1.0, 3.0, 0.0])
        expiry = rng.choice([rng.randint(-500, -1), rng.randint(1, 400)])
        self_signed = int(rng.random() < 0.45)

    chain_valid = 0 if self_signed else int(rng.random() < 0.94)
    name_match = int(rng.random() < 0.94)

    p = ServerProfile(
        name=f"cfg-{index:04d}",
        tls_version=tls, cipher_bits=bits, cipher_mode=mode,
        cipher_recommended=recommended, kex_family=kex_family, kex_bits=kex_bits,
        forward_secrecy=fs, cert_key_bits=cert_bits, cert_key_algo=cert_algo,
        cert_sig_hash=sig, cert_days_to_expiry=expiry,
        cert_self_signed=self_signed, chain_valid=chain_valid, name_match=name_match,
        starttls_offered=1, starttls_completed=1, cleartext_auth=0,
        role_is_relay=int(rng.random() < 0.35),
    )
    p.posture = posture_of(p)
    return p


@dataclass
class GeneratedDataset:
    X: list[list[float]] = field(default_factory=list)
    y: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)      # config name -> grouped CV
    cert_masked: list[bool] = field(default_factory=list)
    feature_names: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))


def _row_from_profile(p: ServerProfile, rng: random.Random, mask_cert: bool) -> list[float]:
    """
    Emit what a passive observer would have recorded for one session against
    this server.  ``mask_cert`` simulates TLS 1.3, where the Certificate message
    is encrypted and every certificate-derived feature is simply unavailable.
    """
    encrypted = p.tls_version > 0
    cert_visible = 1.0 if (encrypted and not mask_cert) else 0.0

    def cert(value: float) -> float:
        return float(value) if cert_visible else MISSING

    ext_count = float(rng.randint(6, 18)) if encrypted else 0.0
    offered = float(rng.randint(24, 70) if p.tls_version >= 12 else rng.randint(8, 30)) \
        if encrypted else 0.0

    values = {
        "tls_version": float(p.tls_version),
        "cipher_iana_recommended": float(p.cipher_recommended),
        "cipher_key_bits": float(p.cipher_bits),
        "cipher_mode": float(p.cipher_mode),
        "kex_family": float(p.kex_family),
        "kex_bits_equiv": float(p.kex_bits),
        "forward_secrecy": float(p.forward_secrecy),
        "cert_visible": cert_visible,

        "cert_key_bits": cert(p.cert_key_bits),
        "cert_key_algo": cert(p.cert_key_algo),
        "cert_sig_hash": cert(p.cert_sig_hash),
        "cert_days_to_expiry": cert(p.cert_days_to_expiry + rng.randint(-15, 15)),
        "cert_self_signed": cert(p.cert_self_signed),
        "chain_valid": cert(p.chain_valid),
        "name_match": cert(p.name_match),

        "starttls_offered": float(p.starttls_offered),
        "starttls_completed": float(p.starttls_completed),
        "cleartext_auth": float(p.cleartext_auth),

        "offered_cipher_count": offered,
        "extension_count": ext_count,
        "alpn_present": float(rng.random() < 0.25),
        "session_resumed": float(encrypted and rng.random() < 0.15),
        "duration_seconds": round(abs(rng.gauss(2.0, 1.2)) + 0.05, 3),
        "bytes_ratio": round(abs(rng.gauss(1.0, 0.8)) + 0.01, 4),
        "protocol": float(rng.choice([1.0, 2.0, 3.0])),
        "role_is_relay": float(p.role_is_relay),
    }
    return [values[name] for name in FEATURE_NAMES]


def generate(
    n_profiles: int = 260,
    sessions_per_profile: int = 8,
    tls13_mask_rate: float = 0.30,
    seed: int = 26159,
    profiles: Optional[list[ServerProfile]] = None,
) -> GeneratedDataset:
    """
    Build the training set.

    ``tls13_mask_rate`` is the knob that makes this a genuine inference problem:
    on masked rows the model must recover the server's true posture from the
    eleven features that survive TLS 1.3 encryption.
    """
    rng = random.Random(seed)
    if profiles is None:
        profiles = [sample_profile(rng, i) for i in range(n_profiles)]

    ds = GeneratedDataset()
    for p in profiles:
        for _ in range(sessions_per_profile):
            encrypted = p.tls_version > 0
            mask = encrypted and rng.random() < tls13_mask_rate
            ds.X.append(_row_from_profile(p, rng, mask))
            ds.y.append(p.posture)
            ds.groups.append(p.name)
            ds.cert_masked.append(mask)
    return ds
