"""
X.509 certificate extraction, validation and trust-path building.

The defining decision in this module: **every validity judgement is made
against the capture clock, not the wall clock.**

A forensic tool analyses old evidence.  Comparing ``not_valid_after`` to
``datetime.now()`` makes every certificate in a 2015 capture report as expired,
every finding wrong, and the tool useless for exactly the archival work that
justifies it.  So the analyser takes the timestamp of the frame that carried
the handshake and asks "was this certificate valid *then*".

Both answers are reported, because they are different findings:
  * ``expired_at_capture``  — the operator was serving a dead certificate.
    That is an incident.
  * ``expired_now``         — it has lapsed since.  That is housekeeping.

Scope, stated honestly: this performs signature verification, validity-window
checks and trust-anchor chaining.  It does not implement full RFC 5280 policy
processing (name constraints, policy mappings), and it cannot check revocation
without a stapled OCSP response — offline, there is nothing to query.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..models import CertInfo, Revocation

WEAK_SIGNATURE_HASHES = {"md5", "sha1", "md2", "md4"}


# --------------------------------------------------------------------------
# trust store
# --------------------------------------------------------------------------

@lru_cache(maxsize=1)
def load_trust_store(bundle_path: Optional[str] = None) -> list[x509.Certificate]:
    """
    Load trusted roots.

    Order of preference: an explicitly supplied bundle, then ``certifi`` (a
    vendored copy of the Mozilla root program — no network at runtime), then
    the platform bundle.  Returns an empty list if none is available, in which
    case chain validation reports ``unknown`` rather than falsely failing.
    """
    paths: list[str] = []
    if bundle_path:
        paths.append(bundle_path)
    try:
        import certifi  # type: ignore
        paths.append(certifi.where())
    except Exception:
        pass
    paths += [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/usr/local/etc/openssl/cert.pem",
        "/etc/ssl/cert.pem",
    ]
    import warnings

    for p in paths:
        try:
            with open(p, "rb") as fh:
                data = fh.read()
            # Real-world root bundles contain a few certificates that violate
            # RFC 5280 (non-positive serials, mostly from the 1990s). They are
            # still trust anchors in every shipping browser, so warning about
            # them on every run is noise.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                certs = x509.load_pem_x509_certificates(data)
            if certs:
                return certs
        except Exception:
            continue
    return []


@lru_cache(maxsize=1)
def _trust_index() -> dict[bytes, list[x509.Certificate]]:
    idx: dict[bytes, list[x509.Certificate]] = {}
    for c in load_trust_store():
        idx.setdefault(c.subject.public_bytes(), []).append(c)
    return idx


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _name_str(name: x509.Name) -> str:
    try:
        cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            return str(cn[0].value)
    except Exception:
        pass
    try:
        return name.rfc4514_string()
    except Exception:
        return "<unparsable>"


def _key_info(cert: x509.Certificate) -> tuple[Optional[str], Optional[int]]:
    try:
        pk = cert.public_key()
    except (ValueError, UnsupportedAlgorithm):
        return None, None
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA", pk.key_size
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return "EC", pk.curve.key_size
    if isinstance(pk, dsa.DSAPublicKey):
        return "DSA", pk.key_size
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448", 448
    return type(pk).__name__, None


def _naive_utc(dt: datetime) -> datetime:
    """cryptography's *_utc properties are tz-aware; older ones are naive."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _not_before(cert: x509.Certificate) -> datetime:
    try:
        return _naive_utc(cert.not_valid_before_utc)
    except AttributeError:  # pragma: no cover - cryptography < 42
        return _naive_utc(cert.not_valid_before)


def _not_after(cert: x509.Certificate) -> datetime:
    try:
        return _naive_utc(cert.not_valid_after_utc)
    except AttributeError:  # pragma: no cover - cryptography < 42
        return _naive_utc(cert.not_valid_after)


def _san_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ext.value
        names = list(san.get_values_for_type(x509.DNSName))
        names += [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        return names
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        return bool(bc.ca)
    except Exception:
        return False


def verify_signed_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """Does `parent`'s public key verify `child`'s signature?"""
    try:
        pk = parent.public_key()
        sig_hash = child.signature_hash_algorithm
        if isinstance(pk, rsa.RSAPublicKey):
            pk.verify(child.signature, child.tbs_certificate_bytes,
                      padding.PKCS1v15(), sig_hash)
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            pk.verify(child.signature, child.tbs_certificate_bytes,
                      ec.ECDSA(sig_hash))
        elif isinstance(pk, dsa.DSAPublicKey):
            pk.verify(child.signature, child.tbs_certificate_bytes, sig_hash)
        elif isinstance(pk, ed25519.Ed25519PublicKey):
            pk.verify(child.signature, child.tbs_certificate_bytes)
        elif isinstance(pk, ed448.Ed448PublicKey):
            pk.verify(child.signature, child.tbs_certificate_bytes)
        else:
            return False
        return True
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError):
        return False


def is_self_signed(cert: x509.Certificate) -> bool:
    if cert.issuer != cert.subject:
        return False
    return verify_signed_by(cert, cert)


def _hostname_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern == host:
        return True
    if pattern.startswith("*."):
        # A wildcard matches exactly one left-most label (RFC 6125 §6.4.3).
        suffix = pattern[2:]
        if "." not in host:
            return False
        return host.split(".", 1)[1] == suffix
    return False


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------

@dataclass
class CertAnalysis:
    chain: list[CertInfo]
    chain_valid: Optional[bool]
    chain_error: Optional[str]
    name_match: Optional[bool]
    revocation: Revocation
    leaf_self_signed: bool
    weak_signature: bool
    smallest_key_bits: Optional[int]
    expired_at_capture: bool
    not_yet_valid_at_capture: bool
    expired_now: bool
    days_to_expiry: Optional[int]


def to_cert_info(cert: x509.Certificate, capture_time: datetime) -> CertInfo:
    algo, bits = _key_info(cert)
    nb, na = _not_before(cert), _not_after(cert)
    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:
        sig_hash = None
    try:
        sig_algo = cert.signature_algorithm_oid._name
    except Exception:
        sig_algo = None
    days = (na - capture_time).days if capture_time else None
    return CertInfo(
        subject=_name_str(cert.subject),
        issuer=_name_str(cert.issuer),
        serial=format(cert.serial_number, "x"),
        not_before=nb,
        not_after=na,
        key_algorithm=algo,
        key_bits=bits,
        signature_algorithm=sig_algo,
        signature_hash=sig_hash,
        self_signed=is_self_signed(cert),
        is_ca=_is_ca(cert),
        san=_san_names(cert),
        sha256_fingerprint=hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest(),
        expired_at_capture=capture_time > na if capture_time else None,
        not_yet_valid_at_capture=capture_time < nb if capture_time else None,
        days_to_expiry_at_capture=days,
    )


def analyse(
    der_certs: list[bytes],
    capture_time: Optional[datetime],
    server_name: Optional[str],
    ocsp_response: Optional[bytes] = None,
) -> CertAnalysis:
    """
    Parse and validate a presented certificate chain as of the capture time.
    """
    now = datetime.now(timezone.utc)
    ref = capture_time or now

    parsed: list[x509.Certificate] = []
    for der in der_certs:
        try:
            parsed.append(x509.load_der_x509_certificate(der))
        except Exception:
            continue

    if not parsed:
        return CertAnalysis([], None, "no parsable certificate presented", None,
                            Revocation.UNKNOWN_OFFLINE, False, False, None,
                            False, False, False, None)

    infos = [to_cert_info(c, ref) for c in parsed]
    leaf = parsed[0]
    leaf_info = infos[0]

    # -- trust path ------------------------------------------------------
    chain_valid: Optional[bool] = None
    chain_error: Optional[str] = None
    trust = _trust_index()

    if is_self_signed(leaf):
        chain_valid = False
        chain_error = "leaf certificate is self-signed; no CA vouches for it"
    elif not trust:
        chain_valid = None
        chain_error = "no trust store available; chain not evaluated"
    else:
        # Build the path using the presented intermediates, then the store.
        by_subject: dict[bytes, x509.Certificate] = {
            c.subject.public_bytes(): c for c in parsed[1:]
        }
        current = leaf
        seen: set[bytes] = set()
        chain_valid = False
        chain_error = "could not build a path to a trusted root"
        for _ in range(10):
            key = current.subject.public_bytes()
            if key in seen:
                chain_error = "certificate path contains a loop"
                break
            seen.add(key)
            issuer_key = current.issuer.public_bytes()

            anchors = trust.get(issuer_key, [])
            anchor = next((a for a in anchors if verify_signed_by(current, a)), None)
            if anchor is not None:
                chain_valid = True
                chain_error = None
                break

            # A self-signed certificate at the top of the presented chain that
            # the trust store does not know is the single most common way a
            # chain fails: a TLS-terminating proxy or a private CA. Following
            # it would land back on itself and report "path contains a loop",
            # which sends the operator looking for the wrong problem entirely.
            if key == issuer_key and current is not leaf:
                chain_error = (
                    f"the chain ends at a self-signed root "
                    f"'{_name_str(current.subject)}' that is not in the trust "
                    f"store — the server presented a private CA, which usually "
                    f"means an intercepting proxy or an internal PKI"
                )
                break

            nxt = by_subject.get(issuer_key)
            if nxt is None:
                chain_error = (
                    f"missing issuer '{_name_str(current.issuer)}' — the chain "
                    "presented by the server is incomplete"
                )
                break
            if not verify_signed_by(current, nxt):
                chain_error = "signature mismatch between certificate and its issuer"
                break
            current = nxt

    # -- validity at the capture clock -----------------------------------
    expired_at_capture = bool(leaf_info.expired_at_capture)
    not_yet_valid = bool(leaf_info.not_yet_valid_at_capture)
    expired_now = now > _not_after(leaf)

    # -- name match -------------------------------------------------------
    name_match: Optional[bool] = None
    if server_name:
        candidates = list(leaf_info.san)
        if not candidates and leaf_info.subject:
            candidates = [leaf_info.subject]
        name_match = any(_hostname_matches(p, server_name) for p in candidates)

    # -- signature strength ----------------------------------------------
    weak_sig = any(
        (i.signature_hash or "").lower() in WEAK_SIGNATURE_HASHES
        for i in infos
        if not (i.self_signed and i.is_ca)   # a self-signed root's own sig is not used
    )

    key_bits = [i.key_bits for i in infos if i.key_bits]
    smallest = min(key_bits) if key_bits else None

    # -- revocation, only if stapled --------------------------------------
    revocation = Revocation.UNKNOWN_OFFLINE
    if ocsp_response:
        revocation = parse_ocsp_staple(ocsp_response)

    return CertAnalysis(
        chain=infos,
        chain_valid=chain_valid,
        chain_error=chain_error,
        name_match=name_match,
        revocation=revocation,
        leaf_self_signed=leaf_info.self_signed,
        weak_signature=weak_sig,
        smallest_key_bits=smallest,
        expired_at_capture=expired_at_capture,
        not_yet_valid_at_capture=not_yet_valid,
        expired_now=expired_now,
        days_to_expiry=leaf_info.days_to_expiry_at_capture,
    )


def parse_ocsp_staple(der: bytes) -> Revocation:
    """
    Read a stapled OCSP response.

    Offline we cannot query a responder — but if the server stapled the answer
    into the handshake, the revocation status is already in the capture.
    """
    try:
        from cryptography.x509 import ocsp
        resp = ocsp.load_der_ocsp_response(der)
        if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return Revocation.UNKNOWN_OFFLINE
        if resp.certificate_status == ocsp.OCSPCertStatus.GOOD:
            return Revocation.GOOD
        if resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            return Revocation.REVOKED
    except Exception:
        pass
    return Revocation.UNKNOWN_OFFLINE
