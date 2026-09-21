"""
The deterministic rule engine.

Rules live in ``kb/rules.yaml`` as data.  This module turns a Session into a
flat namespace of *facts*, evaluates each rule's structured condition against
it, and emits Findings that cite the clause they enforce.

The condition language is deliberately tiny — ``all`` / ``any`` / ``not`` over
field predicates (``eq``, ``in``, ``lt``, ``gt``, ``lte``, ``gte``).  It is not
a general expression language and it never evaluates arbitrary code, so the
rule base stays inspectable data rather than becoming a plugin system.

By construction these findings have no false positives: "TLS 1.0 was
negotiated" is a direct read of an observed field, not a prediction.  If a rule
fires, the condition was true in the capture.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Optional

import yaml

from ..kb import RULES_FILE, kb_path

from ..analyze.ciphers import properties
from ..models import (
    CertVisibility,
    Evidence,
    Finding,
    Session,
    Severity,
    TlsMode,
)

TLS_VERSION_ORDER = {"SSL2.0": 0, "SSL3.0": 1, "1.0": 2, "1.1": 3, "1.2": 4, "1.3": 5}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    standard: str
    remediation: str
    condition: dict
    cap_grade: Optional[str] = None
    applies_to: tuple[str, ...] = ()


@lru_cache(maxsize=1)
def load_rules(path: Optional[str] = None) -> tuple[Rule, ...]:
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    else:
        with open(kb_path(RULES_FILE), "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    out = []
    for r in doc.get("rules", []):
        out.append(
            Rule(
                id=r["id"],
                title=r["title"],
                severity=Severity(r["severity"]),
                standard=r.get("standard", ""),
                remediation=r.get("remediation", ""),
                condition=r.get("condition", {}),
                cap_grade=r.get("cap_grade"),
                applies_to=tuple(r.get("applies_to", [])),
            )
        )
    return tuple(out)


# --------------------------------------------------------------------------
# fact extraction
# --------------------------------------------------------------------------

def build_facts(s: Session) -> dict[str, Any]:
    """Flatten a Session into the namespace rule conditions are evaluated against."""
    props = properties(s.cipher_suite_id) if s.cipher_suite_id is not None else None
    cert_visible = s.cert_visibility == CertVisibility.OBSERVED
    leaf = s.chain[0] if s.chain else None

    kex_bits_known = s.kex_bits is not None and s.kex_bits > 0

    facts: dict[str, Any] = {
        "protocol": s.protocol.value,
        "role": s.role.value,
        "tls_mode": s.tls_mode.value,
        "encrypted": s.tls_version is not None,
        "tls_version": s.tls_version,
        "tls_version_rank": TLS_VERSION_ORDER.get(s.tls_version or "", -1),
        "handshake_complete": s.handshake_complete,
        "resumed": s.resumed,

        # cipher
        "cipher_suite": s.cipher_suite,
        "cipher_broken": bool(props and props.broken and not props.anonymous and not props.export_grade),
        "cipher_anonymous": bool(props and props.anonymous),
        "cipher_export": bool(props and props.export_grade),
        "cipher_null": bool(props and props.is_null),
        "cipher_aead": bool(props and props.aead),
        "cipher_small_block": bool(props and props.small_block),
        "cipher_recommended": bool(props and props.recommended),
        "cipher_bits": s.cipher_bits or 0,

        # key exchange
        "kex": s.kex,
        "kex_bits": s.kex_bits or 0,
        "kex_bits_known": kex_bits_known,
        "forward_secrecy": bool(s.forward_secrecy),

        # STARTTLS
        "starttls_offered": s.starttls_offered,
        "starttls_requested": s.starttls_requested,
        "starttls_accepted": s.starttls_accepted,
        "capability_mangled": s.capability_mangled,
        "capability_seen": s.capability_line is not None,
        "cleartext_auth": s.cleartext_auth is not None,
        "injection_suspected": bool(s.injection_suspected),
        "client_offered_ciphers": s.offered_ciphers,
        "client_offered_versions": s.offered_versions,

        # certificates
        "cert_visibility": s.cert_visibility.value,
        "cert_visible": cert_visible,
        "cert_self_signed": bool(leaf.self_signed) if leaf else False,
        "cert_expired_at_capture": bool(leaf.expired_at_capture) if leaf else False,
        "cert_not_yet_valid": bool(leaf.not_yet_valid_at_capture) if leaf else False,
        "cert_days_to_expiry": leaf.days_to_expiry_at_capture if leaf and leaf.days_to_expiry_at_capture is not None else 99999,
        "cert_key_bits": leaf.key_bits if leaf and leaf.key_bits else 99999,
        "cert_key_algo": leaf.key_algorithm if leaf else None,
        "cert_key_rsa_like": bool(leaf and leaf.key_algorithm in ("RSA", "DSA")),
        "cert_weak_signature": any(
            (c.signature_hash or "").lower() in ("md5", "sha1", "md2", "md4")
            for c in s.chain
            if not (c.self_signed and c.is_ca)
        ),
        "chain_valid": s.chain_valid,
        "name_match": s.name_match,
        "revocation": s.revocation.value,

        # DNS policy
        "mta_sts_published": bool(s.mta_sts_published),
        "tlsa_present": bool(s.tlsa_records),
        "tls_rpt_published": bool(s.tls_rpt_published),
    }
    return facts


# --------------------------------------------------------------------------
# condition evaluation
# --------------------------------------------------------------------------

def _predicate(node: dict, facts: dict[str, Any]) -> bool:
    field = node.get("field")
    if field is None:
        return False
    value = facts.get(field)

    if "eq" in node:
        return value == node["eq"]
    if "ne" in node:
        return value != node["ne"]
    if "in" in node:
        return value in node["in"]
    if "not_in" in node:
        return value not in node["not_in"]
    if "contains" in node:
        if not isinstance(value, (list, set, tuple)):
            return False
        return node["contains"] in value
    if "contains_any" in node:
        if not isinstance(value, (list, set, tuple)):
            return False
        return any(v in value for v in node["contains_any"])
    if "is_null" in node:
        return (value is None) == bool(node["is_null"])
    for op, fn in (
        ("lt", lambda a, b: a < b),
        ("lte", lambda a, b: a <= b),
        ("gt", lambda a, b: a > b),
        ("gte", lambda a, b: a >= b),
    ):
        if op in node:
            if value is None or not isinstance(value, (int, float)):
                return False
            return fn(value, node[op])
    return False


def evaluate(condition: dict, facts: dict[str, Any]) -> bool:
    if not condition:
        return False
    if "all" in condition:
        return all(evaluate(c, facts) if _is_group(c) else _predicate(c, facts)
                   for c in condition["all"])
    if "any" in condition:
        return any(evaluate(c, facts) if _is_group(c) else _predicate(c, facts)
                   for c in condition["any"])
    if "not" in condition:
        inner = condition["not"]
        return not (evaluate(inner, facts) if _is_group(inner) else _predicate(inner, facts))
    return _predicate(condition, facts)


def _is_group(node: Any) -> bool:
    return isinstance(node, dict) and ({"all", "any", "not"} & set(node.keys())) != set()


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def _evidence_for(rule_id: str, s: Session) -> Evidence:
    """Attach the frames that justify a finding, so every claim is traceable."""
    frames: list[int] = []
    excerpt: Optional[str] = None

    if rule_id.startswith(("MS-STRIP", "SMS-AUTH")):
        if s.cleartext_auth and s.cleartext_auth.frame:
            frames.append(s.cleartext_auth.frame)
        if s.capability_line:
            excerpt = s.capability_line[:400]
    elif rule_id.startswith(("SMS-CERT", "SMS-KEY")):
        if s.chain:
            excerpt = f"{s.chain[0].subject} (issuer: {s.chain[0].issuer})"
    elif rule_id.startswith(("SMS-CIPH", "MS-PROTO", "SMS-FS", "SMS-KEX")):
        excerpt = f"{s.tls_version or 'cleartext'} / {s.cipher_suite or 'no cipher'}"

    if not frames:
        frames = [f for f in (s.first_frame, s.last_frame) if f]
    return Evidence(frames=sorted(set(frames)), tcp_stream=s.tcp_stream, excerpt=excerpt)


def _detail_for(rule_id: str, s: Session, facts: dict[str, Any]) -> Optional[str]:
    if rule_id == "MS-PROTO-001":
        return f"Negotiated TLS {s.tls_version}."
    if rule_id == "SMS-CIPH-002":
        return f"Negotiated {s.cipher_suite}."
    if rule_id == "SMS-CIPH-005":
        p = properties(s.cipher_suite_id) if s.cipher_suite_id else None
        return f"Cipher mode is {p.mode}, which is not authenticated encryption." if p else None
    if rule_id == "SMS-CERT-001" and s.chain:
        return (f"Certificate expired {s.chain[0].not_after:%d %b %Y}, "
                f"{abs(s.chain[0].days_to_expiry_at_capture or 0)} days before this traffic was captured.")
    if rule_id == "SMS-CERT-003" and s.chain:
        return f"Subject and issuer are both '{s.chain[0].subject}'."
    if rule_id == "SMS-CERT-004":
        return s.chain_error
    if rule_id == "SMS-CERT-007" and s.chain:
        return f"Expires in {s.chain[0].days_to_expiry_at_capture} days ({s.chain[0].not_after:%d %b %Y})."
    if rule_id == "SMS-KEY-002" and s.chain:
        return f"{s.chain[0].key_algorithm} key of {s.chain[0].key_bits} bits."
    if rule_id == "MS-STRIP-001":
        return (f"Capability list contains '{s.mangled_token}', which is exactly the length of "
                f"the expected keyword. Equal-length substitution preserves packet size, so the "
                f"downgrade leaves no size anomaly downstream.")
    if rule_id == "SMS-AUTH-001" and s.cleartext_auth:
        a = s.cleartext_auth
        return (f"{a.mechanism} credentials for user '{a.username or 'unknown'}' sent before "
                f"any encryption was established.")
    if rule_id == "MS-STRIP-002":
        return "The server advertised STARTTLS; the client proceeded without it."
    if rule_id == "SMS-KEX-001":
        return f"Key exchange strength {s.kex_bits} bits ({s.kex})."
    return None


def apply_rules(s: Session, rules: Optional[tuple[Rule, ...]] = None) -> list[Finding]:
    rules = rules if rules is not None else load_rules()
    facts = build_facts(s)
    findings: list[Finding] = []
    for rule in rules:
        if rule.applies_to and s.role.value not in rule.applies_to:
            continue
        try:
            fired = evaluate(rule.condition, facts)
        except Exception:
            fired = False
        if not fired:
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                standard=rule.standard,
                remediation=rule.remediation,
                detail=_detail_for(rule.id, s, facts),
                cap_grade=rule.cap_grade,
                evidence=_evidence_for(rule.id, s),
            )
        )
    findings.sort(key=lambda f: (f.severity.rank, f.rule_id))
    return findings
