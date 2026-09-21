"""
Asset (server) rollup and remediation ordering.

The problem statement asks for the posture of an email *infrastructure*, not a
list of connections.  A capture with 400 connections to one mail server
produces 400 identical rows, and an administrator cannot act on that.  Sessions
are therefore grouped into assets — one per ``server:port`` — and it is the
asset that carries a grade and a place in the fix queue.

Grouping also surfaces a finding a single session cannot express: a server that
negotiated TLS 1.3 with one client and TLS 1.0 with another is permissively
configured, and that spread is a downgrade opportunity.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Optional

from ..models import Asset, Finding, Grade, ScoreComponents, Session, Severity
from .grade import GRADE_ORDER, band_for, _cap_rank
from .rules import TLS_VERSION_ORDER

# Severity weights used to turn findings into a comparable risk number.
SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}


def _worst_grade(letters: list[str]) -> str:
    return min(letters, key=_cap_rank) if letters else "F"


def build_assets(sessions: list[Session]) -> list[Asset]:
    groups: dict[str, list[Session]] = defaultdict(list)
    for s in sessions:
        groups[s.asset_key].append(s)

    assets: list[Asset] = []
    for key, group in groups.items():
        first = group[0]
        host = first.server_name or first.server.ip
        clients = {s.client.ip for s in group}

        versions = [s.tls_version for s in group if s.tls_version]
        ranks = [TLS_VERSION_ORDER.get(v, -1) for v in versions]
        best = max(versions, key=lambda v: TLS_VERSION_ORDER.get(v, -1)) if versions else None
        worst = min(versions, key=lambda v: TLS_VERSION_ORDER.get(v, -1)) if versions else None

        # Deduplicate findings across the asset's sessions, keeping the worst.
        seen: dict[str, Finding] = {}
        for s in group:
            for f in s.findings:
                if f.rule_id not in seen:
                    seen[f.rule_id] = f
        findings = sorted(seen.values(), key=lambda f: (f.severity.rank, f.rule_id))

        asset_grade = _aggregate_grade(group, findings)

        # Exposure = how much this server's weakness actually costs.
        # Two servers can both grade F; the one carrying 400 authenticated
        # submissions is the one to fix on Monday.
        risk = sum(SEVERITY_WEIGHT.get(f.severity, 0.0) for f in findings)
        creds = any(s.cleartext_auth for s in group)
        reach = 1.0 + 0.25 * (len(group) - 1) + 0.5 * (len(clients) - 1)
        exposure = round(risk * reach + (50.0 if creds else 0.0), 2)

        ml_scores = [s.ml.risk_score for s in group if s.ml and s.ml.risk_score is not None]

        assets.append(
            Asset(
                key=key,
                host=host,
                port=first.server.port,
                protocol=first.protocol,
                role=first.role,
                session_ids=[s.session_id for s in group],
                session_count=len(group),
                distinct_clients=len(clients),
                grade=asset_grade,
                best_tls=best,
                worst_tls=worst,
                version_spread=len(set(ranks)) > 1,
                findings=findings,
                credentials_exposed=creds,
                exposure_score=exposure,
                ml_risk=round(max(ml_scores), 4) if ml_scores else None,
            )
        )

    assets.sort(key=lambda a: (-a.exposure_score, _cap_rank(a.grade.letter if a.grade else "F")))
    return assets


def _aggregate_grade(group: list[Session], findings: list[Finding]) -> Grade:
    """
    Combine session grades into a server grade.

    Protocol support uses the published SSL Labs rule — the average of the best
    and the worst observed — which is the honest way to recover a server-level
    view from multiple observations.  Key exchange and cipher take the worst
    observed, because a server that will negotiate a weak suite with anyone is
    as weak as that suite.
    """
    graded = [s for s in group if s.grade]
    if not graded:
        return Grade(letter="F", raw_score=0.0, components=ScoreComponents())

    protos = [s.grade.components.protocol for s in graded]
    protocol = (max(protos) + min(protos)) / 2.0
    key_exchange = min(s.grade.components.key_exchange for s in graded)
    cipher = min(s.grade.components.cipher for s in graded)

    comps = ScoreComponents(protocol=protocol, key_exchange=key_exchange, cipher=cipher)
    raw = comps.weighted()
    zero = None
    for name, v in (("protocol", protocol), ("key_exchange", key_exchange), ("cipher", cipher)):
        if v == 0.0:
            zero = name
            break
    if zero:
        raw = 0.0

    letter = band_for(raw)
    capped_by = cap_reason = None
    for f in findings:
        if f.cap_grade and _cap_rank(f.cap_grade) < _cap_rank(letter):
            letter, capped_by, cap_reason = f.cap_grade, f.rule_id, f.title

    # If every session graded A+ and nothing capped, the asset keeps A+.
    if letter == "A" and all(s.grade.letter == "A+" for s in graded):
        letter = "A+"

    trusted = all(s.grade.trusted for s in graded)
    return Grade(
        letter=letter, raw_score=round(raw, 1), components=comps,
        capped_by=capped_by, cap_reason=cap_reason, trusted=trusted,
        zero_category=zero,
    )


def overall(assets: list[Asset]) -> tuple[str, float]:
    """Capture-level headline: the worst asset grade, and a mean score."""
    if not assets:
        return "N/A", 0.0
    letters = [a.grade.letter for a in assets if a.grade]
    scores = [a.grade.raw_score for a in assets if a.grade]
    return _worst_grade(letters), round(sum(scores) / len(scores), 1) if scores else 0.0


def remediation_plan(assets: list[Asset]) -> list[dict]:
    """
    Ordered fix list.

    Grouped by rule so an administrator sees "fix this one thing on these four
    servers" rather than the same advice repeated per session.
    """
    by_rule: dict[str, dict] = {}
    for asset in assets:
        for f in asset.findings:
            if f.severity == Severity.INFO:
                continue
            entry = by_rule.setdefault(
                f.rule_id,
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "standard": f.standard,
                    "action": f.remediation,
                    "affected_assets": [],
                    "priority_score": 0.0,
                },
            )
            entry["affected_assets"].append(asset.key)
            entry["priority_score"] += asset.exposure_score

    plan = sorted(
        by_rule.values(),
        key=lambda e: (Severity(e["severity"]).rank, -e["priority_score"]),
    )
    for i, e in enumerate(plan, 1):
        e["order"] = i
        e["priority_score"] = round(e["priority_score"], 2)
        e["affected_assets"] = sorted(set(e["affected_assets"]))
    return plan
