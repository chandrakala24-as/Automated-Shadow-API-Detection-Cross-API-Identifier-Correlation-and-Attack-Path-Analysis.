"""Explainable risk scoring (0-100)."""
from __future__ import annotations

from .models import ANONYMOUS, Endpoint, Finding

IMPACT = {"secrets": 1.0, "location": 0.95, "financial": 0.85, "personal": 0.8}
TYPE_WEIGHT = {"INVALID_TOKEN_ACCEPTED": 1.0, "MISSING_AUTHENTICATION": 0.95, "BOLA": 0.95,
               "BFLA": 0.95, "SECRET_EXPOSURE": 0.9}


def severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def impact_of(categories: list[str]) -> float:
    return max((IMPACT.get(c, 0.5) for c in categories), default=0.4)


def score_finding(finding: Finding, endpoint: Endpoint) -> None:
    exposure = 1.0 if endpoint.classification in ("shadow", "zombie") else 0.5
    if finding.type in ("SHADOW_API", "ZOMBIE_API"):
        base = 30 if finding.type == "ZOMBIE_API" else 25
        extra = round(10 * impact_of(finding.data_categories)) if finding.data_categories else 0
        finding.score = base + extra
        finding.severity = severity(finding.score)
        finding.score_breakdown = {"inventory_base": base, "data_sensitivity": extra}
        return
    parts = {
        "data_impact": round(40 * impact_of(finding.data_categories)),
        "ease_of_exploitation": 30 if finding.attacker == ANONYMOUS else 25,
        "weakness_type": round(15 * TYPE_WEIGHT.get(finding.type, 0.6)),
        "inventory_exposure": round(15 * exposure),
    }
    total = sum(parts.values())
    if finding.confidence != "confirmed":
        parts["review_penalty"] = -round(total * 0.35)
        total += parts["review_penalty"]
    finding.score = min(100, total)
    finding.severity = severity(finding.score)
    finding.score_breakdown = parts
