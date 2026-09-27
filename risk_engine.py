"""SecureMailScope — transparent deterministic risk scoring.

score = 100 - (30*Critical + 20*High + 10*Medium + 5*Low), clamped 0..100.
Bands: 90-100 SECURE · 75-89 LOW RISK · 50-74 MODERATE RISK · 25-49 HIGH RISK · 0-24 CRITICAL
"""
from collections import Counter

from rules import PENALTIES

CRITICAL, HIGH, MEDIUM, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"


def band(score):
    if score >= 90:
        return "SECURE"
    if score >= 75:
        return "LOW RISK"
    if score >= 50:
        return "MODERATE RISK"
    if score >= 25:
        return "HIGH RISK"
    return "CRITICAL"


def compute_risk(findings):
    """Return {score, band, counts, penalty} from a list of finding dicts."""
    counts = Counter(f["severity"] for f in findings)
    penalty = (PENALTIES[CRITICAL] * counts.get(CRITICAL, 0)
               + PENALTIES[HIGH] * counts.get(HIGH, 0)
               + PENALTIES[MEDIUM] * counts.get(MEDIUM, 0)
               + PENALTIES[LOW] * counts.get(LOW, 0))
    score = max(0, min(100, 100 - penalty))
    return {
        "score": score,
        "band": band(score),
        "counts": {s: counts.get(s, 0) for s in (CRITICAL, HIGH, MEDIUM, LOW)},
        "penalty": penalty,
    }


def compute_session_risk(findings):
    """Per-session score using the same transparent formula."""
    return compute_risk(findings)
