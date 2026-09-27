"""SecureMailScope — unsupervised ML anomaly assist (IsolationForest).

ROADMAP PHASE 5 (real ML): an actual scikit-learn IsolationForest over
per-session feature vectors, trained on the capture itself as its own
baseline (unsupervised — no labels, no training data collection).

Honesty contract:
- Labeled `source: "isolation_forest_unsupervised"` in every payload it touches.
- Runs only when ≥ 8 sessions (below that the deterministic detectors are the
  sole signal — this module adds nothing, by design).
- random_state=42, n_estimators=100 → identical capture = identical output.
- Output is an *assist signal*: it can raise a session's anomaly score
  (capped contribution +15) and adds a labeled detector line, but never
  lowers the deterministic score, and it never changes rule-engine findings
  or the posture score math.
"""
import numpy as np
from sklearn.ensemble import IsolationForest

VERSION_SCORE = {"SSLv3": 0.0, "SSLv2": 0.0, "TLS 1.0": 0.2, "TLS 1.1": 0.35,
                 "TLS 1.2": 0.8, "TLS 1.3": 1.0}
CIPHER_POINTS = {"RC4": 0.0, "3DES": 0.15, "DES": 0.15, "NULL": 0.0, "EXP": 0.0}
MIN_SESSIONS = 8
CONTRIBUTION_CAP = 15
SEED = 42


def _features(sessions):
    rows = []
    for s in sessions:
        cipher = (s.get("cipher") or "").upper()
        row = [
            VERSION_SCORE.get(s.get("tls_version"), 0.0 if s.get("tls") == "PLAINTEXT" else 0.5),
            1.0 if s.get("forward_secrecy") else 0.0,
            0.0 if s.get("tls") == "PLAINTEXT" else 1.0,
            min(len(cipher), 60) / 60.0,
            next((0.0 for k in CIPHER_POINTS if k in cipher),
                 1.0 if ("GCM" in cipher or "CHACHA20" in cipher) else 0.6),
            1.0 if s.get("key_exchange") in ("ECDHE", "DHE") else 0.0,
            min(int(s.get("bytes") or 0), 500000) / 500000.0,
            min(int(s.get("packets") or 0), 200) / 200.0,
            min(float(s.get("duration_s") or 0), 600) / 600.0,
            int(s.get("dst_port") or 0) in (25, 587),
        ]
        rows.append(row)
    X = np.array(rows, dtype=float)
    # normalize columns to unit variance where spread exists (deterministic)
    std = X.std(axis=0)
    std[std == 0] = 1.0
    return (X - X.mean(axis=0)) / std


def enrich(sessions):
    """Attach ML anomaly assist to each session (in place). Deterministic."""
    for s in sessions:
        s.setdefault("anomaly_ml", {"available": False,
                                    "source": "isolation_forest_unsupervised",
                                    "score": None, "note": None})
    if len(sessions) < MIN_SESSIONS:
        return sessions

    X = _features(sessions)
    model = IsolationForest(n_estimators=100, random_state=SEED, contamination=0.15)
    model.fit(X)
    raw = -model.score_samples(X)            # higher = more anomalous

    # map raw scores to 0–100 deterministically via rank + spread
    order = np.argsort(raw)                   # ascending
    ranks = np.empty_like(order)
    ranks[order] = np.arange(len(raw))
    norm = ranks / max(1, len(raw) - 1)       # 0..1, ties broken by position only
    ml_scores = (norm * 100).round().astype(int)

    for s, ml in zip(sessions, ml_scores):
        det = s.get("anomaly", {}).get("detected", [])
        base = int(s.get("anomaly", {}).get("score", 0))
        if ml >= 85:
            contribution = min(CONTRIBUTION_CAP, ml - 70)
            det = det + [f"ML assist: session flagged as outlier by unsupervised "
                         f"IsolationForest (contamination 0.15, seed {SEED})"]
            s["anomaly"] = {"score": min(100, base + contribution),
                            "detected": det,
                            "confidence": max(int(s.get("anomaly", {}).get("confidence", 90)), 90)}
        s["anomaly_ml"] = {"available": True,
                           "source": "isolation_forest_unsupervised",
                           "score": int(ml),
                           "note": ("outlier" if ml >= 85 else
                                    "elevated" if ml >= 65 else "in-baseline")}
    return sessions
