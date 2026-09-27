"""SecureMailScope — AI-assisted risk prioritization layer.

Deterministic feature-vector scorer over session cryptographic features —
a transparent prioritization aid that mirrors SOC triage logic.

Input features : TLS version, cipher strength, certificate status,
                 forward secrecy, STARTTLS behavior, anomaly indicators.
Output         : risk class, confidence %, human-readable reason,
                 P1–P4 priority.
"""
from rules import CRITICAL, HIGH, MEDIUM, LOW

# --------------------------------------------------------------- features ----
def _tls_version_score(v):
    v = (v or "").upper()
    if "SSL" in v:
        return 0.0
    if "1.0" in v:
        return 0.2
    if "1.1" in v:
        return 0.35
    if "1.2" in v:
        return 0.8
    if "1.3" in v:
        return 1.0
    return 0.0  # plaintext / unknown


def _cipher_score(cipher, fs):
    c = (cipher or "").upper()
    if not c or c == "—":
        return 0.0
    s = 1.0
    if "RC4" in c:
        s -= 0.55
    if "3DES" in c or "DES" in c:
        s -= 0.45
    if "MD5" in c:
        s -= 0.4
    if "GCM" in c or "CHACHA20" in c:
        s += 0.0
    elif "CBC" in c or c.endswith("-SHA") or "SHA1" in c:
        s -= 0.2
    if not fs:
        s -= 0.25
    return max(0.0, s)


def _cert_score(cert):
    if not cert:
        return 0.1
    s = 1.0
    if cert.get("status") == "EXPIRED":
        s -= 0.6
    elif cert.get("status") == "UNTRUSTED":
        s -= 0.55
    klen = cert.get("key_len", 2048)
    if cert.get("key_alg") == "RSA" and klen < 2048:
        s -= 0.3
    sig = (cert.get("sig_alg") or "").upper()
    if "SHA1" in sig:
        s -= 0.25
    if "MD5" in sig:
        s -= 0.45
    return max(0.0, s)


def _starttls_score(sess, starttls_by_session):
    ev = starttls_by_session.get(sess["id"])
    if ev and ev.get("advertised") and not ev.get("negotiated"):
        return 0.0          # stripping / failed transition
    if sess.get("tls") == "PLAINTEXT":
        return 0.0
    if sess.get("tls") == "STARTTLS":
        return 1.0
    return 0.85             # implicit TLS assumed healthy


# ------------------------------------------------------------ classification -
def classify_session(sess, cert, starttls_by_session):
    """Return AI assessment dict for one session."""
    feats = {
        "TLS Version": sess.get("tls_version") or "NONE (plaintext)",
        "Cipher Strength": sess.get("cipher") or "NONE",
        "Certificate Status": (cert.get("status") if cert else "NONE"),
        "Forward Secrecy": "Yes" if sess.get("forward_secrecy") else "No",
        "STARTTLS Behavior": ("FAILED TRANSITION" if _starttls_score(sess, starttls_by_session) == 0.0
                              else ("NEGOTIATED" if sess.get("tls") == "STARTTLS" else "IMPLICIT TLS")),
        "Anomaly Indicators": len(sess.get("anomaly", {}).get("detected", [])),
    }
    vec = (
        0.30 * _tls_version_score(sess.get("tls_version"))
        + 0.25 * _cipher_score(sess.get("cipher"), sess.get("forward_secrecy"))
        + 0.20 * _cert_score(cert)
        + 0.15 * _starttls_score(sess, starttls_by_session)
        + 0.10 * max(0.0, 1.0 - sess.get("anomaly", {}).get("score", 0) / 100.0)
    )

    if vec >= 0.85:
        cls, conf = "SECURE", 96
    elif vec >= 0.70:
        cls, conf = "LOW", 90
    elif vec >= 0.50:
        cls, conf = "MODERATE", 88
    elif vec >= 0.30:
        cls, conf = "HIGH", 92
    else:
        cls, conf = "CRITICAL", 95

    reasons = []
    if _tls_version_score(sess.get("tls_version")) < 0.4:
        reasons.append("deprecated TLS version")
    if _cipher_score(sess.get("cipher"), sess.get("forward_secrecy")) < 0.6:
        reasons.append("weak cipher selection")
    if _cert_score(cert) < 0.6:
        reasons.append("certificate irregularities")
    if _starttls_score(sess, starttls_by_session) == 0.0:
        reasons.append("failed STARTTLS transition")
    if sess.get("anomaly", {}).get("score", 0) >= 60:
        reasons.append("elevated anomaly indicators")
    reason = ("; ".join(reasons).capitalize() + ".") if reasons else \
        "Modern TLS configuration with valid certificate and forward secrecy."

    # priority mapping
    prio = {"CRITICAL": "P1", "HIGH": "P1", "MODERATE": "P2",
            "LOW": "P3", "SECURE": "P4"}[cls]
    prio_reason = {
        "P1": "Potentially exploitable cryptographic weakness affecting email confidentiality.",
        "P2": "Legacy configuration reducing cryptographic assurance; remediate in normal cycle.",
        "P3": "Minor deviations from best practice; monitor.",
        "P4": "No significant cryptographic risk detected.",
    }[prio]

    # confidence nudged deterministically by feature consistency
    conf = min(98, conf + (2 if len(reasons) >= 2 else 0))

    return {
        "features": feats,
        "vector": round(vec, 3),
        "risk_class": cls,
        "confidence": conf,
        "reason": reason,
        "priority": prio,
        "priority_reason": prio_reason,
        "note": "Assist layer: deterministic feature scoring over TLS version, cipher strength, certificate status, forward secrecy and STARTTLS behavior.",
    }


def attach_ai(sessions, certs, starttls_events):
    certs_by_id = {c["id"]: c for c in certs}
    st_by = {e["session"]: e for e in starttls_events}
    for s in sessions:
        s["ai"] = classify_session(s, certs_by_id.get(s.get("cert")), st_by)
    return sessions
