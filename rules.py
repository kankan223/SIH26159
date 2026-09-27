"""SecureMailScope — deterministic cryptographic weakness rule engine.

Rules are aligned with RFC 8314, NIST SP 800-52 Rev.2 and the NSA
"Eliminating Obsolete TLS" guidance (see research.md).
"""
from datetime import date

# ---------------------------------------------------------------- severity ---
CRITICAL, HIGH, MEDIUM, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"

OBSOLETE_VERSIONS = {"SSLv3": CRITICAL, "SSLv2": CRITICAL}
DEPRECATED_VERSIONS = {"TLS 1.0": HIGH, "TLS 1.1": HIGH}

WEAK_CIPHERS = {
    "RC4": CRITICAL,        # RFC 7465 prohibited, biases exploited
    "3DES": HIGH,           # Sweet32 (64-bit block)
    "DES": HIGH,
    "IDEA": HIGH,
    "NULL": CRITICAL,
    "EXP": CRITICAL,        # export-grade
    "MD5": CRITICAL,
}

# Legacy CBC-SHA1 suites (no AEAD) — medium severity
LEGACY_CBC_TOKENS = ("CBC", "-SHA", "SHA1")

MIN_RSA_KEY_LEN = 2048       # NIST SP 800-57
MIN_EC_KEY_LEN = 256
WEAK_SIG_TOKENS = ("SHA1", "MD5")

PENALTIES = {CRITICAL: 30, HIGH: 20, MEDIUM: 10, LOW: 5}


# ---------------------------------------------------------------- helpers ----
def _version_finding(sess):
    v = (sess.get("tls_version") or "").upper()
    for name, sev in OBSOLETE_VERSIONS.items():
        if name.upper() in v:
            return sev, f"Obsolete protocol version {name} negotiated."
    for name, sev in DEPRECATED_VERSIONS.items():
        if name.upper() in v:
            return sev, f"Deprecated protocol version {name} negotiated."
    return None, None


def _cipher_findings(sess):
    out = []
    c = (sess.get("cipher") or "").upper()
    if not c or c == "—":
        return out
    for token, sev in WEAK_CIPHERS.items():
        if token in c:
            out.append((sev, f"Cipher suite contains weak component {token}.", None))
    return out


def _cert_findings(sess, certs_by_id, today):
    out = []
    cert = certs_by_id.get(sess.get("cert"))
    if not cert:
        return out
    subj = cert.get("subject", "unknown")
    if cert.get("status") == "EXPIRED":
        days = cert.get("days_expired", 0)
        out.append((HIGH, f"Certificate '{subj}' expired {days} days ago.", subj))
    elif cert.get("status") == "UNTRUSTED":
        out.append((HIGH, f"Certificate '{subj}' issued by untrusted/self-signed issuer.", subj))
    klen = cert.get("key_len", 0)
    if cert.get("key_alg") == "RSA" and klen < MIN_RSA_KEY_LEN:
        out.append((HIGH, f"Certificate '{subj}' RSA key length {klen} < {MIN_RSA_KEY_LEN} bits.", subj))
    elif cert.get("key_alg") == "ECDSA" and klen < MIN_EC_KEY_LEN:
        out.append((HIGH, f"Certificate '{subj}' EC key length {klen} < {MIN_EC_KEY_LEN} bits.", subj))
    sig = (cert.get("sig_alg") or "").upper()
    for tok in WEAK_SIG_TOKENS:
        if tok in sig:
            out.append((HIGH if tok == "SHA1" else CRITICAL,
                        f"Certificate '{subj}' signature uses weak hash {tok}.", subj))
    return out


def _session_findings(sess):
    out = []
    if sess.get("tls") == "PLAINTEXT":
        out.append((CRITICAL, "Email session transmitted without any encryption (plaintext).", None))
    return out


# ---------------------------------------------------------------- engine -----
def evaluate_session(sess, certs_by_id, today=None):
    """Return list of finding dicts for one session (deduped within session)."""
    today = today or date.today()
    findings = []

    sev, ev = _version_finding(sess)
    version_flagged = sev is not None
    if sev:
        findings.append(dict(rule_id="TLS-001", title="Deprecated TLS Version",
                             severity=sev, evidence=ev, object=None,
                             impact="Session exposed to known protocol-level cryptographic weaknesses.",
                             recommendation="Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2 or newer (RFC 8314)."))
    for sev, ev, obj in _cipher_findings(sess):
        findings.append(dict(rule_id="CIPH-001", title="Weak Cipher Suite",
                             severity=sev, evidence=ev, object=obj,
                             impact="Confidentiality of email content can be broken with feasible attacks (Sweet32 / RC4 biases).",
                             recommendation="Configure AEAD suites (AES-GCM / ChaCha20) and disable 3DES, RC4, NULL, export ciphers."))
    for sev, ev, obj in _cert_findings(sess, certs_by_id, today):
        findings.append(dict(rule_id="CERT-001", title="Certificate Weakness",
                             severity=sev, evidence=ev, object=obj,
                             impact="Identity assurance lost; enables interception or impersonation of the mail endpoint.",
                             recommendation="Renew certificate, use ≥2048-bit RSA / ≥256-bit EC keys and SHA-256 signatures."))
    for sev, ev, obj in _session_findings(sess):
        findings.append(dict(rule_id="SESS-001", title="Insecure Transport",
                             severity=sev, evidence=ev, object=obj,
                             impact="Email content readable by anyone on the network path.",
                             recommendation="Enforce TLS on all mail ports; reject plaintext fallback (MTA-STS / DANE recommended)."))
    # forward secrecy (separate rule so it consolidates independently)
    if sess.get("tls") != "PLAINTEXT" and sess.get("forward_secrecy") is False \
            and sess.get("key_exchange") == "RSA":
        findings.append(dict(rule_id="SESS-002", title="No Forward Secrecy",
                             severity=MEDIUM,
                             evidence="Static RSA key exchange — past traffic recoverable if the private key is compromised.",
                             object=None,
                             impact="Recorded sessions can be decrypted retroactively.",
                             recommendation="Enable ECDHE key exchange and disable static RSA suites."))

    # dedupe within session (rule_id + title + object)
    seen, uniq = set(), []
    for f in findings:
        key = (f["rule_id"], f["title"], f.get("object"))
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


def attach_findings(sessions, certs, today=None):
    """Attach per-session findings lists. Returns (sessions, per_session_findings)."""
    today = today or date.today()
    certs_by_id = {c["id"]: c for c in certs}
    all_findings = []
    for s in sessions:
        fs = evaluate_session(s, certs_by_id, today)
        for f in fs:
            f = dict(f)
            f["session"] = s["id"]
            f["protocol"] = s.get("protocol")
            f["status"] = "OPEN"
            all_findings.append(f)
        s["findings"] = [f"{f['rule_id']}: {f['title']}" for f in fs]
    return sessions, all_findings


SEV_RANK = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}


def consolidate_findings(per_session_findings):
    """Aggregate per-session findings into one finding per distinct weakness
    (rule_id + title + object). Severity = max occurrence. Evidence lines are
    the unique evidence strings (capped). Used for global scoring & display."""
    groups = {}
    for f in per_session_findings:
        key = (f["rule_id"], f["title"], f.get("object"))
        g = groups.setdefault(key, {
            "rule_id": f["rule_id"], "title": f["title"],
            "severity": f["severity"], "object": f.get("object"),
            "evidence": [], "impact": f["impact"],
            "recommendation": f["recommendation"],
            "sessions": [], "protocol": f.get("protocol"),
            "status": "OPEN",
        })
        if SEV_RANK[f["severity"]] < SEV_RANK[g["severity"]]:
            g["severity"] = f["severity"]
        if f["evidence"] not in g["evidence"]:
            g["evidence"].append(f["evidence"])
        if f["session"] not in g["sessions"]:
            g["sessions"].append(f["session"])
    out = []
    for g in groups.values():
        n = len(g["sessions"])
        g["affected_count"] = n
        g["evidence"] = g["evidence"][:6]
        g["summary"] = f"{g['title']} — affects {n} session(s)" + \
            (f" ({g['object']})" if g.get("object") else "")
        out.append(g)
    out.sort(key=lambda g: SEV_RANK[g["severity"]])
    return out
