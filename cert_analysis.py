"""SecureMailScope — X.509 certificate analysis for parsed captures.

Parses DER certificates (extracted from TLS Certificate handshake messages by
tls_parser) into the exact schema the deterministic rule engine and UI already
consume: subject/issuer/valid_from/valid_until/key_alg/key_len/sig_alg/status/
san/days_expired.

Uses the `cryptography` library when available; without it, certificates are
reported as UNPARSED (analysis degrades gracefully — never crashes, never
invents values). No network revocation checks: passive analysis only.
"""
import datetime
import hashlib
import ipaddress

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    HAVE_CRYPTO = True
except ImportError:      # degraded mode: fingerprints only
    HAVE_CRYPTO = False


def _fingerprint(der):
    return "SHA1:" + hashlib.sha1(der).hexdigest()[:16].upper()


def _san_string(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return ""
    parts = []
    for gn in ext.value:
        if isinstance(gn, x509.DNSName):
            parts.append(gn.value)
        elif isinstance(gn, x509.IPAddress):
            parts.append(str(gn.value))
    return ", ".join(parts[:8])


def _sig_alg_name(cert):
    """Signature algorithm OID → readable name (matches dataset vocabulary)."""
    try:
        alg = cert.signature_algorithm_oid
    except Exception:
        return "UNKNOWN"
    names = {
        "1.2.840.113549.1.1.5": "SHA1withRSA",
        "1.2.840.113549.1.1.11": "SHA256withRSA",
        "1.2.840.113549.1.1.12": "SHA384withRSA",
        "1.2.840.113549.1.1.13": "SHA512withRSA",
        "1.2.840.113549.1.1.4": "MD5withRSA",
        "1.2.840.10045.4.3.2": "SHA256withECDSA",
        "1.2.840.10045.4.3.3": "SHA384withECDSA",
        "1.2.840.10045.4.3.4": "SHA512withECDSA",
        "1.2.840.10045.4.1": "SHA1withECDSA",
    }
    return names.get(alg.dotted_string, f"OID:{alg.dotted_string}")


def _key_info(cert):
    """(key_alg, key_len) in the engine's vocabulary: RSA / ECDSA / other."""
    try:
        pk = cert.public_key()
    except Exception:
        return "UNKNOWN", 0
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA", pk.key_size
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return "ECDSA", pk.curve.key_size
    return "UNKNOWN", 0


def parse_cert(der, today=None):
    """One DER blob → engine-schema cert dict. Never raises."""
    today = today or datetime.date.today()
    if not HAVE_CRYPTO:
        return {"subject": _fingerprint(der), "issuer": "unparsed (cryptography library unavailable)",
                "valid_from": "", "valid_until": "", "key_alg": "UNKNOWN", "key_len": 0,
                "sig_alg": "UNKNOWN", "status": "UNPARSED", "days_expired": 0, "san": ""}
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return {"subject": _fingerprint(der), "issuer": "unparseable DER",
                "valid_from": "", "valid_until": "", "key_alg": "UNKNOWN", "key_len": 0,
                "sig_alg": "UNKNOWN", "status": "UNPARSED", "days_expired": 0, "san": ""}

    try:
        subject = cert.subject.rfc4514_string()
    except Exception:
        subject = "unknown"
    try:
        issuer = cert.issuer.rfc4514_string()
    except Exception:
        issuer = "unknown"

    not_before = cert.not_valid_before_utc.date()
    not_after = cert.not_valid_after_utc.date()

    # status semantics identical to the evaluation datasets (rules.py consumes these)
    if today > not_after:
        status = "EXPIRED"
        days = (today - not_after).days
    elif today < not_before:
        status = "NOT_YET_VALID"
        days = 0
    elif subject == issuer:
        status = "UNTRUSTED"          # self-signed
        days = 0
    else:
        status = "VALID"
        days = 0

    key_alg, key_len = _key_info(cert)
    return {
        "subject": subject or "(empty subject)",
        "issuer": issuer or "(empty issuer)",
        "valid_from": not_before.isoformat(),
        "valid_until": not_after.isoformat(),
        "key_alg": key_alg,
        "key_len": key_len,
        "sig_alg": _sig_alg_name(cert),
        "status": status,
        "days_expired": days,
        "san": _san_string(cert),
    }


def dedupe_certs(chain, existing=None, prefix="CERT"):
    """Parse a DER chain into engine-schema dicts, deduped by DER fingerprint
    against `existing` (list of already-issued cert dicts, mutated in place).
    Returns (cert_dicts_for_this_chain, existing)."""
    existing = existing if existing is not None else []
    known = {}
    for c in existing:
        fp = c.get("_fp")
        if fp:
            known.setdefault(fp, c)
    out = []
    n = len(existing)
    for der in chain[:4]:                       # leaf + up to 3 intermediates
        fp = hashlib.sha256(der).hexdigest()[:16].upper()
        if fp in known:
            out.append(known[fp])
            continue
        info = parse_cert(der)
        info["_fp"] = fp
        n += 1
        info["id"] = f"{prefix}-{n}"
        existing.append(info)
        known[fp] = info
        out.append(info)
    return out, existing
