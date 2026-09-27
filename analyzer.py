"""SecureMailScope — analysis pipeline orchestrator.

Pipeline: input → protocol detection → session reconstruction → TLS/STARTTLS
analysis → certificate analysis → rule engine → risk scoring → AI layer →
anomaly enrichment. Deterministic for a given input.
"""
import json
import os
from datetime import date

from rules import attach_findings, consolidate_findings
from risk_engine import compute_risk
from ai_assist import attach_ai
import anomaly

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# ---------------------------------------------------------------- scenarios --
def list_scenarios():
    out = []
    for fn in sorted(os.listdir(DATA_DIR)):
        if fn.endswith(".json"):
            with open(os.path.join(DATA_DIR, fn)) as f:
                d = json.load(f)
            out.append({
                "id": fn[:-5],
                "name": d["meta"]["name"],
                "file_label": d["meta"].get("file_label", fn),
                "size_hint": d["meta"].get("size_hint", ""),
                "description": d["meta"].get("description", ""),
            })
    return out


def load_scenario(scenario_id):
    path = os.path.join(DATA_DIR, f"{scenario_id}.json")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Unknown scenario: {scenario_id}")
    with open(path) as f:
        return json.load(f)


# ------------------------------------------------------------ pcap upload ----
PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",  # pcap
               b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # pcap (nano)
               b"\x0a\x0d\x0d\x0a")                      # pcapng


def validate_pcap(filename, blob):
    """Return (ok, message). Accepts pcap/pcapng magic; size sanity 1KB–50MB."""
    if not filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        return False, "Unsupported file type — upload a .pcap, .pcapng or .cap capture."
    if len(blob) < 1024:
        return False, "File too small to be a valid capture (< 1 KB)."
    if len(blob) > 50 * 1024 * 1024:
        return False, "Capture exceeds the 50 MB prototype limit."
    if blob[:4] not in PCAP_MAGICS:
        return False, "Not a valid PCAP/PCAPng file (magic bytes missing)."
    size = f"{(len(blob)/1024/1024):.1f} MB" if len(blob) >= 1024*1024 else f"{(len(blob)/1024):.0f} KB"
    return True, f"{filename} validated — {size} capture."


# ---------------------------------------------------------------- pipeline ---
def run_pipeline(scenario_id, today=None):
    """Full deterministic analysis of an evaluation scenario."""
    return analyze_document(load_scenario(scenario_id), scenario_id=scenario_id, today=today)


def analyze_document(doc, scenario_id=None, today=None):
    """Run the deterministic engine over a dataset-shaped document
    (from data/*.json or reconstructed from an uploaded capture by
    upload_pipeline.build_document). Returns the complete result document.
    Shared by both input paths so scoring logic never diverges."""
    today = today or date.today()
    data = doc
    sessions = json.loads(json.dumps(data["sessions"]))   # deep copy
    certs = data["certificates"]
    starttls_events = data.get("starttls_events", [])
    certs_by_id = {c["id"]: c for c in certs}
    scenario_id = (scenario_id or data.get("meta", {}).get("scenario_id")
                   or data.get("meta", {}).get("file_label") or "document")

    # enrich sessions with cert + scenario refs
    for s in sessions:
        s["cert_ref"] = s.get("cert")
        cert = certs_by_id.get(s.get("cert"))
        s["certificate"] = dict(cert) if cert else None

    # rule engine + risk
    sessions, per_session_findings = attach_findings(sessions, certs, today)

    # consolidate to one finding per distinct weakness for scoring & display
    findings = consolidate_findings(per_session_findings)

    # per-session risk (raw per-session findings, transparent formula)
    for s in sessions:
        rf = compute_risk([f for f in per_session_findings if f["session"] == s["id"]])
        s["risk"] = rf

    # AI layer + anomaly enrichment
    sessions = attach_ai(sessions, certs, starttls_events)
    sessions = anomaly.detect(sessions, starttls_events)

    # overall posture (consolidated findings, no double-penalty per session)
    risk = compute_risk(findings)

    # protocol distribution with confidence
    protocols = data.get("protocols", [])

    # TLS version + cipher-security distributions
    tls_versions, cipher_sec = {}, {"STRONG": 0, "LEGACY": 0, "WEAK": 0, "NONE": 0}
    for s in sessions:
        v = s.get("tls_version") or "NONE"
        tls_versions[v] = tls_versions.get(v, 0) + 1
        c = (s.get("cipher") or "").upper()
        if s.get("tls") == "PLAINTEXT" or not c or c == "—":
            cipher_sec["NONE"] += 1
        elif "RC4" in c or "3DES" in c or "MD5" in c or "EXP" in c or "NULL" in c:
            cipher_sec["WEAK"] += 1
        elif "GCM" in c or "CHACHA20" in c:
            cipher_sec["STRONG"] += 1
        else:
            cipher_sec["LEGACY"] += 1

    # status classification
    secure_ct = sum(1 for s in sessions if s["risk"]["band"] in ("SECURE", "LOW RISK"))
    suspicious_ct = sum(1 for s in sessions
                        if s["anomaly"]["score"] >= 70 or s["risk"]["band"] in ("HIGH RISK", "CRITICAL"))

    return {
        "scenario_id": scenario_id,
        "meta": data["meta"],
        "analyzed_at": today.isoformat(),
        "protocols": protocols,
        "sessions": sessions,
        "certificates": certs,
        "findings": findings,
        "risk": risk,
        "tls_versions": tls_versions,
        "cipher_security": cipher_sec,
        "session_stats": {
            "total": len(sessions),
            "tls": sum(1 for s in sessions if s.get("tls") != "PLAINTEXT"),
            "plaintext": sum(1 for s in sessions if s.get("tls") == "PLAINTEXT"),
            "secure": secure_ct,
            "suspicious": suspicious_ct,
        },
        "notes": data.get("notes", ""),
    }
