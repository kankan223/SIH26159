#!/usr/bin/env python3
"""SecureMailScope — end-to-end HTTP verification of the real upload pipeline.

Run with the server already up on 127.0.0.1:5000 (or set SMS_BASE):
    .venv/bin/python tests/e2e_upload.py
"""
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("SMS_BASE", "http://127.0.0.1:5000")
HERE = os.path.dirname(__file__)

ok = fail = 0


def call(path, data=None, raw=None, headers=None):
    req = urllib.request.Request(BASE + path)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
    if raw is not None:
        body = raw
        for k, v in (headers or {}).items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, body) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def check(name, cond, extra=""):
    global ok, fail
    ok += cond
    fail += (not cond)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def multipart(filename, blob):
    return (b"------X\r\nContent-Disposition: form-data; name=\"pcap\"; filename=\""
            + filename.encode() + b"\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            + blob + b"\r\n------X--\r\n")


def main():
    # 1. golden scenario scores via /api/scenarios
    s, b = call("/api/scenarios")
    sc = {x["id"]: x for x in json.loads(b)["scenarios"]}
    check("scenarios endpoint", s == 200 and len(sc) == 6)
    for sid, exp in [("secure", 100), ("weak_tls", 60), ("starttls_downgrade", 0),
                     ("expired_certificate", 60), ("weak_cipher", 40), ("suspicious_tls", 20)]:
        check(f"golden {sid}", sc[sid]["expected_score"] == exp, str(sc[sid]["expected_score"]))

    # 2. analyze three scenarios through the full stack
    for sid, exp in [("secure", 100), ("starttls_downgrade", 0), ("weak_cipher", 40)]:
        s, b = call("/api/analyze", {"scenario_id": sid})
        d = json.loads(b)
        check(f"analyze {sid}", s == 200 and d["risk"]["score"] == exp, str(d.get("risk")))

    # 3. real upload — mixed capture
    blob = open(os.path.join(HERE, "mixed_ok.pcap"), "rb").read()
    s, b = call("/api/analyze?mode=upload", raw=multipart("mixed_ok.pcap", blob),
                headers={"Content-Type": "multipart/form-data; boundary=----X"})
    d = json.loads(b)
    ps = d.get("meta", {}).get("parse_stats", {})
    check("upload mixed 200", s == 200, str(d.get("error")))
    check("upload parsed packets", ps.get("packets") == 486, str(ps))
    check("upload sessions == 11", d["session_stats"]["total"] == 11, str(d.get("session_stats")))
    check("upload has findings", len(d.get("findings", [])) >= 4, str(len(d.get("findings", []))))
    check("upload meta.source", d.get("meta", {}).get("source") == "upload")
    check("upload strip detection",
          any("STRIPTLS" in x for ses in d["sessions"] for x in ses["anomaly"]["detected"]))
    check("upload tls13 session", any(ses["tls_version"] == "TLS 1.3" for ses in d["sessions"]))
    check("upload posture", d["risk"]["score"] == 0 and d["risk"]["band"] == "CRITICAL",
          str(d.get("risk")))
    check("upload ml field", all("anomaly_ml" in ses for ses in d["sessions"]))
    check("upload ml active", all(ses["anomaly_ml"]["available"] for ses in d["sessions"]))
    check("upload ml outliers on weak sessions",
          {ses["id"] for ses in d["sessions"] if ses["anomaly_ml"].get("note") == "outlier"}
          == {"SES-003", "SES-004"},
          str([ses["id"] for ses in d["sessions"] if ses["anomaly_ml"].get("note") == "outlier"]))
    check("upload stream viewer payload",
          any(ses.get("tls_stream", {}).get("client") or ses.get("tls_stream", {}).get("server")
              for ses in d["sessions"]))

    # --- SOC/SIEM exports over the uploaded capture ---
    s, b = call("/api/findings/export?format=stix")
    stix = json.loads(b)
    types = {o["type"] for o in stix.get("objects", [])}
    check("stix export 200", s == 200 and stix.get("type") == "bundle", str(s))
    check("stix has observations",
          {"network-traffic", "x509-certificate", "x-sms-finding", "report"} <= types, str(types))
    s, b2 = call("/api/findings/export?format=stix")
    check("stix deterministic per result", b == b2)
    s, b = call("/api/findings/export?format=csv")
    check("findings csv 200", s == 200 and b"rule_id,title,severity" in b, str(s))
    s, b = call("/api/history")
    hist = json.loads(b)["history"]
    check("history records upload", any(h["source"] == "upload" for h in hist), str(hist))
    if len(hist) >= 2:
        s, b = call("/api/compare", {"a": len(hist) - 2, "b": len(hist) - 1})
        cmp_d = json.loads(b)
        check("compare 200 + fields", s == 200 and all(
            k in cmp_d for k in ("score_delta", "new_findings", "resolved_findings",
                                 "session_changes", "ml_delta")), str(s))
    s, b = call("/api/compare", {"a": 0, "b": 999})
    check("compare out-of-range 400", s == 400, str(s))

    # 4. real upload — expired certificate capture
    blob2 = open(os.path.join(HERE, "expired_cert.pcap"), "rb").read()
    s, b = call("/api/analyze?mode=upload", raw=multipart("expired_cert.pcap", blob2),
                headers={"Content-Type": "multipart/form-data; boundary=----X"})
    d2 = json.loads(b)
    check("upload expired 200", s == 200, str(d2.get("error")))
    check("expired cert detected",
          any(c["status"] == "EXPIRED" for c in d2.get("certificates", [])),
          json.dumps(d2.get("certificates", []))[:120])
    check("expired finding", any("expired" in f["title"].lower()
                                 or "expired" in " ".join(f["evidence"]).lower()
                                 for f in d2["findings"]))

    # 5. rejection paths
    s, b = call("/api/analyze?mode=upload",
                raw=multipart("renamed.pcap", blob2),
                headers={"Content-Type": "multipart/form-data; boundary=----X"})
    check("content sniff wins over filename", s == 200, str(s))

    s, b = call("/api/analyze?mode=upload",
                raw=multipart("junk.pcap", b"\x00" * 2048),
                headers={"Content-Type": "multipart/form-data; boundary=----X"})
    check("junk pcap -> 400", s == 400, f"{s} {b[:80]}")

    gb = open(os.path.join(HERE, "garbage_records.pcap"), "rb").read()
    s, b = call("/api/analyze?mode=upload",
                raw=multipart("garbage_records.pcap", gb),
                headers={"Content-Type": "multipart/form-data; boundary=----X"})
    check("garbage records -> 400", s == 400, f"{s} {b[:80]}")

    s, b = call("/api/analyze?mode=upload",
                raw=multipart("notes.txt", b"hello world " + b"x" * 2000),
                headers={"Content-Type": "multipart/form-data; boundary=----X"})
    check("txt upload -> 400", s == 400, str(s))

    # 6. reports over the last successful upload result
    s, b = call("/api/report/html")
    check("report html 200", s == 200 and b"SecureMailScope" in b)
    check("report html operator chip",
          b"OPERATOR CAPTURE" in b and b"Fully parsed on-engine" in b)
    s, b = call("/api/report/json")
    dj = json.loads(b)
    check("report json parse_stats", dj.get("parse_stats", {}).get("packets") == 7,
          str(dj.get("parse_stats")))

    # 7. audit trail recorded upload events
    s, b = call("/api/settings")
    evs = [e["event"] for e in json.loads(b)["audit"]]
    check("audit analysis_run", "analysis_run" in evs)
    check("audit upload_rejected", "upload_rejected" in evs)

    # 8. security headers on shell responses
    req = urllib.request.Request(BASE + "/")
    with urllib.request.urlopen(req) as r:
        check("CSP header", "default-src 'self'" in r.headers.get("Content-Security-Policy", ""))
        check("nosniff header", r.headers.get("X-Content-Type-Options") == "nosniff")

    print(f"\n{ok} passed, {fail} failed")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
