"""SecureMailScope — SOC/SIEM integration exports (ROADMAP PHASE 7).

Deterministic feeds over the current analysis result:

- STIX 2.1 bundle: network-traffic / domain-name / email-addr / x509-certificate
  observations plus custom `securemailscope:finding` objects carrying severity,
  rule id, and posture context — ingestable by OpenCTI, MISP, Splunk ES, etc.
- Findings CSV: flat, SIEM-friendly key-value rows (one per consolidated finding).

Passive-only: every IOC is extracted from the analyzed capture itself —
SNI/destination hostnames, certificate subjects, sender addresses observed in
the cleartext phase of plaintext sessions. Nothing is probed or resolved.

STIX timestamps are derived from the analysis timestamp (not wall-clock) so the
same result always produces byte-identical output.
"""
import csv
import io

SEV_STIX_LABELS = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


# ------------------------------------------------------------- IOC extraction --
def extract_iocs(result):
    """Deterministic IOC extraction from an analysis result."""
    domains = set()
    ips = set()
    emails = set()
    cert_fps = {}
    for s in result.get("sessions", []):
        dst = s.get("dst") or ""
        if "." in dst and not dst.replace(".", "").isdigit():
            domains.add(dst.lower())
        elif dst:
            ips.add(dst)
        cert = s.get("certificate")
        if cert and cert.get("status") != "VALID":
            subj = cert.get("subject") or ""
            cn = subj.split("CN=")[-1].split(",")[0].strip().lower() if "CN=" in subj else subj.lower()
            if cn and "." in cn:
                domains.add(cn)
            # stable pseudo-fingerprint: analysis-unique cert id + key material
            cid = cert.get("id") or "CERT"
            cert_fps[f"{cid}:{cert.get('key_alg')}:{cert.get('key_len')}"] = cert
    notes = result.get("notes") or ""
    import re
    for m in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", notes):
        emails.add(m.lower())
    return {"domains": sorted(domains), "ips": sorted(ips),
            "emails": sorted(emails), "certs": cert_fps}


# ------------------------------------------------------------------- STIX ----
def _stix_ts(analyzed_at):
    """'2026-09-26' → RFC-3330 UTC stamp at 12:00Z (analysis-derived, stable)."""
    return f"{analyzed_at}T12:00:00.000Z"


def build_stix(result):
    """STIX 2.1 bundle (dict) over the analyzed result. Deterministic."""
    r = result.get("risk", {})
    analyzed = result.get("analyzed_at") or "1970-01-01"
    created = _stix_ts(analyzed)
    iocs = extract_iocs(result)
    objects = []
    sid_by = {}

    # identity: the tool
    tool_id = "identity--a7f3c1d2-0000-4000-8000-5e4c00000001"
    objects.append({
        "type": "identity", "spec_version": "2.1", "id": tool_id,
        "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
        "name": "SecureMailScope", "roles": ["analyzer"],
        "identity_class": "system",
    })

    # x509 certificates (sighting metadata via custom props)
    for fp, cert in iocs["certs"].items():
        cid = "x509-certificate--" + _uuid5(fp)
        objects.append({
            "type": "x509-certificate", "spec_version": "2.1", "id": cid,
            "created": created, "modified": created,
            "issuer": cert.get("issuer", ""),
            "validity_not_before": (cert.get("valid_from") or "") + "T00:00:00.000Z",
            "validity_not_after": (cert.get("valid_until") or "") + "T23:59:59.000Z",
            "subject": cert.get("subject", ""),
            "x_sms_status": cert.get("status", ""),
            "x_sms_key_alg": cert.get("key_alg", ""),
            "x_sms_key_len": cert.get("key_len", 0),
        })

    # network-traffic observations per session (endpoints + TLS context)
    ip_values = {}                                    # stix id → literal IP
    for s in result.get("sessions", []):
        sid = "network-traffic--" + _uuid5(f"sess:{s.get('id')}:{analyzed}")
        sid_by[s.get("id")] = sid
        src_ref = "ipv4-addr--" + _uuid5(f"ip:{s.get('src')}")
        ip_values[src_ref] = s.get("src")
        nt = {
            "type": "network-traffic", "spec_version": "2.1", "id": sid,
            "created": created, "modified": created,
            "src_ref": src_ref,
            "protocols": ["ipv4", "tcp"],
            "src_port": int(s.get("src_port") or 0),
            "dst_port": int(s.get("dst_port") or 0),
            "x_sms_session": s.get("id"),
            "x_sms_protocol": s.get("protocol"),
            "x_sms_tls_mode": s.get("tls"),
            "x_sms_tls_version": s.get("tls_version"),
            "x_sms_cipher": s.get("cipher"),
            "x_sms_anomaly_score": int(s.get("anomaly", {}).get("score", 0)),
        }
        dst = s.get("dst") or ""
        if dst.replace(".", "").isdigit():
            dst_ref = "ipv4-addr--" + _uuid5(f"ip:{dst}")
            ip_values[dst_ref] = dst
            nt["dst_ref"] = dst_ref
        else:
            nt["x_sms_dst_hostname"] = dst
        objects.append(nt)
    for ref, val in sorted(ip_values.items()):        # sorted → deterministic order
        objects.append({
            "type": "ipv4-addr", "spec_version": "2.1", "id": ref,
            "created": created, "modified": created, "value": val,
        })

    # domains / emails as observables
    for d in iocs["domains"]:
        objects.append({
            "type": "domain-name", "spec_version": "2.1",
            "id": "domain-name--" + _uuid5(f"domain:{d}"),
            "created": created, "modified": created, "value": d,
        })
    for e in iocs["emails"]:
        objects.append({
            "type": "email-addr", "spec_version": "2.1",
            "id": "email-addr--" + _uuid5(f"email:{e}"),
            "created": created, "modified": created, "value": e,
        })

    # findings as custom objects, severity-ordered (deterministic input order)
    for f in result.get("findings", []):
        objects.append({
            "type": "x-sms-finding", "spec_version": "2.1",
            "id": "x-sms-finding--" + _uuid5(f"{f['rule_id']}|{f['title']}|{analyzed}"),
            "created": created, "modified": created,
            "name": f"{f['rule_id']}: {f['title']}",
            "severity": f["severity"],
            "labels": [SEV_STIX_LABELS.get(f["severity"], "low")],
            "confidence": int({"CRITICAL": 95, "HIGH": 90, "MEDIUM": 80, "LOW": 70}[f["severity"]]),
            "description": " ".join(f.get("evidence", [])[:3]),
            "x_sms_impact": f.get("impact", ""),
            "x_sms_recommendation": f.get("recommendation", ""),
            "x_sms_sessions": f.get("sessions", []),
            "x_sms_session_refs": [sid_by[x] for x in f.get("sessions", []) if x in sid_by],
        })

    # one report object summarizing the run
    objects.append({
        "type": "report", "spec_version": "2.1",
        "id": "report--" + _uuid5(f"report:{result.get('scenario_id')}:{analyzed}"),
        "created": created, "modified": created,
        "name": f"SecureMailScope posture — {result.get('meta', {}).get('name', 'analysis')}",
        "published": created,
        "report_types": ["cryptographic-posture"],
        "description": (f"Posture {r.get('score')}/100 ({r.get('band')}); "
                        f"{len(result.get('findings', []))} consolidated findings; "
                        f"{len(result.get('sessions', []))} sessions analyzed."),
        "object_refs": [o["id"] for o in objects if o.get("id") != tool_id][:200],
        "created_by_ref": tool_id,
    })

    return {
        "type": "bundle", "id": "bundle--" + _uuid5(f"bundle:{analyzed}:{r.get('score')}"),
        "objects": objects,
    }


def _uuid5(seed):
    """Deterministic UUIDv5 id (namespaced, stable across runs)."""
    import uuid
    return str(uuid.uuid5(uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"), seed))


# -------------------------------------------------------------------- CSV ----
def build_findings_csv(result):
    """Flat SIEM-ready CSV: one row per consolidated finding."""
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    r = result.get("risk", {})
    w.writerow(["# SecureMailScope findings feed",
                f"posture={r.get('score')}/100", f"band={r.get('band')}",
                f"analyzed={result.get('analyzed_at', '')}",
                f"source={result.get('meta', {}).get('file_label', '')}"])
    w.writerow(["rule_id", "title", "severity", "affected_sessions",
                "protocol", "evidence", "impact", "recommendation", "status"])
    for f in result.get("findings", []):
        w.writerow([
            f.get("rule_id", ""), f.get("title", ""), f.get("severity", ""),
            ";".join(f.get("sessions", [])), f.get("protocol") or "",
            " | ".join(f.get("evidence", [])),
            f.get("impact", ""), f.get("recommendation", ""), f.get("status", ""),
        ])
    return buf.getvalue()
