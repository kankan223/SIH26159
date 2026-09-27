"""SecureMailScope — capture comparison (before/after evidence).

Deterministic diff between two analysis results. Pure functions; the UI
renders the payload. Typical use: analyze → remediate → re-analyze →
compare, proving the fix moved the number.
"""

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _fkey(f):
    """Finding identity: rule_id | title | object."""
    return f["rule_id"] + "|" + f["title"] + "|" + str(f.get("object"))


def _row(f):
    return {"rule_id": f["rule_id"], "title": f["title"], "severity": f["severity"],
            "object": f.get("object"), "affected_count": f.get("affected_count", 0)}


def _summary(r):
    m = r.get("meta", {})
    return {
        "scenario_id": r.get("scenario_id"),
        "source": m.get("source", "evaluation"),
        "file_label": m.get("file_label", ""),
        "name": m.get("name", ""),
        "score": r["risk"]["score"],
        "band": r["risk"]["band"],
        "counts": dict(r["risk"]["counts"]),
        "sessions": r["session_stats"]["total"],
        "plaintext": r["session_stats"]["plaintext"],
        "ml_flagged": sum(1 for s in r["sessions"]
                          if s.get("anomaly_ml", {}).get("available")
                          and s["anomaly_ml"].get("note") == "outlier"),
    }


def diff_results(before, after):
    """Two analysis results → structured diff payload (deterministic)."""
    rb, ra = before["risk"], after["risk"]
    fb = {_fkey(f) for f in before["findings"]}
    fa = {_fkey(f) for f in after["findings"]}
    new = [f for f in after["findings"] if _fkey(f) not in fb]
    resolved = [f for f in before["findings"] if _fkey(f) not in fa]
    sb_sum, sa_sum = _summary(before), _summary(after)

    return {
        "before": sb_sum,
        "after": sa_sum,
        "score_delta": ra["score"] - rb["score"],
        "counts_delta": {k: ra["counts"].get(k, 0) - rb["counts"].get(k, 0)
                         for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "new_findings": [_row(f) for f in new],
        "resolved_findings": [_row(f) for f in resolved],
        "session_changes": _session_changes(before, after),
        "ml_delta": {"before": sb_sum["ml_flagged"], "after": sa_sum["ml_flagged"]},
    }


def _session_changes(before, after):
    """Per-session diffs keyed by session id (stable SES-00n numbering)."""
    sb = {s["id"]: s for s in before["sessions"]}
    sa = {s["id"]: s for s in after["sessions"]}
    out = []
    for sid in sorted(set(sb) | set(sa)):
        b, a = sb.get(sid), sa.get(sid)
        if b and not a:
            out.append({"id": sid, "change": "removed",
                        "risk_before": b["risk"]["score"], "risk_after": None})
        elif a and not b:
            out.append({"id": sid, "change": "added",
                        "risk_before": None, "risk_after": a["risk"]["score"]})
        else:
            fields = {}
            for k in ("tls", "tls_version", "cipher", "forward_secrecy"):
                if (b.get(k) or "") != (a.get(k) or ""):
                    fields[k] = [b.get(k), a.get(k)]
            delta = a["risk"]["score"] - b["risk"]["score"]
            if fields or delta:
                out.append({"id": sid, "change": "changed", "fields": fields,
                            "risk_before": b["risk"]["score"],
                            "risk_after": a["risk"]["score"], "risk_delta": delta})
    return out
