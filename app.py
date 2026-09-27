"""SecureMailScope — Flask application (SIH26159)."""
import glob
import json
import os

from flask import Flask, Response, jsonify, render_template, request

import analyzer
import audit
import report as report_mod
import upload_pipeline
import siem
import compare

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 60 * 1024 * 1024  # 60 MB upload cap


@app.after_request
def _security_headers(resp):
    """Baseline hardening headers on every response (no external config needed)."""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
    return resp

# latest analysis kept in memory (prototype scope: single analyst session)
STATE = {"result": None}

# bounded analysis history for before/after comparison — persisted to
# config/history.json so the slots (and comparisons) survive server restarts
HISTORY = []
HISTORY_MAX = 12

# ------------------------------------------------------------ settings state --
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
CONFIG_DIR = os.path.join(os.path.dirname(__file__), "config")
SETTINGS_PATH = os.path.join(CONFIG_DIR, "settings.json")

SETTINGS_DEFAULT = {
    # evaluation = curated assessment captures; live = operator-supplied captures only
    "data_mode": "evaluation",
    # auto-generated report retention (accepts: session|7d|30d|90d|forever)
    "retention": "session",
}
RETENTION_VALUES = ("session", "7d", "30d", "90d", "forever")
SETTINGS = dict(SETTINGS_DEFAULT)

# ------------------------------------------------------------- history state --
HISTORY_PATH = os.path.join(CONFIG_DIR, "history.json")


def _remember(result):
    """Store an analysis snapshot for capture comparison (newest last), then persist."""
    HISTORY.append(result)
    del HISTORY[:-HISTORY_MAX]
    _save_history()


def _save_history():
    """Atomic write (tmp + os.replace) of the bounded history file.
    Best-effort: if the disk write fails, comparison still works in-session."""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        tmp = HISTORY_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(HISTORY, f)
        os.replace(tmp, HISTORY_PATH)
    except OSError:
        pass


def _load_history():
    """Restore persisted history at startup; corrupt/incomplete → start empty.
    Only well-formed results are kept so a hand-edit can't wedge compare."""
    if os.path.isfile(HISTORY_PATH):
        try:
            with open(HISTORY_PATH) as f:
                d = json.load(f)
            if isinstance(d, list):
                HISTORY[:] = [h for h in d if isinstance(h, dict)
                              and "risk" in h and "sessions" in h][-HISTORY_MAX:]
        except (OSError, ValueError):
            pass
    return HISTORY


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scenarios")
def api_scenarios():
    scen = analyzer.list_scenarios()
    for s in scen:
        # deterministic preview of the expected posture (pipelines are cheap on demo data)
        try:
            r = analyzer.run_pipeline(s["id"])
            s["expected_band"] = r["risk"]["band"]
            s["expected_score"] = r["risk"]["score"]
        except Exception:
            pass
    return jsonify({"scenarios": scen})


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    payload = request.get_json(silent=True) or {}
    mode = request.args.get("mode") or payload.get("mode")
    scenario_id = payload.get("scenario_id")

    if mode == "upload":
        f = request.files.get("pcap")
        if not f or not f.filename:
            audit.record("upload_rejected", "upload request contained no file")
            return jsonify({"error": "No PCAP file received."}), 400
        blob = f.read()
        ok, msg = analyzer.validate_pcap(f.filename, blob)
        if not ok:
            audit.record("upload_rejected", f"{f.filename} — {msg}")
            return jsonify({"error": msg}), 400
        try:
            result = upload_pipeline.run_upload(blob, f.filename)
        except upload_pipeline.UploadError as e:
            audit.record("upload_rejected", f"{f.filename} — {e}")
            return jsonify({"error": str(e)}), 400
        upload_note = msg
        src_label = f"upload '{f.filename}'"
    else:
        if not scenario_id:
            return jsonify({"error": "No scenario selected."}), 400
        try:
            result = analyzer.run_pipeline(scenario_id)
        except FileNotFoundError:
            return jsonify({"error": f"Unknown scenario '{scenario_id}'."}), 404
        upload_note = None
        src_label = f"capture '{scenario_id}'"

    if upload_note:
        result["meta"]["upload_note"] = upload_note
    STATE["result"] = result
    _remember(result)
    audit.record("analysis_run",
                 f"{src_label} — {len(result['sessions'])} sessions, "
                 f"posture {result['risk']['score']}/100 ({result['risk']['band']})")
    return jsonify(result)


@app.route("/api/findings/export")
def api_findings_export():
    """SOC/SIEM feed over the current analysis: STIX 2.1 bundle or findings CSV."""
    if not STATE.get("result"):
        return jsonify({"error": "Run an analysis first."}), 400
    result = STATE["result"]
    kind = (request.args.get("format") or "stix").lower()
    stamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
    if kind == "csv":
        body = siem.build_findings_csv(result)
        fname = f"securemailscope_findings_{stamp}.csv"
        audit.record("siem_export", f"findings CSV — {result['scenario_id']} ({len(result['findings'])} finding(s))")
        return Response(body, mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})
    bundle = siem.build_stix(result)
    body = json.dumps(bundle, indent=2)
    fname = f"securemailscope_stix_{stamp}.json"
    audit.record("siem_export",
                 f"STIX 2.1 bundle — {result['scenario_id']} ({len(bundle['objects'])} object(s))")
    return Response(body, mimetype="application/stix+json",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/api/history")
def api_history():
    """Snapshots available for capture comparison (oldest first)."""
    return jsonify({"history": [{
        "slot": i,
        "scenario_id": h.get("scenario_id"),
        "source": h.get("meta", {}).get("source", "evaluation"),
        "file_label": h.get("meta", {}).get("file_label", ""),
        "name": h.get("meta", {}).get("name", ""),
        "score": h["risk"]["score"], "band": h["risk"]["band"],
        "sessions": h["session_stats"]["total"],
    } for i, h in enumerate(HISTORY)]})


@app.route("/api/compare", methods=["POST"])
def api_compare():
    """Diff two history slots (a=before, b=after) — before/after evidence."""
    payload = request.get_json(silent=True) or {}
    try:
        a, b = int(payload.get("a")), int(payload.get("b"))
    except (TypeError, ValueError):
        return jsonify({"error": "history slots 'a' and 'b' required."}), 400
    if not (0 <= a < len(HISTORY) and 0 <= b < len(HISTORY)):
        return jsonify({"error": "history slot out of range."}), 400
    if a == b:
        return jsonify({"error": "select two different snapshots."}), 400
    d = compare.diff_results(HISTORY[a], HISTORY[b])
    audit.record("comparison_run",
                 f"slots {a} vs {b} — {d['before']['score']} → {d['after']['score']} "
                 f"({d['score_delta']:+d}), new {len(d['new_findings'])}, resolved {len(d['resolved_findings'])}")
    return jsonify(d)


@app.route("/api/report/html")
def api_report_html():
    if not STATE.get("result"):
        return jsonify({"error": "Run an analysis first."}), 400
    result = STATE["result"]
    report_mod.save_reports(result)
    html = report_mod.build_html(result)
    audit.record("report_export",
                 f"HTML forensic report — {result['scenario_id']} ({len(html) / 1024:.1f} KB)")
    return html


@app.route("/api/report/json")
def api_report_json():
    if not STATE.get("result"):
        return jsonify({"error": "Run an analysis first."}), 400
    result = STATE["result"]
    path, _ = report_mod.save_reports(result)
    with open(path) as f:
        data = json.load(f)
    audit.record("report_export", f"JSON report — {result['scenario_id']}")
    return jsonify(data)


# ----------------------------------------------------------------- settings ---
@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        prev_mode = SETTINGS["data_mode"]
        prev_ret = SETTINGS["retention"]

        if "data_mode" in payload:
            if payload["data_mode"] not in ("evaluation", "live"):
                audit.record("mode_change_rejected",
                             f"rejected invalid data_mode value: '{payload['data_mode']}'")
                return jsonify({"error": "data_mode must be 'evaluation' or 'live'."}), 400
            SETTINGS["data_mode"] = payload["data_mode"]

        if "retention" in payload:
            if payload["retention"] not in RETENTION_VALUES:
                audit.record("retention_change_rejected",
                             f"rejected invalid retention value: '{payload['retention']}'")
                return jsonify({"error": "invalid retention value."}), 400
            SETTINGS["retention"] = payload["retention"]

        retention_changed = SETTINGS["retention"] != prev_ret
        if retention_changed:
            # sweep only when the retention window itself changes — other settings
            # updates must never silently delete report artifacts
            apply_retention()
        if "data_mode" in payload or "retention" in payload:
            save_settings()   # persist so settings survive server restarts
            if SETTINGS["data_mode"] != prev_mode:
                audit.record("mode_change", f"data_mode: {prev_mode} → {SETTINGS['data_mode']}")
            if retention_changed:
                audit.record("retention_change", f"retention: {prev_ret} → {SETTINGS['retention']}")
    else:
        # reads never sweep — the artifact table must stay stable while viewed
        pass
    return jsonify({
        "settings": SETTINGS,
        "reports": _report_inventory(),
        "audit": audit.tail(400),   # window for the paginated panel (page size 50)
    })


def _report_inventory():
    """On-disk generated reports, newest first."""
    out = []
    for p in sorted(glob.glob(os.path.join(REPORTS_DIR, "*.json")) +
                    glob.glob(os.path.join(REPORTS_DIR, "*.html")),
                    key=os.path.getmtime, reverse=True):
        st = os.stat(p)
        out.append({
            "name": os.path.basename(p),
            "kind": "html" if p.endswith(".html") else "json",
            "size_bytes": st.st_size,
            "mtime": int(st.st_mtime),
        })
    return out


def _ttl_seconds(v):
    return {"session": 0, "7d": 7 * 86400, "30d": 30 * 86400,
            "90d": 90 * 86400, "forever": -1}[v]


def load_settings():
    """Restore persisted settings at startup. Missing or corrupt file → defaults;
    unknown/invalid keys in the file are ignored so a hand-edit can't wedge the app."""
    if os.path.isfile(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH) as f:
                d = json.load(f)
            if d.get("data_mode") in ("evaluation", "live"):
                SETTINGS["data_mode"] = d["data_mode"]
            if d.get("retention") in RETENTION_VALUES:
                SETTINGS["retention"] = d["retention"]
        except (OSError, ValueError):
            pass  # unreadable/corrupt JSON → run on defaults
    return SETTINGS


def save_settings():
    """Atomic write (tmp + os.replace) so a crash mid-write can't corrupt the file."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    tmp = SETTINGS_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(SETTINGS, f, indent=2)
        f.write("\n")
    os.replace(tmp, SETTINGS_PATH)


load_settings()   # restore persisted settings at import time (works under any WSGI runner)
_load_history()   # restore persisted comparison slots (works under any WSGI runner)


def apply_retention():
    """Sweep auto-generated reports per the retention window.
    Called when retention changes and when a new analysis session starts.
    'session' → artifacts from prior sessions are removed; 'forever' keeps all."""
    ttl = _ttl_seconds(SETTINGS["retention"])
    if ttl < 0:
        return {"removed": 0}
    removed = 0
    now = __import__("time").time()
    for p in (glob.glob(os.path.join(REPORTS_DIR, "*.json")) +
              glob.glob(os.path.join(REPORTS_DIR, "*.html"))):
        if now - os.path.getmtime(p) > ttl:
            try:
                os.remove(p)
                removed += 1
            except OSError:
                pass
    return {"removed": removed}


# client-side events eligible for the audit trail (whitelist — nothing else accepted)
CLIENT_AUDIT_EVENTS = {"session_inspect"}


@app.route("/api/audit/record", methods=["POST"])
def api_audit_record():
    """Record a whitelisted client-side operator action (e.g. session inspection)."""
    payload = request.get_json(silent=True) or {}
    event = payload.get("event")
    detail = str(payload.get("detail") or "")[:200]
    if event not in CLIENT_AUDIT_EVENTS:
        return jsonify({"error": "event type not allowed."}), 400
    entry = audit.record(event, detail)
    return jsonify({"ok": True, "entry": entry})


@app.route("/api/audit/export")
def api_audit_export():
    """Download the full audit trail as JSON or CSV (oldest first)."""
    kind = (request.args.get("format") or "json").lower()
    events = audit.read_all()
    stamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")

    if kind == "csv":
        import csv
        import io
        buf = io.StringIO()
        w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
        w.writerow(["timestamp", "event", "detail"])
        for e in events:
            w.writerow([e.get("ts", ""), e.get("event", ""), e.get("detail", "")])
        body = buf.getvalue()
        fname = f"securemailscope_audit_{stamp}.csv"
        audit.record("audit_export", f"CSV audit trail export — {len(events)} event(s)")
        return Response(body, mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})

    body = json.dumps({"tool": "SecureMailScope", "exported_at": stamp,
                       "event_count": len(events), "events": events}, indent=2)
    fname = f"securemailscope_audit_{stamp}.json"
    audit.record("audit_export", f"JSON audit trail export — {len(events)} event(s)")
    return Response(body, mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/api/reports/clear", methods=["POST"])
def api_reports_clear():
    """Operator-initiated sweep: remove all auto-generated report artifacts now."""
    removed = 0
    for p in (glob.glob(os.path.join(REPORTS_DIR, "*.html")) +
              glob.glob(os.path.join(REPORTS_DIR, "*.json"))):
        try:
            os.remove(p)
            removed += 1
        except OSError:
            pass
    audit.record("reports_cleared", f"removed {removed} report artifact(s)")
    return jsonify({"removed": removed, "reports": _report_inventory(), "audit": audit.tail(400)})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # 'Session only' retention: sweep artifacts from previous server sessions at boot
    removed = apply_retention().get("removed", 0)
    if removed:
        print(f"Retention sweep: removed {removed} expired report artifact(s).")
    print("SecureMailScope running → http://localhost:%d" % port)
    print(f"Settings: data_mode={SETTINGS['data_mode']} retention={SETTINGS['retention']} ({SETTINGS_PATH})")
    print(f"History: {len(HISTORY)} comparison slot(s) restored ({HISTORY_PATH})")
    app.run(host="127.0.0.1", port=port, debug=False)
