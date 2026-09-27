"""SecureMailScope — forensic report generation (JSON + standalone HTML)."""
import json
import os
from datetime import datetime

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLOR = {"CRITICAL": "#e5484d", "HIGH": "#f76b15", "MEDIUM": "#f5d90a", "LOW": "#30a46c"}
SEV_PENALTY = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}


def _esc(x):
    return str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _band_color(score):
    if score >= 90: return "#30a46c"
    if score >= 75: return "#46c46c"
    if score >= 50: return "#f5d90a"
    if score >= 25: return "#f76b15"
    return "#e5484d"


def _chip(text, color, dark_text=False):
    tc = "#0b0f1a" if dark_text else "#fff"
    return (f"<span class='chip' style='background:{color};color:{tc}'>"
            f"{_esc(text)}</span>")


REPORT_CSS = """
  :root {
    --bg:#0b0f1a; --bg2:#0d1220; --panel:#111a2e; --panel2:#0e1626;
    --border:#1e2a45; --border2:#27385c;
    --text:#d8dee9; --muted:#8296b3; --dim:#5a6b85;
    --cyan:#22d3ee; --cyan2:#7dd3fc;
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body {
    font-family:'Segoe UI', system-ui, Arial, sans-serif; background:var(--bg);
    color:var(--text); font-size:14px; line-height:1.5;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  .wrap { max-width:980px; margin:0 auto; padding:28px 22px 10px; }
  a { color:var(--cyan2); }

  /* header */
  .brand { display:flex; align-items:center; gap:12px; }
  .logo-mark {
    width:42px; height:42px; border-radius:10px; display:grid; place-items:center;
    background:linear-gradient(135deg,#164e63,#0e7490); color:#a5f3fc;
    font-size:20px; border:1px solid #155e75; flex:none;
  }
  h1 { font-size:20px; font-weight:600; letter-spacing:.3px; }
  h1 span { color:var(--cyan); }
  .tagline { font-size:11.5px; color:var(--dim); }
  .meta { color:var(--muted); font-size:12px; margin:12px 0 0; }
  .meta b { color:var(--text); }
  .docline { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-top:8px; }

  /* sections */
  section {
    background:var(--panel); border:1px solid var(--border); border-radius:10px;
    padding:18px; margin-top:16px;
  }
  h2 {
    font-size:11.5px; text-transform:uppercase; letter-spacing:1.2px;
    color:var(--muted); margin-bottom:14px; font-weight:600;
  }
  h2 .n { color:var(--cyan); margin-right:6px; }

  /* chips */
  .chip {
    display:inline-block; font-size:10.5px; font-weight:700; letter-spacing:.6px;
    padding:2px 8px; border-radius:4px;
  }
  .chip.outline { background:transparent; color:var(--muted); border:1px solid var(--border2); }

  /* exec summary */
  .exec { display:flex; gap:22px; align-items:center; flex-wrap:wrap; }
  .ring {
    width:150px; height:150px; border-radius:50%; flex:none;
    background:conic-gradient(var(--col) calc(var(--pct)*1%), #16213a 0);
    display:grid; place-items:center;
  }
  .ring-inner {
    width:116px; height:116px; border-radius:50%; background:var(--bg2);
    display:flex; flex-direction:column; align-items:center; justify-content:center;
  }
  .ring-inner b { font-size:32px; color:var(--col); }
  .ring-inner small { color:var(--muted); font-size:11px; }
  .tiles { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; flex:1; min-width:320px; }
  .tile { background:var(--panel2); border:1px solid var(--border); border-radius:8px; padding:10px 12px; }
  .tile .l { font-size:10px; text-transform:uppercase; letter-spacing:.8px; color:var(--muted); }
  .tile .v { font-size:22px; font-weight:700; margin-top:2px; }
  .tile .s { font-size:10.5px; color:var(--dim); }
  .sevline { margin-top:14px; display:flex; gap:8px; flex-wrap:wrap; align-items:center; font-size:12px; color:var(--muted); }

  /* tables */
  table { width:100%; border-collapse:collapse; font-size:12.5px; }
  th {
    text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.8px;
    color:var(--muted); padding:7px 9px; border-bottom:1px solid var(--border2);
  }
  td { padding:7px 9px; border-bottom:1px solid var(--border); vertical-align:top; }
  tr:last-child td { border-bottom:none; }
  td.mono, .mono { font-family:Consolas, Menlo, monospace; font-size:12px; }
  .dim { color:var(--dim); }
  .num { text-align:right; }

  /* bars */
  .barrow { display:grid; grid-template-columns:170px 1fr 46px; gap:10px; align-items:center; margin-bottom:8px; font-size:12px; }
  .barrow .lab { color:var(--muted); }
  .track { height:8px; background:var(--panel2); border:1px solid var(--border); border-radius:4px; overflow:hidden; }
  .fill { height:100%; border-radius:4px; }
  .barrow .val { text-align:right; color:var(--text); }

  /* findings */
  .finding { background:var(--panel2); border:1px solid var(--border); border-left-width:3px;
             border-radius:8px; padding:12px 14px; margin-bottom:10px; }
  .finding .head { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .finding .head b.id { font-family:Consolas, monospace; }
  .finding .body { margin-top:8px; font-size:12.5px; }
  .finding .kv { color:var(--muted); font-size:10.5px; text-transform:uppercase; letter-spacing:.8px; margin:8px 0 3px; }
  .evi { font-family:Consolas, monospace; font-size:11.5px; color:#b8c8de; background:#060910;
         border:1px solid var(--border); border-radius:6px; padding:6px 9px; margin:3px 0; }
  .sesslist { font-family:Consolas, monospace; font-size:11px; color:var(--muted); }

  ol.rec { margin-left:20px; font-size:13px; }
  ol.rec li { margin-bottom:7px; }
  ol.rec b { color:var(--cyan2); }

  footer {
    margin-top:22px; color:var(--dim); font-size:11px;
    border-top:1px solid var(--border); padding:12px 2px 26px; line-height:1.6;
  }
  @media (max-width:720px) { .tiles { grid-template-columns:repeat(2,1fr); } }
  @media print { body { background:#0b0f1a; } section { break-inside:avoid; } }
"""


def build_json(result):
    """Compact machine-readable summary."""
    return {
        "tool": "SecureMailScope",
        "version": "1.0",
        "scenario": result["meta"]["name"],
        "source_file": result["meta"].get("file_label"),
        "analyzed_at": result["analyzed_at"],
        "security_posture": result["risk"],
        "protocol_analysis": result["protocols"],
        "tls_version_distribution": result["tls_versions"],
        "cipher_security": result["cipher_security"],
        "session_stats": result["session_stats"],
        "parse_stats": result["meta"].get("parse_stats"),
        "certificates": result["certificates"],
        "findings": [
            {
                "rule_id": f["rule_id"], "title": f["title"],
                "severity": f["severity"],
                "sessions": f["sessions"], "affected_count": f["affected_count"],
                "protocol": f.get("protocol"), "evidence": f["evidence"],
                "impact": f["impact"], "recommendation": f["recommendation"],
                "status": f["status"],
            }
            for f in result["findings"]
        ],
        "notes": result["notes"],
    }


def _cap_stats(result):
    """Parse-statistics line for uploaded captures (empty for evaluation data)."""
    ps = result["meta"].get("parse_stats")
    if not ps:
        return ""
    return (f"<br><span class=\"dim\">Fully parsed on-engine: {ps['packets']} packets → "
            f"{ps['tcp_flows']} TCP flows → {ps['sessions']} mail/TLS sessions · "
            f"{ps['certificates_parsed']} certificate(s) analyzed"
            + (" · session cap reached, largest flows shown" if ps.get("sessions_truncated") else "")
            + "</span>")


def build_html(result):
    """Standalone HTML forensic report — dark SOC theme, self-contained, printable."""
    r = result["risk"]
    counts = r["counts"]
    stats = result["session_stats"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    col = _band_color(r["score"])

    # ---- protocol bars -----------------------------------------------------
    proto_max = max((p["sessions"] for p in result["protocols"]), default=1) or 1
    proto_bars = "\n".join(
        f"<div class='barrow'><span class='lab'>{_esc(p['name'])}</span>"
        f"<span class='track'><span class='fill' style='width:{100 * p['sessions'] / proto_max:.0f}%;background:var(--cyan)'></span></span>"
        f"<span class='val'>{p['sessions']} · {p['confidence']}%</span></div>"
        for p in result["protocols"])

    # ---- TLS version bars --------------------------------------------------
    def tls_color(v):
        u = v.upper()
        if u == "NONE":
            return "#5a6b85"
        if "SSL" in u or "1.0" in u or "1.1" in u:
            return SEV_COLOR["HIGH"]
        return "#22d3ee"

    tls_sorted = sorted(result["tls_versions"].items(), key=lambda kv: -kv[1])
    tls_max = max((n for _, n in tls_sorted), default=1) or 1
    tls_bars = "\n".join(
        f"<div class='barrow'><span class='lab mono'>{_esc(v)}</span>"
        f"<span class='track'><span class='fill' style='width:{100 * n / tls_max:.0f}%;background:{tls_color(v)}'></span></span>"
        f"<span class='val'>{n}</span></div>"
        for v, n in tls_sorted) or "<div class='dim'>No TLS sessions.</div>"

    # ---- cipher security bars ----------------------------------------------
    cs = result["cipher_security"]
    cs_max = max(cs.values(), default=1) or 1
    cs_colors = {"STRONG": "#30a46c", "LEGACY": "#f5d90a", "WEAK": "#e5484d", "NONE": "#5a6b85"}
    cs_bars = "\n".join(
        f"<div class='barrow'><span class='lab'>{k}</span>"
        f"<span class='track'><span class='fill' style='width:{100 * cs[k] / cs_max:.0f}%;background:{cs_colors[k]}'></span></span>"
        f"<span class='val'>{cs[k]}</span></div>"
        for k in ("STRONG", "LEGACY", "WEAK", "NONE"))

    # ---- certificates -------------------------------------------------------
    def cert_chip(c):
        st = c["status"]
        color = SEV_COLOR["LOW"] if st == "VALID" else (
            SEV_COLOR["HIGH"] if st == "EXPIRED" else SEV_COLOR["CRITICAL"])
        extra = (f" <span class='dim'>({c['days_expired']}d ago)</span>"
                 if st == "EXPIRED" and c.get("days_expired") else "")
        return _chip(st, color) + extra

    cert_rows = "\n".join(
        f"<tr><td class='mono'>{_esc(c['subject'])}</td><td>{_esc(c['issuer'])}</td>"
        f"<td class='mono'>{_esc(c['valid_from'])} → {_esc(c['valid_until'])}</td>"
        f"<td class='mono'>{_esc(c['key_alg'])} {c.get('key_len', '')}</td>"
        f"<td class='mono'>{_esc(c['sig_alg'])}</td>"
        f"<td>{cert_chip(c)}</td></tr>"
        for c in result["certificates"])

    # ---- finding cards -------------------------------------------------------
    findings_html = ""
    for f in sorted(result["findings"], key=lambda x: SEV_ORDER.index(x["severity"])):
        sev = f["severity"]
        ev = "".join(f"<div class='evi'>{_esc(e)}</div>" for e in f["evidence"])
        findings_html += (
            f"<div class='finding' style='border-left-color:{SEV_COLOR[sev]}'>"
            f"<div class='head'>{_chip(sev, SEV_COLOR[sev], dark_text=(sev == 'MEDIUM'))}"
            f"<b class='id'>{_esc(f['rule_id'])}</b> <b>{_esc(f['title'])}</b>"
            f"<span class='chip outline'>{f['affected_count']} session(s)</span>"
            f"<span class='chip outline'>−{SEV_PENALTY[sev]} posture</span></div>"
            f"<div class='body'><div class='kv'>Evidence</div>{ev}"
            f"<div class='kv'>Impact</div><div>{_esc(f['impact'])}</div>"
            f"<div class='kv'>Recommendation</div><div>{_esc(f['recommendation'])}</div>"
            f"<div class='kv'>Affected Sessions</div>"
            f"<div class='sesslist'>{_esc(', '.join(f['sessions']))}</div>"
            f"</div></div>")
    if not findings_html:
        findings_html = "<div class='dim'>No findings — cryptographic posture is clean.</div>"

    # ---- AI prioritization ---------------------------------------------------
    ai_top = sorted((s for s in result["sessions"]
                     if s["ai"]["risk_class"] in ("CRITICAL", "HIGH")),
                    key=lambda s: s["risk"]["score"])[:8]
    if ai_top:
        def prio_chip(p):
            return _chip(p, SEV_COLOR["CRITICAL"]) if p == "P1" else \
                "<span class='chip outline'>%s</span>" % _esc(p)

        ai_rows = "\n".join(
            f"<tr><td class='mono'>{_esc(s['id'])}</td>"
            f"<td>{_chip(s['ai']['risk_class'], SEV_COLOR['CRITICAL' if s['ai']['risk_class'] == 'CRITICAL' else 'HIGH'])}</td>"
            f"<td class='num'>{s['ai']['confidence']}%</td>"
            f"<td>{prio_chip(s['ai']['priority'])}</td>"
            f"<td>{_esc(s['ai']['reason'])}</td></tr>"
            for s in ai_top)
        ai_table = ("<table><tr><th>Session</th><th>Risk Class</th><th>Confidence</th>"
                    f"<th>Priority</th><th>Reason</th></tr>{ai_rows}</table>")
    else:
        ai_table = "<div class='dim'>No sessions classified HIGH or CRITICAL — no prioritization action required.</div>"

    # ---- exec summary tiles ---------------------------------------------------
    penalty = sum(SEV_PENALTY[f["severity"]] for f in result["findings"])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SecureMailScope Forensic Report — {_esc(result['meta']['name'])}</title>
<style>{REPORT_CSS}</style>
</head>
<body>
<div class="wrap">

<header>
  <div class="brand">
    <div class="logo-mark">🛡</div>
    <div>
      <h1>Secure<span>MailScope</span></h1>
      <div class="tagline">Cryptographic Security Posture Report · AI-Assisted Assessment for Secure Email Communications</div>
    </div>
  </div>
  <p class="meta">Scenario: <b>{_esc(result['meta']['name'])}</b> · Source: <span class="mono">{_esc(result['meta'].get('file_label', ''))}</span>
   · Capture window: {_esc(result['meta'].get('capture_window', ''))} · Generated: {now}
  {_cap_stats(result)}</p>
  <div class="docline">
    <span class="chip outline">SIH26159 · NTRO</span>
    <span class="chip outline">PASSIVE ANALYSIS</span>
    <span class="chip outline">{'OPERATOR CAPTURE — FULLY PARSED' if result['meta'].get('source') == 'upload' else 'EVALUATION DATASET'}</span>
  </div>
</header>

<section>
  <h2><span class="n">01</span>Executive Summary</h2>
  <div class="exec">
    <div class="ring" style="--pct:{r['score']};--col:{col}">
      <div class="ring-inner"><b>{r['score']}</b><small>/ 100 · {_esc(r['band'])}</small></div>
    </div>
    <div class="tiles">
      <div class="tile"><div class="l">Sessions Analyzed</div><div class="v">{stats['total']}</div><div class="s">{stats['tls']} encrypted · {stats['plaintext']} plaintext</div></div>
      <div class="tile"><div class="l">Suspicious Sessions</div><div class="v" style="color:{SEV_COLOR['CRITICAL'] if stats['suspicious'] else '#30a46c'}">{stats['suspicious']}</div><div class="s">anomaly score ≥ 70</div></div>
      <div class="tile"><div class="l">Findings</div><div class="v">{len(result['findings'])}</div><div class="s">consolidated weaknesses</div></div>
      <div class="tile"><div class="l">Posture Penalty</div><div class="v" style="color:{col}">−{penalty}</div><div class="s">from baseline 100</div></div>
    </div>
  </div>
  <div class="sevline">
    <span>Severity mix:</span>
    {_chip(str(counts['CRITICAL']) + ' Critical', SEV_COLOR['CRITICAL'])}
    {_chip(str(counts['HIGH']) + ' High', SEV_COLOR['HIGH'])}
    {_chip(str(counts['MEDIUM']) + ' Medium', SEV_COLOR['MEDIUM'], dark_text=True)}
    {_chip(str(counts['LOW']) + ' Low', SEV_COLOR['LOW'])}
  </div>
</section>

<section>
  <h2><span class="n">02</span>Protocol Analysis</h2>
  {proto_bars}
</section>

<section>
  <h2><span class="n">03</span>TLS Analysis</h2>
  {tls_bars}
  <div class="kv" style="margin-top:12px">Cipher security mix</div>
  {cs_bars}
</section>

<section>
  <h2><span class="n">04</span>Certificate Analysis</h2>
  <table>
    <tr><th>Subject</th><th>Issuer</th><th>Validity</th><th>Key</th><th>Signature</th><th>Status</th></tr>
    {cert_rows}
  </table>
</section>

<section>
  <h2><span class="n">05</span>Findings ({len(result['findings'])})</h2>
  {findings_html}
</section>

<section>
  <h2><span class="n">06</span>AI Risk Prioritization</h2>
  {ai_table}
  <p class="dim" style="font-size:11px;margin-top:10px">Assist layer: deterministic feature scoring over TLS version, cipher strength,
  certificate status, forward secrecy, STARTTLS behavior and anomaly indicators. Not a trained model.</p>
</section>

<section>
  <h2><span class="n">07</span>Recommendations</h2>
  <ol class="rec">
    <li><b>Protocol versions.</b> Disable SSLv3/TLS 1.0/1.1; require TLS 1.2+ (prefer TLS 1.3) per RFC 8314.</li>
    <li><b>Cipher suites.</b> Remove 3DES, RC4, NULL and export suites; allow AEAD (AES-GCM / ChaCha20) only.</li>
    <li><b>Certificates.</b> Renew expired certificates; enforce ≥2048-bit RSA / ≥256-bit EC keys with SHA-256 signatures; automate expiry alerting.</li>
    <li><b>STARTTLS enforcement.</b> Deploy MTA-STS / DANE so downgrade and stripping attempts fail closed.</li>
    <li><b>Forward secrecy.</b> Enable ECDHE everywhere; disable static RSA key exchange.</li>
    <li><b>Monitoring.</b> Keep continuous passive posture assessment on mail ports 25/465/587/993/995.</li>
  </ol>
</section>

<footer>Generated by SecureMailScope (SIH26159) — deterministic rule engine aligned with
RFC 8314 / NIST SP 800-52 Rev.2. Risk model: 100 − (30·Critical + 20·High + 10·Medium + 5·Low),
clamped 0–100. Passive analysis only: no exploitation, no live scanning; this report evaluates
the supplied evaluation dataset.</footer>

</div>
</body>
</html>"""


def save_reports(result):
    """Write JSON + HTML to reports/. Returns (json_path, html_path)."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jpath = os.path.join(REPORTS_DIR, f"report_{result['scenario_id']}_{stamp}.json")
    hpath = os.path.join(REPORTS_DIR, f"report_{result['scenario_id']}_{stamp}.html")
    with open(jpath, "w") as f:
        json.dump(build_json(result), f, indent=2)
    with open(hpath, "w") as f:
        f.write(build_html(result))
    return jpath, hpath
