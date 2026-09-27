# SecureMailScope — Demo Video Script (script.md)

> Target duration: **3:00**. This script tells you exactly what to open, click, select,
> what appears, and what to say. Practice twice before recording.

**Recommended setup:** 1920×1080, browser fullscreen, dark theme, close extra tabs.
Start recording on the Overview Dashboard with the default (Secure) scenario; load the
STARTTLS Downgrade scenario live during Step 2 — it demonstrates the pipeline better.

**Before recording (upload step):** copy the demo capture to a descriptive filename so it
reads well on camera and in the audit trail:
```bash
cp tests/mixed_ok.pcap ~/gateway_demo.pcap
```
It is a real pcap (486 packets, 12 TCP flows): STARTTLS→TLS 1.2, TLS 1.3, a TLS 1.0/3DES
downgrade, a STRIPTLS-forced plaintext session, POP3S with a self-signed cert, plaintext
POP3 logins, and four bulk IMAPS baseline sessions — enough volume for the unsupervised
IsolationForest assist to fire live (it flags the downgrade and stripped sessions as outliers).

---

## 00:00 – 00:15 — Problem Introduction
**Screen:** Overview Dashboard (Secure Enterprise Mail scenario).
**Say:**
> "Email between organizations is usually encrypted with opportunistic TLS — but if the
> negotiation is weak, downgraded, or the certificate is invalid, mail flows silently
> exposed. SecureMailScope, our solution to SIH26159 from NTRO, passively analyzes captured
> email traffic and evaluates the cryptographic security posture of SMTP, IMAP and POP3
> communication."

**Highlight:** Posture score ring (100/100 · SECURE), light/dark theme toggle, DATA MODE: EVALUATION badge.
**Why it matters:** instantly frames the product as a passive posture-assessment tool.

## 00:15 – 00:30 — Dashboard Overview
**Do:** Move mouse over: score gauge, Critical/High/Medium/Low counters, protocol
distribution bars, TLS version chart, cipher security bars, recent findings list.
**Say:**
> "The dashboard gives a SOC analyst the full picture at a glance — overall posture score,
> severity breakdown, protocol and TLS distribution, and recent findings."
**Highlight:** The five posture KPI cards and the risk trend chart.

## 00:30 – 00:50 — Capture Selection + Analysis Pipeline
**Do:** Navigate to **Analysis**. Select **STARTTLS Downgrade** from the Capture Library. Click **Analyze Capture**.
Watch the pipeline log: Loading capture → Detecting protocols → Reconstructing sessions →
Analyzing TLS handshakes → Inspecting certificates → Evaluating cryptographic posture →
Running anomaly analysis → Generating risk assessment (≈2 s).
**Say:**
> "For this assessment I'm loading a capture from the mail-security evaluation set showing a
> STARTTLS downgrade attack. SecureMailScope reconstructs sessions and runs the full analysis pipeline."
**Result after:** Protocol detected **SMTP · 98% confidence**, sessions reconstructed **18**,
TLS sessions **14** (4 plaintext), posture score **0/100 · CRITICAL** — say: "the stripped
sessions sent mail in cleartext, which collapses the posture — exactly the attack impact
we want to surface instantly."
**Highlight:** The terminal-style pipeline — it mirrors real packet-analysis workflows.

## 00:50 – 01:15 — Protocol + Session Explorer + TLS Handshake View
**Do:** Open **Session Explorer**. Point at the table columns (Session ID, Protocol, TLS
version, Cipher, Certificate, Risk, Status). Click session **SES-014**.
In the detail drawer, open the **TLS Handshake** timeline.
**Say:**
> "Eighteen sessions were reconstructed. Session SES-014 stands out — the handshake shows
> TLS 1.0 negotiated, a 3DES cipher suite, an expired certificate, and no forward secrecy.
> These fields are exactly what an on-path attacker would want."
**Highlight:** Weak fields glow red/amber in the handshake timeline.

## 01:15 – 01:40 — Certificate Analysis + Cryptographic Weaknesses
**Do:** In the same drawer, scroll to the **Certificate card** (STATUS: EXPIRED, "Certificate
expired 142 days ago"). Then open **Findings Center**.
**Say:**
> "The certificate for the mail host expired 142 days ago — there is no identity assurance.
> Our deterministic rule engine, aligned with NIST SP 800-52 and RFC 8314 guidance, flags
> deprecated TLS, 3DES, the expired certificate, and the failed STARTTLS transition — each
> with evidence, impact, and a recommendation."
**Highlight:** Finding IDs (e.g., TLS-001), severity chips, evidence text.

## 01:40 – 01:55 — AI-Assisted Risk Classification
**Do:** Open session **SES-014**'s **AI Assessment** panel. Show input features → output.
**Say:**
> "The engine combines deterministic cryptographic analysis with an AI-assisted
> prioritization layer to help analysts focus on the highest-risk sessions. For this session
> it classifies risk as HIGH with 94% confidence and assigns priority P1 — deprecated TLS
> combined with weak cipher selection and certificate irregularities."
**Highlight:** Risk class, confidence bar, reason text, P1 chip.
**Why it matters:** SOC triage — analysts see the worst sessions first.

## 01:55 – 02:10 — Remediation Center
**Do:** Open **Remediation Center**. Show the step list for the TLS 1.0 finding
(1. Disable TLS 1.0 · 2. Require TLS 1.2+ · 3. Replace weak cipher · 4. Renew certificate ·
5. Retest STARTTLS). Click **Mark Resolved** on one finding.
**Say:**
> "Every finding maps to actionable remediation steps. Marking a finding resolved
> recalculates the posture score — simulating the effect of a fix."
**Result:** The what-if gauge uses the same transparent math as the engine — projected
score = 100 − (penalties still open). Resolving the CRITICAL finding reads **30/100**
(100 − 70 remaining), and clearing all five projects **100/100**. Say: "the projection
reuses the scoring engine, so the number is defensible, not cosmetic."
**Highlight:** Live score change — shows measurable impact of remediation.

## 02:10 – 02:30 — Real Capture Upload (Live Evidence)
**Do:** Back to **Analysis**. In the upload card, choose `gateway_demo.pcap` and click
**Analyze Upload**. Let the terminal print the real parse lines:
`✓ gateway_demo.pcap validated — 631 KB capture` →
`✓ Parsed 486 packets → 12 TCP flows → 11 mail/TLS session(s), 2 certificate(s) analyzed`.
Open **Session Explorer** and click the plaintext SMTP session carrying the
**STARTTLS stripped** anomaly line.
**Say:**
> "Everything so far used the evaluation library — now watch the engine work on a real
> packet capture. SecureMailScope dissects the file on-engine: 486 packets, TCP streams,
> TLS handshakes, certificates. Eleven mail sessions reconstructed — and here, a live
> STRIPTLS indicator: the server advertised STARTTLS, but the session fell back to
> plaintext. The unsupervised IsolationForest assist — trained on this capture as its own
> baseline — independently flagged this and the TLS 1.0 downgrade session as outliers.
> This is not a prepared dataset; every field you see came from real bytes on the wire."
**Result:** Posture **0/100 · CRITICAL** — plaintext fallback, untrusted self-signed
certificates, TLS 1.0 with 3DES. ML outlier chips on the dashboard KPI; the stripped
session's drawer shows the **Captured TLS Stream** — real parsed records from the file.
**Highlight:** The parse-statistics line in the terminal — visible proof of real parsing,
not a canned result.
**If short on time:** this step and the report step can share their runtime — the report
below is generated from this upload.

## 02:30 – 02:45 — Report Generation (on the uploaded capture)
**Do:** Open **Reporting**. Click **Generate HTML Report** (open it). Point at the header
chip **OPERATOR CAPTURE — FULLY PARSED** and the parse-statistics line, then scroll:
Executive Summary → Posture → Findings → Prioritization → Recommendations.
**Say:**
> "For forensics and compliance, analysts export a machine-readable JSON summary or a
> complete HTML forensic report — generated locally, and identical in structure whether
> the input came from the evaluation library or the operator's own capture."
**Highlight:** The OPERATOR CAPTURE marker and parse statistics in the report header —
evidence the report is derived from the same fully-parsed result.

## 02:45 – 03:00 — Production Path / Closing
**Screen:** Back to Overview Dashboard (library scenario still loaded).
**Say:**
> "SecureMailScope already parses operator captures end-to-end on-engine — PCAP
> dissection, TCP reassembly, TLS and X.509 analysis — with an unsupervised anomaly
> assist, and it installs fully offline for air-gapped networks. The production path
> adds enterprise scale-out, role-based access, X.509 chain validation with revocation,
> and SOC/SIEM feed integration. Passive analysis only, by design. Thank you."
**Highlight:** Keep the dashboard score visible during the final sentence.

---

## FEATURES TO SHOW — Checklist
- [x] Real PCAP upload — fully parsed on-engine (packets → TCP flows → TLS handshakes → X.509 certificates), parse statistics in the terminal
- [x] STRIPTLS / plaintext-fallback detection on operator captures
- [x] Capture library with expected-posture chips (evaluation datasets)
- [x] Light/print theme toggle (persisted, print-optimized)
- [x] SMTP / IMAP / POP3 protocol detection with confidence
- [x] Session reconstruction + Session Explorer table
- [x] STARTTLS / TLS analysis + visual handshake timeline
- [x] Certificate analysis card (incl. expired-cert case)
- [x] Weak crypto detection (TLS version, 3DES/RC4, key length, signature, forward secrecy)
- [x] Deterministic risk scoring with banded labels
- [x] AI-assisted prioritization (class / confidence / reason / P1–P4)
- [x] Anomaly detection with visual gauge + unsupervised IsolationForest assist (fires on captures with ≥ 8 sessions)
- [x] Findings Center with severity filters
- [x] Remediation Center with Mark Resolved + score recompute
- [x] JSON export + HTML forensic report
- [x] Overview dashboard with offline canvas visualizations (zero CDN dependencies)
- [x] DATA MODE: EVALUATION badge + capture switching

## Pacing Notes
- Don't read the dashboard aloud — let the camera sweep.
- The pipeline animation is the "wow" moment: narrate while it plays.
- The upload step (02:10) is the *evidence* moment: let the parse-statistics line sit on
  screen for a beat before narrating — it is the visual proof of real parsing.
- During the upload step, never say "demo" or "prepared" — the whole point is that these
  fields came from real bytes; the evaluation library framing is for Steps 1–8 only.
- If time is short, drop the report scroll (02:30 step) to 5 seconds — the OPERATOR CAPTURE
  chip in the header carries the point.
- Never say "our AI detects all attacks" — use the prioritization framing above.

## Production Path (mention briefly, end of video / Q&A)
**Shipped in this build:** full PCAP/PCAPng parser (pure Python, no external runtime deps) ·
TCP stream reconstruction · TLS handshake reconstruction incl. TLS 1.3 · X.509 certificate
analysis · unsupervised IsolationForest anomaly assist · offline wheelhouse install for
air-gapped networks (OFFLINE_INSTALL.md) · hardened container image.
**Next:** enterprise scale-out (workers/queues) · role-based access & multi-tenancy ·
X.509 chain validation with OCSP/CRL revocation · supervised triage models on labeled SOC
data · SOC/SIEM feed integration (STIX/TAXII).

---

## Appendix — One-Click Demo Deep-Links (optional shortcuts)

Load with the server running (`python app.py`). Each URL jumps straight to a demo moment:

| Step | URL |
|---|---|
| Dashboard after analysis | `http://localhost:5000/?autostart=starttls_downgrade` |
| Straight to SES-014 drawer | `http://localhost:5000/?autostart=starttls_downgrade&view=sessions&session=SES-014` |
| Findings Center pre-loaded | `http://localhost:5000/?autostart=starttls_downgrade&view=findings` |
| Remediation Center pre-loaded | `http://localhost:5000/?autostart=starttls_downgrade&view=remediation` |
| Report preview pre-generated | `http://localhost:5000/?autostart=starttls_downgrade&report=1` |
| Animated pipeline (default click-path) | select the scenario card and press **Analyze Capture** |
| Real-capture upload (Step 02:10) | **no deep-link — file chooser is the point**; pre-copy `tests/mixed_ok.pcap` → `~/gateway_demo.pcap` and pick it live |

Notes: add `&animated=1` to play the pipeline terminal animation instead of instant analysis.
The deep-links are a convenience for rehearsal and Q&A — the scripted click-path above remains
the primary demo route since it shows the pipeline terminal.
