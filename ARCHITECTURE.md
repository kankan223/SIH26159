# SecureMailScope — Architecture

## System Architecture
```
┌───────────────────────────── Browser ─────────────────────────────┐
│  index.html  ·  style.css (dark + light/print themes)             │
│  app.js (SPA: views, canvas charts, confirm modal, audit panel,   │
│  keyboard nav, deep-links — zero CDN dependencies, fully offline) │
└──────────────────────────────┬────────────────────────────────────┘
                        fetch /api/*
┌──────────────────────────────▼────────────────────────────────────┐
│                          Flask (app.py)                           │
│  GET  /                     SPA shell                             │
│  GET  /api/scenarios        capture library (+ expected posture)  │
│  POST /api/analyze          run pipeline (scenario_id or upload)  │
│  GET  /api/report/html      HTML forensic report                  │
│  GET  /api/report/json      JSON export                           │
│  GET  /api/findings/export  SOC/SIEM feed: STIX 2.1 bundle or findings CSV
  GET  /api/history          analysis snapshots for comparison (persisted across restarts)
  POST /api/compare          diff two history slots (before/after evidence)
  GET/POST /api/settings     data mode + retention (persisted)     │
│  POST /api/reports/clear    operator-initiated artifact sweep     │
│  GET  /api/audit/export     audit trail as JSON or CSV            │
│  POST /api/audit/record     whitelisted client-side audit events  │
└──────┬───────────┬───────────┬────────────┬───────────┬──────────┘
       ▼           ▼           ▼            ▼           ▼
  analyzer.py  rules.py   risk_engine.py ai_assist.py anomaly.py
  (analyze_   (rule        (score calc)  (classifier) (detectors)
   document)   engine)              audit.py (JSONL trail)
       │                           report.py (artifacts)
       ├── data/*.json — 6 deterministic evaluation scenarios
       └── upload_pipeline.py — real capture parsing for uploads:
             pcap_reader.py   (pcap/pcapng → packets → TCP flows)
             tls_parser.py    (TLS records + handshakes, TLS 1.3 aware)
             cert_analysis.py (X.509 DER via cryptography)
             ml_anomaly.py    (IsolationForest assist)
  config/      — settings.json (persisted) · audit.jsonl (append-only)
  reports/     — generated report artifacts (retention-swept)
```

## Data Flow (pipeline)
1. **Input** — uploaded PCAP (double-validated: magic bytes + full parse) or
   capture-library selection (evaluation mode; LIVE mode accepts operator captures only)
2. **Protocol Detection** — SMTP/IMAP/POP3 identification + confidence from capture signals
3. **Session Reconstruction** — uploads: sequence-based TCP stream reassembly →
   mail/TLS sessions; evaluation: curated datasets (identical schema, identical engine)
4. **TLS/STARTTLS Analysis** — negotiated version, cipher suite, key exchange, forward secrecy
   (uploads: full handshake reconstruction from reassembled streams, incl. TLS 1.3)
5. **Certificate Analysis** — subject/issuer/validity/key/sig-alg evaluation
6. **Rule Engine** (`rules.py`) — deterministic weakness findings with evidence/impact/rec
7. **Risk Scoring** (`risk_engine.py`) — 100 − (30C + 20H + 10M + 5L), clamped, banded
8. **AI-Assisted Prioritization** (`ai_assist.py`) — feature vector → class/confidence/reason/P1–P4
9. **Anomaly Detection** (`anomaly.py`) — 6 deterministic detectors → 0–100 score per session
10. **Output** — dashboard, session drawer, findings, remediation, JSON/HTML report
11. **Audit** — every operator action lands in the trail: analysis runs, report exports,
    rejected uploads, session inspections, policy changes, artifact sweeps

## Components
| File | Responsibility | Type |
|---|---|---|
| `app.py` | Flask routes, settings state + persistence, retention sweeps, audit endpoints | Real |
| `audit.py` | Append-only JSONL audit trail (thread-locked appends, torn-line-tolerant reads) | Real |
| `analyzer.py` | PCAP validation, shared `analyze_document` engine over evaluation datasets and reconstructed captures | Real |
| `upload_pipeline.py` | Capture → session reconstruction: flows, stream reassembly, TLS facts, STRIPTLS detection | Real |
| `pcap_reader.py` | Pure-Python pcap/pcapng reader (Ethernet/raw-IP/SLL/SLL2, VLAN, IPv4/IPv6, TCP/UDP) | Real |
| `tls_parser.py` | TLS record + handshake parser (ClientHello/ServerHello/Certificate/Alerts, TLS 1.3) | Real |
| `cert_analysis.py` | X.509 DER analysis via `cryptography` (validity, key size, sig alg, SAN) | Real |
| `ml_anomaly.py` | Unsupervised IsolationForest outlier assist (fixed seed, deterministic) | Real (unsupervised) |
| `rules.py` | Weakness rules (TLS version, cipher, cert, forward secrecy, STARTTLS) | Real (deterministic) |
| `risk_engine.py` | Transparent scoring + risk bands | Real |
| `ai_assist.py` | Feature-vector risk classifier + priority (deterministic assist layer) | Simulated AI |
| `anomaly.py` | 6 deterministic detectors (downgrade, cipher change, failed STARTTLS, mismatch, handshake, failure ratio) | Simulated |
| `siem.py` | STIX 2.1 bundle + findings CSV feeds (deterministic UUIDv5 ids, passive IOC extraction) | Real |
| `compare.py` | Deterministic diff between analysis snapshots (posture, findings, sessions) | Real |
| `report.py` | JSON + HTML forensic report generation (dark SOC theme) | Real |
| `wsgi.py` | Production WSGI entrypoint (gunicorn) with boot-time retention sweep | Real |
| `data/*.json` | Compact scenario datasets (sessions/protocols/tls/certs) | Evaluation data |
| `config/settings.json` | Persisted data mode + retention (survives restarts) | Real |
| `config/audit.jsonl` | Append-only operator audit trail | Real |
| `config/history.json` | Bounded analysis history (12) for comparison — survives restarts | Real |
| `templates/index.html`, `static/*` | SPA UI, canvas visualizations, themes, confirm modal, audit panel | Real |
| `walkthrough.js`, `sweep.js` | Playwright verification harnesses (demo flow + visual sweep) | Test tooling |

## Settings & Data-Mode Layer
- **Two settings**, persisted in `config/settings.json` (atomic tmp + `os.replace` writes,
  loaded at import time so any WSGI runner restores them; corrupt file → safe defaults):
  - `data_mode`: `evaluation` (curated capture library + uploads) or `live`
    (operator-supplied captures only — library cards disabled, selector locked,
    Analyze blocked, deep-link autostart suppressed; enabling it requires confirmation)
  - `retention`: `session` | `7d` | `30d` | `90d` | `forever`
- **Retention sweeps** run only when the window changes and at server boot
  ("session" = per server session); GET reads never sweep; data-mode changes never delete

## Audit Trail Layer
- **Append-only JSONL** at `config/audit.jsonl`; one event per line `{ts, event, detail}`;
  thread-locked appends; I/O errors swallowed so auditing never breaks a request path
- **Server-side events:** `analysis_run`, `report_export`, `upload_rejected`,
  `mode_change`, `retention_change`, `reports_cleared`, `audit_export` (+ `*_rejected`
  when invalid values are POSTed)
- **Client-side events:** `session_inspect` (first drawer open per session, via
  `POST /api/audit/record` — a **whitelist** of client event types; anything else → HTTP 400)
- **Panel:** newest-first log with instant search, category chips
  (Policy / Analysis / Reports / Rejections), windowed pagination (50 events + "Show older"),
  and JSON/CSV export (`/api/audit/export` — always the full trail, itself audited)
- **Destructive actions** (clear store, retention changes that would delete artifacts,
  enabling LIVE mode) require an in-app confirmation dialog with exact impact counts

## Frontend
- **Views:** Overview Dashboard, Analysis, Session Explorer, Findings Center,
  Remediation Center, Reporting, Settings — keyboard `1–7`, deep-linkable
  (`/?autostart=<id>&view=<view>&session=<id>`)
- **Themes:** dark SOC (default) + light/print, toggled in the top bar, persisted in
  `localStorage`, applied pre-paint (no flash); canvas charts repaint per theme;
  `@media print` outputs a clean light report of the active view
- **Charts:** hand-rolled canvas (gauge, bars, risk profile) — zero CDN dependencies
- **Safety:** all dynamic content HTML-escaped; confirm modal guards destructive actions

## What Is Real
- File upload + validation (magic bytes **and** full parse), capture registry, pipeline orchestration
- **Capture ingestion for uploads:** pure-Python pcap/pcapng dissection, TCP flow tracking with
  sequence-based stream reassembly, TLS 1.0–1.3 handshake reconstruction, DER certificate
  analysis (validity/key/sig-alg/SAN), STRIPTLS + plaintext-fallback detection
- Deterministic rule engine, risk math, banding, filtering, session drill-down
- Anomaly detectors (rule-driven), AI prioritization layer (feature scoring),
  unsupervised IsolationForest outlier assist (fixed seed, labeled in payloads)
- JSON/HTML report generation (with parse statistics), dashboard visualizations, Mark-Resolved recompute
- Settings persistence, data-mode policy enforcement, retention sweeps
- Append-only audit trail with search/filter/pagination/export
- SOC/SIEM exports: STIX 2.1 bundle (network-traffic, x509-certificate, custom finding + report objects; deterministic UUIDv5 ids from the analysis timestamp) and flat findings CSV; IOCs extracted from the analyzed capture only
- Capture comparison: bounded in-session history (12 snapshots) + deterministic diff (score delta, new/resolved findings, per-session field changes, ML-outlier drift), audited as `comparison_run`
- Captured TLS Stream viewer: uploaded captures expose the real parsed records (cleartext transcript, handshake messages, alerts) in the session drawer; evaluation scenarios render a reconstructed timeline of the same events, explicitly labeled as session-fact reconstruction rather than capture bytes
- Security headers (CSP/nosniff/frame-deny/referrer-policy), gunicorn entrypoint,
  offline wheelhouse install, hardened container image

## What Is Still Simplified
- TCP reassembly is per-flow and sequence-based; out-of-order reassembly at enterprise
  capture scale remains roadmap work
- X.509 chain building and revocation (OCSP/CRL) — leaf certificate properties are evaluated
- Supervised ML triage trained on labeled SOC data — the deployed layer is unsupervised + deterministic

## Production Roadmap (phases 1–3 shipped; 4–5 partial; 8 shipped)
1. ✅ **Full PCAP parser** — pure-Python pcap/pcapng dissection (`pcap_reader.py`); zero extra runtime deps, air-gap friendly
2. ✅ **TCP stream reconstruction** — per-flow sequence-based reassembly (`upload_pipeline.py`); enterprise-scale hardening remains
3. ✅ **TLS handshake reconstruction** — ClientHello/ServerHello/Certificate/Alerts, TLS 1.3 supported_versions (`tls_parser.py`)
4. ◑ **X.509 validation** — leaf properties via `cryptography` (`cert_analysis.py`); RFC 5280 path building + OCSP/CRL remain
5. ◑ **ML anomaly detection** — IsolationForest assist shipped (`ml_anomaly.py`); supervised models on labeled data remain
6. **Enterprise deployment** — role-based access, multi-tenant, scale-out workers (hardening baseline shipped: headers, WSGI entry)
7. ◑ **SOC/SIEM integration** — STIX 2.1 + CSV feeds shipped (`siem.py`, `/api/findings/export`); forwarder push (Splunk/ELK), STIX/TAXII collection exchange remains
8. ✅ **Air-gapped deployment** — offline wheelhouse install (`OFFLINE_INSTALL.md`), hardened non-root Dockerfile

## Verification
- `walkthrough.js` — scripted end-to-end demo flow, 130 assertions (pipeline, findings,
  remediation math, exports, settings persistence, audit, confirmations, theme,
  dataset + captured stream viewers)
- `sweep.js` — every page × both themes: theme bg, overflow, rendering, chart painting
- `tests/e2e_upload.py` — 43 HTTP-level checks: golden scenario scores, real upload parsing
  (packets → flows → sessions → certificates), TLS 1.3 + STRIPTLS + expired-cert detection,
  ML outlier targeting, STIX/CSV export, history + compare (incl. rejection paths → HTTP 400),
  report markers, audit events, security headers
- `tests/test_history_persist.py` — boots its own server twice to prove comparison slots
  survive a restart (file written, restored, still comparable; bounded at 12; corrupt file → empty)
- Run: `node walkthrough.js` / `node sweep.js` (needs `npm i playwright` + a running server);
  `.venv/bin/python tests/e2e_upload.py` (needs the server on 127.0.0.1:5000);
  `.venv/bin/python tests/test_history_persist.py` (self-managed server on :5177)

## Security / Ethical Posture
Passive analysis only. The engine never connects to, scans, or exploits live targets;
it evaluates operator-supplied captures and curated evaluation datasets. The AI layer
is a transparent deterministic prioritization aid, not a trained model.
