# 🧠 SecureMailScope — Brain File (Project Tracker)

> Single source of truth for the SIH26159 prototype. Update after each major phase.

---

## Project Identity
- **Name:** SecureMailScope
- **Tagline:** AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications
- **SIH PS:** SIH26159 · Org: **NTRO** · Theme: Blockchain & Cybersecurity · Category: Software
- **Type:** Engineering prototype with a real capture-analysis core (round 18) — PCAP/TLS/X.509 parsing, ML assist, deployment hardening shipped; enterprise scale/auth remain roadmap
- **Current Phase:** ✅ Phases 0–7 complete + real-version pass (round 18) — verified and demo-ready
- **Stack:** Python 3 / Flask + HTML / CSS / Vanilla JS + offline canvas charts (zero CDN dependencies)

## Ethical Guardrails (must hold for every change)
Passive analysis only. No exploitation, no MITM, no scanning of live targets, no offensive
tooling. Prototype analyzes supplied captures / controlled demo datasets only. AI layer is an
honest deterministic prioritization layer — never claim a trained neural network.

## Phase Plan (used throughout the project)

| Phase | Scope | Status |
|---|---|---|
| **0. Research** | STARTTLS/STRIPTLS, MTA-STS/DANE/TLS-RPT, RFC 8314, NIST SP 800-52r2, NSA obsolete-TLS list, weak primitives (RC4/3DES/SHA1/<2048-bit), Scapy/PyShark PCAP tooling, AI triage patterns → `research.md` | ✅ Done |
| **1. Scaffold** | Flask app, folder structure, requirements.txt, config | ✅ Done |
| **2. Data Layer** | 6 compact deterministic demo datasets (secure, weak_tls, starttls_downgrade, expired_certificate, weak_cipher, suspicious_tls) | ✅ Done |
| **3. Analysis Core** | analyzer.py (protocol/session/cert normalization) · rules engine (weakness detection) · risk_engine.py (100 − penalties, banded) · anomaly.py (6 deterministic detectors) · ai_assist.py (feature-vector classifier → class/confidence/reason/P-priority) | ✅ Done |
| **4. Reporting** | report.py → JSON export + standalone HTML report (exec summary, posture, TLS, cert, findings, prioritization, recommendations) into `reports/` | ✅ Done |
| **5. Frontend** | Dark SOC UI: Overview Dashboard, Analysis, Session Explorer, TLS Handshake View, Findings Center, Remediation Center, Reporting page; scenario switcher + DEMO MODE badge | ✅ Done |
| **6. Verification** | All 6 scenarios analyzed (100/60/0/60/40/20), upload validation (junk rejected HTTP 400, valid pcap accepted), JSON + HTML reports (HTTP 200), index/static assets served, server log clean | ✅ Done |
| **7. Polish** | Consolidated findings (no double-penalty), separate no-FS rule, upload mode via query string, KB/MB hint, script.md synced to real numbers, venv setup documented. Rounds 2–6: real-data risk chart, true remediation math, dark-themed HTML report, UI polish, light/print theme, production presentation pass, Settings page (data-mode gate + retention) | ✅ Done |

## Architecture (as built)
```
securemailscope/
├── app.py           # Flask routes: /, /api/*, report export
├── audit.py         # Append-only JSONL audit trail (config/audit.jsonl)
├── analyzer.py      # PCAP validation + session/protocol/cert pipeline
├── rules.py         # Deterministic weakness rule engine (severity rules)
├── risk_engine.py   # Score = 100 − (30C+20H+10M+5L), clamp, band label
├── anomaly.py       # 6 deterministic anomaly detectors → score 0–100
├── ai_assist.py     # Feature-vector risk classifier + P1–P4 prioritization
├── report.py        # JSON + HTML report generation
├── data/            # 6 scenario JSONs (sessions/protocols/tls/certs/...)
├── templates/index.html
├── static/style.css, app.js   # SPA logic + hand-rolled canvas charts
├── reports/         # Generated report artifacts
├── config/          # settings.json (persisted settings) + audit.jsonl (audit trail)
└── docs: README.md, ARCHITECTURE.md, script.md (demo), research.md, brain.md
```

## Data Flow (pipeline the demo walks through)
PCAP/demo input → protocol detection (SMTP/IMAP/POP3 + confidence) → session reconstruction →
TLS handshake analysis → certificate analysis → rule-engine weakness detection → risk scoring →
AI-assisted prioritization → anomaly detection → remediation → forensic report.

## Scenario Registry (deterministic, never random)
| ID | File | Posture story |
|---|---|---|
| secure | data/secure.json | All TLS 1.2/1.3, valid certs → score 100 SECURE |
| weak_tls | data/weak_tls.json | TLS 1.0 mix → 60 MODERATE RISK |
| starttls_downgrade | data/starttls_downgrade.json | Stripped STARTTLS + TLS 1.0 + 3DES → 0 CRITICAL (demo scenario) |
| expired_certificate | data/expired_certificate.json | Expired 142-day cert → 60 MODERATE RISK |
| weak_cipher | data/weak_cipher.json | 3DES/RC4/CBC-SHA1 → 40 HIGH RISK |
| suspicious_tls | data/suspicious_tls.json | Cert mismatch + downgrade pattern → 20 CRITICAL, anomaly HIGH |

## Key Invariants (don't break during edits)
- Risk math: deterministic; identical scenario → identical score every run.
- Demo pipeline animation: 1–3 s max; never fake long loading.
- Every visible button performs a real action; no lorem ipsum; no console errors.
- Scenario switch immediately updates dashboard, sessions, findings, AI panel.
- Mark Resolved updates finding state and recomputes posture score.

## Demo Assets
- `script.md` — 3-minute video script with timestamps, narration, on-screen actions + checklist
- `README.md` — purpose, features, setup, run, scenarios, limitations (concise)
- `ARCHITECTURE.md` — system diagram, data flow, real vs simulated, production roadmap (8 phases)

## Open Items / Notes
- [x] Research documented with citations
- [x] All 6 scenarios load through the same analyzer pipeline
- [x] Dashboard visualizations (protocol, TLS version mix, cipher security) as offline canvas charts
- [x] Endpoint sweep: scenarios / analyze / upload validation / report json+html / static — all HTTP 200/400 as expected, clean server log
- [x] SES-014 demo targets verified: AI HIGH · 94% · P1, anomaly 91
- [x] Full browser walkthrough (Playwright + Firefox, `walkthrough.js`): **39/39 checks** — dashboard, pipeline, SES-014 drawer, findings + filters, remediation recompute, JSON/HTML export, scenario switch, zero console errors (screenshots in `shots/`)
- [x] Fixed during walkthrough: Reporting page hidden until analysis (now activates on ingest), scoped-variable bug in findings status rendering
- [x] Polish round 2: Session Risk Profile chart now plots real per-session scores (was synthetic data); what-if projection uses real penalty math (100 − open penalties, resolves to exactly 100); findings rows get severity edge markers; Analyze button shows Analyzing… state; dashboard resize redraws charts; empty-dashboard CTA; deep-link appendix in script.md; ARCHITECTURE.md Chart.js references removed
- [x] Polish round 3: HTML forensic report rebuilt in the dark SOC theme — branded header with chips (SIH26159 · PASSIVE ANALYSIS · CONTROLLED DEMO DATA), conic-gradient posture ring, KPI tiles incl. posture-penalty, CSS distribution bars (protocol/TLS/cipher), severity-coded finding cards with evidence blocks + posture cost, AI prioritization table, structured recommendations, transparent-math footer; printable (break-inside avoid) and verified in Firefox (42/42 walkthrough checks incl. standalone file render, no overflow)
- [x] Polish round 4 (UI): scenario cards show expected posture band chips (server-computed, deterministic); topbar live posture chip (score/band, updates on every analysis); keyboard shortcuts 1–6 for view switching; animated count-up posture gauge (respects reduced-motion); Analysis terminal gets macOS-style header + pulsing LIVE badge; Analyze button spinner state; KPI accent left-borders; dashboard findings rows jump straight to the evidence in Findings Center; status column reflects resolved state; session rows keyboard-accessible (Enter/Space); focus-visible rings; card hover states; ambient page glow; footer divider; 54/54 walkthrough checks green, zero console errors
- [x] Polish round 5 (theme + presentation): light/print theme — `data-theme` attr set pre-paint from localStorage (no FOUC), full light palette override, theme-aware canvas charts (track/grid/label/bar colors), topbar toggle (☀/🌙, aria-pressed, persisted), `@media print` stylesheet (white bg, chrome hidden, active view printed, color-adjust exact); **production presentation pass** — all user-facing surfaces de-demoed: DEMO MODE → DATA MODE: EVALUATION badge, Demonstration Scenarios → Capture Library, Scenario → Capture selector, roadmap/prototype wording removed from upload hint + footer, report v1.0 + EVALUATION DATASET chip, AI note reads as assist-layer feature disclosure; internal docs (README/ARCHITECTURE/brain) keep honest prototype framing; 62/62 walkthrough checks green incl. theme persistence across reload
- [x] Polish round 6 (Settings page): nav ⚙ Settings + keyboard shortcut 7; **data-mode policy** (evaluation ↔ live toggle switch, persisted server-side via GET/POST `/api/settings`) — LIVE gates the capture library (cards `.gated`+disabled, topbar select disabled, Analyze blocked with message, deep-link autostart suppressed, Operator card shows deployment profile); **report retention** (session/7d/30d/90d/forever select → POST sweeps expired artifacts from reports/ only when the window changes; sweep also at server boot for "session"; reads never sweep) + "Clear report store now" (`/api/reports/clear`) + live artifact inventory table (name/kind/size/mtime); transient action messages guarded against async re-render overwrites; walkthrough extended to 73 checks (73/73 green, zero console errors)
- [x] Polish round 7 (settings persistence): settings survive restarts via `config/settings.json` — atomic writes (tmp + `os.replace`), loaded at import time (WSGI-safe), unknown/invalid keys ignored, corrupt file silently falls back to defaults; invalid POST values rejected (HTTP 400) and never written; startup banner logs the active settings + path; verified across kill/restart cycles (set → restart → survive; corrupt file → defaults; 73/73 walkthrough still green)
- [x] Polish round 8 (audit trail): `audit.py` — append-only JSONL at `config/audit.jsonl`, thread-locked appends, I/O errors swallowed (never breaks request path), torn-line-tolerant tail(); events: mode_change, retention_change, reports_cleared + *_rejected for invalid values; Audit Trail panel on Settings (monospace newest-first log, color-coded event types, append-only chip); exposed via `/api/settings` GET and `/api/reports/clear` responses; walkthrough self-resets settings baseline at boot (persistence made a live-mode state leak visible); 77/77 checks green
- [x] Polish round 9 (confirmations): themed in-app confirm modal (no native confirm()) — promise-based confirmDialog() with backdrop-click, Esc (cancel) and Enter (confirm) handling, danger-solid confirm button, focus moves to Cancel; wired into Clear report store (states exact artifact count; no-op message when already empty) and retention changes (warns with the precise number of artifacts the new window would sweep, computed from the live inventory, only when > 0; Cancel reverts the select); 85/85 checks green incl. cancel/confirm/keyboard paths
- [x] Polish round 10 (audit coverage): analysis runs (analysis_run: source + session count + posture score/band), report exports (report_export: JSON/HTML + scenario + size), and rejected uploads (upload_rejected: filename + reason) are recorded server-side; panel color-codes the new types (green/cyan/orange); audit panel live-refreshes after every ingest via refreshAudit(); 88/88 checks green
- [x] Polish round 11 (audit export): `/api/audit/export?format=json|csv` — full trail oldest-first, RFC-4180 CSV (quoted details with embedded commas/arrows), JSON envelope {tool, exported_at, event_count, events}, timestamped download filenames via Content-Disposition; Export JSON / Export CSV buttons on the Audit Trail card with status hint; exports are themselves audited (audit_export events); walkthrough verifies both downloads by parsing the fetched files (CSV header/rows, JSON envelope roundtrip); 94/94 checks green
- [x] Polish round 12 (audit search/filters): client-side instant search box (matches ts/event/detail, highlighted rows) + category chips All/Policy/Analysis/Reports/Rejections (auditCategory maps event types, future types default to Policy visibility); hint line shows "N of M shown — exports always include the full trail" (exports unaffected by filters by design); no-match state keeps the total count visible; 103/103 checks green
- [x] Polish round 13 (audit pagination): windowed pagination in the audit panel — 50-event window with dashed "Show N older events (M hidden)" expander (+50 per click); server payload raised to tail(400) so the window is meaningful; search/filters operate on the full in-memory trail (matches beyond the window are findable), filter or search changes reset the window to 50, new events re-reset; walkthrough seeds 60 events and verifies cap/expand/search-across-trail/reset; 110/110 checks green
- [x] Polish round 14 (LIVE-mode confirmation): enabling LIVE data mode now requires the confirm dialog (states the lockout: operator-supplied captures only, library disabled + selector locked); Cancel reverts the switch and keeps EVALUATION; switching back to Evaluation stays friction-free (consistent with the retention-dialog rule: confirm only restrictive/destructive directions); 113/113 checks green
- [x] Polish round 15 (session inspection audit): POST `/api/audit/record` accepts only whitelisted client event types (CLIENT_AUDIT_EVENTS; anything else → HTTP 400, detail capped at 200 chars); openDrawer records `session_inspect` on first open per session per analysis (session flag, no duplicates on re-open) with detail: id, protocol, TLS version, cipher, anomaly score; fires best-effort via auditClient() — never blocks the drawer; panel color-codes it blue under the ANALYSIS filter; 115/115 checks green
- [x] Polish round 16 (visual sweep): `sweep.js` — every page × both themes with per-page assertions (theme bg, no horizontal overflow, key element renders, all 5 dashboard charts painted in each theme) + overlay captures (session drawer, findings detail in light); 33/33 sweep checks green, zero console errors; 16 screenshots in `shots/sweep/{dark,light}/`; primary demo shots re-refreshed via walkthrough (115/115); app left in demo-recommended dark state
- [x] Polish round 17 (docs sync): ARCHITECTURE.md rewritten to match the as-built system — API surface (settings/clear/audit endpoints), settings & data-mode layer (persistence semantics, sweep rules), audit trail layer (server + whitelisted client events, panel features, export), frontend section (views, themes, charts, safety), verification section (walkthrough 115 + sweep 33), updated component table incl. audit.py/config/, roadmap typo TAXOI→TAXII fixed
- [x] **Round 18 — "real version" pass (roadmap phases 1–3, 5, 8 shipped):**
  - `pcap_reader.py` — pure-Python pcap/pcapng reader (both endiannesses, µs/ns, SHB/IDB/EPB, if_tsresol; Ethernet/VLAN/raw-IP/SLL/SLL2/Null; IPv4+IPv6 incl. extension headers; TCP/UDP dissection; ParseError → operator-readable 400)
  - `tls_parser.py` — TLS record + handshake parser: ClientHello (SNI, cipher list, supported_versions), ServerHello (TLS 1.3 version via supported_versions ext — SH format is 2 raw bytes, CH is count-prefixed), Certificate (DER chains), Alerts; ext-vector length bug found+fixed via extension-loop rewrite; `find_tls_start()` locates the cleartext→TLS boundary for STARTTLS streams (sustained-binary detector + strict header validation — v1 heuristic was wrong at transition offsets, caught by test captures)
  - `cert_analysis.py` — X.509 via cryptography (subject/issuer RFC4514, validity incl. NOT_YET_VALID, RSA/ECDSA key size, sig-alg OID map, SAN, SHA-256 fingerprint dedupe); graceful UNPARSED fallback without the lib
  - `upload_pipeline.py` — flows → client/server direction (server = lower port) → per-direction reassembly (ISN-relative, retransmission-tolerant, 5 MB cap) → TLS facts → STARTTLS strip detection (advertised∧¬negotiated∧¬implicit) → dataset-schema sessions → analyzer engine; mail-focus guard (mail port or SNI); MAX_SESSIONS 400; no reference fallback — UploadError → 400 + audit
  - `ml_anomaly.py` — IsolationForest (n_estimators=100, seed 42, contamination 0.15) over 10 normalized session features; ≥8 sessions only; rank-based 0–100 score; raises deterministic anomaly by ≤15 with labeled detector line; `anomaly_ml` payload {available, source: "isolation_forest_unsupervised", score, note}; verified deterministic + outlier-detecting
  - `analyzer.py` refactor — `run_pipeline(scenario_id)` → thin wrapper over new `analyze_document(doc, scenario_id)` shared by both input paths (single scoring engine, no divergence)
  - `app.py` — upload route: real parse, no fallback; ParseError/UploadError → HTTP 400 + `upload_rejected` audit; `after_request` security headers (CSP default-src 'self' w/ style-src unsafe-inline, nosniff, frame-deny, referrer-policy)
  - `report.py` — parse_stats in JSON, `_cap_stats()` line + OPERATOR CAPTURE—FULLY PARSED chip for uploads (EVALUATION DATASET chip kept for scenarios)
  - Frontend — upload terminal prints real parse stats + truncation warning; session drawer shows ML assist line (available/score/note); settings copy de-demoed to "uploads fully parsed on-engine"; ENGINE_BUILD 2026.09 unchanged
  - `wsgi.py` + gunicorn entry; `Dockerfile` (py3.14-slim, non-root sms, healthcheck, only reports/+config/ writable) + `.dockerignore`; `OFFLINE_INSTALL.md` wheelhouse guide; requirements pinned (Flask 3.0.3, scikit-learn 1.9.1, cryptography 50.0.1, numpy 2.5.3)
  - Verification: `gen_test_pcaps.py` + `tests/e2e_upload.py` (33/33 — golden scores via API, real-parse upload assertions incl. TLS 1.3/STRIPTLS/expired-cert, content-sniff-beats-filename, junk/garbage/txt → 400, report markers, audit events, headers); walkthrough 115/115 (harness now archives config/audit.jsonl at boot — trail pollution from e2e runs had broken 2 absolute-count checks); sweep 33/33; golden scores byte-identical (100/60/0/60/40/20); full-result determinism verified
  - Tools quirks: write_file/str_replace calls intermittently returned mangled parameters (fixed by re-reading + surgical edits); run_terminal_command output swallowed when `pkill -f "app.py"`-style pattern matched the shell's own cmdline — use PID-file kills and keep patterns bracketed `[.]py`
- [x] **Round 19 — demo script: real-capture upload step:** script.md retimed to 3:00 with a new **02:10–02:30 Real Capture Upload (Live Evidence)** step — upload `~/gateway_demo.pcap` (pre-copied from `tests/mixed_ok.pcap`; cp line in the pre-recording setup), narrate the real parse-statistics terminal lines (✓ Parsed 41 packets → 7 TCP flows → 6 mail/TLS session(s), 2 certificate(s) analyzed), open the STRIPTLS-flagged plaintext SMTP session; report step (02:30) now generates from the uploaded capture and points at the OPERATOR CAPTURE — FULLY PARSED chip + parse-stats line; closing narration rewritten to "already parses operator captures end-to-end" (was claiming PCAP parsing/ML as future — false after round 18); Production Path section split Shipped vs Next; checklist + pacing notes updated ("never say demo during the upload step; let the parse-stats line sit on screen"); deep-link appendix notes the upload step is deliberately click-path-only (file chooser is the point). Support fixes: `gen_test_pcaps.py` demo timestamps → 2026 (2025 looked stale on camera); `upload_pipeline.py` meta polish — size_hint "9 KB" (was 0.0 MB), capture_window full seconds + explicit duration "(0.4 s)"; regression caught by harnesses: timedelta needs `.total_seconds()` for the `:.1f` format (500'd the upload route; e2e 33/33, walkthrough 115/115, sweep 33/33 re-verified after fix)
- [x] **Round 20 — four-feature expansion (user-picked):**
  - **SOC/SIEM export (roadmap phase 7, partial):** `siem.py` — STIX 2.1 bundle (identity, network-traffic per session with TLS context extensions, ipv4-addr values, x509-certificate, domain-name, email-addr, custom x-sms-finding with severity/labels/refs, report object with object_refs) + flat findings CSV; deterministic UUIDv5 ids seeded from analysis timestamp (same result → byte-identical bundle); passive IOC extraction (SNI domains, invalid-cert subjects, addresses, note emails). Route `/api/findings/export?format=stix|csv`, audited `siem_export`, mimetype application/stix+json. Reporting card with Export STIX Bundle / Findings CSV buttons.
  - **Capture comparison:** bounded HISTORY (12) in app.py via `_remember()` on every analyze; `GET /api/history` (slot summaries) + `POST /api/compare {a,b}` → compare.diff_results (score delta, counts delta, new/resolved findings keyed rule_id|title|object, per-session field/risk changes, ml outlier drift); audited `comparison_run`; Reporting card with before/after pickers (preselected last two) + delta render (+green/−red). Demo story verified: starttls_downgrade → secure = +100, 5 resolved.
  - **Captured TLS Stream viewer:** uploaded captures carry tls_stream (parsed events + remainders); drawer renders real records — cleartext phase transcript decoded from remainder hex (hexTranscript, ≥4 printable chars, 14-line cap), STARTTLS request marker, ClientHello (SNI + cipher count)/ServerHello (version+cipher)/Certificate/KeyExchange/CCS/Alert lines, "parsed from capture · N TLS records parsed" chip. Initial version showed nothing on plaintext sessions (remainders only had SMTP dialogue) — fixed by transcript rendering; caught by walkthrough.
  - **ML in demo:** gen_test_pcaps mixed_ok.pcap grown to 486 packets/12 flows/11 sessions (4 bulk IMAPS baseline sessions + 2nd plaintext POP3) → IsolationForest (≥8 sessions) now fires live: outliers = SES-003 (TLS 1.0/3DES) + SES-004 (STRIPTLS) — aligns with rule engine. Dashboard suspicious-KPI note shows cyan "N ML outliers" (kpiSuspiciousNote). script.md upload step re-quoted (631 KB, 486, 12, 11, 2; ML narration added).
  - Verification: e2e extended to 43 (stix types/determinism, csv, history, compare 200+400s, ml active + exact outlier set {SES-003,SES-004}); walkthrough extended to 124 (new STEP 12: browser upload via setInputFiles, parse-stats terminal lines, server-side audit delta, stream viewer ≥3 lines + capture-derived chip, SIEM buttons, comparison pickers + zero-delta regex /[(]\+?0[)]/ on identical uploads); sweep 33/33; golden scores untouched. New shots 12/13.
- [ ] Optional: verify `pip install -r requirements.txt` → `python app.py` on a clean machine
- [x] **Round 21 — persistence + eval stream viewer + SIEM guide (three followups):**
  - **History persistence:** comparison slots now survive restarts — `_remember()` persists to `config/history.json` (atomic tmp + os.replace, best-effort: disk failure never breaks analysis); `_load_history()` restores at import time (WSGI-safe, like `load_settings()`), validating entries (`risk`+`sessions` present) and clamping to 12; corrupt file → clean empty; boot banner prints restored slot count (app.py `__main__` + `wsgi.py`); `config/history.json(.tmp)` gitignored. Full results are stored (not summaries) — payload safe (cert dicts carry no DER) and `compare.diff_results` works across restarts unchanged.
  - `tests/test_history_persist.py` (14 checks) — self-managed server on :5177 (Popen/SIGTERM, no external server needed): two analyses → compare → file holds 2 results → restart → slots restored + compare still works (+100) + comparison_run audited → bound test (11 more → exactly 12, oldest dropped, file mirrors memory) → corrupt file → clean empty; finally-block restores pre-test config/ files. Gotcha caught: audit trail is newest-first — `audit[0]`, not `audit[-1]`.
  - **Dataset stream viewer:** `datasetStreamHtml(s)` in app.js renders a reconstructed TLS stream timeline for evaluation scenarios — STARTTLS request/220 + ClientHello (version)/ServerHello (version+cipher)/Certificate (subject)/KeyExchange (FS)/CCS×2/appdata×2; PLAINTEXT SMTP (port 25/587) → failed-upgrade timeline (request → "no TLS response — plaintext continued (STARTTLS stripped)"); gates: skip uploaded sessions (`s.tls_stream` — real records already rendered), mail ports only; header "TLS Stream (Reconstructed)" + chip "reconstructed from session facts · not from the capture bytes" (honesty preserved; no CSS additions needed). v1 gate bug: dataset sessions carry no per-session `starttls_events` (it's a top-level doc array) → plaintext sessions skipped, walkthrough crashed on `#drawer .stream-box` timeout; fixed with the port-25/587 canStarttls rule. Goldens untouched (drawer-only render).
  - Walkthrough STEP 4b (+6 checks → 130/130): SES-014 reconstructed stream (ClientHello+3DES, "reconstructed" chip), plaintext stripped-upgrade stream, SES-015 (993)/SES-018 (995) implicit-TLS render; new shot 04c.
  - **SIEM ingest guide:** OFFLINE_INSTALL.md §6 — export endpoints (curl), object-type table (identity/report/x-sms-finding/network-traffic/ipv4-addr/domain-name/email-addr/x509-certificate with x_sms_* fields), OpenCTI (manual import + scheduled connector pull, idempotent UUIDv5 ids), Splunk ES (CSV INDEXED_EXTRACTIONS with comment-row note + STIX/TAXII add-on), MISP import, correlation via `x_sms_session` (= SES-### matching UI/reports/audit), no-auth warning (fronting proxy), passive-only note.
  - Verification: e2e 43/43, walkthrough 130/130, sweep 33/33, `tests/test_history_persist.py` 14/14, golden scores byte-identical (100/60/0/60/40/20). Docs synced (README features/limitations, ARCHITECTURE components/verification/stream-viewer bullet, .gitignore).

## Vocabulary (keep consistent everywhere)
Posture Score · Finding · Severity (Critical/High/Medium/Low) · Session · STARTTLS ·
Forward Secrecy · Cipher Suite · AI Risk Class (SECURE/LOW/MODERATE/HIGH/CRITICAL) ·
AI Priority (P1–P4) · Anomaly Score · Remediation · DEMO MODE
