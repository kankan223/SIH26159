# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**
Smart India Hackathon 2026 — Problem Statement **SIH26159** · Org: **NTRO** · Theme: Blockchain & Cybersecurity · Category: Software

SecureMailScope passively analyzes captured email traffic (PCAP upload or controlled demo scenarios), reconstructs SMTP/IMAP/POP3 sessions, inspects STARTTLS/TLS negotiation and certificates, detects cryptographic weaknesses with a deterministic rule engine, scores the security posture, prioritizes risk with an AI-assisted layer, and exports forensic reports.

> **Engineering scope:** the capture-analysis path is real — uploads are dissected on-engine (PCAP/PCAPng → TCP reassembly → TLS handshake reconstruction → X.509 parsing) and scored by the deterministic rule engine. An unsupervised IsolationForest assist flags outlier sessions. Passive analysis only — no exploitation, no scanning of live targets.

## Features
- **Overview Dashboard** — posture score, severity KPIs, protocol/TLS/cipher distributions, recent findings, risk trend (offline canvas charts — zero CDN dependencies); dashboard notes when the ML assist flagged outliers
- **Light/print theme** — persisted toggle in the top bar; print stylesheet included
- **Analysis page** — PCAP upload with double validation, 6-capture evaluation library, animated pipeline
- **Real capture parsing** — pure-Python pcap/pcapng reader (Ethernet/raw-IP/SLL, VLAN, IPv4/IPv6), sequence-based TCP stream reassembly, TLS 1.0–1.3 record + handshake reconstruction (ClientHello/ServerHello/Certificate/Alerts, TLS 1.3 supported_versions aware), STARTTLS strip (STRIPTLS) and plaintext-fallback detection
- **X.509 certificate analysis** — DER chain parsing via `cryptography`: subject/issuer, validity window, RSA/EC key size, signature algorithm, SAN; expired/self-signed/weak-key detection feeds the same rule engine
- **Unsupervised ML assist** — IsolationForest (fixed seed → deterministic) over per-session feature vectors; raises anomaly scores with a labeled, capped contribution; disabled below 8 sessions
- **Session Explorer** — sortable session table + detail drawer (metadata, TLS negotiation, key exchange, certificate, weaknesses, remediation)
- **TLS Handshake View** — visual ClientHello→Encrypted Session timeline with weak-field highlighting
- **Certificate Analysis** — subject/issuer/validity/key/sig algorithm cards with expired-cert demo
- **Weakness Rule Engine** — deterministic rules aligned to RFC 8314 / NIST SP 800-52 / NSA obsolete-TLS guidance
- **Risk Scoring** — 100 − (Critical 30 / High 20 / Medium 10 / Low 5), banded SECURE→CRITICAL
- **AI-Assisted Prioritization** — feature-vector classifier → risk class, confidence %, reason, P1–P4 (honest prototype inference layer)
- **Anomaly Detection** — 6 deterministic detectors (downgrade, cipher change, failed STARTTLS, cert mismatch, odd handshake, TLS failure ratio) with 0–100 gauge, plus the ML assist above
- **Findings Center** — severity filters + evidence detail
- **Remediation Center** — step-by-step fixes, Mark Resolved (frontend state) with live score recompute
- **Reporting** — JSON export + standalone HTML forensic report (uploaded captures include parse statistics and an OPERATOR CAPTURE marker)
- **SOC/SIEM Feed** — STIX 2.1 bundle (network-traffic + x509-certificate observations, custom finding objects, report object) and a flat findings CSV via `/api/findings/export` — ingestable by OpenCTI, MISP, Splunk ES or ELK; IOCs (SNI domains, certificate subjects, observed addresses) are extracted from the analyzed capture only
- **Capture Comparison** — the last 12 analyses are kept (persisted in `config/history.json`, they survive restarts); diff any two as before/after remediation evidence: posture delta, new/resolved findings, per-session changes, ML-outlier drift
- **Captured TLS Stream viewer** — for uploaded captures the session drawer shows the real parsed records: the cleartext STARTTLS transcript, ClientHello/ServerHello/Certificate messages, ChangeCipherSpec and alerts — byte-derived evidence, not a canned timeline; evaluation scenarios get an equivalent drawer timeline explicitly labeled "reconstructed from session facts · not from the capture bytes"
- **Deployment hardening** — security headers (CSP, nosniff, frame-deny, referrer-policy) on every response, gunicorn WSGI entry (`wsgi.py`), Dockerfile (non-root, healthcheck), offline wheelhouse install for air-gapped networks ([OFFLINE_INSTALL.md](OFFLINE_INSTALL.md))
- **Settings** — data-mode policy (evaluation capture library vs. operator-supplied captures only), report retention windows (session / 7 / 30 / 90 days / forever) with immediate sweeps, an on-disk report artifact inventory, and an append-only audit trail of policy changes (persisted in `config/audit.jsonl`, with in-panel search, category filters, and JSON/CSV export). Destructive actions (clearing the store, retention changes that would delete artifacts) require explicit in-app confirmation with exact impact counts

## Architecture
```
Browser (HTML/CSS/Vanilla JS + canvas charts — fully offline)
   │  fetch /api/*
   ▼
Flask app.py ──► analyzer.py ──► rules.py ──► risk_engine.py ──► ai_assist.py ──► anomaly.py
     │                │ (rule engine, risk math, AI layer over any session document)
     │                ├── data/*.json (6 deterministic evaluation scenarios)
     │                └── upload_pipeline.py (uploaded captures)
     │                      ├─ pcap_reader.py   (pcap/pcapng → packets → TCP flows)
     │                      ├─ tls_parser.py    (TLS records + handshakes)
     │                      ├─ cert_analysis.py (X.509 via cryptography)
     │                      └─ ml_anomaly.py    (IsolationForest assist)
report.py ──► reports/ (JSON + HTML forensic report)      audit.py ──► config/audit.jsonl
```
Details: [ARCHITECTURE.md](ARCHITECTURE.md) · Research basis: [research.md](research.md)

## Setup
```bash
# Python 3.10+
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run
```bash
python app.py
# open http://localhost:5000

# production:
gunicorn --workers 2 --threads 4 --bind 127.0.0.1:8000 wsgi:app
```

## Uploading your own captures
Any .pcap/.pcapng/.cap (Ethernet, raw-IP, Linux SLL; 1 KB–50 MB) containing
SMTP/IMAP/POP3 traffic on ports 25/587/465/143/993/110/995. Captures are fully
parsed on-engine; sessions that cannot be classified as mail/TLS are dropped,
and unparseable files are rejected with a precise error (audited). Evaluation
scenario scores stay byte-identical to the published registry.

## Demo Scenarios
| Scenario | Data | Story |
|---|---|---|
| Secure Enterprise Mail | `data/secure.json` | TLS 1.2/1.3 everywhere → 100/100 SECURE |
| Weak TLS Configuration | `data/weak_tls.json` | TLS 1.0/SSLv3 mix → MODERATE/HIGH |
| STARTTLS Downgrade | `data/starttls_downgrade.json` | Stripped STARTTLS + TLS 1.0 + 3DES → CRITICAL demo (use in video) |
| Expired Certificate | `data/expired_certificate.json` | Cert expired 142 days ago → MODERATE |
| Weak Cipher Suite | `data/weak_cipher.json` | 3DES/RC4/CBC-SHA1 → HIGH RISK |
| Suspicious TLS | `data/suspicious_tls.json` | Cert mismatch + downgrade pattern → anomaly HIGH |

Full walkthrough with narration: [script.md](script.md)

## Limitations (current scope)
- TCP reassembly is per-flow and sequence-based; enterprise-scale capture volumes need the queue/worker layer on the roadmap
- Certificate chain building and revocation (OCSP/CRL) are out of scope — leaf properties are evaluated locally
- The ML layer is an unsupervised outlier assist over the analyzed capture, not a supervised classifier trained on labeled SOC data
- Frontend-only remediation state (no persistence across restarts)
- Settings, audit trail, and analysis history persist to local JSON files; no multi-user auth or role separation yet
