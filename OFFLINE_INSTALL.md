# SecureMailScope — Air-Gapped / Offline Deployment

The engine is built for classified and isolated networks: **zero CDN assets** in
the UI, no telemetry, no outbound connections at runtime, and a dependency set
that installs fully offline from a wheelhouse.

## 1. Build the wheelhouse (internet machine)

Same platform + Python version as the target (e.g. manylinux x86_64, Python 3.14):

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt gunicorn==23.0.0
pip download -r requirements.txt gunicorn==23.0.0 -d wheelhouse/
```

Transfer `wheelhouse/`, the project tree, and verify SHA-256 sums before import.

## 2. Install offline (target machine)

```bash
python -m venv .venv && . .venv/bin/activate
pip install --no-index --find-links wheelhouse/ -r requirements.txt gunicorn==23.0.0
```

## 3. Run

```bash
. .venv/bin/activate
gunicorn --workers 2 --threads 4 --bind 127.0.0.1:8000 wsgi:app
```

`wsgi.py` restores persisted settings from `config/settings.json` and runs the
boot-time retention sweep. Health probe: `GET /` (200).

## 4. Hardening checklist

- Bind gunicorn to localhost or a fronting reverse proxy — never 0.0.0.0 on shared networks
- Run as a dedicated non-root account; only `reports/` and `config/` are writable
- `config/settings.json` and `config/audit.jsonl` are the operator-relevant state —
  include them in backups; the audit trail is append-only
- Baseline response headers (nosniff / frame-deny / CSP / referrer-policy) ship
  in-code via `app.py::_security_headers`; add TLS termination at the proxy
- Uploads are validated twice (magic bytes + full parse) and rejected captures
  never touch the engine; every rejection is audit-recorded

## 5. Container image

`Dockerfile` (python:3.14-slim + gunicorn, non-root `sms` user, healthcheck) is
provided; build with `docker build -t securemailscope:1.0 .` on a connected
machine and `docker save`/`docker load` to move it into the enclave.

## 6. SIEM / SOC ingestion (STIX 2.1 + findings CSV)

SecureMailScope exports the current analysis as a **STIX 2.1 bundle**
(`application/stix+json`) and a flat **findings CSV**, from the Reporting view
(Export STIX Bundle / Findings CSV) or directly:

```bash
curl -o posture_stix.json  'http://127.0.0.1:8000/api/findings/export?format=stix'
curl -o posture_findings.csv 'http://127.0.0.1:8000/api/findings/export?format=csv'
```

A run must be completed first (the feed covers `STATE["result"]`). Object ids
are deterministic UUIDv5 (namespaced, seeded from the analysis timestamp), so
the same analysis always yields a byte-identical bundle — idempotent to re-ingest.

### Bundle contents

| STIX type | Meaning |
|---|---|
| `identity` | the tool (SecureMailScope, `created_by_ref` of the report) |
| `report` | one per run: posture score/band, finding count, `object_refs` |
| `x-sms-finding` | one per consolidated finding — `severity`, `labels`, `confidence`, `x_sms_impact`, `x_sms_recommendation`, `x_sms_sessions`, `x_sms_session_refs` |
| `network-traffic` | one per session: ports + `x_sms_session/protocol/tls_mode/tls_version/cipher/anomaly_score`; `dst_ref` (ipv4) or `x_sms_dst_hostname` |
| `ipv4-addr` / `domain-name` / `email-addr` | endpoints, SNI/subject hostnames, cleartext-phase addresses |
| `x509-certificate` | non-VALID certificates with `x_sms_status/key_alg/key_len` |

### OpenCTI

- **Manual:** Knowledge → Data → Import → File, upload `posture_stix.json`
  (the bundle is self-contained; custom `x_sms_*` properties are preserved).
- **Scheduled pull:** run the `curl` above from cron/systemd-timer into the
  OpenCTI ingestion directory of an "External Import" connector; idempotent ids
  mean re-pulls update rather than duplicate.
- Findings appear as observable + relationship graphs under the report object.

### Splunk Enterprise Security

- **Findings CSV (simplest):** index the CSV as a scripted/monitoring input
  (`INDEXED_EXTRACTIONS=CSV` in props.conf); skip the first line — it is a
  `# SecureMailScope findings feed, posture=…` comment row. Fields: `rule_id,
title, severity, affected_sessions, protocol, evidence, impact, recommendation,
status`.
- **STIX bundle:** use a STIX 2.x ingestion app (e.g. the Splunk STIX/TAXII
  add-on) pointed at the fetched file/endpoint; `x-sms-finding` objects map to
  threat-actuator-style custom objects, `network-traffic` to observables.
- Correlate `x_sms_session` across objects — it carries the engine's `SES-###`
  session id, which also matches the UI, reports, and audit trail.

### MISP

Event Actions → Import from… → STIX 2.1, upload the bundle; findings land as
galaxy-free custom objects with tags `critical|high|medium|low` (from `labels`).

> **Note:** the prototype API ships no authentication — put the reverse proxy
> (see §4) in front and issue the polling key there. Exports are passive,
> evidence-only feeds; nothing is probed, resolved, or scored out-of-band.
