# SecureMailScope — Research Notes (SIH26159)

**Problem Statement:** "SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications"
**Organization:** National Technical Research Organisation (NTRO) · **Theme:** Blockchain & Cybersecurity · **Category:** Software

---

## 1. Problem Domain

Organizations rely on email protocols (SMTP, IMAP, POP3) whose encryption is largely
**opportunistic** — traffic is captured on the wire (PCAP) or observed at the gateway, and the
analyst must answer: *is this email infrastructure actually protected by strong cryptography?*
SecureMailScope addresses this with passive, non-intrusive analysis of captured sessions.

## 2. Key Concepts Researched

### 2.1 Opportunistic TLS & STARTTLS
- STARTTLS (RFC 3207 for SMTP; RFC 2595 for IMAP/POP3) upgrades a **cleartext** connection to TLS.
- The negotiation itself is cleartext → an on-path attacker can **strip** STARTTLS (STRIPTLS
  attack) or replace the keyword with garbage; many clients silently fall back to plaintext.
- USENIX Security '21 ("A Security Analysis of STARTTLS in the Email Context", Poddebniak et al.):
  of 28 tested clients, only 3 showed no STARTTLS-specific vulnerabilities.
- MITM downgrade is feasible because there is **no default policy enforcement**.

### 2.2 Enforcement Mechanisms (production relevance)
- **MTA-STS** (RFC 8460): DNS-hosted policy forcing TLS for inbound SMTP, defeating downgrades.
  Adoption remains low (APNIC, 2024).
- **DANE** (RFC 7672): TLSA records bind X.509 certs to DNSSEC — certificate-pinning alternative.
- **TLS-RPT** (RFC 8460): recipients report TLS failures back to the sending domain.
- EFF **STARTTLS Policy List**: mirrored-policy list used to detect downgrade behavior.

### 2.3 Transport Security Standards (basis of our rule engine)
- **RFC 8314** ("Cleartext Considered Obsolete"): TLS 1.2+ required, TLS 1.0/1.1 should not be
  used; recommends implicit TLS on 465 (SMTPS), 993 (IMAPS), 995 (POP3S).
- **NIST SP 800-52 Rev. 2**: US government systems must support TLS 1.2 (FIPS ciphers) and
  should prefer TLS 1.3; mandates disabling weak suites.
- **NSA "Eliminating Obsolete TLS" (Jan 2021)**: obsolete = SSLv2/SSLv3, TLS 1.0/1.1, and
  cipher mechanisms RC4, DES/3DES, IDEA, export-grade, NULL.
- Deprecated protocol severity mapping used in the prototype:
  SSLv3 → CRITICAL (POODLE-class), TLS 1.0/1.1 → HIGH, TLS 1.2 → OK, TLS 1.3 → best.

### 2.4 Weak Cryptographic Primitives
| Primitive | Status | Severity in engine |
|---|---|---|
| RC4 | Prohibited (RFC 7465); biases exploited in practice | CRITICAL |
| 3DES (TDES) | Sweet32 birthday attacks on 64-bit blocks; NIST disallowed after 2023 | HIGH |
| CBC-SHA1 suites | Legacy; BEAST/Lucky13 class issues | MEDIUM |
| RSA key < 2048 | Factorable range; NIST minimum is 2048 (SP 800-57) | HIGH |
| SHA1 signatures | Chosen-prefix collisions demonstrated (2017/2020) | HIGH |
| MD5 signatures | Broken; collisions trivial | CRITICAL |
| No forward secrecy (static RSA key exchange) | Compromised key decrypts past captures | MEDIUM |
| Expired / mismatched certificate | No identity assurance; MITM window | HIGH |
| Self-signed / untrusted issuer | Identity not verifiable | MEDIUM |

### 2.5 Certificate Analysis (X.509)
Fields the prototype evaluates: Subject (CN/SAN), Issuer, validity window, public-key
algorithm + length (RSA ≥ 2048 / EC ≥ 256), signature algorithm (SHA256+), chain trust.
Production would perform full **chain validation** (RFC 5280) incl. revocation (OCSP/CRL) —
simulated deterministically in the prototype from prebuilt scenarios.

### 2.6 PCAP Analysis Tooling
- **Scapy** (`rdpcap`/`PcapReader`): packet iteration, TCP session reassembly basics.
- **PyShark**: tshark-wrapper, decode_as for `225→smtp`, `993→imaps` style dissection.
- TLS handshake extraction: filter `tcp` + `tls.record.content_type == 22`, ClientHello
  (type 1, cipher list, extensions), ServerHello (chosen version/cipher), Certificate msg.
- Python `cryptography`/`pyOpenSSL`: parse DER certs for expiry, key length, signature alg.
- Production must reconstruct out-of-order TCP segments — a known hard problem (kept simulated).

### 2.7 AI-Assisted Prioritization (lightweight, honest)
- Prototype uses a **deterministic feature-vector classifier**: features = TLS version score,
  cipher strength, certificate status, forward secrecy, STARTTLS behavior, anomaly indicators.
- Output: risk class (SECURE→CRITICAL), confidence, human-readable reason, P1–P4 priority.
- This mirrors how real SOCs triage (risk-based queueing); no trained NN is claimed.
- Production roadmap: Isolation Forest / autoencoder anomaly models over session features,
  trained on labeled SOC data; XGBoost-style ranking for triage queues.

### 2.8 Anomaly Detection Signals (deterministic set used)
- TLS version downgrade between sessions from same source
- Unexpected cipher change across connections to same destination
- Repeated failed STARTTLS attempts (stripping indicator)
- Certificate mismatch (cert CN ≠ destination hostname)
- Unusual handshake sequence (e.g., immediate close after ClientHello)
- Excessive TLS failure ratio on one link

## 3. Related Products / Landscape
- **testssl.sh / SSL Labs**: point-in-time TLS scanners (active probing, not passive).
- **Zeek (Bro)**: passive framework with SMTP/TLS logs — closest architectural inspiration.
- **Wireshark**: manual expert analysis; SecureMailScope automates the cryptographic subset.
- Gap: passive *email-protocol-focused cryptographic posture* tools with AI triage are rare →
  the SIH problem statement targets this gap.

## 4. Design Decisions Derived From Research
1. Rule engine encodes RFC 8314 / NIST 800-52 / NSA obsolete-TLS guidance (defensible, citable).
2. Scoring: start at 100, subtract Critical 30 / High 20 / Medium 10 / Low 5, clamp 0–100 —
   transparent and explainable to judges.
3. Risk bands: 90–100 SECURE, 75–89 LOW, 50–74 MODERATE, 25–49 HIGH, 0–24 CRITICAL.
4. Passive-only posture: analyze supplied captures/demo data; no active probing or exploitation
   (aligned with ethical constraints of the PS).
5. Six deterministic demo scenarios so judges see cause→effect reliably, never random output.

## 5. Sources
- RFC 3207 (SMTP STARTTLS), RFC 2595 (IMAP/POP3 TLS), RFC 8314 (cleartext obsolete)
- RFC 8460 (MTA-STS), RFC 7672 (DANE), RFC 5280 (X.509), RFC 7465 (prohibit RC4)
- NIST SP 800-52 Rev.2, NIST SP 800-57 (key sizes)
- NSA guidance "Eliminating Obsolete Transport Layer Security" (2021)
- Poddebniak et al., USENIX Security 2021 — STARTTLS security analysis
- DigiCert/Elie Bursztein articles on STRIPTLS & downgrade attacks; EFF STARTTLS-EWS
- APNIC blog (2024): SMTP downgrade attacks and MTA-STS adoption
