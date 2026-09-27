"""SecureMailScope — uploaded capture → session reconstruction pipeline.

Real end-to-end parsing for operator-supplied captures:
  pcap/pcapng bytes → pcap_reader packets → bidirectional TCP flows →
  byte-stream reassembly (sequence-number based, retransmission-tolerant) →
  TLS handshake reconstruction (tls_parser) → X.509 analysis (cert_analysis) →
  STARTTLS strip / plaintext-fallback detection → session dicts in the exact
  schema the evaluation datasets use → analyzer.analyze_document runs the
  deterministic rule engine, risk math, AI layer and anomaly detectors.

Deterministic: identical capture → identical sessions/scores. No reference
fallback — if the capture cannot be parsed into mail/TLS sessions, an
UploadError with an operator-readable message is raised (HTTP 400).
"""
import datetime
from collections import defaultdict

import pcap_reader
import tls_parser
from tls_parser import version_name
import cert_analysis
import analyzer as _analyzer

MAIL_PORTS = {25: "SMTP", 587: "SMTP", 465: "SMTP",
              143: "IMAP", 993: "IMAP",
              110: "POP3", 995: "POP3"}
IMPLICIT_TLS_PORTS = {465, 993, 995}

MAX_SESSIONS = 400          # session cap per capture (larger captures note truncation)
MAX_STREAM = 5 * 1024 * 1024   # per-direction reassembly cap

CIPHER_NAMES = {
    "0004": "RC4-MD5", "0005": "RC4-SHA", "000a": "DES-CBC3-SHA",
    "002f": "AES128-SHA", "0035": "AES256-SHA",
    "003c": "AES128-SHA256", "003d": "AES256-SHA256",
    "0033": "DHE-RSA-AES128-SHA", "0039": "DHE-RSA-AES256-SHA",
    "009c": "RSA-AES128-GCM-SHA256", "009d": "RSA-AES256-GCM-SHA384",
    "c013": "ECDHE-RSA-AES128-SHA", "c014": "ECDHE-RSA-AES256-SHA",
    "c023": "ECDHE-ECDSA-AES128-SHA256", "c027": "ECDHE-RSA-AES128-SHA256",
    "c028": "ECDHE-RSA-AES256-SHA256",
    "c02b": "ECDHE-ECDSA-AES128-GCM-SHA256", "c02c": "ECDHE-ECDSA-AES256-GCM-SHA384",
    "c02f": "ECDHE-RSA-AES128-GCM-SHA256", "c030": "ECDHE-RSA-AES256-GCM-SHA384",
    "1301": "TLS_AES_128_GCM_SHA256", "1302": "TLS_AES_256_GCM_SHA384",
    "1303": "TLS_CHACHA20_POLY1305_SHA256",
}


class UploadError(ValueError):
    """Capture parsed but no analyzable mail/TLS sessions — operator-readable."""


# ------------------------------------------------------------ reassembly -----
def _pick_directions(pkts):
    """Classify flow endpoints: returns (client_ep, server_ep). Server = the
    listening side (lower port); on equal ports, first sender is the client."""
    a = (pkts[0]["src_ip"], pkts[0]["src_port"])
    b = (pkts[0]["dst_ip"], pkts[0]["dst_port"])
    if a[1] < b[1]:
        return b, a                     # a is the server
    if b[1] < a[1]:
        return a, b                     # b is the server
    return a, b


def _isn(pkts, ep):
    for p in pkts:
        if (p["src_ip"], p["src_port"]) == ep and p["flags"] & pcap_reader.SYN \
                and not p["flags"] & pcap_reader.ACK and p["ip_proto"] == 6:
            return p["seq"]
    for p in pkts:
        if (p["src_ip"], p["src_port"]) == ep and p["payload"] and p["ip_proto"] == 6:
            return p["seq"]
    return None


def _stream(pkts, ep, isn):
    """Ordered, deduped byte stream for one direction (seq-wrap safe)."""
    mine = [p for p in pkts if (p["src_ip"], p["src_port"]) == ep and p["payload"]]
    if not mine:
        return b""
    if isn is None:
        isn = mine[0]["seq"]
    mine.sort(key=lambda p: ((p["seq"] - isn) & 0xFFFFFFFF, p["ts"]))
    out = bytearray()
    seen = set()
    for p in mine:
        rs = (p["seq"] - isn) & 0xFFFFFFFF
        ln = len(p["payload"])
        k = (rs, ln)
        if k in seen:
            continue          # retransmission / duplicate ACK data
        seen.add(k)
        end = rs + ln
        if len(out) < end:
            if end > MAX_STREAM:
                break         # direction cap: keep what reassembled
            out.extend(b"\x00" * (end - len(out)))
        out[rs:rs + ln] = p["payload"]
    return bytes(out[:MAX_STREAM])


# ------------------------------------------------------------ plaintext -----
def _ascii_phase(data):
    """True if the stream starts with a printable-ASCII protocol phase."""
    if not data:
        return False
    head = data[:64]
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(head) >= 0.9


def _starttls_info(c2s, s2c, implicit):
    """STARTTLS negotiation signals from the cleartext phase of a mail flow."""
    info = {"plaintext_phase": bool(c2s and _ascii_phase(c2s)),
            "advertised": False, "negotiated": False, "client_cmd": None}
    if implicit or not info["plaintext_phase"]:
        return info
    if b"STARTTLS" in s2c[:1024]:
        info["advertised"] = True
    if c2s[:8].upper().startswith(b"STARTTLS") or c2s[:8].upper().startswith(b"STARTTL"):
        info["client_cmd"] = "STARTTLS"
    return info


# ------------------------------------------------------------ TLS session ---
def _tls_facts(c2s, s2c):
    """Extract TLS handshake facts from both directions of a flow."""
    ch = sh = None
    certs = []
    alerts = []
    rec_c, rem_c = tls_parser.seg_tls(c2s, "c")
    rec_s, rem_s = tls_parser.seg_tls(s2c, "s")
    for ev in rec_c:
        for m in ev.get("messages", []):
            if m["type"] == tls_parser.HT_CLIENT_HELLO and ch is None:
                ch = m
    for ev in rec_s:
        for m in ev.get("messages", []):
            if m["type"] == tls_parser.HT_SERVER_HELLO and sh is None:
                sh = m
            elif m["type"] == tls_parser.HT_CERTIFICATE:
                certs.extend(m.get("certs", []))
        if ev.get("kind") == "alert":
            alerts.append(ev)
    for ev in rec_c:
        if ev.get("kind") == "alert":
            alerts.append(ev)
    # embedded handshake copies must be JSON-safe: replace DER blobs with markers
    for ev in rec_c + rec_s:
        for m in ev.get("messages", []):
            if isinstance(m.get("certs"), list):
                m["certs"] = [f"<DER certificate, {len(d)} bytes>" for d in m["certs"]]
    return {"ch": ch, "sh": sh, "certs": certs, "alerts": alerts,
            "events": {"client": rec_c, "server": rec_s},
            "remainders": {"client": rem_c, "server": rem_s},
            "tls_seen": bool(rec_c or rec_s)}


def _version_and_cipher(facts):
    ch, sh = facts["ch"], facts["sh"]
    ver_struct = None
    cipher_code = None
    if sh:
        ver_struct = sh["version"]
        cipher_code = sh.get("cipher")
    elif ch:
        ver_struct = ch["version"]
        # TLS 1.3 client offering 1.3 over legacy 0x0303: show best offer
        sv = ch.get("extensions", {}).get("supported_versions")
        if sv and tls_parser.TLS13 in sv:
            ver_struct = tls_parser.TLS13
    version = version_name(ver_struct) if ver_struct else None
    cipher = CIPHER_NAMES.get(cipher_code, f"0x{cipher_code}") if cipher_code else None

    key_exchange = None
    if cipher:
        c = cipher.upper()
        if version == "TLS 1.3":
            key_exchange = "ECDHE"          # TLS 1.3 key exchange is always (EC)DHE
        elif c.startswith("ECDHE"):
            key_exchange = "ECDHE"
        elif c.startswith("DHE"):
            key_exchange = "DHE"
        else:
            key_exchange = "RSA"            # static RSA / unrecognized → no FS assumed
    return version, cipher, key_exchange


def _cipher_strength(cipher):
    c = (cipher or "").upper()
    if not c or c in ("—", "NONE"):
        return "NONE"
    if "RC4" in c or "3DES" in c or "DES-" in c or "MD5" in c or "EXP" in c or "NULL" in c:
        return "WEAK"
    if "GCM" in c or "CHACHA20" in c:
        return "STRONG"
    return "LEGACY"


def _cert_mismatch(cert, dst):
    """Leaf cert subject/SAN vs destination hostname (SNI or reverse label).
    Skipped when the destination is a bare IP — the intended name is unknown."""
    if not cert or not dst or "." not in dst:
        return False
    if dst.replace(".", "").isdigit():
        return False                     # IPv4 literal: no hostname to match against
    subj = (cert.get("subject") or "").lower()
    san = (cert.get("san") or "").lower()
    d = dst.lower()
    cn = subj.split("cn=")[-1].split(",")[0].strip() if "cn=" in subj else subj
    for cand in (san.split(", ") if san else []):
        if cand == d or cand.endswith("." + d) or d.endswith("." + cand):
            return False
    return not (cn == d or cn.endswith("." + d) or d.endswith("." + cn))


# ------------------------------------------------------------ flow → sess ---
def _flow_session(key, pkts, cert_bag, idx):
    """Analyze one TCP flow → (session dict | None, starttls_event | None)."""
    c_ep, s_ep = _pick_directions(pkts)
    dst_port = s_ep[1]
    protocol = MAIL_PORTS.get(dst_port)

    isn_c = _isn(pkts, c_ep)
    isn_s = _isn(pkts, s_ep)
    c2s = _stream(pkts, c_ep, isn_c)
    s2c = _stream(pkts, s_ep, isn_s)

    facts = _tls_facts(c2s, s2c)
    implicit = dst_port in IMPLICIT_TLS_PORTS
    st = _starttls_info(c2s, s2c, implicit)

    has_tls = facts["tls_seen"] or (facts["ch"] is not None)
    # mail-focus guard: keep flows on mail ports, or TLS flows whose
    # ClientHello SNI names the destination (mail-protocol heuristics stay
    # conservative — anything else is noise and is dropped)
    sni = (facts["ch"] or {}).get("sni")
    mail_related = bool(protocol) or bool(sni)
    if not has_tls and not st["plaintext_phase"]:
        return None, None                     # not a mail/TLS flow (noise)
    if not mail_related:
        return None, None                     # TLS noise without SNI

    version, cipher, kx = _version_and_cipher(facts) if has_tls else (None, None, None)
    cert = None
    if facts["certs"]:
        entries, cert_bag = cert_analysis.dedupe_certs(facts["certs"], cert_bag)
        if entries:
            cert = entries[0]                 # leaf first

    # TLS mode classification (matches dataset vocabulary)
    if not has_tls:
        tls_mode = "PLAINTEXT"
    elif implicit:
        tls_mode = "IMPLICIT TLS"
    elif st["plaintext_phase"]:
        # cleartext phase seen: upgraded only if a handshake actually followed
        tls_mode = "STARTTLS" if facts["sh"] is not None else "PLAINTEXT"
    else:
        tls_mode = "STARTTLS"                 # TLS on a cleartext mail port

    # negotiate flag: TLS handshake actually completed after plaintext phase
    if st["plaintext_phase"] and st["client_cmd"] and facts["sh"] is not None:
        st["negotiated"] = True

    detected = []
    if st["advertised"] and not st["negotiated"] and not implicit:
        detected.append("STARTTLS stripped — advertised by server but negotiation "
                        "fell back to plaintext (possible STRIPTLS attack)")
    if cert and _cert_mismatch(cert, _display_dst(facts, s_ep)):
        detected.append(f"Certificate mismatch — leaf subject does not match "
                        f"destination '{_display_dst(facts, s_ep)}'")

    ts0 = pkts[0]["ts"]
    ts1 = max(p["ts"] for p in pkts)
    sess = {
        "id": f"SES-{idx:03d}",
        "protocol": protocol or "OTHER",
        "src": c_ep[0],
        "dst": _display_dst(facts, s_ep),
        "src_port": c_ep[1],
        "dst_port": dst_port,
        "tls": tls_mode,
        "tls_version": version or "NONE",
        "cipher": cipher or "—",
        "key_exchange": kx or "—",
        "forward_secrecy": kx in ("ECDHE", "DHE"),
        "cert": cert["id"] if cert else None,
        "packets": len(pkts),
        "bytes": sum(len(p["payload"]) for p in pkts),
        "duration_s": round(max(0.0, ts1 - ts0), 1),
        "anomaly": {"score": 0, "detected": detected, "confidence": 92},
        "tls_stream": {
            "client": facts["events"]["client"],
            "server": facts["events"]["server"],
            "remainders": facts["remainders"],
            "plaintext_phase": st["plaintext_phase"],
            "client_cmd": st["client_cmd"],
        },
        "capture_meta": {"flow": f"{c_ep[0]}:{c_ep[1]} → {s_ep[0]}:{s_ep[1]}"},
    }

    st_event = None
    if st["advertised"] or (protocol == "SMTP" and st["plaintext_phase"]):
        st_event = {"session": sess["id"],
                    "advertised": st["advertised"],
                    "negotiated": st["negotiated"] or tls_mode in ("STARTTLS", "IMPLICIT TLS")}
    return sess, st_event


def _display_dst(facts, s_ep):
    """Prefer SNI hostname, fall back to server IP."""
    ch = facts.get("ch")
    if ch and ch.get("sni"):
        return ch["sni"]
    return s_ep[0]


# ------------------------------------------------------------ entrypoint ----
def build_document(blob, filename, today=None):
    """Capture bytes → dataset-shaped document for analyzer.analyze_document."""
    today = today or datetime.date.today()
    packets = list(pcap_reader.iter_packets(blob))
    flows = pcap_reader.group_flows(packets)

    cert_bag = []
    sessions = []
    starttls_events = []
    truncated = False
    for key, pkts in flows:
        if pkts[0]["ip_proto"] != 6:
            continue                       # UDP (DNS etc.) out of scope
        if len(sessions) >= MAX_SESSIONS:
            truncated = True
            break
        s, ev = _flow_session(key, pkts, cert_bag, len(sessions) + 1)
        if s:
            sessions.append(s)
            if ev:
                starttls_events.append(ev)

    if not sessions:
        raise UploadError(
            "No email or TLS sessions could be reconstructed from this capture — "
            "verify it contains SMTP/IMAP/POP3 traffic on ports 25/587/465/143/993/110/995.")

    # unsupervised anomaly assist (deterministic; skipped when too few sessions)
    import ml_anomaly
    ml_anomaly.enrich(sessions)

    proto_counts = defaultdict(int)
    for s in sessions:
        proto_counts[s["protocol"]] += 1
    protocols = [{"name": p, "sessions": n, "confidence": 99}
                 for p, n in sorted(proto_counts.items(), key=lambda kv: (-kv[1], kv[0]))]

    tls_ct = sum(1 for s in sessions if s["tls"] != "PLAINTEXT")
    stats = {
        "packets": len(packets),
        "tcp_flows": sum(1 for _k, pkts in flows if pkts[0]["ip_proto"] == 6),
        "sessions": len(sessions),
        "tls_sessions": tls_ct,
        "plaintext_sessions": len(sessions) - tls_ct,
        "certificates_parsed": len(cert_bag),
        "sessions_truncated": truncated,
    }
    t0 = datetime.datetime.fromtimestamp(min(p["ts"] for p in packets))
    t1 = datetime.datetime.fromtimestamp(max(p["ts"] for p in packets))

    size_kb = len(blob) / 1024
    meta = {
        "name": f"Uploaded capture — {filename}",
        "file_label": filename,
        "size_hint": f"{size_kb:.0f} KB" if size_kb < 1024 else f"{size_kb / 1024:.1f} MB",
        "capture_window": f"{t0.strftime('%Y-%m-%d %H:%M:%S')} – {t1.strftime('%H:%M:%S')}"
                           + (f" ({(t1 - t0).total_seconds():.1f} s)" if t1 > t0 else ""),
        "description": "Operator-supplied packet capture, fully parsed "
                       "(PCAP dissection, TCP reassembly, TLS/X.509 analysis).",
        "source": "upload",
        "parse_stats": stats,
    }
    notes = (f"Parsed {stats['packets']} packets → {stats['tcp_flows']} TCP flows; "
             f"{stats['tls_sessions']} TLS handshakes reconstructed, "
             f"{stats['plaintext_sessions']} plaintext mail sessions; "
             f"{stats['certificates_parsed']} certificate(s) analyzed.")

    return {
        "meta": meta,
        "protocols": protocols,
        "certificates": cert_bag,
        "sessions": sessions,
        "starttls_events": starttls_events,
        "notes": notes,
    }


def run_upload(blob, filename, today=None):
    """Uploaded capture bytes → complete analysis result via the shared engine.
    Malformed captures surface as UploadError (HTTP 400 + audit), never 500."""
    today = today or datetime.date.today()
    try:
        doc = build_document(blob, filename, today=today)
    except pcap_reader.ParseError as e:
        raise UploadError(str(e)) from e
    return _analyzer.analyze_document(doc, scenario_id=filename, today=today)
