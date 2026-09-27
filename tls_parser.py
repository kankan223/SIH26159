"""SecureMailScope — TLS record + handshake message parser (pure Python).

Parses TLS 1.0–1.3 record layers and handshake messages over reassembled TCP
byte streams: ClientHello (offered ciphers, SNI), ServerHello (chosen
version/cipher, TLS 1.3 supported_versions awareness), Certificate (DER
chains), Alert, and ChangeCipherSpec. Used by upload_pipeline to reconstruct
sessions; feeds the same deterministic rule engine the evaluation datasets use.

TLS 1.3 note: the outer record version is 0x0303 (legacy) and the real
negotiated version (0x0304) lives in a supported_versions extension of
ServerHello — handled here so TLS 1.3 sessions classify correctly.
"""
import struct

# ------------------------------------------------------------ constants ------
CT_CCS, CT_ALERT, CT_HANDSHAKE, CT_APPDATA = 20, 21, 22, 23

HT_CLIENT_HELLO = 1
HT_SERVER_HELLO = 2
HT_CERTIFICATE = 11

EXT_SNI = 0
EXT_SUPPORTED_VERSIONS = 43

MAX_TLS_RECORD = 18432          # 2^14 + 2048 (encrypted padding allowance)
MAX_HANDSHAKE_MSG = 262144      # fragment-assembly hard cap

LEGACY_VERSION_NAMES = {(3, 0): "SSLv3", (3, 1): "TLS 1.0",
                        (3, 2): "TLS 1.1", (3, 3): "TLS 1.2"}
TLS13 = (3, 4)


class TLSError(ValueError):
    """Malformed TLS stream — operator-readable message."""


def version_name(v):
    """(major, minor) → 'TLS 1.2' / 'SSLv3' / 'TLS 1.3' / f'TLS 0x{majorminor}'."""
    if v == TLS13:
        return "TLS 1.3"
    if v in LEGACY_VERSION_NAMES:
        return LEGACY_VERSION_NAMES[v]
    return f"TLS 0x{v[0]:02x}{v[1]:02x}"


def _u16(b, pos):
    return struct.unpack("!H", b[pos:pos + 2])[0]


def _u24(b, pos):
    return (b[pos] << 16) | (b[pos + 1] << 8) | b[pos + 2]


# ------------------------------------------------------- record processing ---
def _parse_client_hello(body):
    m = {"ciphers": [], "sni": None, "extensions": {}}
    if len(body) < 35:
        raise TLSError("ClientHello truncated")
    m["version"] = (body[0], body[1])
    pos = 2 + 32                                  # skip random
    sl = body[pos]
    pos += 1 + sl                                 # session id
    if pos + 2 > len(body):
        raise TLSError("ClientHello cipher list truncated")
    cs_len = _u16(body, pos)
    pos += 2
    if cs_len % 2 != 0 or pos + cs_len > len(body):
        raise TLSError("ClientHello cipher list malformed")
    for i in range(0, cs_len, 2):
        m["ciphers"].append(f"{body[pos + i]:02x}{body[pos + i + 1]:02x}")
    pos += cs_len
    if pos >= len(body):
        raise TLSError("ClientHello compression truncated")
    cm_len = body[pos]
    pos += 1 + cm_len
    m["extensions"] = _parse_ext_vector(body, pos)
    if m["sni"] is None:
        m["sni"] = m["extensions"].get("sni")
    return m


def _parse_server_hello(body):
    m = {"extensions": {}}
    if len(body) < 39:
        raise TLSError("ServerHello truncated")
    m["version"] = (body[0], body[1])
    pos = 2 + 32                                  # skip random
    sl = body[pos]
    pos += 1 + sl                                 # session id
    if pos + 3 > len(body):
        raise TLSError("ServerHello truncated")
    m["cipher"] = f"{_u16(body, pos):04x}"
    pos += 2
    pos += 1                                      # compression
    m["extensions"] = _parse_ext_vector(body, pos, server_hello=True)
    sv = m["extensions"].get("supported_versions")
    if sv:
        m["version"] = sv                         # TLS 1.3 real version
    return m


def _parse_ext_vector(body, pos, server_hello=False):
    """Extensions arrive as a 2-byte total length + entries; slice exactly."""
    if pos + 2 > len(body):
        return {}
    vlen = _u16(body, pos)
    return _parse_extensions(body[pos + 2:pos + 2 + vlen], server_hello=server_hello)


def _parse_certificate(body):
    """TLS Certificate message → list of DER blobs (leaf first)."""
    if len(body) < 3:
        raise TLSError("Certificate message truncated")
    total = _u24(body, 0)
    pos = 3
    end = min(3 + total, len(body))
    chain = []
    while pos + 3 <= end:
        dlen = _u24(body, pos)
        pos += 3
        if dlen == 0 or pos + dlen > len(body):
            break
        chain.append(body[pos:pos + dlen])
        pos += dlen
        if pos + 2 <= end:                        # per-cert extensions vector
            ext_len = _u16(body, pos)
            pos += 2 + ext_len
        else:
            break
    return chain


def _parse_handshake(mtype, body):
    """One full handshake message → dict (raises TLSError if malformed)."""
    if mtype == HT_CLIENT_HELLO:
        return _parse_client_hello(body)
    if mtype == HT_SERVER_HELLO:
        return _parse_server_hello(body)
    if mtype == HT_CERTIFICATE:
        return {"certs": _parse_certificate(body)}
    return {}


def _parse_extensions(raw, server_hello=False):
    """Raw extension bytes → {name: value}. Unknown/duplicate extensions ignored.
    supported_versions format differs: ServerHello carries a single 2-byte
    version; ClientHello carries a 1-byte count + version list."""
    out = {}
    pos = 0
    n = len(raw)
    while pos + 4 <= n:
        etype = _u16(raw, pos)
        elen = _u16(raw, pos + 2)
        pos += 4
        if pos + elen > n:
            break
        data = raw[pos:pos + elen]
        pos += elen
        if etype == EXT_SNI and elen >= 5 and data[0] == 0:
            ln = _u16(data, 1)
            if 3 + ln <= elen:
                out["sni"] = data[3:3 + ln].decode("ascii", "replace")
        elif etype == EXT_SUPPORTED_VERSIONS:
            if server_hello and elen == 2:
                out["supported_versions"] = (data[0], data[1])
            elif not server_hello and elen >= 1:
                cnt = data[0]
                if cnt % 2 == 0 and 2 <= cnt <= elen - 1:
                    vers = []
                    for i in range(0, cnt, 2):
                        vers.append((data[1 + i], data[2 + i]))
                    out["supported_versions"] = vers
    return out


def _printable_ratio(b):
    if not b:
        return 1.0
    ok = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return ok / len(b)


def find_tls_start(payload, max_scan=16384):
    """Locate where the cleartext protocol phase ends and TLS begins.

    STARTTLS connections carry an SMTP/IMAP/POP3 cleartext phase before the
    handshake, so the TLS layer does not start at stream offset 0. Method:
    find the first non-printable byte that starts a sustained binary region
    (next 64 bytes < 20% printable — stray control chars in text are skipped),
    then require a strictly valid TLS record header at that boundary — a
    check that can never turn ASCII junk into a record.
    Returns the record-header offset, or None (pure plaintext / not TLS).
    """
    n = len(payload)
    limit = min(n, max_scan)
    t = None
    for i in range(limit):
        b = payload[i]
        if 32 <= b < 127 or b in (9, 10, 13):
            continue
        if _printable_ratio(payload[i:min(i + 64, n)]) < 0.2:
            t = i
            break
    if t is None:
        return None                     # printable to the end → plaintext
    for off in range(max(0, t - 2), min(t + 8, n - 5) + 1):
        if payload[off] not in (CT_HANDSHAKE, CT_APPDATA, CT_ALERT, CT_CCS):
            continue
        ln = _u16(payload, off + 3)
        if ln == 0 or ln > MAX_TLS_RECORD:
            continue
        if off + 5 + ln > n and off + 5 + max(1, ln // 2) > n:
            continue
        return off
    return None


def seg_tls(payload, direction):
    """Parse TLS records from one TCP segment payload.

    Returns (events, remainder_hex):
      events       : handshake/alert/ccs/appdata dicts for frontend display
      remainder_hex: hex of trailing bytes that did not form a full record
                     (ciphertext awaiting the next segment) — displayed verbatim
    Each record consumes exactly 5 + length bytes — no heuristics, no garbage.
    """
    events = []
    pos = find_tls_start(payload)
    if pos is None:
        return [], payload[:2048].hex()                 # plaintext phase (shown verbatim)
    n = len(payload)
    while pos + 5 <= n:
        ctype = payload[pos]
        ver = (payload[pos + 1], payload[pos + 2])
        ln = _u16(payload, pos + 3)
        if ctype not in (CT_CCS, CT_ALERT, CT_HANDSHAKE, CT_APPDATA):
            return events, payload[pos:].hex()          # not TLS
        if ln > MAX_TLS_RECORD:
            return events, payload[pos:].hex()
        if pos + 5 + ln > n:
            return events, payload[pos:].hex()          # partial record — keep hex
        body = payload[pos + 5:pos + 5 + ln]
        pos += 5 + ln
        ev = {"dir": direction, "record_version": version_name(ver)}
        if ctype == CT_HANDSHAKE:
            ev["kind"] = "handshake"
            ev["messages"] = _messages(body)
        elif ctype == CT_ALERT:
            ev["kind"] = "alert"
            if len(body) >= 2:
                ev["level"], ev["description"] = body[0], body[1]
        elif ctype == CT_CCS:
            ev["kind"] = "ccs"
        else:
            ev["kind"] = "appdata"
        events.append(ev)
    if pos < n:
        return events, payload[pos:].hex()
    return events, ""


def _messages(body):
    """Record body → list of parsed handshake messages (partial tail ignored)."""
    out = []
    pos = 0
    n = len(body)
    while pos + 4 <= n:
        mtype = body[pos]
        ln = _u24(body, pos + 1)
        if ln > MAX_HANDSHAKE_MSG:
            break
        if pos + 4 + ln > n:
            break                       # fragmented across segments: ignore tail
        msg_body = body[pos + 4:pos + 4 + ln]
        pos += 4 + ln
        try:
            m = _parse_handshake(mtype, msg_body)
        except TLSError:
            m = {"parse_error": True}
        m["type"] = mtype
        out.append(m)
    return out
