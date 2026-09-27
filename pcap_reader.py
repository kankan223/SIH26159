"""SecureMailScope — pure-Python pcap/pcapng reader + link/network/transport dissection.

No external dependencies. Streams packets as dicts:
    {ts, link_type, eth_type, ip_proto, src_ip, dst_ip, src_port, dst_port,
     seq, ack, flags, payload, payload_sha1}

Supported link types: Ethernet, raw IPv4/IPv6, Linux SLL (cooked), SLL2, Null/Loopback.
The reader validates magic bytes and raises ValueError with an operator-readable message
on malformed input — the caller maps that to HTTP 400 + audit record.
"""
import hashlib
import struct

# ------------------------------------------------------------------ magics ---
MAGIC_PCAP_LE = b"\xd4\xc3\xb2\xa1"          # little-endian microsecond
MAGIC_PCAP_BE = b"\xa1\xb2\xc3\xd4"          # big-endian microsecond
MAGIC_PCAP_LE_NS = b"\x4d\x3c\xb2\xa1"       # little-endian nanosecond
MAGIC_PCAP_BE_NS = b"\xa1\xb2\x3c\x4d"       # big-endian nanosecond
MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"

PCAP_MAGICS = (MAGIC_PCAP_LE, MAGIC_PCAP_BE, MAGIC_PCAP_LE_NS, MAGIC_PCAP_BE_NS, MAGIC_PCAPNG)

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101           # raw IPv4/IPv6 (some tools use 12/14)
LINKTYPE_SLL = 113
LINKTYPE_SLL2 = 276

VALID_LINKTYPES = {LINKTYPE_NULL, LINKTYPE_ETHERNET, 12, 14, LINKTYPE_RAW,
                   LINKTYPE_SLL, LINKTYPE_SLL2}

MAX_PACKET = 262144          # 256 KB per record hard cap (junk guard)

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


class ParseError(ValueError):
    """Malformed capture — operator-readable message, maps to HTTP 400."""


# ---------------------------------------------------------------- packets ----
def iter_packets(blob):
    """Yield packet dicts from a pcap or pcapng byte blob.
    Raises ParseError on malformed input; silently skips non-IP frames."""
    if len(blob) < 16:
        raise ParseError("Capture too small to contain a file header.")
    magic = blob[:4]

    if magic == MAGIC_PCAPNG:
        yield from _iter_pcapng(blob)
    elif magic in PCAP_MAGICS:
        yield from _iter_pcap(blob)
    else:
        raise ParseError("Not a valid PCAP/PCAPng file (magic bytes missing).")


def _yield_ip_packet(ts, link_type, frame):
    """Dissect one link-layer frame into a packet dict (or None if not IP/TCP/UDP)."""
    eth_type = None
    off = 0
    if link_type == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        eth_type = struct.unpack("!H", frame[12:14])[0]
        off = 14
        # VLAN tags (802.1Q, max 2 stacked)
        vlans = 0
        while eth_type == 0x8100 and vlans < 2:
            if len(frame) < off + 4:
                return None
            eth_type = struct.unpack("!H", frame[off + 2:off + 4])[0]
            off += 4
            vlans += 1
        if eth_type == 0x8100:   # >2 stacked VLAN tags — treat as non-IP
            return None
    elif link_type == LINKTYPE_NULL:
        if len(frame) < 4:
            return None
        off = 4
        eth_type = struct.unpack("!I", frame[:4])[0]  # AF_INET, host order
    elif link_type in (12, 14, LINKTYPE_RAW):
        # raw IP: family from the IP version nibble
        if not frame:
            return None
        if frame[0] >> 4 == 4:
            eth_type = 0x0800
        elif frame[0] >> 4 == 6:
            eth_type = 0x86DD
        else:
            return None
    elif link_type == LINKTYPE_SLL:
        if len(frame) < 16:
            return None
        eth_type = struct.unpack("!H", frame[14:16])[0]
        off = 16
    elif link_type == LINKTYPE_SLL2:
        if len(frame) < 20:
            return None
        eth_type = struct.unpack("!H", frame[16:18])[0]
        off = 20
    else:
        return None

    if eth_type not in (0x0800, 0x86DD):
        return None

    # ---- IPv4 / IPv6 ----
    if eth_type == 0x86DD:
        if len(frame) < off + 40:
            return None
        nxt = frame[off + 6]
        # skip extension headers (Hop-by-Hop, Routing, DestOpt, AH)
        hops = 0
        while nxt in (0, 43, 60, 51) and hops < 8:
            ext_len = (frame[off + 1] * 8) + (4 if nxt == 51 else 8)
            if len(frame) < off + ext_len:
                return None
            nxt = frame[off]
            off += ext_len
            hops += 1
        src_ip = _fmt_ip6(frame[off:off + 16])
        dst_ip = _fmt_ip6(frame[off + 8:off + 24])
        off += 40
        ip_proto = nxt
    else:
        if len(frame) < off + 20:
            return None
        ver_ihl = frame[off]
        if ver_ihl >> 4 != 4:
            return None
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(frame) < off + ihl:
            return None
        ip_proto = frame[off + 9]
        src_ip = _fmt_ip4(frame[off + 12:off + 16])
        dst_ip = _fmt_ip4(frame[off + 16:off + 20])
        off += ihl

    if not src_ip or not dst_ip:
        return None

    # ---- TCP / UDP ----
    if ip_proto == 6 and len(frame) >= off + 20:
        sport, dport = struct.unpack("!HH", frame[off:off + 4])
        seq, ack = struct.unpack("!II", frame[off + 4:off + 12])
        data_off = (frame[off + 12] >> 4) * 4
        if data_off < 20 or len(frame) < off + data_off:
            return None
        flags = frame[off + 13]
        payload = frame[off + data_off:]
        return {
            "ts": ts, "link_type": link_type, "eth_type": eth_type, "ip_proto": 6,
            "src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": dport,
            "seq": seq, "ack": ack, "flags": flags,
            "payload": bytes(payload),
            "payload_sha1": hashlib.sha1(payload).hexdigest()[:12],
        }
    if ip_proto == 17 and len(frame) >= off + 8:
        sport, dport, ulen = struct.unpack("!HHH", frame[off:off + 6])
        if ulen < 8 or len(frame) < off + ulen:
            return None
        payload = frame[off + 8:off + ulen]
        return {
            "ts": ts, "link_type": link_type, "eth_type": eth_type, "ip_proto": 17,
            "src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": dport,
            "seq": 0, "ack": 0, "flags": 0,
            "payload": bytes(payload),
            "payload_sha1": hashlib.sha1(payload).hexdigest()[:12],
        }
    return None


def _fmt_ip4(b):
    if len(b) != 4:
        return ""
    return ".".join(str(x) for x in b)


def _fmt_ip6(b):
    if len(b) != 16:
        return ""
    groups = [f"{(b[i] << 8) | b[i + 1]:x}" for i in range(0, 16, 2)]
    s = ":".join(groups)
    return "::" if s == "0:0:0:0:0:0:0:0" else s


def _iter_pcap(blob):
    if len(blob) < 24:
        raise ParseError("Truncated pcap file header.")
    magic = blob[:4]
    endian = "<" if magic in (MAGIC_PCAP_LE, MAGIC_PCAP_LE_NS) else ">"
    nanos = magic in (MAGIC_PCAP_LE_NS, MAGIC_PCAP_BE_NS)
    link_type = struct.unpack(endian + "I", blob[20:24])[0]
    if link_type not in VALID_LINKTYPES:
        raise ParseError(
            f"Unsupported capture link type {link_type} — Ethernet or raw-IP captures expected.")

    off = 24
    n = len(blob)
    while off + 16 <= n:
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", blob[off:off + 16])
        off += 16
        if incl_len > MAX_PACKET:
            raise ParseError("Capture record exceeds the per-packet size cap — file may be corrupt.")
        if off + incl_len > n:
            break   # truncated final record: keep what parsed
        frame = blob[off:off + incl_len]
        off += incl_len
        ts = ts_sec + ts_frac / (1e9 if nanos else 1e6)
        pkt = _yield_ip_packet(ts, link_type, frame)
        if pkt:
            yield pkt


def _iter_pcapng(blob):
    """pcapng: SHB carries endianness; IDB carries link type + timestamp resolution.
    Multiple interfaces: the first recognized IDB's link type wins."""
    n = len(blob)
    off = 0
    endian = "<"
    link_type = None
    nanos = False
    saw_shb = False
    first_shb = True
    while off + 12 <= n:
        block_type, block_len = struct.unpack(endian + "II", blob[off:off + 8])
        if first_shb and block_type == 0x0A0D0D0A and not (12 <= block_len <= n - off):
            # 0x0A0D0D0A is endian-symmetric; the length is not — probe both.
            alt = struct.unpack(">II", blob[off:off + 8])
            if 12 <= alt[1] <= n - off:
                block_type, block_len = alt
        if block_len < 12:
            raise ParseError("Malformed pcapng block length.")
        if off + block_len > n:
            break   # truncated final block: keep what parsed
        body = blob[off + 8:off + block_len - 4]
        if block_type == 0x0A0D0D0A:                     # SHB
            bom = body[0:4] if len(body) >= 4 else b""
            if bom == b"\x4d\x3c\xb2\xa1":        # byte-swapped LE magic → BE file
                endian = ">"
            elif bom == b"\x1a\x2b\x3c\x4d":        # native LE magic
                endian = "<"
            first_shb = False
            saw_shb = True
        elif block_type == 0x00000001:                   # IDB
            if link_type is None and len(body) >= 8:
                lt = struct.unpack(endian + "H", body[0:2])[0]
                if lt in VALID_LINKTYPES:
                    link_type = lt
                    # if_tsresol option (code 9): bit 0x80 → nanoseconds
                    opt_off = 8
                    while opt_off + 4 <= len(body):
                        code, olen = struct.unpack(endian + "HH", body[opt_off:opt_off + 4])
                        if code == 0:
                            break
                        if code == 9 and olen == 1:
                            nanos = bool(body[opt_off + 4] & 0x80)
                        opt_off += 4 + olen
                        opt_off += -opt_off % 4
        elif block_type == 0x00000006 and link_type is not None:   # EPB
            if len(body) >= 20:
                _iface, ts_hi, ts_lo, cap_len, _orig_len = struct.unpack(
                    endian + "IIIII", body[:20])
                if cap_len > MAX_PACKET:
                    raise ParseError(
                        "Capture record exceeds the per-packet size cap — file may be corrupt.")
                if len(body) >= 20 + cap_len:
                    frame = body[20:20 + cap_len]
                    ts = ((ts_hi << 32) | ts_lo) / (1e9 if nanos else 1e6)
                    pkt = _yield_ip_packet(ts, link_type, frame)
                    if pkt:
                        yield pkt
        # unknown block types are skipped (they advance by block_len)
        off += block_len
    if not saw_shb:
        raise ParseError("PCAPng file contains no section header block.")
    if link_type is None:
        raise ParseError("PCAPng file contains no usable interface description block.")


# ----------------------------------------------------------------- flows -----
def make_flow_key(pkt):
    """Canonical bidirectional flow key (tuple)."""
    a = (pkt["src_ip"], pkt["src_port"])
    b = (pkt["dst_ip"], pkt["dst_port"])
    if a <= b:
        return (a, b)
    return (b, a)


def group_flows(packets):
    """Group packets into bidirectional TCP/UDP flows, preserving capture order."""
    flows = {}
    order = []
    for p in packets:
        if p["ip_proto"] not in (6, 17):
            continue
        k = make_flow_key(p)
        if k not in flows:
            flows[k] = []
            order.append(k)
        flows[k].append(p)
    return [(k, flows[k]) for k in order]
