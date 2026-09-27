#!/usr/bin/env python3
"""SecureMailScope — synthetic test-capture generator (verification only).

Builds real pcap files (Ethernet/IPv4/TCP) that exercise the full upload
pipeline: STARTTLS negotiation, TLS 1.3 and TLS 1.2 handshakes with parseable
self-signed DER certificates, TLS 1.0 + 3DES, plaintext fallback (STARTTLS
stripped), and a junk/garbage variant for rejection-path checks.

Not shipped to operators — developer tooling, like walkthrough.js/sweep.js.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))

# ----------------------------------------------------------------- helpers ---
def eth_ip_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                          (5 << 4), flags, 8192, 0, 0)
    tcp_seg = tcp_hdr + payload
    total = 20 + len(tcp_seg)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0x4000,
                         64, 6, 0,
                         bytes(int(x) for x in src_ip.split(".")),
                         bytes(int(x) for x in dst_ip.split(".")))
    # checksums left zero — parser ignores them; shape is what matters
    frame = b"\x00" * 6 + b"\x11" * 6 + struct.pack("!H", 0x0800) + ip_hdr + tcp_seg
    return frame


def write_pcap(path, frames, ts0=1790400000.0):   # 2026-09-26 05:20 UTC (demo-fresh)
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
    ts = ts0
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(f), len(f))
        out += f
        ts += 0.01
    with open(path, "wb") as fh:
        fh.write(bytes(out))
    print(f"wrote {path} ({len(out)} bytes, {len(frames)} frames)")


class Flow:
    """Tiny deterministic TCP flow builder (client 10.10.1.20, server side)."""

    def __init__(self, dst_ip, dst_port, sport):
        self.c = ("10.10.1.20", sport)
        self.s = (dst_ip, dst_port)
        self.seq_c = 1000
        self.seq_s = 5000
        self.frames = []

    def _send(self, frm, to, payload):
        seq = self.seq_c if frm == self.c else self.seq_s
        ack = self.seq_s if frm == self.c else self.seq_c
        f = eth_ip_tcp(frm[0], to[0], frm[1], to[1], seq, ack, 0x18, payload)
        self.frames.append(f)
        if frm == self.c:
            self.seq_c += len(payload)
        else:
            self.seq_s += len(payload)

    def c2s(self, payload):
        self._send(self.c, self.s, payload)

    def s2c(self, payload):
        self._send(self.s, self.c, payload)

    def handshake_payloads(self):
        return None


# ------------------------------------------------------------------ TLS ------
def u8(v):  return bytes([v])
def u16(v): return struct.pack("!H", v)
def u24(v): return struct.pack("!I", v)[1:]


def tls_record(ctype, body, ver=(3, 3)):
    return u8(ctype) + u8(ver[0]) + u8(ver[1]) + u16(len(body)) + body


def hs_msg(mtype, body):
    return u8(mtype) + u24(len(body)) + body


def client_hello(legacy=(3, 3), sni="mail.example.net", ciphers=(0x1301, 0xc02f, 0x002f),
                 supported=((3, 4), (3, 3))):
    sni_b = sni.encode()
    sni_ext = u16(0) + u16(len(sni_b) + 3) + u16(len(sni_b)) + sni_b
    sv_list = b"".join(u8(a) + u8(b) for a, b in supported)
    sv_ext = u16(43) + u16(len(sv_list) + 1) + u8(len(sv_list)) + sv_list
    exts = sni_ext + sv_ext
    cs = b"".join(u16(c) for c in ciphers)
    body = (u8(legacy[0]) + u8(legacy[1]) + b"\x42" * 32 + u8(0)
            + u16(len(cs)) + cs + u8(1) + u8(0) + u16(len(exts)) + exts)
    return hs_msg(1, body)


def server_hello(version=(3, 3), cipher=0xc02f, tls13=False):
    exts = b""
    if tls13:
        exts = u16(43) + u16(2) + u8(3) + u8(4)
    body = (u8(version[0]) + u8(version[1]) + b"\x11" * 32 + u8(0)
            + u16(cipher) + u8(0) + u16(len(exts)) + exts)
    return hs_msg(2, body)


def make_self_signed_cert(cn, days=365, key_bits=2048, sig_hash="sha256",
                          not_after=None, not_before=None):
    """Real DER certificate via the cryptography library."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    nb = not_before or datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    na = not_after or (nb + datetime.timedelta(days=days))
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)          # self-signed
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(nb).not_valid_after(na))
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    h = {"sha256": hashes.SHA256(), "sha1": hashes.SHA1()}[sig_hash]
    cert = builder.sign(key, h)
    return cert.public_bytes(serialization.Encoding.DER)


def certificate_msg(ders):
    entries = b"".join(u24(len(d)) + d + u16(0) for d in ders)
    return hs_msg(11, u24(len(entries)) + entries)


# ------------------------------------------------------------- scenarios -----
def flow_starttls_ok(cert_der):
    """SMTP STARTTLS that upgrades successfully (TLS 1.2 ECDHE-RSA-AES256-GCM)."""
    f = Flow("93.184.216.34", 25, 40001)
    f.s2c(b"220 mx.example.net ESMTP ready\r\n")
    f.c2s(b"EHLO client.local\r\n")
    f.s2c(b"250-mx.example.net\r\n250-STARTTLS\r\n250 SIZE 35882577\r\n")
    f.c2s(b"STARTTLS\r\n")
    f.s2c(b"220 2.0.0 Ready to start TLS\r\n")
    f.c2s(tls_record(22, client_hello()))
    f.s2c(tls_record(22, server_hello((3, 3), 0xc02f)) +
          tls_record(22, certificate_msg([cert_der])) +
          tls_record(22, hs_msg(12, b"\xAA" * 300)) +            # ServerKeyExchange
          tls_record(22, hs_msg(14, b"")))                        # ServerHelloDone
    f.c2s(tls_record(22, hs_msg(16, b"\xBB" * 66)) +              # ClientKeyExchange
          tls_record(20, b"\x01" + b"\x00" * 47))                 # CCS+Finished
    f.s2c(tls_record(20, b"\x01" + b"\x00" * 47))
    f.c2s(tls_record(23, b"MAIL FROM:<a@example.org> RCPT TO:<b@example.net>\r\n"))
    f.s2c(tls_record(23, b"250 OK\r\n"))
    return f.frames


def flow_tls13(cert_der):
    """IMAPS (993) TLS 1.3 handshake — version lives in supported_versions."""
    f = Flow("93.184.216.34", 993, 41002)
    f.c2s(tls_record(22, client_hello(), ver=(3, 3)))
    f.s2c(tls_record(22, server_hello(tls13=True, cipher=0x1301), ver=(3, 3)) +
          tls_record(22, certificate_msg([cert_der]), ver=(3, 3)) +
          tls_record(23, b"\x9f" * 900, ver=(3, 3)))              # encrypted flights
    f.c2s(tls_record(23, b"\x5a" * 400, ver=(3, 3)))
    f.s2c(tls_record(23, b"* OK [CAPABILITY IMAP4rev1] Ready\r\n", ver=(3, 3)))
    return f.frames


def flow_tls10_3des():
    """SMTP STARTTLS negotiated down to TLS 1.0 with 3DES-CBC-SHA."""
    f = Flow("198.51.100.7", 25, 42003)
    f.s2c(b"220 oldrelay.partner.net ESMTP\r\n")
    f.c2s(b"EHLO client.local\r\n")
    f.s2c(b"250-oldrelay.partner.net\r\n250-STARTTLS\r\n250 OK\r\n")
    f.c2s(b"STARTTLS\r\n")
    f.s2c(b"220 Ready\r\n")
    f.c2s(tls_record(22, client_hello(legacy=(3, 1), ciphers=(0x000a, 0x0005),
                                      supported=((3, 1),))))
    f.s2c(tls_record(22, server_hello((3, 1), 0x000a), ver=(3, 1)) +
          tls_record(22, hs_msg(12, b"\xCC" * 200), ver=(3, 1)) +
          tls_record(22, hs_msg(14, b""), ver=(3, 1)))
    f.c2s(tls_record(22, hs_msg(16, b"\xDD" * 64), ver=(3, 1)) +
          tls_record(20, b"\x01" + b"\x00" * 47, ver=(3, 1)))
    f.s2c(tls_record(20, b"\x01" + b"\x00" * 47, ver=(3, 1)))
    f.c2s(tls_record(23, b"MAIL FROM:<c@example.org>\r\n", ver=(3, 1)))
    return f.frames


def flow_starttls_stripped():
    """STRIPTLS: server advertises STARTTLS, client sends it, but a downgrade
    reply forces plaintext fallback — session stays cleartext (SMTP)."""
    f = Flow("203.0.113.9", 25, 43004)
    f.s2c(b"220 mx.target.example ESMTP\r\n")
    f.c2s(b"EHLO client.local\r\n")
    f.s2c(b"250-mx.target.example\r\n250-STARTTLS\r\n250 OK\r\n")
    f.c2s(b"STARTTLS\r\n")
    f.s2c(b"454 4.7.0 TLS not available due to temporary reason\r\n")  # injected
    f.c2s(b"MAIL FROM:<d@example.org> RCPT TO:<e@target.example>\r\nDATA\r\n")
    f.s2c(b"250 OK\r\n354 go\r\n")
    return f.frames


def flow_pop3s(cert_der):
    """POP3S (995) implicit TLS 1.2 — no plaintext phase."""
    f = Flow("93.184.216.34", 995, 44005)
    f.c2s(tls_record(22, client_hello(sni="pop.example.net",
                                      ciphers=(0xc030, 0x0035))))
    f.s2c(tls_record(22, server_hello((3, 3), 0xc030)) +
          tls_record(22, certificate_msg([cert_der])))
    f.c2s(tls_record(23, b"USER bob\r\nPASS s3cret\r\n"))
    f.s2c(tls_record(23, b"+OK maildrop locked\r\n"))
    return f.frames


def flow_pop3_plaintext(sport=45006, user="alice"):
    """POP3 (110) pure plaintext credentials."""
    f = Flow("198.51.100.7", 110, sport)
    f.s2c(b"+OK POP3 ready\r\n")
    f.c2s(f"USER {user}\r\nPASS hunter2\r\nLIST\r\n".encode())
    f.s2c(b"+OK password accepted\r\n+OK 2 messages\r\n")
    return f.frames


def junk_flow():
    """Random binary noise on a non-mail port — must be filtered out."""
    f = Flow("8.8.8.8", 443, 48008)
    f.c2s(bytes(range(256)) * 2)
    f.s2c(b"\xde\xad\xbe\xef" * 64)
    return f.frames


def flow_imaps_bulk(cert_der, sport, total_bytes):
    """IMAPS (993) TLS 1.2 session carrying bulk appdata — baseline traffic
    for the unsupervised ML assist (varying sizes → real spread)."""
    f = Flow("93.184.216.34", 993, sport)
    f.c2s(tls_record(22, client_hello(sni="mail.example.net",
                                      ciphers=(0xc02f, 0x002f))))
    f.s2c(tls_record(22, server_hello((3, 3), 0xc02f)) +
          tls_record(22, certificate_msg([cert_der])))
    chunk = b"M" * 1400
    full = total_bytes // 1400
    for _ in range(full):
        f.c2s(tls_record(23, chunk))
    if total_bytes % 1400:
        f.c2s(tls_record(23, b"M" * (total_bytes % 1400)))
    f.s2c(tls_record(23, b"+ OK appdata delivered\r\n"))
    return f.frames


def main():
    out = os.path.join(os.path.dirname(__file__), "tests")
    os.makedirs(out, exist_ok=True)

    cert_ok = make_self_signed_cert("mx.example.net")
    cert_pop = make_self_signed_cert("pop.example.net")

    frames = []
    frames += flow_starttls_ok(cert_ok)
    frames += flow_tls13(cert_ok)
    frames += flow_tls10_3des()
    frames += flow_starttls_stripped()
    frames += flow_pop3s(cert_pop)
    frames += flow_pop3_plaintext(45006, "alice")
    # bulk-traffic tail: 4 healthy IMAPS sessions → IsolationForest has a real
    # baseline (MIN_SESSIONS = 8) and the demo shows a live ML outlier verdict
    frames += flow_imaps_bulk(cert_ok, 46008, 240000)
    frames += flow_imaps_bulk(cert_ok, 46009, 180000)
    frames += flow_imaps_bulk(cert_ok, 46010, 120000)
    frames += flow_imaps_bulk(cert_ok, 46011, 60000)
    frames += flow_pop3_plaintext(47007, "bob")          # sparse-outlier profile
    frames += junk_flow()
    write_pcap(os.path.join(out, "mixed_ok.pcap"), frames)

    # expired-cert capture (single POP3S flow)
    expired = make_self_signed_cert(
        "old.example.net",
        not_before=datetime_utc(-200), not_after=datetime_utc(-30))
    write_pcap(os.path.join(out, "expired_cert.pcap"),
               flow_pop3s(expired) + flow_pop3_plaintext())

    # weak-key cert (1024-bit RSA; cryptography 50 refuses SHA1 signing, so
    # the key-size rule exercises the weak-cert detection path)
    weak = make_self_signed_cert("weak.example.net", key_bits=1024, sig_hash="sha256")
    write_pcap(os.path.join(out, "weak_cert.pcap"),
               flow_pop3s(weak) + flow_starttls_ok(make_self_signed_cert("mx.example.net")))

    # rejection-path junk: valid magic, garbage records
    with open(os.path.join(out, "garbage_records.pcap"), "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        fh.write(os.urandom(2048))
    print("wrote tests/garbage_records.pcap")


def datetime_utc(days):
    import datetime
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)


if __name__ == "__main__":
    main()
