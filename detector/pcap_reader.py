"""Small, defensive PCAP / PCAPNG reader written in pure Python.

It only READS bytes and extracts TCP header metadata. It never executes or
transmits anything from the file. Works without Scapy/Npcap.
"""
import ipaddress
import struct


class PcapFormatError(Exception):
    """Raised when a file is not a valid / supported capture file."""


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MAX_PACKET = 262144
MAX_BLOCK = 16 * 1024 * 1024


def check_magic(path):
    with open(path, "rb") as f:
        head = f.read(4)
    if head in PCAP_MAGICS:
        return "pcap"
    if head == PCAPNG_MAGIC:
        return "pcapng"
    raise PcapFormatError("Not a valid PCAP/PCAPNG file (unknown file signature).")


def iter_packets(path):
    """Yield dicts: timestamp, is_tcp, src, dst, sport, dport, flags."""
    kind = check_magic(path)
    gen = _read_pcap(path) if kind == "pcap" else _read_pcapng(path)
    for ts, linktype, data in gen:
        yield _parse(ts, linktype, data)


def _read_pcap(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            raise PcapFormatError("File is too short to be a PCAP file.")
        endian, res = PCAP_MAGICS[hdr[:4]]
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        while True:
            ph = f.read(16)
            if not ph:
                return
            if len(ph) < 16:
                raise PcapFormatError("Truncated packet header.")
            sec, frac, incl, _orig = struct.unpack(endian + "IIII", ph)
            if incl > MAX_PACKET:
                raise PcapFormatError("Corrupt capture (packet length too large).")
            data = f.read(incl)
            if len(data) < incl:
                raise PcapFormatError("Truncated packet data.")
            yield sec + frac * res, linktype, data


def _read_pcapng(path):
    ifaces = []      # list of (linktype, tsresol)
    endian = "<"
    with open(path, "rb") as f:
        while True:
            head = f.read(8)
            if not head:
                return
            if len(head) < 8:
                raise PcapFormatError("Truncated PCAPNG block.")
            btype_raw = head[:4]
            if btype_raw == PCAPNG_MAGIC:                      # Section header
                total_raw = head[4:8]
                bom = f.read(4)
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise PcapFormatError("Bad PCAPNG byte-order marker.")
                total = struct.unpack(endian + "I", total_raw)[0]
                if total < 12 or total > MAX_BLOCK:
                    raise PcapFormatError("Bad PCAPNG section block.")
                f.read(total - 12)
                ifaces = []
                continue
            btype, total = struct.unpack(endian + "II", head)
            if total < 12 or total > MAX_BLOCK or total % 4:
                raise PcapFormatError("Corrupt PCAPNG block length.")
            body = f.read(total - 8)
            if len(body) < total - 8:
                raise PcapFormatError("Truncated PCAPNG block.")
            body = body[:-4]
            if btype == 1:                                      # Interface description
                link = struct.unpack(endian + "H", body[0:2])[0]
                ifaces.append((link, _tsresol(body[8:], endian)))
            elif btype == 6:                                    # Enhanced packet
                if len(body) < 20:
                    raise PcapFormatError("Corrupt enhanced packet block.")
                iid, hi, lo, cap, _orig = struct.unpack(endian + "IIIII", body[:20])
                if iid >= len(ifaces) or cap > len(body) - 20:
                    raise PcapFormatError("Corrupt enhanced packet block.")
                link, res = ifaces[iid]
                yield ((hi << 32) | lo) * res, link, body[20:20 + cap]


def _tsresol(opts, endian):
    res = 1e-6
    i = 0
    while i + 4 <= len(opts):
        code, ln = struct.unpack(endian + "HH", opts[i:i + 4])
        if code == 0:
            break
        if code == 9 and ln >= 1 and i + 5 <= len(opts):
            v = opts[i + 4]
            res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        i += 4 + ((ln + 3) // 4) * 4
    return res


def _parse(ts, linktype, data):
    non_tcp = {"timestamp": ts, "is_tcp": False}
    try:
        if linktype == 1:                                       # Ethernet
            if len(data) < 14:
                return non_tcp
            etype = struct.unpack("!H", data[12:14])[0]
            off = 14
            while etype in (0x8100, 0x88A8) and len(data) >= off + 4:   # VLAN tags
                etype = struct.unpack("!H", data[off + 2:off + 4])[0]
                off += 4
            if etype not in (0x0800, 0x86DD):
                return non_tcp
            ip = data[off:]
        elif linktype in (101, 12, 228, 229):                  # raw IP
            ip = data
        elif linktype == 113:                                   # Linux cooked
            ip = data[16:]
        elif linktype == 276:                                   # Linux cooked v2
            ip = data[20:]
        elif linktype == 0:                                     # BSD loopback
            ip = data[4:]
        else:
            return non_tcp
        return _parse_ip(ts, ip) or non_tcp
    except (struct.error, IndexError, ValueError):
        return non_tcp


def _parse_ip(ts, ip):
    if not ip:
        return None
    ver = ip[0] >> 4
    if ver == 4 and len(ip) >= 20:
        ihl = (ip[0] & 0x0F) * 4
        frag = struct.unpack("!H", ip[6:8])[0] & 0x1FFF
        if ip[9] != 6 or frag != 0 or ihl < 20:
            return None
        src = str(ipaddress.IPv4Address(ip[12:16]))
        dst = str(ipaddress.IPv4Address(ip[16:20]))
        tcp = ip[ihl:]
    elif ver == 6 and len(ip) >= 40:
        nh, off = ip[6], 40
        while nh in (0, 43, 60):                                # skip extension headers
            if len(ip) < off + 8:
                return None
            nh, ln = ip[off], ip[off + 1]
            off += (ln + 1) * 8
        if nh != 6:
            return None
        src = str(ipaddress.IPv6Address(ip[8:24]))
        dst = str(ipaddress.IPv6Address(ip[24:40]))
        tcp = ip[off:]
    else:
        return None
    if len(tcp) < 14:
        return None
    sport, dport = struct.unpack("!HH", tcp[:4])
    return {"timestamp": ts, "is_tcp": True, "src": src, "dst": dst,
            "sport": sport, "dport": dport, "flags": tcp[13]}
