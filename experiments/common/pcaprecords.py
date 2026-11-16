"""pcaprecords.py — minimal, fast reader/writer for legacy libpcap files.

Only what the experiments need, implemented with fixed-offset `struct`
parsing (no Scapy): iterate records as (timestamp, bytes), and extract the
transport 5-tuple of a frame.  Supported link types: Ethernet (1, with one
802.1Q tag), Linux cooked v1 (113), raw IPv4/IPv6 (101, 228, 229).  IPv4
options are honoured; IPv6 extension headers are not walked (such packets
simply yield no 5-tuple).  Anything unrecognized yields None — the parser
accepts exactly the fixed-layout grammar it knows and nothing else.
"""

import struct

LEGACY_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),   # little-endian, µs
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),   # big-endian, µs
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little-endian, ns
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big-endian, ns
}

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229


class PcapFormatError(ValueError):
    pass


def read_header(f):
    magic = f.read(4)
    if magic not in LEGACY_MAGICS:
        raise PcapFormatError("not a legacy pcap file (pcapng is not supported)")
    endian, tick = LEGACY_MAGICS[magic]
    rest = f.read(20)
    if len(rest) != 20:
        raise PcapFormatError("truncated global header")
    _vmaj, _vmin, _tz, _sig, snaplen, linktype = struct.unpack(endian + "HHiIII", rest)
    return endian, tick, snaplen, linktype & 0x0FFFFFFF


def iter_records(path):
    """Yield (timestamp_seconds: float, frame: bytes, linktype: int) for each record."""
    with open(path, "rb") as f:
        endian, tick, _snaplen, linktype = read_header(f)
        rec = struct.Struct(endian + "IIII")
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                return
            ts_sec, ts_frac, incl_len, _orig_len = rec.unpack(hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                return
            yield ts_sec + ts_frac / tick, data, linktype


class PcapWriter:
    """Write legacy pcap (µs, little-endian, Ethernet by default)."""

    def __init__(self, path, linktype=LINKTYPE_ETHERNET, snaplen=262144):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        self._rec = struct.Struct("<IIII")

    def write(self, ts, data):
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec += 1
            usec -= 1_000_000
        self.f.write(self._rec.pack(sec, usec, len(data), len(data)))
        self.f.write(data)

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _ip_offset(frame, linktype):
    """Return (offset_of_ip_header, ethertype) or None."""
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        etype = (frame[12] << 8) | frame[13]
        off = 14
        if etype == 0x8100:  # single VLAN tag
            if len(frame) < 18:
                return None
            etype = (frame[16] << 8) | frame[17]
            off = 18
        return off, etype
    if linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        return 16, (frame[14] << 8) | frame[15]
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not frame:
            return None
        ver = frame[0] >> 4
        return 0, 0x0800 if ver == 4 else 0x86DD if ver == 6 else 0
    return None


def five_tuple(frame, linktype):
    """-> (proto, src, sport, dst, dport) with dotted/colon string addresses, or None."""
    r = _ip_offset(frame, linktype)
    if r is None:
        return None
    off, etype = r
    if etype == 0x0800:
        if len(frame) < off + 20 or (frame[off] >> 4) != 4:
            return None
        ihl = (frame[off] & 0x0F) * 4
        proto = frame[off + 9]
        src = "%d.%d.%d.%d" % tuple(frame[off + 12:off + 16])
        dst = "%d.%d.%d.%d" % tuple(frame[off + 16:off + 20])
        l4 = off + ihl
    elif etype == 0x86DD:
        if len(frame) < off + 40:
            return None
        proto = frame[off + 6]
        src = _ipv6_str(frame[off + 8:off + 24])
        dst = _ipv6_str(frame[off + 24:off + 40])
        l4 = off + 40
    else:
        return None
    if proto == 6:
        name = "tcp"
    elif proto == 17:
        name = "udp"
    else:
        return None
    if len(frame) < l4 + 4:
        return None
    sport, dport = struct.unpack_from("!HH", frame, l4)
    return name, src, sport, dst, dport


def ip_addresses(frame, linktype):
    """-> (src, dst) strings for any IPv4/IPv6 frame, or None."""
    r = _ip_offset(frame, linktype)
    if r is None:
        return None
    off, etype = r
    if etype == 0x0800 and len(frame) >= off + 20:
        return ("%d.%d.%d.%d" % tuple(frame[off + 12:off + 16]),
                "%d.%d.%d.%d" % tuple(frame[off + 16:off + 20]))
    if etype == 0x86DD and len(frame) >= off + 40:
        return _ipv6_str(frame[off + 8:off + 24]), _ipv6_str(frame[off + 24:off + 40])
    return None


def _ipv6_str(b):
    import ipaddress
    return str(ipaddress.IPv6Address(bytes(b)))


def to_ethernet(frame, linktype, src_mac=b"\x02\xbb\x00\x00\x00\x01", dst_mac=b"\x02\xbb\x00\x00\x00\x02"):
    """Re-frame an IP packet from any supported link type as Ethernet; None if not IP."""
    r = _ip_offset(frame, linktype)
    if r is None:
        return None
    off, etype = r
    if etype not in (0x0800, 0x86DD):
        return None
    if linktype == LINKTYPE_ETHERNET and off == 14:
        return frame
    return dst_mac + src_mac + struct.pack("!H", etype) + frame[off:]
