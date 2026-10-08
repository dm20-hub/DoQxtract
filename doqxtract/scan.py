"""Capture reader.

It keeps the IPv4 UDP packets that use port 853 and stores the fields that the extractor needs.
The QUIC header fields (header form, packet type, version, connection identifier lengths and the first byte)
are read from the cleartext part of the datagram. They are not used by the features, but they help to inspect a capture.
"""
import collections
import struct

import dpkt
import numpy as np

SERVER_PORT = 853

PACKET_DTYPE = np.dtype([
    ("ts", "f8"),       # capture timestamp in seconds
    ("src", "u4"),      # source IPv4 address as an integer
    ("sp", "u2"),       # source UDP port
    ("dst", "u4"),      # destination IPv4 address as an integer
    ("dp", "u2"),       # destination UDP port
    ("ul", "u2"),       # UDP length field (UDP header plus payload)
    ("form", "i1"),     # QUIC header form, 1 for a long header and 0 for a short header
    ("ptype", "i1"),    # QUIC long header packet type, -1 for a short header
    ("ver", "u4"),      # QUIC version of a long header packet
    ("dcl", "u1"),      # destination connection identifier length of a long header packet
    ("scl", "u1"),      # source connection identifier length of a long header packet
    ("b0", "u1"),       # first byte of the UDP payload
])


def scan_capture(path):
    """Read a pcap or pcapng file.

    Returns a numpy array with one row per UDP port 853 packet, in capture order, and a dictionary of counters.
    Only Ethernet (with at most one VLAN tag), Linux cooked and raw IP captures are read. IPv6 packets and
    IPv4 fragments other than the first one are skipped and counted.
    """
    unp = struct.unpack_from
    counters = collections.Counter()
    rows = []
    with open(path, "rb") as handle:
        magic = handle.read(4)
        handle.seek(0)
        is_pcapng = magic == b"\x0a\x0d\x0d\x0a"
        reader = dpkt.pcapng.Reader(handle) if is_pcapng else dpkt.pcap.Reader(handle)
        datalink = reader.datalink()
        for ts, buf in reader:
            counters["packets"] += 1
            try:
                if datalink == 1:                                   # Ethernet
                    ethertype = unp("!H", buf, 12)[0]
                    offset = 14
                    if ethertype == 0x8100:                         # one VLAN tag
                        ethertype = unp("!H", buf, 16)[0]
                        offset = 18
                elif datalink == 113:                               # Linux cooked capture
                    ethertype = unp("!H", buf, 14)[0]
                    offset = 16
                elif datalink in (101, 12, 228):                    # raw IP
                    ethertype = 0x0800 if buf[0] >> 4 == 4 else 0x86DD
                    offset = 0
                else:
                    counters["unsupported_link_type"] += 1
                    continue
                if ethertype != 0x0800:
                    counters["not_ipv4"] += 1
                    continue
                header_len = (buf[offset] & 15) * 4
                if buf[offset + 9] != 17:
                    counters["not_udp"] += 1
                    continue
                if unp("!H", buf, offset + 6)[0] & 0x1FFF:          # fragment offset other than zero
                    counters["ip_fragment"] += 1
                    continue
                src = unp("!I", buf, offset + 12)[0]
                dst = unp("!I", buf, offset + 16)[0]
                udp = offset + header_len
                sp, dp, udp_len = unp("!HHH", buf, udp)
                if sp != SERVER_PORT and dp != SERVER_PORT:
                    counters["other_udp_port"] += 1
                    continue
                payload = buf[udp + 8:]
                b0 = payload[0] if payload else 0
                form = b0 >> 7
                ptype = (b0 >> 4) & 3 if form else -1
                version = unp("!I", payload, 1)[0] if form and len(payload) >= 5 else 0
                dcl = payload[5] if form and len(payload) >= 6 else 0
                scl = payload[6 + dcl] if form and len(payload) > 6 + dcl else 0
            except (struct.error, IndexError):
                counters["malformed"] += 1
                continue
            rows.append((ts, src, sp, dst, dp, udp_len, form, ptype, version, dcl, scl, b0))
    packets = np.array(rows, dtype=PACKET_DTYPE)
    info = dict(counters)
    info.setdefault("packets", 0)
    info["kept"] = len(packets)
    info["format"] = "pcapng" if is_pcapng else "pcap"
    info["link_type"] = datalink
    return packets, info
