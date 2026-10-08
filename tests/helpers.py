"""Builds small synthetic packet arrays for the tests."""
import numpy as np

from doqxtract.scan import PACKET_DTYPE

SERVER = 0x0A000001          # 10.0.0.1
CLIENT = 0x0A000002          # 10.0.0.2


def make_packets(rows):
    """rows holds (time, client_ip, client_port, server_ip, to_server, udp_length) tuples in capture order."""
    out = np.zeros(len(rows), dtype=PACKET_DTYPE)
    for i, (t, cip, cport, sip, to_server, ul) in enumerate(rows):
        out['ts'][i] = t
        out['ul'][i] = ul
        if to_server:
            out['src'][i], out['sp'][i], out['dst'][i], out['dp'][i] = cip, cport, sip, 853
        else:
            out['src'][i], out['sp'][i], out['dst'][i], out['dp'][i] = sip, 853, cip, cport
    return out


def flow(times, cport=40000, cip=CLIENT, sip=SERVER, directions=None, lengths=None):
    """Packets of one flow. By default the packets go from the client to the server and have a UDP length of 100."""
    n = len(times)
    directions = [True] * n if directions is None else directions
    lengths = [100] * n if lengths is None else lengths
    return [(t, cip, cport, sip, d, ul) for t, d, ul in zip(times, directions, lengths)]


def in_capture_order(*flows):
    """Merge flows into one packet list sorted by time, the way a capture stores them."""
    rows = [row for f in flows for row in f]
    return make_packets(sorted(rows, key=lambda r: r[0]))
