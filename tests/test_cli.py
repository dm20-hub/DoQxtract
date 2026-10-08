import dpkt
import numpy as np
import pandas as pd

from doqxtract.cli import main
from doqxtract.extract import FEATURES


def frame(src_ip, dst_ip, sport, dport, payload):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=bytes(src_ip), dst=bytes(dst_ip), p=dpkt.ip.IP_PROTO_UDP, data=udp)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=b'\x02' * 6, dst=b'\x04' * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


def write_capture(path, packets):
    with open(path, 'wb') as handle:
        writer = dpkt.pcap.Writer(handle)
        for ts, buf in packets:
            writer.writepkt(buf, ts=ts)


def test_command_line_on_a_small_capture(tmp_path):
    client, server = [10, 0, 0, 2], [10, 0, 0, 1]
    packets = []
    for i in range(10):
        up = i % 2 == 0
        payload = bytes([0x40]) + bytes(60 + (0 if up else 10))
        buf = frame(client, server, 43210, 853, payload) if up else frame(server, client, 853, 43210, payload)
        packets.append((1000.0 + 0.5 * i, buf))
    # traffic that must be ignored, a DNS packet on port 53 and a packet on another UDP port
    packets.append((1010.0, frame(client, server, 43211, 53, b'x' * 20)))
    packets.append((1010.5, frame(client, server, 43211, 4433, b'x' * 20)))
    write_capture(tmp_path / 'small.pcap', packets)

    out = tmp_path / 'features.csv'
    code = main([str(tmp_path / 'small.pcap'), '-o', str(out), '-N', '5', '--label', 'Example', '--class-name', 'Benign', '--utc-offset', '5.5'])
    assert code == 0
    table = pd.read_csv(out)
    assert list(table.columns) == ['SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort', 'TimeStamp'] + FEATURES + ['Class', 'Label']
    assert len(table) == 2
    assert set(table.SourceIP) == {'10.0.0.2'} and set(table.DestinationIP) == {'10.0.0.1'}
    assert set(table.SourcePort) == {43210} and set(table.DestinationPort) == {853}
    assert table.TimeStamp.iloc[0] == '1970-01-01 05:46:40'          # 1000 s after the epoch plus 5.5 hours
    assert table.Class.iloc[0] == 'Benign' and table.Label.iloc[0] == 'Example'
    # client frames 1 + 60 + 8 + 34 = 103 bytes, server frames 113 bytes
    assert table.FlowBytesSent.iloc[0] == 3 * 103 and table.FlowBytesReceived.iloc[0] == 2 * 113
    assert np.isfinite(table[FEATURES].to_numpy()).all()


def test_capture_without_port_853_traffic_fails_cleanly(tmp_path):
    write_capture(tmp_path / 'none.pcap', [(1.0, frame([10, 0, 0, 2], [10, 0, 0, 1], 5000, 53, b'x' * 20))])
    assert main([str(tmp_path / 'none.pcap'), '-o', str(tmp_path / 'out.csv')]) == 1
    assert not (tmp_path / 'out.csv').exists()
