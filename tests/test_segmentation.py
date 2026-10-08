import numpy as np

from doqxtract import extract_records
from helpers import CLIENT, SERVER, flow, in_capture_order


def records(packets, **kw):
    df, stats = extract_records(packets, **kw)
    return df, stats


def test_five_packets_make_one_record():
    df, stats = records(in_capture_order(flow([0, 1, 2, 3, 4])))
    assert len(df) == 1 and df.n.iloc[0] == 5
    assert stats['discarded_records'] == 0


def test_a_sixth_packet_does_not_extend_the_record():
    df, stats = records(in_capture_order(flow([0, 1, 2, 3, 4, 5])))
    assert len(df) == 1
    assert stats['discarded_records'] == 1 and stats['discarded_packets'] == 1


def test_idle_gap_discards_the_open_record():
    packets = in_capture_order(flow([0, 1, 2, 52, 53, 54, 55, 56]))
    df, stats = records(packets)
    assert len(df) == 1
    assert df.first_ts.iloc[0] == 52
    assert stats['discarded_records'] == 1 and stats['discarded_packets'] == 3


def test_idle_gap_of_exactly_the_limit_keeps_the_record():
    df, stats = records(in_capture_order(flow([0, 1, 2, 42, 43])))
    assert len(df) == 1 and df.first_ts.iloc[0] == 0


def test_duration_limit_discards_the_open_record():
    packets = in_capture_order(flow([0, 20, 40, 60, 61, 62, 63, 64, 65]))
    df, stats = records(packets, T=50.0)
    assert len(df) == 1 and df.first_ts.iloc[0] == 61
    assert stats['discarded_records'] == 1 and stats['discarded_packets'] == 4


def test_a_record_that_reaches_n_is_kept_even_if_it_is_longer_than_the_limit():
    df, _ = records(in_capture_order(flow([0, 30, 60, 90, 120])), T=100.0)
    assert len(df) == 1 and df.Duration.iloc[0] == 120


def test_record_still_open_at_the_end_of_the_capture_is_dropped():
    df, stats = records(in_capture_order(flow([0, 1, 2, 3])))
    assert len(df) == 0
    assert stats['discarded_records'] == 1 and stats['discarded_packets'] == 4


def test_no_packets_gives_no_records():
    df, stats = records(in_capture_order())
    assert len(df) == 0 and stats['records'] == 0


def test_flows_do_not_interfere_when_their_packets_interleave():
    a = flow([0, 2, 4, 6, 8], cport=40000)
    b = flow([1, 3, 5, 7, 9], cport=40001)
    df, _ = records(in_capture_order(a, b))
    assert sorted(df.cport) == [40000, 40001]
    assert (df.n == 5).all()


def test_both_directions_belong_to_one_flow_and_the_record_is_oriented_to_the_server():
    packets = in_capture_order(flow([0, 1, 2, 3, 4], directions=[True, False, True, False, True], lengths=[100, 60, 100, 60, 100]))
    df, _ = records(packets)
    assert len(df) == 1
    assert df.FlowBytesSent.iloc[0] == 3 * 134
    assert df.FlowBytesReceived.iloc[0] == 2 * 94
    assert df.cip.iloc[0] == CLIENT and df.sip.iloc[0] == SERVER


def test_a_record_that_starts_with_a_server_packet_is_still_oriented_to_the_server():
    packets = in_capture_order(flow([0, 1, 2, 3, 4], directions=[False, True, True, True, True], lengths=[60, 100, 100, 100, 100]))
    df, _ = records(packets)
    assert df.FlowBytesReceived.iloc[0] == 94 and df.FlowBytesSent.iloc[0] == 4 * 134


def test_server_addresses_that_share_their_low_bits_are_different_flows():
    other = 0x0A010001                       # 10.1.0.1, same low 16 bits as 10.0.0.1
    a = flow([0, 2, 4, 6, 8], sip=SERVER, lengths=[100] * 5)
    b = flow([1, 3, 5, 7, 9], sip=other, lengths=[200] * 5)
    df, _ = records(in_capture_order(a, b))
    assert len(df) == 2
    assert sorted(df.PacketLengthMean) == [134.0, 234.0]


def test_a_different_packet_count_changes_the_records():
    packets = in_capture_order(flow(list(range(10))))
    assert len(records(packets, N=5)[0]) == 2
    assert len(records(packets, N=3)[0]) == 3
    assert len(records(packets, N=10)[0]) == 1
