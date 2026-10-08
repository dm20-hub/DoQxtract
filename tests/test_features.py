import numpy as np
import pytest

from doqxtract import FEATURES, extract_records
from doqxtract.reference import compute_features
from helpers import flow, in_capture_order


def one_record(times, directions, lengths):
    df, _ = extract_records(in_capture_order(flow(times, directions=directions, lengths=lengths)), N=len(times))
    assert len(df) == 1
    return df.iloc[0]


def check(row, expected):
    for name, value in expected.items():
        assert row[name] == pytest.approx(value, rel=1e-9, abs=1e-12), name


def test_known_record():
    row = one_record([0.0, 0.010, 0.030, 0.031, 0.100], [True, False, True, False, True], [100, 80, 100, 90, 100])
    check(row, dict(
        Duration=0.1, FlowBytesSent=402, FlowSentRate=4020, FlowBytesReceived=238, FlowReceivedRate=2380,
        PacketLengthVariance=64, PacketLengthStandardDeviation=8, PacketLengthMean=128, PacketLengthMedian=134,
        PacketLengthMode=134, PacketLengthSkewFromMedian=-2.25, PacketLengthSkewFromMode=-0.75,
        PacketLengthCoefficientofVariation=0.0625,
        PacketTimeMean=0.0342, PacketTimeMedian=0.030, PacketTimeMode=0.0,
        ResponseTimeTimeVariance=2.025e-5, ResponseTimeTimeStandardDeviation=0.0045, ResponseTimeTimeMean=0.0055,
        ResponseTimeTimeMedian=0.0055, ResponseTimeTimeMode=0.001, ResponseTimeTimeSkewFromMedian=0.0,
        ResponseTimeTimeSkewFromMode=1.0, ResponseTimeTimeCoefficientofVariation=0.0045 / 0.0055))


def test_zero_duration_takes_the_sentinels():
    row = one_record([5.0] * 5, [True, False, True, False, True], [100, 80, 100, 90, 100])
    check(row, dict(Duration=0, FlowSentRate=-1, FlowReceivedRate=-1,
                    PacketTimeVariance=0, PacketTimeMean=0, PacketTimeSkewFromMedian=-10, PacketTimeSkewFromMode=-10,
                    PacketTimeCoefficientofVariation=-1))


def test_record_without_a_response_takes_the_response_sentinels():
    row = one_record([0.0, 0.1, 0.2, 0.3, 0.4], [True] * 5, [100] * 5)
    check(row, dict(FlowBytesReceived=0, FlowReceivedRate=0,
                    ResponseTimeTimeVariance=-1, ResponseTimeTimeStandardDeviation=-1, ResponseTimeTimeMean=-1,
                    ResponseTimeTimeMedian=0, ResponseTimeTimeMode=-1, ResponseTimeTimeSkewFromMedian=0,
                    ResponseTimeTimeSkewFromMode=0, ResponseTimeTimeCoefficientofVariation=1))


def test_constant_packet_length_has_zero_dispersion_and_the_skew_sentinel():
    row = one_record([0.0, 0.1, 0.2, 0.3, 0.4], [True] * 5, [100] * 5)
    check(row, dict(PacketLengthVariance=0, PacketLengthStandardDeviation=0, PacketLengthSkewFromMedian=-10,
                    PacketLengthSkewFromMode=-10, PacketLengthCoefficientofVariation=0))


def test_mode_ties_take_the_smallest_value():
    row = one_record([0.0, 0.1, 0.2, 0.3, 0.4], [True] * 5, [100, 100, 200, 200, 300])
    assert row['PacketLengthMode'] == 134


def test_response_gap_is_rounded_to_six_decimals():
    row = one_record([0.0, 0.0123456789, 0.5, 0.6, 0.7], [True, False, True, True, True], [100] * 5)
    assert row['ResponseTimeTimeMean'] == pytest.approx(0.012346, abs=1e-12)


def test_reference_implementation_gives_the_same_features():
    times, directions, lengths = [0.0, 0.010, 0.030, 0.031, 0.100], [True, False, True, False, True], [100, 80, 100, 90, 100]
    row = one_record(times, directions, lengths)
    features = compute_features([l + 34 for l in lengths], times, directions)
    assert len(features) == len(FEATURES) == 29
    np.testing.assert_allclose(features, row[FEATURES].to_numpy(dtype=float), rtol=1e-9, atol=1e-12)
