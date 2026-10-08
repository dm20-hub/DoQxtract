"""The vectorized extractor and the literal transcription of the algorithms must give the same records and features."""
import numpy as np
import pytest

from doqxtract import FEATURES, extract_records
from doqxtract.reference import compute_features, segment
from helpers import CLIENT, SERVER, in_capture_order


def random_capture(seed, flows=40, packets_per_flow=40):
    """Flows with short gaps, some long gaps, repeated timestamps and mixed directions."""
    rng = np.random.default_rng(seed)
    all_flows = []
    for f in range(flows):
        gaps = rng.exponential(0.2, packets_per_flow)
        gaps[rng.random(packets_per_flow) < 0.05] = rng.uniform(41, 130)         # idle gaps and long gaps
        gaps[rng.random(packets_per_flow) < 0.10] = 0.0                          # repeated timestamps
        times = np.round(rng.uniform(0, 50) + np.cumsum(gaps), 6)
        directions = rng.random(packets_per_flow) < 0.5
        lengths = rng.choice([60, 70, 90, 100, 150, 1200], packets_per_flow)
        server = SERVER if f % 3 else 0x0A010001
        all_flows.append([(t, CLIENT, 40000 + f, server, bool(d), int(l)) for t, d, l in zip(times, directions, lengths)])
    return in_capture_order(*all_flows)


@pytest.mark.parametrize('seed', [1, 2, 3])
@pytest.mark.parametrize('N,T', [(5, 120.0), (3, 120.0), (8, 120.0), (5, 6.0)])
def test_records_and_features_agree(seed, N, T):
    packets = random_capture(seed)
    df, _ = extract_records(packets, N=N, T=T)
    ref = [(r.client_ip, r.client_port, r.first_seen, compute_features(r.frames, r.times, r.to_server))
           for r in segment(packets, N=N, T=T)]
    assert len(df) == len(ref) > 0
    ref.sort(key=lambda r: (r[0], r[1], r[2]))
    df = df.sort_values(['cip', 'cport', 'first_ts']).reset_index(drop=True)
    assert list(df.cip) == [r[0] for r in ref]
    assert list(df.cport) == [r[1] for r in ref]
    assert list(df.first_ts) == [r[2] for r in ref]
    np.testing.assert_allclose(df[FEATURES].to_numpy(dtype=float), np.array([r[3] for r in ref]), rtol=1e-9, atol=1e-12)
