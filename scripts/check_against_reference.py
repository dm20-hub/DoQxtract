"""Compares the vectorized extractor with the literal reference implementation on a capture.

usage: python scripts/check_against_reference.py CAPTURE [-N 5] [--idle 40] [--max-duration 120] [--sample 0]
--sample 0 compares the features of every record. A positive value compares a random sample of that size.
The reference implementation is slow, so a full comparison of a large capture takes minutes.
"""
import argparse
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from doqxtract import FEATURES, extract_records, scan_capture
from doqxtract.reference import compute_features, segment


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('capture')
    ap.add_argument('-N', '--packets', type=int, default=5)
    ap.add_argument('--idle', type=float, default=40.0)
    ap.add_argument('--max-duration', type=float, default=120.0)
    ap.add_argument('--sample', type=int, default=0)
    args = ap.parse_args()

    packets, _ = scan_capture(args.capture)
    t0 = time.time()
    df, _ = extract_records(packets, N=args.packets, T=args.max_duration, I=args.idle)
    t_vec = time.time() - t0
    t0 = time.time()
    ref = sorted(segment(packets, N=args.packets, T=args.max_duration, I=args.idle),
                 key=lambda r: (r.client_ip, r.client_port, r.server_ip, r.first_seen))
    t_ref = time.time() - t0
    df = df.sort_values(['cip', 'cport', 'sip', 'first_ts']).reset_index(drop=True)
    print(f'records: vectorized {len(df)} ({t_vec:.0f} s), reference {len(ref)} ({t_ref:.0f} s)')
    if len(df) != len(ref):
        print('different number of records')
        return 1
    same_records = (np.array([r.client_ip for r in ref]) == df.cip.to_numpy()).all() and \
        (np.array([r.client_port for r in ref]) == df.cport.to_numpy()).all() and \
        (np.array([r.server_ip for r in ref]) == df.sip.to_numpy()).all() and \
        (np.array([r.first_seen for r in ref]) == df.first_ts.to_numpy()).all()
    print('same flows and start times for every record:', bool(same_records))
    if not same_records:
        return 1
    if args.sample and args.sample < len(ref):
        chosen = np.sort(np.random.default_rng(0).choice(len(ref), args.sample, replace=False))
    else:
        chosen = np.arange(len(ref))
    t0 = time.time()
    expected = np.array([compute_features(ref[i].frames, ref[i].times, ref[i].to_server) for i in chosen])
    found = df[FEATURES].to_numpy(dtype=float)[chosen]
    close = np.isclose(found, expected, rtol=1e-9, atol=1e-12)
    bad_rows = np.flatnonzero(~close.all(1))
    exact = int((found == expected).all(1).sum())
    print(f'features compared for {len(chosen)} records ({time.time() - t0:.0f} s)')
    print(f'  identical in all 29 features for {exact} records, equal within 1e-9 for {len(chosen) - len(bad_rows)} records')
    for i in bad_rows[:5]:
        names = [FEATURES[j] for j in np.flatnonzero(~close[i])]
        print('  mismatch at record', chosen[i], names)
    return 1 if len(bad_rows) else 0


if __name__ == '__main__':
    sys.exit(main())
