"""Command line interface. Usage: python -m doqxtract CAPTURE -o features.csv"""
import argparse
import sys

import numpy as np
import pandas as pd

from . import __version__
from .extract import FEATURES, SERVER_PORT, extract_records
from .scan import scan_capture


def dotted(addresses):
    """IPv4 addresses from integers to dotted notation."""
    return pd.Series(addresses).map(lambda x: '.'.join(str((int(x) >> s) & 255) for s in (24, 16, 8, 0)))


def to_table(df, label=None, class_name=None, utc_offset=0.0):
    """Output table with the flow identifiers, the 29 features and the optional Class and Label columns."""
    stamp = pd.to_datetime(df.first_ts.to_numpy(), unit='s') + pd.Timedelta(hours=utc_offset)
    table = pd.DataFrame({'SourceIP': dotted(df.cip.to_numpy()), 'DestinationIP': dotted(df.sip.to_numpy()),
                          'SourcePort': df.cport.astype(int).to_numpy(), 'DestinationPort': SERVER_PORT,
                          'TimeStamp': stamp.strftime('%Y-%m-%d %H:%M:%S')})
    for name in FEATURES:
        table[name] = df[name].to_numpy()
    if class_name is not None:
        table['Class'] = class_name
    if label is not None:
        table['Label'] = label
    if not np.isfinite(table[FEATURES].to_numpy()).all():
        raise RuntimeError('a feature is not finite')
    return table


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='doqxtract',
        description='Extract flow level features from a DNS over QUIC capture (IPv4, UDP port 853). '
                    'Every output row describes one record of exactly N packets.')
    parser.add_argument('capture', help='pcap or pcapng file')
    parser.add_argument('-o', '--out', required=True, help='output CSV file')
    parser.add_argument('-N', '--packets', type=int, default=5, help='packets per record (default 5)')
    parser.add_argument('--idle', type=float, default=40.0, help='idle limit in seconds (default 40)')
    parser.add_argument('--max-duration', type=float, default=120.0, help='duration limit in seconds (default 120)')
    parser.add_argument('--label', help='value of an extra Label column')
    parser.add_argument('--class-name', help='value of an extra Class column')
    parser.add_argument('--utc-offset', type=float, default=0.0,
                        help='hours added to the UTC capture time in the TimeStamp column (default 0)')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    args = parser.parse_args(argv)
    if args.packets < 2:
        parser.error('--packets must be at least 2')

    packets, info = scan_capture(args.capture)
    print(f"{args.capture}: {info['packets']} packets read, {info['kept']} on UDP port 853", file=sys.stderr)
    skipped = {k: v for k, v in info.items() if k in ('not_ipv4', 'not_udp', 'ip_fragment', 'malformed', 'unsupported_link_type') and v}
    if skipped:
        print('skipped: ' + ', '.join(f'{k} {v}' for k, v in skipped.items()), file=sys.stderr)
    if info['kept'] == 0:
        print('no IPv4 UDP port 853 packets found', file=sys.stderr)
        return 1

    df, stats = extract_records(packets, N=args.packets, T=args.max_duration, I=args.idle)
    table = to_table(df, args.label, args.class_name, args.utc_offset)
    table.to_csv(args.out, index=False, float_format='%.15g')
    share = 100.0 * stats['discarded_packets'] / stats['packets']
    print(f"{args.out}: {stats['records']} records of {args.packets} packets", file=sys.stderr)
    print(f"discarded: {stats['discarded_records']} shorter records holding {stats['discarded_packets']} packets "
          f"({share:.1f}% of the UDP port 853 packets)", file=sys.stderr)
    return 0
