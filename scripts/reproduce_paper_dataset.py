"""Rebuilds the four N = 5 datasets of the paper from the four captures.

usage: python scripts/reproduce_paper_dataset.py CAPTURE_DIR [--out datasets]
CAPTURE_DIR must hold Benign.pcap, Dnscat2.pcap, Dnstt.pcapng and Iodine.pcapng.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from doqxtract.cli import main

# capture file, label, class, output file
DATASETS = [
    ('Benign.pcap', 'Benign', 'Benign', 'Benign_N5.csv'),
    ('Dnscat2.pcap', 'DNSCat2', 'Malicious', 'Dnscat2_N5.csv'),
    ('Dnstt.pcapng', 'DNSTT', 'Malicious', 'Dnstt_N5.csv'),
    ('Iodine.pcapng', 'Iodine', 'Malicious', 'Iodine_N5.csv'),
]

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('captures', help='folder with the four captures')
    ap.add_argument('--out', default='datasets', help='output folder (default datasets)')
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    for capture, label, class_name, out in DATASETS:
        code = main([os.path.join(args.captures, capture), '-N', '5', '--label', label, '--class-name', class_name,
                     '--utc-offset', '5.5', '-o', os.path.join(args.out, out)])
        if code:
            sys.exit(code)
