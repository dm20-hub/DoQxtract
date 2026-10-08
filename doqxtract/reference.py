"""Literal transcription of the segmentation algorithm and the feature algorithm.

It reads one packet at a time in plain Python and follows the steps of the pseudocode in the paper, so it is meant to be
read and not to be fast. extract.py is the vectorized version that the command line tool uses, and the tests check that
both versions give the same records and the same features.
"""
from collections import Counter

import numpy as np

from .extract import FRAME_OVERHEAD, SERVER_PORT


class Record:
    """An open record of one flow."""

    def __init__(self, first_seen, client_ip, client_port, server_ip):
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.frames = []        # frame length of every packet
        self.times = []         # capture time of every packet
        self.to_server = []     # True for a client to server packet


def four_tuple(p):
    """Flow key of a packet and its direction. Port 853 marks the server and the other endpoint is the client."""
    if int(p['dp']) == SERVER_PORT:
        return (int(p['src']), int(p['sp']), int(p['dst']), int(p['dp'])), True
    return (int(p['dst']), int(p['dp']), int(p['src']), int(p['sp'])), False


def segment(packets, N=5, T=120.0, I=40.0):
    """Algorithm 1. Yields every record that reaches exactly N packets, in the order in which the records are completed.

    packets is the packet array of scan_capture in capture order. A record that ends because of the idle limit or the
    duration limit holds fewer than N packets and is dropped, and so is a record that is still open after the last packet.
    """
    F = {}                                                  # open record of every flow
    for p in packets:
        k, to_server = four_tuple(p)
        t = float(p['ts'])
        if k in F and t - F[k].last_seen > I:
            del F[k]                                        # idle gap, discard
        if k not in F:
            F[k] = Record(t, k[0], k[1], k[2])
        r = F[k]
        r.frames.append(int(p['ul']) + FRAME_OVERHEAD)
        r.times.append(t)
        r.to_server.append(to_server)
        r.last_seen = t
        if len(r.frames) == N:
            yield r
            del F[k]
        elif r.last_seen - r.first_seen > T:
            del F[k]                                        # duration limit, discard


def _statistics(series):
    """Variance, standard deviation, mean, median, mode, skewness from the median, skewness from the mode and
    coefficient of variation of a non empty series. Variance and standard deviation are population statistics."""
    x = np.asarray(series, dtype=float)
    mean = float(np.mean(x))
    variance = float(np.var(x))
    std = float(np.sqrt(variance))
    median = float(np.median(x))
    counts = Counter(series)
    top = max(counts.values())
    mode = float(min(value for value, c in counts.items() if c == top))     # ties go to the smallest value
    if std > 0:
        skew_median = 3 * (mean - median) / std
        skew_mode = (mean - mode) / std
    else:
        skew_median = skew_mode = -10.0
    cv = std / mean if mean != 0 else -1.0
    return [variance, std, mean, median, mode, skew_median, skew_mode, cv]


def compute_features(frames, times, to_server):
    """Algorithm 2. The 29 features of one record, in the order of extract.FEATURES."""
    n = len(frames)
    tau = [t - times[0] for t in times]                     # relative arrival times, zero for the first packet
    duration = tau[-1]
    sent = float(sum(l for l, c in zip(frames, to_server) if c))
    received = float(sum(l for l, c in zip(frames, to_server) if not c))
    sent_rate = sent / duration if duration > 0 else -1.0
    received_rate = received / duration if duration > 0 else -1.0
    # response gaps, rounded to six decimals the way numpy rounds them
    gaps = [float(np.round(tau[i + 1] - tau[i], 6)) for i in range(n - 1) if to_server[i] and not to_server[i + 1]]
    response = _statistics(gaps) if gaps else [-1.0, -1.0, -1.0, 0.0, -1.0, 0.0, 0.0, 1.0]
    return [duration, sent, sent_rate, received, received_rate] + _statistics(frames) + _statistics(tau) + response
