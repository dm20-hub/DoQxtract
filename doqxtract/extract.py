"""Segmentation (Algorithm 1) and the 29 flow features (Algorithm 2) of DoQxtract, vectorized with numpy.

Flows are identified by the client address and port and the server address and port, without regard to direction.
The server is the endpoint that uses port 853, and every record is oriented from the client to the server.
A record ends when it holds N packets or when its duration exceeds the duration limit T. A packet that arrives
more than the idle limit I after the previous packet of its flow ends the open record and starts a new one.
Records that end before they hold N packets are discarded, as are records that are still open at the end of the capture.

Conventions of the 29 features:
  the packet length is the frame length, which is the UDP length field plus 34 bytes of Ethernet and IPv4 headers,
  variance and standard deviation are population statistics, the mode takes the smallest value when values tie,
  a rate is -1 when the duration is zero, a skewness is -10 when the standard deviation is zero,
  a coefficient of variation is -1 when the mean is zero, the relative arrival time of the first packet is zero,
  a response time is the gap, rounded to 6 decimals, at every client to server packet that is directly followed by a
  server to client packet, and a record without any such gap takes the values -1, -1, -1, 0, -1, 0, 0, 1.
"""
import numpy as np
import pandas as pd

SERVER_PORT = 853
FRAME_OVERHEAD = 34   # Ethernet header (14 bytes) plus IPv4 header without options (20 bytes)

FEATURES = ['Duration', 'FlowBytesSent', 'FlowSentRate', 'FlowBytesReceived', 'FlowReceivedRate',
            'PacketLengthVariance', 'PacketLengthStandardDeviation', 'PacketLengthMean', 'PacketLengthMedian', 'PacketLengthMode',
            'PacketLengthSkewFromMedian', 'PacketLengthSkewFromMode', 'PacketLengthCoefficientofVariation',
            'PacketTimeVariance', 'PacketTimeStandardDeviation', 'PacketTimeMean', 'PacketTimeMedian', 'PacketTimeMode',
            'PacketTimeSkewFromMedian', 'PacketTimeSkewFromMode', 'PacketTimeCoefficientofVariation',
            'ResponseTimeTimeVariance', 'ResponseTimeTimeStandardDeviation', 'ResponseTimeTimeMean', 'ResponseTimeTimeMedian',
            'ResponseTimeTimeMode', 'ResponseTimeTimeSkewFromMedian', 'ResponseTimeTimeSkewFromMode',
            'ResponseTimeTimeCoefficientofVariation']


def prepare(packets):
    """Split the packet array of scan_capture into client and server sides. The server is the endpoint that uses port 853."""
    to_server = packets['dp'] == SERVER_PORT
    client_ip = np.where(to_server, packets['src'], packets['dst']).astype(np.int64)
    client_port = np.where(to_server, packets['sp'], packets['dp']).astype(np.int64)
    server_ip = np.where(to_server, packets['dst'], packets['src']).astype(np.int64)
    return dict(ts=packets['ts'], c2s=to_server, frame=packets['ul'].astype(np.int64) + FRAME_OVERHEAD,
                cport=client_port, cip=client_ip, sip=server_ip, form=packets['form'], ptype=packets['ptype'])


def segment_key(ts, N, T=120.0, I=40.0):
    """Segment the packets of one flow. ts holds the timestamps in capture order.
    A segment closes after the packet that makes the count N or the duration larger than T,
    and before a packet that arrives after an idle gap larger than I. The last segment closes at the end of the flow."""
    n = len(ts)
    out = []
    i = 0
    while i < n:
        start = i
        first = ts[i]
        last = first
        cnt = 1
        while True:
            if cnt >= N or (last - first) > T:
                break
            if i + 1 >= n or ts[i + 1] - last > I:
                break
            i += 1
            last = ts[i]
            cnt += 1
        out.append((start, i + 1))
        i += 1
    return out


def segments(d, N, T=120.0, I=40.0):
    """Group the packets by flow (stable, so the capture order is kept inside a flow) and segment every flow.
    Returns the packet order and an array of (start, end) positions in that order."""
    order = np.lexsort((d['sip'], d['cport'], d['cip']))
    cip, cport, sip, ts = d['cip'][order], d['cport'][order], d['sip'][order], d['ts'][order]
    changed = (cip[1:] != cip[:-1]) | (cport[1:] != cport[:-1]) | (sip[1:] != sip[:-1])
    cuts = np.flatnonzero(np.r_[True, changed, True])
    segs = []
    for a, b in zip(cuts[:-1], cuts[1:]):
        for s, e in segment_key(ts[a:b].tolist(), N, T, I):
            segs.append((a + s, a + e))
    return order, np.array(segs, dtype=np.int64).reshape(-1, 2)


def _mode_rows(M):
    """Row wise mode with ties going to the smallest value. Infinity marks padding and never wins."""
    S = np.sort(M, axis=1)
    out = np.empty(len(S))
    step = max(1, 4_000_000 // (S.shape[1] ** 2))
    for i in range(0, len(S), step):
        blk = S[i:i + step]
        cnt = (blk[:, :, None] == blk[:, None, :]).sum(2)
        cnt = np.where(np.isfinite(blk), cnt, 0)
        out[i:i + step] = blk[np.arange(len(blk)), cnt.argmax(1)]
    return out


def _stats(M):
    mean = M.mean(1)
    var = M.var(1)
    std = np.sqrt(var)
    med = np.median(M, axis=1)
    mode = _mode_rows(M)
    return mean, var, std, med, mode


def feats_block(Lm, tm, fm):
    """Features of S records with n packets each, in the order of FEATURES.
    Lm holds the frame lengths, tm the relative arrival times and fm marks the client to server packets. All are S x n."""
    S, n = Lm.shape
    dur = tm[:, -1]
    sent = (Lm * fm).sum(1).astype(float)
    recv = (Lm * ~fm).sum(1).astype(float)
    with np.errstate(divide='ignore', invalid='ignore'):
        sr = np.where(dur > 0, sent / dur, -1.0)
        rr = np.where(dur > 0, recv / dur, -1.0)
    Lf = Lm.astype(float)
    lm, lv, ls, lmed, lmode = _stats(Lf)
    with np.errstate(divide='ignore', invalid='ignore'):
        lsm = np.where(ls > 0, 3 * (lm - lmed) / ls, -10.0)
        lsk = np.where(ls > 0, (lm - lmode) / ls, -10.0)
        lcv = np.where(lm != 0, ls / lm, -1.0)
    tm_, tv, ts_, tmed, tmode = _stats(tm)
    with np.errstate(divide='ignore', invalid='ignore'):
        tsm = np.where(ts_ > 0, 3 * (tm_ - tmed) / ts_, -10.0)
        tsk = np.where(ts_ > 0, (tm_ - tmode) / ts_, -10.0)
        tcv = np.where(tm_ != 0, ts_ / tm_, -1.0)
    # response times, the gap at every client to server packet that is directly followed by a server to client packet
    if n > 1:
        trans = (~fm[:, 1:]) & fm[:, :-1]
        R = np.where(trans, np.round(tm[:, 1:] - tm[:, :-1], 6), np.nan)
        m = trans.sum(1)
    else:
        R = np.full((S, 1), np.nan)
        m = np.zeros(S, int)
    rvar = np.full(S, -1.0)
    rstd = np.full(S, -1.0)
    rmean = np.full(S, -1.0)
    rmed = np.zeros(S)
    rmode = np.full(S, -1.0)
    rsm = np.zeros(S)
    rsk = np.zeros(S)
    rcv = np.ones(S)
    has = m > 0
    if has.any():
        Rh = R[has]
        with np.errstate(all='ignore'):
            mu = np.nanmean(Rh, 1)
            va = np.nanvar(Rh, 1)
            sd = np.sqrt(va)
            md = np.nanmedian(Rh, 1)
        mo = _mode_rows(np.where(np.isnan(Rh), np.inf, Rh))
        with np.errstate(divide='ignore', invalid='ignore'):
            sm = np.where(sd > 0, 3 * (mu - md) / sd, -10.0)
            sk = np.where(sd > 0, (mu - mo) / sd, -10.0)
            cv = np.where(mu != 0, sd / mu, -1.0)
        rvar[has], rstd[has], rmean[has], rmed[has], rmode[has] = va, sd, mu, md, mo
        rsm[has], rsk[has], rcv[has] = sm, sk, cv
    return np.column_stack([dur, sent, sr, recv, rr, lv, ls, lm, lmed, lmode, lsm, lsk, lcv,
                            tv, ts_, tm_, tmed, tmode, tsm, tsk, tcv, rvar, rstd, rmean, rmed, rmode, rsm, rsk, rcv])


def extract_records(packets, N=5, T=120.0, I=40.0, orient='client', full_only=True):
    """Segment the packets and compute the features of every record.

    packets comes from scan_capture. With the default arguments the result holds the records of the paper, which are
    the records with exactly N packets and the client to server direction as forward. orient='first' takes the direction
    of the first packet of a record as forward instead, and full_only=False also returns the shorter records.

    Returns a data frame and a dictionary of counts. The data frame has one row per record, sorted by the time of its
    first packet, with the columns first_ts, cport, cip, sip, first_c2s, n, seg, has_long and the 29 features.
    """
    d = prepare(packets)
    order, segs = segments(d, N, T, I)
    stats = dict(packets=int(len(d['ts'])), segments=int(len(segs)))
    if len(segs) == 0:
        stats.update(records=0, discarded_records=0, discarded_packets=0)
        return pd.DataFrame(columns=['first_ts', 'cport', 'cip', 'sip', 'first_c2s', 'n', 'seg', 'has_long'] + FEATURES), stats
    ts = d['ts'][order]
    fr = d['frame'][order]
    c2s = d['c2s'][order]
    cport = d['cport'][order]
    form = d['form'][order]
    cip = d['cip'][order]
    sip = d['sip'][order]
    ln = segs[:, 1] - segs[:, 0]
    rows, meta = [], []
    for n in np.unique(ln):
        if full_only and n != N:
            continue
        sel = np.flatnonzero(ln == n)
        st = segs[sel, 0]
        ix = st[:, None] + np.arange(n)[None, :]
        Lm = fr[ix]
        tabs = ts[ix]
        cm = c2s[ix]
        tm = tabs - tabs[:, :1]
        fm = cm if orient == 'client' else (cm == cm[:, :1])
        rows.append(feats_block(Lm, tm, fm))
        meta.append(pd.DataFrame({'first_ts': tabs[:, 0], 'cport': cport[st], 'cip': cip[st], 'sip': sip[st],
                                  'first_c2s': cm[:, 0], 'n': n, 'seg': sel, 'has_long': (form[ix] == 1).any(1)}))
    if not rows:
        stats.update(records=0, discarded_records=int(len(segs)), discarded_packets=int(ln.sum()))
        return pd.DataFrame(columns=['first_ts', 'cport', 'cip', 'sip', 'first_c2s', 'n', 'seg', 'has_long'] + FEATURES), stats
    df = pd.concat([pd.concat(meta, ignore_index=True), pd.DataFrame(np.vstack(rows), columns=FEATURES)], axis=1)
    df = df.sort_values(['first_ts', 'seg'], kind='stable').reset_index(drop=True)
    kept_packets = int(df['n'].sum())
    stats.update(records=int(len(df)), discarded_records=int(len(segs) - len(df)), discarded_packets=int(ln.sum() - kept_packets))
    return df, stats
