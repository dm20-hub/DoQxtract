# DoQxtract

![License](https://img.shields.io/badge/license-MIT-blue) ![Python](https://img.shields.io/badge/python-3.9%2B-blue)

DoQxtract extracts flow level features from DNS over QUIC (DoQ) traffic. It reads a packet capture, cuts the UDP port 853 packets of every flow into records of a fixed number of packets, and writes 29 statistical features for every record. The features use only packet lengths, directions and arrival times, so no payload is needed and the encryption of DoQ does not matter.

The code accompanies the paper "Detection and Attribution of Malicious DNS over QUIC Tunnels using Machine Learning" by Moulya D M, Saurashtra Matawale and Saumya Hegde (Department of Computer Science and Engineering, NITK Surathkal).

## Contents

* [Overview](#overview)
* [Install](#install)
* [Use](#use)
* [What a record is](#what-a-record-is)
* [Why these defaults](#why-these-defaults)
* [Features](#features)
* [Output columns](#output-columns)
* [Python API](#python-api)
* [Limits](#limits)
* [Tests and the reference implementation](#tests-and-the-reference-implementation)
* [Reproducing the datasets of the paper](#reproducing-the-datasets-of-the-paper)
* [Project structure](#project-structure)
* [References](#references)
* [Citation](#citation)
* [License](#license)
* [Contact](#contact)

## Overview

DoQxtract works in five steps.

1. It reads a pcap or pcapng file and keeps the IPv4 UDP packets that use port 853.
2. It groups the packets into flows by client address and port and by server address and port.
3. It cuts every flow into records of exactly N packets, using an idle limit and a duration limit.
4. It computes 29 features for every record.
5. It writes one CSV row for every record.

```
capture.pcap -> packets on UDP port 853 -> flows -> records of N packets -> 29 features -> features.csv
```

The defaults are N = 5, an idle limit of 40 seconds and a duration limit of 120 seconds. The tool is vectorized with numpy. A plain Python reference implementation of the two algorithms of the paper and a test suite check that it gives the same records and the same features.

## Install

```bash
git clone https://github.com/dm20-hub/DoQxtract.git
cd DoQxtract
pip install .
```

The tool needs Python 3 with numpy, pandas and dpkt. It was tested with Python 3.13, numpy 2.5, pandas 3.0 and dpkt 1.9.8.

Python 3.9 or newer is required. The tests also pass with Python 3.9 (numpy 2.0, pandas 2.3) and Python 3.12. On the benign capture of the paper, all three Python versions write a byte identical CSV file.

Many Linux systems refuse `pip install` into the system Python. A virtual environment avoids that.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

On Windows the second command is `.venv\Scripts\activate`.

## Use

```bash
doqxtract capture.pcap -o features.csv
```

Without installing, the same command runs from the repository folder as `python -m doqxtract capture.pcap -o features.csv`.

The default packet count is N = 5, so every record holds exactly 5 packets. The default idle limit is 40 seconds and the default duration limit is 120 seconds. The option `-N` changes the packet count, for example `doqxtract capture.pcap -N 8 -o features.csv`.

The tool prints how many packets it read, how many records it wrote and how many shorter records it discarded. This is the output for the benign capture of the paper.

```
Benign.pcap: 443157 packets read, 443157 on UDP port 853
features.csv: 70456 records of 5 packets
discarded: 30258 shorter records holding 90877 packets (20.5% of the UDP port 853 packets)
```

| Option | Meaning |
|---|---|
| `-N`, `--packets` | Packets per record, 5 by default |
| `--idle` | Idle limit in seconds, 40 by default |
| `--max-duration` | Duration limit in seconds, 120 by default |
| `--label`, `--class-name` | Add a `Label` or a `Class` column with this value |
| `--utc-offset` | Hours added to the capture time in the `TimeStamp` column, 0 by default |

The same steps are available from Python.

```python
from doqxtract import scan_capture, extract_records

packets, info = scan_capture("capture.pcap")
records, stats = extract_records(packets, N=5)
```

## What a record is

A flow is identified by the client address and port and the server address and port, without regard to direction, so both directions of a DoQ connection fall into one flow. Port 853 marks the server and the other endpoint is the client. Every record is oriented from the client to the server, so the sent bytes always count client packets.

DoQxtract keeps at most one open record for each flow. A record ends when it holds N packets or when its duration exceeds the duration limit T. A packet that arrives more than the idle limit I after the previous packet of its flow ends the open record and starts a new one. Records that end before they hold N packets are discarded, and so are records that are still open at the end of the capture. Every row of the output therefore describes exactly N packets. The rule is applied to each flow separately, so the output does not depend on how packets of different flows interleave.

A fixed N gives every kind of traffic records of the same length, so the byte totals and the duration of a record cannot reveal its class. The defaults N = 5, I = 40 s and T = 120 s are the values used in the paper, which also justifies them.

## Why these defaults

The packet count N = 5 follows work on early traffic classification. The first five packets of a TCP connection are enough to identify the application [1]. The sizes of the first few packets of an encrypted SSL connection recognize the application with more than 85% accuracy [2]. The paper varies N from 3 to 10 on the DoQ captures, and the Stage 1 accuracy stays above 99.98% for every value.

The idle limit I = 40 s and the duration limit T = 120 s follow DoHLyzer [4], whose feature names DoQxtract also uses. In its file `meter/flow_session.py` a packet that arrives more than 40 seconds after the previous packet of its flow starts a new flow, through the constant `EXPIRED_UPDATE`. In flow output mode the sweep of finished flows is triggered when a flow lasts more than 120 seconds. Reusing these limits keeps the timing rules of the records aligned with those of DoHLyzer. The DoQ specification gives no idle timeout value and leaves it to the implementation [5], so I is a measurement choice and not a protocol constant. Draper-Gil et al. compared flow timeouts of 15, 30, 60 and 120 seconds for encrypted and VPN traffic [3]. Their classifiers were most accurate with 15 seconds. The authors conclude that short timeouts work better than the commonly assumed 600 seconds.

On the four captures of the paper the two limits change little. At N = 5 the duration limit never discards a record, because a record with fewer than five packets spans at most three gaps of 40 seconds, which is 120 seconds. Any T from 60 seconds upward gives the same four datasets. The idle limit matters only for the benign capture. The values I = 5, 10, 20, 40, 60 and 120 seconds give 70,126, 70,177, 70,276, 70,456, 70,657 and 71,157 benign records. For all of them at least 97% of the benign records of the default stay the same, and the tunnel records do not change. The options `--idle` and `--max-duration` reproduce these counts.

## Features

Every record has the five flow features Duration, FlowBytesSent, FlowSentRate, FlowBytesReceived and FlowReceivedRate. It also has eight statistics for each of three series, the packet lengths (PacketLength), the relative arrival times (PacketTime) and the response times (ResponseTimeTime). The eight statistics are Variance, StandardDeviation, Mean, Median, Mode, SkewFromMedian, SkewFromMode and CoefficientofVariation. The names follow the DoHLyzer benchmark.

The 29 column names, in the order of the output, are the following.

| Group | Columns |
|---|---|
| Flow | `Duration`, `FlowBytesSent`, `FlowSentRate`, `FlowBytesReceived`, `FlowReceivedRate` |
| Packet length | `PacketLengthVariance`, `PacketLengthStandardDeviation`, `PacketLengthMean`, `PacketLengthMedian`, `PacketLengthMode`, `PacketLengthSkewFromMedian`, `PacketLengthSkewFromMode`, `PacketLengthCoefficientofVariation` |
| Packet time | `PacketTimeVariance`, `PacketTimeStandardDeviation`, `PacketTimeMean`, `PacketTimeMedian`, `PacketTimeMode`, `PacketTimeSkewFromMedian`, `PacketTimeSkewFromMode`, `PacketTimeCoefficientofVariation` |
| Response time | `ResponseTimeTimeVariance`, `ResponseTimeTimeStandardDeviation`, `ResponseTimeTimeMean`, `ResponseTimeTimeMedian`, `ResponseTimeTimeMode`, `ResponseTimeTimeSkewFromMedian`, `ResponseTimeTimeSkewFromMode`, `ResponseTimeTimeCoefficientofVariation` |

* The packet length is the frame length, which is the UDP length field plus 34 bytes of Ethernet and IPv4 headers.
* The relative arrival time of a packet is its capture time minus the capture time of the first packet of the record, so the first packet has time zero and the duration is the last relative time.
* A response time is the gap between a client packet and the server packet that directly follows it, rounded to six decimals. DoQ encrypts the stream content, so a query cannot be matched to its answer, and a gap may end at an acknowledgment as well as at an answer.
* The variance and the standard deviation are population statistics, and the mode is the smallest value when two values tie.
* The skewness values are 3 (mean minus median) divided by the standard deviation and (mean minus mode) divided by the standard deviation. The coefficient of variation is the standard deviation divided by the mean.
* Undefined values take fixed numbers. A rate is -1 when the duration is zero, a skewness is -10 when the standard deviation is zero and a coefficient of variation is -1 when the mean is zero.
* A record in which no client packet is directly followed by a server packet has no response times. Its eight response statistics are -1, -1, -1, 0, -1, 0, 0 and 1 in the order listed above.

## Output columns

`SourceIP`, `DestinationIP`, `SourcePort`, `DestinationPort`, `TimeStamp`, the 29 features and, when requested, `Class` and `Label`. The source is always the client and the destination port is always 853. `TimeStamp` is the capture time of the first packet of the record in whole seconds.

`TimeStamp` is written as `YYYY-MM-DD HH:MM:SS` in UTC plus the offset given by `--utc-offset`. Numbers have up to 15 significant digits. The file starts with a header line.

## Python API

```python
from doqxtract import FEATURES, scan_capture, extract_records

packets, info = scan_capture("capture.pcap")
records, stats = extract_records(packets, N=5, T=120.0, I=40.0)

print(stats)
print(records[FEATURES].shape)
```

For the benign capture of the paper this prints the following.

```
{'packets': 443157, 'segments': 100714, 'records': 70456, 'discarded_records': 30258, 'discarded_packets': 90877}
(70456, 29)
```

`scan_capture` returns a numpy array with one row for every IPv4 UDP packet on port 853, in capture order, and a dictionary of counters. The array has the fields `ts`, `src`, `sp`, `dst`, `dp`, `ul`, `form`, `ptype`, `ver`, `dcl`, `scl` and `b0`. The dictionary holds `packets`, `kept`, `format` and `link_type`, and it also counts the packets that were skipped.

`extract_records` returns a data frame with one row for every record, sorted by the time of its first packet, and a dictionary of counts with the keys `packets`, `segments`, `records`, `discarded_records` and `discarded_packets`. The data frame holds the 29 features and the columns `first_ts` (capture time of the first packet in seconds), `cport` (client port), `cip` (client address as an integer), `sip` (server address as an integer), `first_c2s` (whether the first packet goes from the client to the server), `n` (packets in the record), `seg` (index of the record among the segments) and `has_long` (whether a packet of the record has a QUIC long header).

With `orient='first'` the direction of the first packet of a record counts as forward instead of the client to server direction. With `full_only=False` the shorter records are returned as well.

## Limits

* Only IPv4 over UDP is read. IPv6 packets are skipped and counted.
* Captures with Ethernet (at most one VLAN tag), Linux cooked or raw IP link types are supported, in pcap and pcapng format.
* UDP port 853 is assumed to carry DoQ. DNS over DTLS also uses UDP port 853 and cannot be told apart.
* The frame length assumes an IPv4 header without options. IPv4 fragments after the first one are skipped.
* The packets of a capture are held in memory.

## Tests and the reference implementation

```bash
pip install pytest
pytest
```

The suite has 34 tests and runs in a few seconds.

`doqxtract/reference.py` is a literal transcription of the two algorithms of the paper in plain Python, one packet at a time. It is slow and meant to be read. The tests check that it gives the same records and the same features as the vectorized code that the command line tool uses. `scripts/check_against_reference.py` makes the same comparison on a real capture.

```bash
python scripts/check_against_reference.py capture.pcap -N 5
```

## Reproducing the datasets of the paper

```bash
python scripts/reproduce_paper_dataset.py /path/to/captures --out datasets
```

The folder with the captures must hold `Benign.pcap`, `Dnscat2.pcap`, `Dnstt.pcapng` and `Iodine.pcapng`. The script uses N = 5 and writes four CSV files with 70,456 benign, 210,018 DNSCat2, 90,334 DNSTT and 140,000 Iodine records, which is 510,808 records of 5 packets. The captures and the generated datasets are not stored in this repository.

## Project structure

```
DoQxtract/
├── doqxtract/
│   ├── __init__.py       package interface
│   ├── __main__.py       entry point of python -m doqxtract
│   ├── cli.py            command line tool and CSV writer
│   ├── scan.py           capture reader
│   ├── extract.py        segmentation and features, vectorized
│   └── reference.py      literal transcription of the two algorithms
├── scripts/
│   ├── reproduce_paper_dataset.py   rebuilds the four datasets of the paper
│   └── check_against_reference.py   compares both implementations on a capture
├── tests/                pytest suite
├── LICENSE
├── pyproject.toml
├── requirements.txt
└── README.md
```

## References

[1] L. Bernaille, R. Teixeira, I. Akodkenou, A. Soule and K. Salamatian. Traffic classification on the fly. ACM SIGCOMM Computer Communication Review 36(2), pages 23 to 26, 2006. https://doi.org/10.1145/1129582.1129589

[2] L. Bernaille and R. Teixeira. Early recognition of encrypted applications. Passive and Active Network Measurement (PAM 2007), Lecture Notes in Computer Science 4427, pages 165 to 175, 2007. https://doi.org/10.1007/978-3-540-71617-4_17

[3] G. Draper-Gil, A. H. Lashkari, M. S. I. Mamun and A. A. Ghorbani. Characterization of encrypted and VPN traffic using time-related features. 2nd International Conference on Information Systems Security and Privacy (ICISSP 2016), pages 407 to 414. https://doi.org/10.5220/0005740704070414

[4] DoHLyzer, GitHub repository, file `meter/flow_session.py`. https://github.com/ahlashkari/DoHlyzer

[5] C. Huitema, S. Dickinson and A. Mankin. DNS over Dedicated QUIC Connections. RFC 9250, May 2022, Section 5.5.2. https://www.rfc-editor.org/rfc/rfc9250

## Citation

If you use this code, please cite the paper above.

A BibTeX entry follows.

```bibtex
@unpublished{moulya2026doqxtract,
  author = {{Moulya D M} and Matawale, Saurashtra and Hegde, Saumya},
  title  = {Detection and Attribution of Malicious {DNS} over {QUIC} Tunnels using Machine Learning},
  note   = {Manuscript in preparation},
  year   = {2026}
}
```

## License

MIT, see `LICENSE`.

## Contact

Questions and bug reports are welcome in the [issue tracker](https://github.com/dm20-hub/DoQxtract/issues) of this repository.
