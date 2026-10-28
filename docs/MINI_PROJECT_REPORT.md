# Mini-Project Report: TCP SYN Flood Detection and Monitoring System

## Abstract
TCP SYN flooding exhausts a server's half-open connection resources. This project builds a defensive
monitoring system that reads TCP traffic (live, simulated or from PCAP files), counts initial SYN packets
in configurable time windows, flags windows exceeding experimental thresholds as *suspicious*, stores
results in SQLite and presents them on a dark-themed Flask dashboard with charts, alerts and CSV reports.
The system never generates attack traffic.

## Objectives
1. Capture and parse TCP packets safely. 2. Detect initial SYN packets and measure rates per window and source.
3. Raise de-duplicated alerts with severity. 4. Provide a real-time dashboard and history reports.
5. Support repeatable offline analysis of PCAP/PCAPNG files and a safe simulation mode.

## Methodology
Requirement analysis -> modular design (capture, detection, alerting, storage, web) -> incremental
implementation: offline analyzer, window detection, SQLite, Flask API, dashboard, live capture, PCAP upload ->
unit/integration testing with synthetic data -> verification of packet flags in Wireshark.

## Algorithm
For each packet: if IPv4/IPv6 TCP and SYN=1, ACK=0 -> increment window and per-source counters.
When a window ends: suspicious if total >= T or any source >= S. Severity by ratio observed/threshold
(<2 LOW, 2-5 MEDIUM, >=5 HIGH). Consecutive suspicious windows merge into one alert. O(1) work per packet.

## Implementation
Python 3 / Flask REST API; Scapy `AsyncSniffer` in a single background thread for live mode; a pure-Python
PCAP/PCAPNG reader for offline files; SQLite tables `sessions`, `windows`, `alerts`; HTML/CSS/JS with Chart.js
polling the API every 2 seconds; CSV export through the `csv` module.

## Results
The 15 automated tests pass. With default thresholds (5 s window, 100 total / 80 per source):
- `normal_traffic.pcap`: SYNs seen, 0 suspicious windows.
- `single_source_burst.pcap`: consecutive suspicious windows from 203.0.113.50, merged into one alert.
- `multi_source_burst.pcap`: 2 suspicious windows via the total threshold only (6 sources x 15 SYN/s).
- Invalid and empty files are rejected with clear messages (HTTP 422).

## Limitations
Threshold detection can give false positives (flash crowds, scanners, load tests) and false negatives (slow
floods below the threshold). Spoofed source addresses limit attribution. Detection only - no mitigation.
Single-sensor view; the PCAP reader supports common link types only.

## Conclusion
The project demonstrates a complete, working, defensive monitoring pipeline and shows why high SYN counts
are indicators that need verification. Future work: adaptive baselines, half-open connection tracking,
notifications and ML-based anomaly detection.
