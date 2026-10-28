# Viva Questions and Answers

1. **What is a TCP SYN flood?** A denial-of-service technique where many connection requests (SYN) are sent so the server keeps half-open connections and runs out of resources.
2. **Explain the three-way handshake.** Client SYN -> server SYN+ACK -> client ACK.
3. **How do you identify an initial SYN?** SYN flag set and ACK flag not set (flags & 0x02 and not flags & 0x10).
4. **Why not count SYN+ACK?** It is the server's reply, not a new connection attempt.
5. **Does a high SYN count prove an attack?** No. Busy servers, scans, load tests or flash crowds also cause spikes. The system labels it "suspicious" and recommends verification.
6. **What is a time window?** A fixed interval (default 5 s); counts are made per window so rates are comparable.
7. **Why two thresholds?** The total threshold catches distributed bursts; the per-source threshold catches one noisy host.
8. **How are thresholds chosen?** Experimentally from normal-traffic baselines; they are configurable, not universal.
9. **How are duplicate alerts avoided?** Consecutive suspicious windows merge into one alert with a repeat counter; every window is still stored.
10. **Why run capture in a thread?** So Flask request handling is never blocked; a one-worker rule prevents duplicates.
11. **Why SQLite?** Serverless, simple, ships with Python; parameterized queries prevent SQL injection.
12. **How are uploads handled safely?** Extension + magic-byte check, size limit, random server-chosen filename, parsed (never executed), deleted afterwards.
13. **Role of Scapy / Npcap / Wireshark?** Scapy captures live packets; Npcap is the Windows capture driver; Wireshark independently verifies packets.
14. **Limitations?** Threshold-based; spoofed sources cannot be attributed; no mitigation; single-machine view; IPv4/IPv6 TCP only.
15. **Possible improvements?** Adaptive baselines, half-open connection tracking, email alerts, ML anomaly detection, multi-sensor aggregation.
16. **How is a SYN flood mitigated in practice?** SYN cookies, backlog tuning, rate limiting, firewalls / upstream scrubbing.
