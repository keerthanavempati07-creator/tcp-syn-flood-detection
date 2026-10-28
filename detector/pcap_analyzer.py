"""Offline PCAP analysis: reads a capture file and runs the SYN detector on it."""
from datetime import datetime

from detector.pcap_reader import PcapFormatError, iter_packets
from detector.syn_detector import SynDetector


def analyze_pcap(path, window, threshold, per_source, max_packets=1_000_000):
    windows = []
    det = SynDetector(window, threshold, per_source, on_window=windows.append,
                      history=100000)
    truncated = False
    count = 0
    for meta in iter_packets(path):
        det.process(meta)
        count += 1
        if count >= max_packets:
            truncated = True
            break
    det.flush()
    snap = det.snapshot()
    if count == 0:
        raise PcapFormatError("The capture file contains no packets.")
    message = "Analysis complete."
    if snap["tcp_packets"] == 0:
        message = "The file contains packets, but none are IPv4/IPv6 TCP packets."
    elif snap["syn_packets"] == 0:
        message = "TCP packets found, but no initial SYN packets."
    if truncated:
        message += " (Stopped after %d packets - file limit.)" % max_packets
    fmt = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "message": message,
        "totals": {k: snap[k] for k in ("total_packets", "tcp_packets", "syn_packets",
                                         "unique_sources", "suspicious_windows",
                                         "windows_analyzed")},
        "settings": snap["settings"],
        "sources": snap["sources"],
        "suspicious": [
            {"window_start": fmt(w["window_start"]), "window_end": fmt(w["window_end"]),
             "syn_count": w["syn_count"], "severity": w["severity"],
             "top_sources": w["top_sources"], "reasons": w["reasons"]}
            for w in windows if w["suspicious"]],
        "_windows": windows,      # used by app.py for DB storage (removed before JSON)
        "_totals_raw": snap,
    }
