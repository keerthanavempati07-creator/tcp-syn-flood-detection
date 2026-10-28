"""Time-window SYN detection engine (works for live, simulated and offline data).

A packet is an INITIAL SYN when the SYN flag is set and the ACK flag is NOT set.
(SYN+ACK is the server's reply, so it is not counted.)
High SYN counts only mean "suspicious" - they do not prove a SYN flood.
"""
import math
import threading
from collections import Counter, deque

SYN = 0x02
ACK = 0x10


def is_initial_syn(flags):
    return bool(flags & SYN) and not (flags & ACK)


def severity_for(ratio):
    if ratio >= 5:
        return "HIGH"
    if ratio >= 2:
        return "MEDIUM"
    return "LOW"


class _Bucket:
    def __init__(self, start):
        self.start = start
        self.total = 0
        self.tcp = 0
        self.syn = 0
        self.syn_sources = Counter()


class SynDetector:
    """Feed packet metadata dicts into process(). Finished windows are reported
    through the on_window callback."""

    def __init__(self, window_seconds=5, syn_threshold=100, per_source_threshold=80,
                 on_window=None, history=120):
        self.window = int(window_seconds)
        self.threshold = int(syn_threshold)
        self.per_source_threshold = int(per_source_threshold)
        self.on_window = on_window
        self._lock = threading.RLock()
        self._bucket = None
        self.total_packets = 0
        self.tcp_packets = 0
        self.syn_packets = 0
        self.suspicious_windows = 0
        self.windows_analyzed = 0
        self.sources = {}                  # ip -> {"syn", "tcp", "last_seen"}
        self.timeline = deque(maxlen=history)

    # ----- input -----
    def process(self, meta):
        """meta keys: timestamp, is_tcp(optional, default True), src, dst, sport,
        dport, flags."""
        done = []
        with self._lock:
            ts = meta["timestamp"]
            self._advance(ts, done)
            b = self._bucket
            b.total += 1
            self.total_packets += 1
            if meta.get("is_tcp", True):
                b.tcp += 1
                self.tcp_packets += 1
                src = meta["src"]
                info = self.sources.setdefault(src, {"syn": 0, "tcp": 0, "last_seen": ts})
                info["tcp"] += 1
                info["last_seen"] = ts
                if is_initial_syn(meta["flags"]):
                    b.syn += 1
                    b.syn_sources[src] += 1
                    self.syn_packets += 1
                    info["syn"] += 1
        self._emit(done)

    def tick(self, now):
        """Close the current window if time has moved past it (used in live mode)."""
        done = []
        with self._lock:
            if self._bucket and now >= self._bucket.start + self.window:
                done.append(self._close(self._bucket))
                self._bucket = None
        self._emit(done)

    def flush(self):
        done = []
        with self._lock:
            if self._bucket:
                done.append(self._close(self._bucket))
                self._bucket = None
        self._emit(done)

    # ----- internals -----
    def _advance(self, ts, done):
        ws = math.floor(ts / self.window) * self.window
        if self._bucket is None:
            self._bucket = _Bucket(ws)
        elif ws > self._bucket.start:
            done.append(self._close(self._bucket))
            self._bucket = _Bucket(ws)
        # ws < start (late packet): simply counted in the current window

    def _close(self, b):
        top = b.syn_sources.most_common(5)
        flagged = [ip for ip, n in b.syn_sources.items() if n >= self.per_source_threshold]
        reasons = []
        if b.syn >= self.threshold:
            reasons.append("total SYN count >= threshold")
        if flagged:
            reasons.append("single-source SYN count >= per-source threshold")
        max_src = top[0][1] if top else 0
        ratio = max(b.syn / self.threshold, max_src / self.per_source_threshold)
        suspicious = bool(reasons)
        result = {
            "window_start": b.start, "window_end": b.start + self.window,
            "window_seconds": self.window, "total_packets": b.total,
            "tcp_packets": b.tcp, "syn_count": b.syn,
            "unique_sources": len(b.syn_sources),
            "top_sources": [[ip, n] for ip, n in top],
            "flagged_sources": flagged, "reasons": reasons,
            "suspicious": suspicious,
            "severity": severity_for(ratio) if suspicious else "NONE",
            "threshold": self.threshold,
            "per_source_threshold": self.per_source_threshold,
        }
        self.windows_analyzed += 1
        if suspicious:
            self.suspicious_windows += 1
        self.timeline.append(result)
        return result

    def _emit(self, results):
        if self.on_window:
            for r in results:
                self.on_window(r)

    # ----- output -----
    def snapshot(self):
        from datetime import datetime
        with self._lock:
            top = sorted(self.sources.items(), key=lambda kv: kv[1]["syn"], reverse=True)[:15]
            cur = self._bucket
            return {
                "total_packets": self.total_packets,
                "tcp_packets": self.tcp_packets,
                "syn_packets": self.syn_packets,
                "unique_sources": len(self.sources),
                "suspicious_windows": self.suspicious_windows,
                "windows_analyzed": self.windows_analyzed,
                "current_window": {"start": cur.start, "syn": cur.syn} if cur else None,
                "sources": [{"ip": ip, "syn": v["syn"], "tcp": v["tcp"],
                             "last_seen": datetime.fromtimestamp(v["last_seen"]).strftime("%H:%M:%S")}
                            for ip, v in top],
                "timeline": [{"t": datetime.fromtimestamp(w["window_start"]).strftime("%H:%M:%S"),
                              "total": w["total_packets"], "tcp": w["tcp_packets"],
                              "syn": w["syn_count"], "suspicious": w["suspicious"]}
                             for w in self.timeline],
                "settings": {"window_seconds": self.window, "syn_threshold": self.threshold,
                             "per_source_threshold": self.per_source_threshold},
            }
