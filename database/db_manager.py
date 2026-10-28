"""SQLite storage. Every query is parameterized (no string-built SQL)."""
import json
import os
import sqlite3
from datetime import datetime


def fmt_ts(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mode TEXT NOT NULL,                -- live | simulation | pcap
    source_label TEXT,                 -- interface name or uploaded file label
    started_at TEXT NOT NULL,
    ended_at TEXT,
    window_seconds INTEGER NOT NULL,
    syn_threshold INTEGER NOT NULL,
    per_source_threshold INTEGER NOT NULL,
    status TEXT NOT NULL,              -- running | completed | failed
    total_packets INTEGER DEFAULT 0,
    tcp_packets INTEGER DEFAULT 0,
    syn_packets INTEGER DEFAULT 0,
    suspicious_windows INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    total_packets INTEGER, tcp_packets INTEGER, syn_count INTEGER,
    unique_sources INTEGER,
    suspicious INTEGER NOT NULL,
    severity TEXT,
    detection_status TEXT NOT NULL,    -- normal | suspicious
    top_sources TEXT                   -- JSON list of [ip, syn_count]
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    window_start TEXT, window_end TEXT,
    syn_count INTEGER, max_syn_count INTEGER,
    threshold INTEGER, per_source_threshold INTEGER, window_seconds INTEGER,
    sources TEXT,                      -- JSON list of [ip, syn_count]
    repeat_count INTEGER DEFAULT 1,    -- how many consecutive windows were merged
    status TEXT NOT NULL DEFAULT 'new',-- new | acknowledged
    hidden INTEGER NOT NULL DEFAULT 0, -- 1 = cleared from display (record is kept)
    message TEXT
);
"""

SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


class DBManager:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _run(self, sql, params=()):
        conn = self._conn()
        try:
            with conn:
                return conn.execute(sql, params).lastrowid
        finally:
            conn.close()

    def _all(self, sql, params=()):
        conn = self._conn()
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    # ---------- sessions ----------
    def create_session(self, mode, label, window, thr, per_src):
        return self._run(
            "INSERT INTO sessions (mode, source_label, started_at, window_seconds,"
            " syn_threshold, per_source_threshold, status) VALUES (?,?,?,?,?,?,'running')",
            (mode, label, now_str(), window, thr, per_src))

    def finish_session(self, session_id, status, stats=None):
        stats = stats or {}
        self._run(
            "UPDATE sessions SET ended_at=?, status=?, total_packets=?, tcp_packets=?,"
            " syn_packets=?, suspicious_windows=? WHERE id=?",
            (now_str(), status, stats.get("total_packets", 0), stats.get("tcp_packets", 0),
             stats.get("syn_packets", 0), stats.get("suspicious_windows", 0), session_id))

    def list_sessions(self, limit=50):
        return self._all("SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,))

    # ---------- windows ----------
    def add_window(self, session_id, r):
        self._run(
            "INSERT INTO windows (session_id, window_start, window_end, total_packets,"
            " tcp_packets, syn_count, unique_sources, suspicious, severity, detection_status,"
            " top_sources) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (session_id, fmt_ts(r["window_start"]), fmt_ts(r["window_end"]), r["total_packets"],
             r["tcp_packets"], r["syn_count"], r["unique_sources"], int(r["suspicious"]),
             r["severity"], "suspicious" if r["suspicious"] else "normal",
             json.dumps(r["top_sources"])))

    def list_windows(self, limit=200, suspicious_only=False):
        sql = "SELECT * FROM windows"
        if suspicious_only:
            sql += " WHERE suspicious=1"
        return self._all(sql + " ORDER BY id DESC LIMIT ?", (limit,))

    # ---------- alerts ----------
    def add_alert(self, session_id, r, message):
        return self._run(
            "INSERT INTO alerts (session_id, created_at, updated_at, severity, window_start,"
            " window_end, syn_count, max_syn_count, threshold, per_source_threshold,"
            " window_seconds, sources, message) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (session_id, now_str(), now_str(), r["severity"], fmt_ts(r["window_start"]),
             fmt_ts(r["window_end"]), r["syn_count"], r["syn_count"], r["threshold"],
             r["per_source_threshold"], r["window_seconds"], json.dumps(r["top_sources"]),
             message))

    def update_alert_repeat(self, alert_id, r):
        rows = self._all("SELECT severity, max_syn_count FROM alerts WHERE id=?", (alert_id,))
        if not rows:
            return
        old = rows[0]
        sev = r["severity"] if SEV_ORDER[r["severity"]] > SEV_ORDER[old["severity"]] else old["severity"]
        self._run(
            "UPDATE alerts SET updated_at=?, window_end=?, repeat_count=repeat_count+1,"
            " max_syn_count=?, severity=?, sources=? WHERE id=?",
            (now_str(), fmt_ts(r["window_end"]), max(old["max_syn_count"], r["syn_count"]),
             sev, json.dumps(r["top_sources"]), alert_id))

    def list_alerts(self, limit=100, include_hidden=False):
        sql = "SELECT * FROM alerts"
        if not include_hidden:
            sql += " WHERE hidden=0"
        return self._all(sql + " ORDER BY id DESC LIMIT ?", (limit,))

    def acknowledge_alert(self, alert_id):
        self._run("UPDATE alerts SET status='acknowledged' WHERE id=?", (alert_id,))

    def hide_alerts(self, alert_id=None):
        """'Clear' only hides alerts from the dashboard. Nothing is deleted."""
        if alert_id is None:
            self._run("UPDATE alerts SET hidden=1")
        else:
            self._run("UPDATE alerts SET hidden=1 WHERE id=?", (alert_id,))

    # ---------- export ----------
    def export_rows(self):
        return self._all(
            "SELECT s.id AS session_id, s.mode, s.source_label, s.started_at AS session_started,"
            " w.window_start, w.window_end, s.window_seconds, s.syn_threshold,"
            " s.per_source_threshold, w.total_packets, w.tcp_packets, w.syn_count,"
            " w.unique_sources, w.detection_status, w.severity, w.top_sources"
            " FROM windows w JOIN sessions s ON s.id = w.session_id ORDER BY w.id")
