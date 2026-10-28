"""Run all tests:  python -m unittest discover -s tests -v"""
import csv
import io
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import make_samples                                   # noqa: E402
from app import create_app                            # noqa: E402
from database.db_manager import DBManager             # noqa: E402
from detector.alert_manager import AlertManager       # noqa: E402
from detector.pcap_analyzer import analyze_pcap       # noqa: E402
from detector.pcap_reader import PcapFormatError      # noqa: E402
from detector.syn_detector import SynDetector         # noqa: E402

SAMPLES = os.path.join(ROOT, "sample_data")


def pkt(ts, src="10.0.0.1", flags=0x02):
    return {"timestamp": ts, "src": src, "dst": "10.0.0.99", "sport": 1234, "dport": 80,
            "flags": flags}


def run(packets, window=5, thr=10, per=8):
    out = []
    d = SynDetector(window, thr, per, on_window=out.append)
    for p in packets:
        d.process(p)
    d.flush()
    return d, out


class DetectorTests(unittest.TestCase):
    def test_1_normal_tcp_traffic(self):
        d, w = run([pkt(100 + i * .1, flags=0x18) for i in range(50)])
        self.assertEqual(d.syn_packets, 0)
        self.assertFalse(any(x["suspicious"] for x in w))

    def test_2_non_syn_packets_ignored(self):
        flags = [0x10, 0x12, 0x11, 0x04, 0x18]          # ACK, SYN+ACK, FIN+ACK, RST, PSH+ACK
        d, _ = run([pkt(100 + i * .01, flags=f) for i in range(100) for f in flags])
        self.assertEqual(d.syn_packets, 0)

    def test_3_syn_below_threshold(self):
        d, w = run([pkt(100 + i * .1) for i in range(5)])
        self.assertEqual(d.syn_packets, 5)
        self.assertFalse(w[0]["suspicious"])

    def test_4_syn_above_threshold(self):
        _, w = run([pkt(100 + i * .01) for i in range(30)])
        self.assertTrue(w[0]["suspicious"])
        self.assertEqual(w[0]["syn_count"], 30)

    def test_5_multiple_sources(self):
        # 6 sources x 3 SYN = 18 total (>=10) but nobody reaches the per-source limit (8)
        pk = [pkt(100 + i * .01 + j * .001, src="10.0.0.%d" % j) for j in range(6) for i in range(3)]
        d, w = run(pk)
        self.assertTrue(w[0]["suspicious"])
        self.assertEqual(w[0]["unique_sources"], 6)
        self.assertEqual(w[0]["flagged_sources"], [])
        self.assertEqual(d.snapshot()["unique_sources"], 6)

    def test_10_repeated_windows_dedup(self):
        db = DBManager(os.path.join(tempfile.mkdtemp(), "t.db"))
        am = AlertManager(db)
        sid = db.create_session("pcap", "t", 5, 10, 8)
        _, w = run([pkt(100 + i * .1) for i in range(30)] + [pkt(105 + i * .1) for i in range(30)]
                   + [pkt(130 + i * .1) for i in range(30)])        # two consecutive + one later
        for r in w:
            am.handle_window(sid, r)
        alerts = db.list_alerts()
        self.assertEqual(len(alerts), 2)                             # 3 suspicious windows -> 2 alerts
        self.assertEqual(sorted(a["repeat_count"] for a in alerts), [1, 2])
        self.assertEqual(len(db.list_windows()), 3)                  # history keeps every window


class PcapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        make_samples.OUT = SAMPLES
        os.makedirs(SAMPLES, exist_ok=True)
        import random
        random.seed(7)
        make_samples.write_pcap("normal_traffic.pcap", make_samples.normal_traffic())
        p = make_samples.normal_traffic()
        make_samples.add_burst(p, ["203.0.113.50"], 20, 10, 40)
        make_samples.write_pcap("single_source_burst.pcap", p)
        with open(os.path.join(SAMPLES, "invalid_file.pcap"), "wb") as f:
            f.write(b"this is not a capture file")
        import struct
        with open(os.path.join(SAMPLES, "empty_capture.pcap"), "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def test_normal_pcap(self):
        r = analyze_pcap(os.path.join(SAMPLES, "normal_traffic.pcap"), 5, 100, 80)
        self.assertEqual(r["totals"]["suspicious_windows"], 0)
        self.assertGreater(r["totals"]["syn_packets"], 0)

    def test_burst_pcap(self):
        r = analyze_pcap(os.path.join(SAMPLES, "single_source_burst.pcap"), 5, 100, 80)
        self.assertGreaterEqual(r["totals"]["suspicious_windows"], 2)
        self.assertEqual(r["suspicious"][0]["top_sources"][0][0], "203.0.113.50")

    def test_6_invalid_and_empty_pcap(self):
        with self.assertRaises(PcapFormatError):
            analyze_pcap(os.path.join(SAMPLES, "invalid_file.pcap"), 5, 100, 80)
        with self.assertRaises(PcapFormatError):
            analyze_pcap(os.path.join(SAMPLES, "empty_capture.pcap"), 5, 100, 80)


class ApiTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.app = create_app({"TESTING": True, "DB_PATH": os.path.join(tmp, "t.db"),
                               "LOG_DIR": tmp, "REPORTS_DIR": tmp, "UPLOAD_DIR": tmp})
        self.c = self.app.test_client()

    def tearDown(self):
        m = self.app.extensions["monitor"]
        if m.is_running():
            m.stop()

    def test_7_start_stop_and_no_double_worker(self):
        self.assertEqual(self.c.post("/api/monitor/start", json={"mode": "simulation"}).status_code, 200)
        self.assertEqual(self.c.post("/api/monitor/start", json={"mode": "simulation"}).status_code, 409)
        self.assertEqual(self.c.post("/api/monitor/stop").status_code, 200)
        self.assertEqual(self.c.post("/api/monitor/stop").status_code, 409)

    def test_7b_validation(self):
        self.assertEqual(self.c.post("/api/monitor/start", json={"mode": "bad"}).status_code, 400)
        self.assertEqual(self.c.post("/api/monitor/start",
                                     json={"mode": "simulation", "window_seconds": 0}).status_code, 400)

    def test_frontend_and_backend_are_served_together(self):
        for path, marker in (("/", b'data-page="dashboard"'),
                             ("/alerts", b'data-page="alerts"'),
                             ("/reports", b'data-page="reports"')):
            response = self.c.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(marker, response.data)

        script = self.c.get("/static/js/dashboard.js")
        self.assertEqual(script.status_code, 200)
        self.assertIn(b'fetch(url, opts)', script.data)
        script.close()

        self.assertIn("state", self.c.get("/api/status").get_json())
        self.assertIn("interfaces", self.c.get("/api/interfaces").get_json())
        self.assertIn("timeline", self.c.get("/api/statistics").get_json())
        self.assertIn("alerts", self.c.get("/api/alerts").get_json())
        self.assertIn("sessions", self.c.get("/api/reports").get_json())

    def test_9_dashboard_updates(self):
        self.c.post("/api/monitor/start", json={"mode": "simulation", "window_seconds": 1,
                                                "syn_threshold": 3, "per_source_threshold": 3})
        time.sleep(2.6)
        s = self.c.get("/api/status").get_json()
        self.assertTrue(s["running"])
        self.assertGreater(s["stats"]["total_packets"], 0)
        self.assertIn("timeline", self.c.get("/api/statistics").get_json())

    def test_8_database_and_csv_export(self):
        path = os.path.join(SAMPLES, "single_source_burst.pcap")
        with open(path, "rb") as f:
            r = self.c.post("/api/pcap/analyze", data={"file": (io.BytesIO(f.read()), "x.pcap")},
                            content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200)
        self.assertGreater(r.get_json()["totals"]["suspicious_windows"], 0)
        self.assertGreater(len(self.c.get("/api/reports").get_json()["sessions"]), 0)
        resp = self.c.get("/api/reports/export")
        rows = list(csv.DictReader(io.StringIO(resp.data.decode())))
        self.assertTrue(any(x["detection_status"] == "suspicious" for x in rows))
        resp.close()

    def test_alert_ack_and_clear_keep_history(self):
        self.c.post("/api/pcap/analyze", data={"file": (io.BytesIO(open(
            os.path.join(SAMPLES, "single_source_burst.pcap"), "rb").read()), "x.pcap")},
            content_type="multipart/form-data")
        a = self.c.get("/api/alerts").get_json()["alerts"]
        self.c.post("/api/alerts/%d/acknowledge" % a[0]["id"])
        self.c.post("/api/alerts/clear", json={})
        self.assertEqual(self.c.get("/api/alerts").get_json()["alerts"], [])
        kept = self.c.get("/api/alerts?include_cleared=1").get_json()["alerts"]
        self.assertEqual(len(kept), len(a))
        self.assertEqual(kept[0]["status"], "acknowledged")

    def test_upload_rejects_bad_files(self):
        r = self.c.post("/api/pcap/analyze", data={"file": (io.BytesIO(b"hello"), "a.txt")},
                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)
        r = self.c.post("/api/pcap/analyze", data={"file": (io.BytesIO(b"not a pcap"), "a.pcap")},
                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 422)
        self.assertEqual(self.c.post("/api/pcap/analyze").status_code, 400)


if __name__ == "__main__":
    unittest.main()
