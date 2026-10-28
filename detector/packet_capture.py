"""Background monitoring worker (live capture with Scapy, or safe simulation).

Packet capture runs in its own thread - never inside a Flask request handler.
Only ONE worker can run at a time.
"""
import logging
import random
import threading
import time

from detector.syn_detector import SynDetector

log = logging.getLogger("syn_monitor.capture")

try:                                   # Scapy is optional: only needed for live mode
    from scapy.all import IP, IPv6, TCP, AsyncSniffer, get_if_list
    SCAPY_AVAILABLE = True
except Exception:                      # ImportError or missing Npcap/libpcap
    SCAPY_AVAILABLE = False


class MonitorError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


def list_interfaces():
    if not SCAPY_AVAILABLE:
        return []
    try:
        return list(get_if_list())
    except Exception:
        return []


def packet_to_meta(pkt):
    ts = float(pkt.time)
    if pkt.haslayer(TCP):
        layer = pkt[IP] if pkt.haslayer(IP) else (pkt[IPv6] if pkt.haslayer(IPv6) else None)
        if layer is not None:
            tcp = pkt[TCP]
            return {"timestamp": ts, "is_tcp": True, "src": layer.src, "dst": layer.dst,
                    "sport": int(tcp.sport), "dport": int(tcp.dport), "flags": int(tcp.flags)}
    return {"timestamp": ts, "is_tcp": False}


class MonitorManager:
    def __init__(self, db, alerts):
        self.db = db
        self.alerts = alerts
        self._lock = threading.Lock()
        self._thread = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self.detector = None
        self.session_id = None
        self.state = "stopped"          # stopped | running | error
        self.mode = None
        self.interface = None
        self.error = None
        self.started_at = None

    # ----- public API -----
    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self, mode, interface, window, threshold, per_source):
        with self._lock:
            if self.is_running():
                raise MonitorError("Monitoring is already running.", 409)
            if mode == "live" and not SCAPY_AVAILABLE:
                raise MonitorError(
                    "Scapy/Npcap is not available. Install it with 'pip install scapy' "
                    "(and Npcap on Windows) - or use Simulation mode.", 503)
            label = interface or ("default interface" if mode == "live" else "synthetic")
            self.session_id = self.db.create_session(mode, label, window, threshold, per_source)
            sid = self.session_id
            self.detector = SynDetector(
                window, threshold, per_source,
                on_window=lambda r: self.alerts.handle_window(sid, r))
            self.mode, self.interface, self.error = mode, interface, None
            self._stop.clear()
            self._ready.clear()
            target = self._run_live if mode == "live" else self._run_simulation
            self._thread = threading.Thread(target=target, name="monitor-worker", daemon=True)
            self._thread.start()
            self._ready.wait(timeout=4)        # wait for start-up success / failure
            if self.error:
                self._thread.join(timeout=3)
                self.db.finish_session(sid, "failed", self.detector.snapshot())
                self.state = "error"
                raise MonitorError(self.error, 500)
            self.state = "running"
            self.started_at = time.time()
            return sid

    def stop(self):
        with self._lock:
            if not self.is_running():
                raise MonitorError("Monitoring is not running.", 409)
            self._stop.set()
            self._thread.join(timeout=8)
            self.detector.flush()
            self.db.finish_session(self.session_id, "completed", self.detector.snapshot())
            self.state = "stopped"

    def status(self):
        running = self.is_running()
        if self.state == "running" and not running:     # worker died by itself
            self.state = "error"
        snap = self.detector.snapshot() if self.detector else None
        return {"state": self.state, "running": running, "mode": self.mode,
                "interface": self.interface, "session_id": self.session_id,
                "error": self.error,
                "uptime_seconds": int(time.time() - self.started_at)
                if running and self.started_at else 0,
                "stats": snap}

    # ----- workers -----
    def _fail(self, message):
        log.error(message)
        self.error = message
        self._ready.set()

    def _run_live(self):
        det = self.detector
        sniffer = None
        try:
            def handle(pkt):
                try:
                    det.process(packet_to_meta(pkt))
                except Exception:
                    log.exception("packet error")
            sniffer = AsyncSniffer(iface=self.interface or None, prn=handle, store=False)
            sniffer.start()
            time.sleep(1.0)
            if not sniffer.running:
                exc = getattr(sniffer, "exception", None)
                self._fail("Could not start packet capture (%s). Windows: install Npcap and run "
                           "the terminal as Administrator. Linux/macOS: run with sudo. Check the "
                           "interface name." % (exc or "permission or interface problem"))
                return
            self._ready.set()
            while not self._stop.wait(1.0):
                det.tick(time.time())
                if not sniffer.running:
                    self.error = "Packet capture stopped unexpectedly."
                    return
        except PermissionError:
            self._fail("Permission denied. Run as Administrator (Windows) or with sudo (Linux).")
        except Exception as exc:
            self._fail("Capture error: %s" % exc)
        finally:
            if sniffer is not None:
                try:
                    if sniffer.running:
                        sniffer.stop()
                except Exception:
                    pass

    def _run_simulation(self):
        """Feeds SYNTHETIC metadata (no real packets exist) into the detector.
        Pattern: 12 s normal, 10 s burst from one test address, repeat every 30 s."""
        det = self.detector
        clients = ["192.168.1.%d" % i for i in range(10, 16)]
        burst_src = "203.0.113.50"          # TEST-NET-3 documentation address
        self._ready.set()
        t0 = time.time()
        while not self._stop.wait(0.2):
            now = time.time()
            phase = (now - t0) % 30
            for _ in range(random.randint(0, 2)):                  # normal SYNs
                det.process({"timestamp": now, "src": random.choice(clients),
                             "dst": "192.168.1.1", "sport": random.randint(40000, 60000),
                             "dport": 443, "flags": 0x02})
            for _ in range(random.randint(8, 20)):                 # ordinary data/ACK
                det.process({"timestamp": now, "src": random.choice(clients),
                             "dst": "192.168.1.1", "sport": 50000, "dport": 443, "flags": 0x10})
            if random.random() < 0.3:                              # some non-TCP packets
                det.process({"timestamp": now, "is_tcp": False})
            if 12 <= phase < 22:                                   # synthetic burst
                for _ in range(8):
                    det.process({"timestamp": now, "src": burst_src, "dst": "192.168.1.1",
                                 "sport": random.randint(1024, 65000), "dport": 80,
                                 "flags": 0x02})
            det.tick(now)
