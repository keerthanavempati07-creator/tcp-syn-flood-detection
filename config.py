"""Central configuration. Change values here (or use environment variables)."""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    BASE_DIR = BASE_DIR
    # Generated files are kept OUTSIDE the source folders
    DB_PATH = os.path.join(BASE_DIR, "data", "syn_monitor.db")
    LOG_DIR = os.path.join(BASE_DIR, "logs")
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")
    UPLOAD_DIR = os.path.join(BASE_DIR, "data", "uploads_tmp")

    # Upload safety
    ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024      # 50 MB
    MAX_PCAP_PACKETS = 1_000_000               # stop reading after this many packets

    # Detection defaults (experimental values - tune for YOUR network)
    DEFAULT_WINDOW_SECONDS = 5
    DEFAULT_SYN_THRESHOLD = 100                # total initial SYNs per window
    DEFAULT_PER_SOURCE_THRESHOLD = 80          # initial SYNs from ONE source per window

    # Web server: localhost only by default
    HOST = os.environ.get("SYN_HOST", "127.0.0.1")
    PORT = int(os.environ.get("SYN_PORT", "5000"))

    # Optional login (HTTP Basic). Set both to enable.
    DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "")
    DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")


def ensure_dirs(cfg):
    for key in ("LOG_DIR", "REPORTS_DIR", "UPLOAD_DIR"):
        os.makedirs(cfg[key], exist_ok=True)
    os.makedirs(os.path.dirname(cfg["DB_PATH"]), exist_ok=True)
