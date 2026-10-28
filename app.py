"""Flask application: dashboard pages + JSON API."""
import csv
import hmac
import logging
import os
import re
import uuid
from datetime import datetime
from logging.handlers import RotatingFileHandler

from flask import Flask, Response, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from config import Config, ensure_dirs
from database.db_manager import DBManager
from detector.alert_manager import AlertManager
from detector.packet_capture import MonitorError, MonitorManager, SCAPY_AVAILABLE, list_interfaces
from detector.pcap_analyzer import analyze_pcap
from detector.pcap_reader import PcapFormatError, check_magic

IFACE_RE = re.compile(r"^[\w\s.\-{}\\():/]{0,200}$")


def _int(data, key, default, lo, hi):
    raw = data.get(key, default)
    try:
        val = int(raw)
    except (TypeError, ValueError):
        raise ValueError("%s must be a whole number." % key)
    if not lo <= val <= hi:
        raise ValueError("%s must be between %d and %d." % (key, lo, hi))
    return val


def _settings(data, cfg):
    return (_int(data, "window_seconds", cfg["DEFAULT_WINDOW_SECONDS"], 1, 3600),
            _int(data, "syn_threshold", cfg["DEFAULT_SYN_THRESHOLD"], 1, 1_000_000),
            _int(data, "per_source_threshold", cfg["DEFAULT_PER_SOURCE_THRESHOLD"], 1, 1_000_000))


def _csv_safe(v):
    """Stop spreadsheet formula injection."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@"):
        return "'" + v
    return v


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    ensure_dirs(app.config)

    handler = RotatingFileHandler(os.path.join(app.config["LOG_DIR"], "app.log"),
                                  maxBytes=1_000_000, backupCount=3)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("syn_monitor")
    root.setLevel(logging.INFO)
    if not root.handlers:
        root.addHandler(handler)

    db = DBManager(app.config["DB_PATH"])
    alerts = AlertManager(db)
    monitor = MonitorManager(db, alerts)
    app.extensions["monitor"] = monitor
    app.extensions["db"] = db

    # ---------- optional login ----------
    @app.before_request
    def check_auth():
        user, pw = app.config["DASHBOARD_USER"], app.config["DASHBOARD_PASSWORD"]
        if not user or not pw:
            return None
        a = request.authorization
        if a and hmac.compare_digest(a.username or "", user) and \
                hmac.compare_digest(a.password or "", pw):
            return None
        return Response("Login required.", 401, {"WWW-Authenticate": 'Basic realm="SYN Monitor"'})

    def err(message, code=400):
        return jsonify({"error": message}), code

    # ---------- pages ----------
    @app.route("/")
    def index():
        return render_template("index.html", defaults=app.config)

    @app.route("/alerts")
    def alerts_page():
        return render_template("alerts.html")

    @app.route("/reports")
    def reports_page():
        return render_template("reports.html")

    # ---------- monitoring ----------
    @app.get("/api/status")
    def api_status():
        s = monitor.status()
        s["scapy_available"] = SCAPY_AVAILABLE
        s["defaults"] = {"window_seconds": app.config["DEFAULT_WINDOW_SECONDS"],
                         "syn_threshold": app.config["DEFAULT_SYN_THRESHOLD"],
                         "per_source_threshold": app.config["DEFAULT_PER_SOURCE_THRESHOLD"]}
        return jsonify(s)

    @app.get("/api/interfaces")
    def api_interfaces():
        return jsonify({"interfaces": list_interfaces(), "scapy_available": SCAPY_AVAILABLE})

    @app.post("/api/monitor/start")
    def api_start():
        data = request.get_json(silent=True) or {}
        mode = data.get("mode", "simulation")
        if mode not in ("live", "simulation"):
            return err("mode must be 'live' or 'simulation'.")
        iface = str(data.get("interface", "") or "").strip()
        if not IFACE_RE.match(iface):
            return err("Invalid interface name.")
        try:
            window, thr, per = _settings(data, app.config)
            sid = monitor.start(mode, iface, window, thr, per)
        except ValueError as exc:
            return err(str(exc))
        except MonitorError as exc:
            return err(exc.message, exc.status)
        return jsonify({"message": "Monitoring started.", "session_id": sid})

    @app.post("/api/monitor/stop")
    def api_stop():
        try:
            monitor.stop()
        except MonitorError as exc:
            return err(exc.message, exc.status)
        return jsonify({"message": "Monitoring stopped."})

    @app.get("/api/statistics")
    def api_statistics():
        stats = monitor.status()["stats"]
        if not stats:
            return jsonify({"timeline": [], "sources": [], "settings": None,
                            "current_window": None})
        return jsonify({k: stats[k] for k in ("timeline", "sources", "settings", "current_window")})

    # ---------- alerts ----------
    @app.get("/api/alerts")
    def api_alerts():
        limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
        include_hidden = request.args.get("include_cleared") == "1"
        return jsonify({"alerts": db.list_alerts(limit, include_hidden)})

    @app.post("/api/alerts/<int:alert_id>/acknowledge")
    def api_ack(alert_id):
        db.acknowledge_alert(alert_id)
        return jsonify({"message": "Alert acknowledged."})

    @app.post("/api/alerts/clear")
    def api_clear():
        data = request.get_json(silent=True) or {}
        db.hide_alerts(data.get("id"))
        return jsonify({"message": "Alerts cleared from display (history kept)."})

    # ---------- reports ----------
    @app.get("/api/reports")
    def api_reports():
        only = request.args.get("suspicious_only") == "1"
        return jsonify({"sessions": db.list_sessions(50),
                        "windows": db.list_windows(200, only)})

    @app.get("/api/reports/export")
    def api_export():
        rows = db.export_rows()
        name = "syn_report_%s.csv" % datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(app.config["REPORTS_DIR"], name)
        cols = ["session_id", "mode", "source_label", "session_started", "window_start",
                "window_end", "window_seconds", "syn_threshold", "per_source_threshold",
                "total_packets", "tcp_packets", "syn_count", "unique_sources",
                "detection_status", "severity", "top_sources"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for r in rows:
                w.writerow({c: _csv_safe(r.get(c)) for c in cols})
        return send_file(path, mimetype="text/csv", as_attachment=True, download_name=name)

    # ---------- offline PCAP ----------
    @app.post("/api/pcap/analyze")
    def api_pcap():
        f = request.files.get("file")
        if not f or not f.filename:
            return err("No file uploaded.")
        label = secure_filename(f.filename)[:80] or "upload"
        if os.path.splitext(label)[1].lower() not in app.config["ALLOWED_EXTENSIONS"]:
            return err("Only .pcap, .pcapng or .cap files are allowed.")
        try:
            window, thr, per = _settings(request.form, app.config)
        except ValueError as exc:
            return err(str(exc))
        tmp = os.path.join(app.config["UPLOAD_DIR"], uuid.uuid4().hex + ".bin")  # server-chosen name
        f.save(tmp)
        try:
            check_magic(tmp)
            result = analyze_pcap(tmp, window, thr, per, app.config["MAX_PCAP_PACKETS"])
        except PcapFormatError as exc:
            return err(str(exc), 422)
        except Exception:
            logging.getLogger("syn_monitor").exception("pcap analysis failed")
            return err("Could not analyze the file. It may be corrupt.", 422)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
        sid = db.create_session("pcap", label, window, thr, per)
        for w in result.pop("_windows"):
            alerts.handle_window(sid, w)
        db.finish_session(sid, "completed", result.pop("_totals_raw"))
        result["session_id"] = sid
        result["filename"] = label
        return jsonify(result)

    # ---------- errors ----------
    @app.errorhandler(413)
    def too_big(_e):
        return err("File too large (limit %d MB)." % (app.config["MAX_CONTENT_LENGTH"] // 1048576), 413)

    @app.errorhandler(404)
    def not_found(_e):
        return err("Not found.", 404)

    @app.errorhandler(500)
    def server_error(_e):
        return err("Internal server error.", 500)

    return app


if __name__ == "__main__":
    application = create_app()
    print("SYN Flood Detection & Monitoring - open http://%s:%d" %
          (application.config["HOST"], application.config["PORT"]))
    application.run(host=application.config["HOST"], port=application.config["PORT"],
                    debug=False, threaded=True)
