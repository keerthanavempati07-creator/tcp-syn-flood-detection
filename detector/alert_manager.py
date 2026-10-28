"""Turns suspicious windows into alerts and avoids duplicate alerts.

Rule: if a suspicious window directly follows the previous suspicious window of the
same session, it is MERGED into the existing alert (repeat_count + 1) instead of
creating a new alert. Every window is still stored in the `windows` table.
"""
import logging

log = logging.getLogger("syn_monitor.alerts")


class AlertManager:
    def __init__(self, db):
        self.db = db
        self._last = {}   # session_id -> {"alert_id": int, "window_end": float}

    def handle_window(self, session_id, r):
        self.db.add_window(session_id, r)
        if not r["suspicious"]:
            return None
        last = self._last.get(session_id)
        if last and r["window_start"] <= last["window_end"] + 0.001:
            self.db.update_alert_repeat(last["alert_id"], r)
            last["window_end"] = r["window_end"]
            return last["alert_id"]
        message = ("Suspicious SYN activity: %d initial SYN packets in %ds (threshold %d). "
                   "This is NOT a confirmed attack - verify with Wireshark/logs."
                   % (r["syn_count"], r["window_seconds"], r["threshold"]))
        alert_id = self.db.add_alert(session_id, r, message)
        self._last[session_id] = {"alert_id": alert_id, "window_end": r["window_end"]}
        log.warning("ALERT #%s %s: %s", alert_id, r["severity"], message)
        return alert_id
