# TCP SYN Flood Detection and Monitoring System

A beginner-friendly cybersecurity mini project (Python + Flask + Scapy + SQLite + Chart.js).
It **detects and reports** suspicious TCP SYN activity. It contains **no attack or flooding code**.

> Only monitor networks you are authorised to monitor. High SYN activity is *suspicious*, not proof of
> an attack. Thresholds are experimental values - tune them for your own network.

## 1. Quick start (5 minutes, works without admin rights)

Requires **Python 3.9+** (https://www.python.org/downloads/ - tick "Add Python to PATH" on Windows).

### Windows (PowerShell / CMD)
```
cd tcp-syn-flood-detection
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python tests\make_samples.py
python app.py
```
If PowerShell blocks activation: `Set-ExecutionPolicy -Scope Process Bypass`, then activate again.

### Linux / macOS
```
cd tcp-syn-flood-detection
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python tests/make_samples.py
python app.py
```
Open **http://127.0.0.1:5000** in your browser.

Expected console output: `SYN Flood Detection & Monitoring - open http://127.0.0.1:5000`

## 2. Try it (no network needed)
1. **Simulation mode:** choose *Simulation*, click **Start**. After ~15 s the synthetic burst creates
   suspicious windows (amber bars) and an alert. Click **Stop**.
2. **PCAP analysis:** on the dashboard, upload `sample_data/single_source_burst.pcap` -> *Analyze*.
   Try `normal_traffic.pcap` (no alerts) and `multi_source_burst.pcap` (total threshold only).
   `invalid_file.pcap` and `empty_capture.pcap` show the error messages.
3. **Alerts page:** Acknowledge / Clear (clearing only hides; history is kept).
4. **Reports page:** view sessions/windows and **Export CSV** (also saved in `reports/`).

## 3. Live capture (optional)
Needs Scapy (already in requirements) plus packet-capture permissions:
- **Windows:** install **Npcap** (https://npcap.com, tick "WinPcap API-compatible mode"), then run the terminal **as Administrator**.
- **Linux:** `sudo venv/bin/python app.py` (or grant `cap_net_raw` to Python).
- **macOS:** `sudo venv/bin/python app.py`.

Choose *Live capture*, optionally pick an interface name, click **Start**. If capture cannot start, a clear
error message is shown (missing Scapy, missing Npcap, permission denied, wrong interface).
For harmless test traffic on your own machine just browse any website or run `curl http://localhost`.
Verify the same packets in **Wireshark** with the display filter `tcp.flags.syn==1 && tcp.flags.ack==0`.

## 4. Run the tests
```
python -m unittest discover -s tests -v
```
15 tests cover: normal TCP, non-SYN packets, below/above threshold, multiple sources, invalid/empty PCAP,
start/stop + no duplicate workers, database + CSV export, dashboard API updates, alert deduplication,
acknowledge/clear keeping history, upload validation.

## 5. Project structure
```
app.py                     Flask app: pages + JSON API
config.py                  Settings (thresholds, limits, paths)
detector/syn_detector.py   Time-window detection engine (the core algorithm)
detector/alert_manager.py  Alert creation + de-duplication
detector/packet_capture.py Background worker: live (Scapy) or simulation
detector/pcap_reader.py    Safe pure-Python PCAP/PCAPNG parser
detector/pcap_analyzer.py  Offline analysis
database/db_manager.py     SQLite (parameterized queries)
templates/ static/         Dashboard (HTML/CSS/JS + Chart.js)
data/ logs/ reports/       Generated DB, logs, CSV reports (kept outside source code)
sample_data/ tests/        Synthetic captures and unit tests
docs/                      Architecture, report, viva Q&A, troubleshooting
```

## 6. API
Flask serves both the HTML frontend and the `/api/*` backend from the same origin;
no separate frontend server or CORS configuration is needed. The dashboard JavaScript
uses these endpoints for monitoring, alerts, reports, and PCAP analysis.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | /api/status | Monitoring state + live statistics |
| POST | /api/monitor/start | JSON: mode, interface, window_seconds, syn_threshold, per_source_threshold |
| POST | /api/monitor/stop | Stop worker (409 if not running) |
| GET | /api/alerts | Alerts (`?include_cleared=1`) |
| POST | /api/alerts/&lt;id&gt;/acknowledge, /api/alerts/clear | Display-only changes |
| GET | /api/statistics | Chart data + source table |
| GET | /api/reports, /api/reports/export | History / CSV download |
| POST | /api/pcap/analyze | Multipart upload (`file`) - offline analysis |

## 7. Detection algorithm (summary)
1. Read a packet (live / simulated / from PCAP). 2. Keep only IPv4/IPv6 TCP packets.
3. *Initial SYN* = SYN flag set **and** ACK flag not set (SYN+ACK is a server reply). 4. Put the packet
into a fixed time window (default 5 s). 5. Count SYNs per window and per source IP.
6. Window is **suspicious** if total SYNs >= threshold (default 100) **or** one source >= per-source
threshold (default 80). 7. Store the window in SQLite; severity = LOW/MEDIUM/HIGH by ratio to threshold
(<2x / 2-5x / >=5x). 8. Consecutive suspicious windows are merged into one alert (no alert spam).

## 8. Security notes
Binds to 127.0.0.1 by default. Optional login: set `DASHBOARD_USER` and `DASHBOARD_PASSWORD`
environment variables (HTTP Basic - use HTTPS if exposed beyond localhost). Uploads: extension, magic bytes
and 50 MB limit checked; stored under a random server-chosen name and deleted right after analysis.
SQL is parameterized; all dynamic text is HTML-escaped; CSV cells are protected against formula injection.

## 9. Offline charts
Chart.js loads from a CDN. For fully offline use, download
`https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js` to `static/js/chart.umd.min.js` and change the
script tag at the bottom of `templates/index.html` to `{{ url_for('static', filename='js/chart.umd.min.js') }}`.

## 10. College demo script (10 minutes)
1. Explain architecture (docs/ARCHITECTURE.md). 2. Show Wireshark filter `tcp.flags.syn==1 && tcp.flags.ack==0`.
3. Start Simulation, show amber suspicious windows + alert. 4. Upload the three sample PCAPs.
5. Acknowledge/clear an alert, show history remains. 6. Export CSV. 7. Show test run (15 OK).
8. State limitations: threshold-based, not proof of attack, no spoofed-source attribution.
# tcp-syn-flood-detection
